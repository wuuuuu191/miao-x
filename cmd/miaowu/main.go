// miaowu —— 妙妙屋X 架构复刻：单二进制双模式（master / agent）。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v3"

	"miao-x/internal/agent"
	"miao-x/internal/auth"
	"miao-x/internal/master"
	"miao-x/internal/securechan"
	"miao-x/internal/storage"
	"miao-x/internal/subparser"
	"miao-x/internal/subscribe"
)

//go:embed web/dist
var webFS embed.FS

type Config struct {
	Mode          string `yaml:"mode"`            // master | agent
	Port          string `yaml:"port"`            // master 监听端口
	DataDir       string `yaml:"data_dir"`        // 数据目录(默认 ./data)
	MasterServer  string `yaml:"master_server"`   // agent: 主控地址
	Token         string `yaml:"token"`           // agent: 服务器 token
	MasterPubKey  string `yaml:"master_pub_key"`  // agent: 主控公钥
	ListenPort    int    `yaml:"listen_port"`     // agent: 本地管理端口
	XrayPath      string `yaml:"xray_path"`       // agent: xray 路径
	XrayConfigDir string `yaml:"xray_config_dir"` // agent: xray 配置目录
	// SSL（面板 https，同 3X-UI 的域名证书模式）：
	//  - cert_file+key_file: 直接使用用户提供的证书
	//  - domain(+email):     内置 ACME(HTTP-01) 自动申请/续期, 证书存 data/certs
	//  - 都为空:             纯 HTTP
	Domain   string `yaml:"domain"`
	Email    string `yaml:"email"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// M3: 面板对外基础 URL（如 https://panel.example.com）—— 设置后订阅链接以它为准，
	// 不再信任 X-Forwarded-* 头。留空则用请求 Host。
	PublicBaseURL string `yaml:"public_base_url"`
}

// validUsername M2: 用户名白名单 —— 防头部注入/命名空间冲突（__global__ 为系统保留字）
func validUsername(name string) bool {
	if name == "__global__" {
		return false
	}
	if len(name) < 3 || len(name) > 32 {
		return false
	}
	for _, c := range name {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func main() {
	cfgPath := flag.String("c", "config.yaml", "配置文件路径")
	flag.Parse()

	cfg := loadConfig(*cfgPath)
	switch cfg.Mode {
	case "agent", "remote":
		runAgent(cfg)
	default:
		runMaster(cfg)
	}
}

func loadConfig(path string) Config {
	cfg := Config{Mode: "master", Port: "12889", DataDir: "./data", ListenPort: 62789,
		XrayPath: "", XrayConfigDir: "./xray-config"}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("配置解析失败: %v", err)
		}
	} else {
		log.Printf("未找到 %s，使用默认配置 (master :%s)", path, cfg.Port)
	}
	// M22: 环境变量覆盖（Docker 场景不必生成 config.yaml）
	if v := os.Getenv("PORT"); v != "" {
		cfg.Port = v
	}
	if v := os.Getenv("MIAOWU_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("MIAOWU_PUBLIC_BASE_URL"); v != "" {
		cfg.PublicBaseURL = v
	}
	return cfg
}

// ==================== MASTER ====================

func runMaster(cfg Config) {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil { // L16: 数据目录 0700
		log.Fatalf("创建数据目录失败: %v", err)
	}
	store, err := storage.Open(filepath.Join(cfg.DataDir, "miaowu.db"))
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer store.Close()

	ident, err := securechan.LoadOrGenerate(filepath.Join(cfg.DataDir, "master.key"))
	if err != nil {
		log.Fatalf("加载主控密钥失败: %v", err)
	}
	pubKey := ident.PublicKeyBase64()
	_ = store.SetSetting("master_pub_key", pubKey)

	hub := master.NewHub(store, ident)
	mux := http.NewServeMux()

	// ---- agent WS 入口（不走会话鉴权，token 在 header） ----
	mux.HandleFunc("/api/agent/ws", hub.HandleAgentWS)

	// ---- 初始化向导 / 登录 ----
	mux.HandleFunc("/api/setup/status", func(w http.ResponseWriter, r *http.Request) {
		n, _ := store.CountUsers()
		writeJSON(w, map[string]any{"initialized": n > 0})
	})
	mux.HandleFunc("/api/setup/init", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Username == "" || len(p.Password) < 6 {
			writeErr(w, http.StatusBadRequest, "用户名或密码过短(至少6位)")
			return
		}
		if !validUsername(p.Username) {
			writeErr(w, http.StatusBadRequest, "用户名仅允许 3-32 位字母/数字/下划线/连字符")
			return
		}
		if n, _ := store.CountUsers(); n > 0 {
			writeErr(w, http.StatusForbidden, "已初始化")
			return
		}
		if err := store.CreateUser(&storage.User{Username: p.Username, Role: "admin", IsActive: true}, auth.HashPassword(p.Password)); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]string{"ok": "initialized"})
	})
	// S6: 登录接口限流（5 次/分钟/IP，防爆破）
	mux.Handle("/api/login", auth.RateLimit(5, 5, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request")
			return
		}
		u, hash, err := store.GetUser(p.Username)
		if err != nil || !auth.VerifyPassword(p.Password, hash) {
			writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
			return
		}
		if !u.IsActive {
			writeErr(w, http.StatusForbidden, "账号已禁用")
			return
		}
		tok, err := store.CreateSession(u.Username, 7*24*time.Hour)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]any{"token": tok, "role": u.Role, "username": u.Username})
	})))

	// ---- 通用 admin API ----

	// 登出（L9）
	mux.Handle("/api/logout", auth.Middleware(store, false, func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_ = store.DeleteSession(tok)
		writeJSON(w, map[string]string{"ok": "logged_out"})
	}))
	// 修改自己密码（L9）
	mux.Handle("/api/user/password", auth.Middleware(store, false, func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Old string `json:"old"`
			New string `json:"new"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || len(p.New) < 6 {
			writeErr(w, http.StatusBadRequest, "新密码至少 6 位")
			return
		}
		username := auth.CurrentUser(r)
		_, hash, err := store.GetUser(username)
		if err != nil || !auth.VerifyPassword(p.Old, hash) {
			writeErr(w, http.StatusUnauthorized, "旧密码错误")
			return
		}
		if err := store.UpdateUserPassword(username, auth.HashPassword(p.New)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"ok": "password_changed"})
	}))

	// 用户管理
	mux.Handle("/api/admin/users", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		users, _ := store.ListUsers()
		writeJSON(w, users)
	}))
	mux.Handle("/api/admin/users/create", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Quota    int64  `json:"monthly_quota"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Username == "" || len(p.Password) < 6 {
			writeErr(w, http.StatusBadRequest, "参数错误")
			return
		}
		if !validUsername(p.Username) {
			writeErr(w, http.StatusBadRequest, "用户名仅允许 3-32 位字母/数字/下划线/连字符（__global__ 为保留字）")
			return
		}
		if p.Role != "admin" {
			p.Role = "user"
		}
		if err := store.CreateUser(&storage.User{Username: p.Username, Role: p.Role, IsActive: true, MonthlyQuota: p.Quota},
			auth.HashPassword(p.Password)); err != nil {
			writeErr(w, http.StatusBadRequest, "创建失败: "+err.Error())
			return
		}
		writeJSON(w, map[string]string{"ok": "created"})
	}))
	mux.Handle("/api/admin/users/delete", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Username == "" {
			writeErr(w, http.StatusBadRequest, "bad request")
			return
		}
		if p.Username == auth.CurrentUser(r) {
			writeErr(w, http.StatusBadRequest, "不能删除自己")
			return
		}
		if err := store.DeleteUser(p.Username); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]string{"ok": "deleted"})
	}))
	mux.Handle("/api/admin/users/status", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Username string `json:"username"`
			Active   bool   `json:"is_active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Username == "" {
			writeErr(w, http.StatusBadRequest, "bad request")
			return
		}
		if err := store.UpdateUserFields(p.Username, map[string]any{"is_active": boolInt(p.Active)}); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]string{"ok": "updated"})
	}))

	// 节点管理（admin 操作全局池）
	mux.Handle("/api/admin/nodes", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			nodes, err := store.ListAllNodes()
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			// 附带本月入站流量（按 服务器|入站tag 匹配同步节点）
			traffic, _ := store.NodeTrafficMonth()
			out := make([]map[string]any, 0, len(nodes))
			for _, n := range nodes {
				item := map[string]any{
					"id": n.ID, "username": n.Username, "raw_url": n.RawURL,
					"node_name": n.NodeName, "protocol": n.Protocol, "server": n.Server,
					"enabled": n.Enabled, "tag": n.Tag, "origin_server_id": n.OriginServerID,
					"created_at": n.CreatedAt,
				}
				if t, ok := traffic[fmt.Sprintf("%d|%s", n.OriginServerID, n.NodeName)]; ok {
					item["monthly_traffic"] = map[string]int64{"up": t[0], "down": t[1]}
				}
				out = append(out, item)
			}
			writeJSON(w, out)
		case http.MethodPost:
			var p struct {
				URLs     []string `json:"urls"`
				Raw      string   `json:"raw"`
				Username string   `json:"username"`
				Tag      string   `json:"tag"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				writeErr(w, 400, "bad request")
				return
			}
			owner := p.Username
			if owner == "" {
				owner = auth.CurrentUser(r)
			}
			imported, failed := importNodes(store, owner, p.Raw, p.URLs, p.Tag)
			writeJSON(w, map[string]any{"imported": imported, "failed": failed})
		default:
			writeErr(w, 405, "method not allowed")
		}
	}))
	mux.Handle("/api/admin/nodes/", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/nodes/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeErr(w, 400, "bad id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			n, err := store.GetNode(id)
			if err != nil {
				writeErr(w, 404, "not found")
				return
			}
			writeJSON(w, n)
		case http.MethodPut:
			var p struct {
				NodeName string `json:"node_name"`
				Tag      string `json:"tag"`
				Enabled  bool   `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				writeErr(w, 400, "bad request")
				return
			}
			n, err := store.GetNode(id)
			if err != nil {
				writeErr(w, 404, "not found")
				return
			}
			n.NodeName = p.NodeName
			n.Tag = p.Tag
			n.Enabled = p.Enabled
			if err := store.UpdateNode(n); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]string{"ok": "updated"})
		case http.MethodDelete:
			if err := store.DeleteNode(id); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]string{"ok": "deleted"})
		default:
			writeErr(w, 405, "method not allowed")
		}
	}))

	// 用户侧节点（自助导入）
	mux.Handle("/api/user/nodes", auth.Middleware(store, false, func(w http.ResponseWriter, r *http.Request) {
		username := auth.CurrentUser(r)
		switch r.Method {
		case http.MethodGet:
			nodes, _ := store.ListNodes(username)
			writeJSON(w, nodes)
		case http.MethodPost:
			var p struct {
				Raw  string   `json:"raw"`
				URLs []string `json:"urls"`
				Tag  string   `json:"tag"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				writeErr(w, 400, "bad request")
				return
			}
			imported, failed := importNodes(store, username, p.Raw, p.URLs, p.Tag)
			writeJSON(w, map[string]any{"imported": imported, "failed": failed})
		default:
			writeErr(w, 405, "method not allowed")
		}
	}))

	// 订阅管理（admin）
	mux.Handle("/api/admin/subscriptions", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			subs, _ := store.ListSubscriptions()
			writeJSON(w, subs)
		case http.MethodPost:
			var p struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Owner       string `json:"owner"`
				ExpireAt    string `json:"expire_at"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Name == "" {
				writeErr(w, 400, "缺少 name")
				return
			}
			sub := &storage.Subscription{Name: p.Name, Description: p.Description, Owner: p.Owner}
			if p.ExpireAt != "" {
				if t, err := time.Parse("2006-01-02", p.ExpireAt); err == nil {
					sub.ExpireAt = &t
				}
			}
			id, err := store.CreateSubscription(sub)
			if err != nil {
				writeErr(w, 400, "创建失败: "+err.Error())
				return
			}
			writeJSON(w, map[string]any{"id": id})
		default:
			writeErr(w, 405, "method not allowed")
		}
	}))
	mux.Handle("/api/admin/subscriptions/", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/admin/subscriptions/"), "/")
		id, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			writeErr(w, 400, "bad id")
			return
		}
		if len(parts) == 2 && parts[1] == "bind" {
			var p struct {
				Username string `json:"username"`
				Bind     bool   `json:"bind"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Username == "" {
				writeErr(w, 400, "bad request")
				return
			}
			if err := store.BindSubscription(p.Username, id, p.Bind); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]string{"ok": "done"})
			return
		}
		switch r.Method {
		case http.MethodDelete:
			if err := store.DeleteSubscription(id); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]string{"ok": "deleted"})
		default:
			writeErr(w, 405, "method not allowed")
		}
	}))

	// 用户重置订阅 token（L10: ResetUserToken 的调用点 —— token 泄露时自助轮换）
	mux.Handle("/api/user/reset-token", auth.Middleware(store, false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "method not allowed")
			return
		}
		tok, err := store.ResetUserToken(auth.CurrentUser(r))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"token": tok, "note": "旧订阅链接立即失效，请在客户端更新"})
	}))

	// 用户信息（含订阅链接与token）
	mux.Handle("/api/user/profile", auth.Middleware(store, false, func(w http.ResponseWriter, r *http.Request) {
		username := auth.CurrentUser(r)
		u, _, err := store.GetUser(username)
		if err != nil {
			writeErr(w, 404, "user not found")
			return
		}
		tok, _ := store.GetUserToken(username)
		up, down, _ := store.UserTrafficMonth(username)
		host := requestHost(r, cfg)
		subURL := fmt.Sprintf("http://%s/api/subscribe/%s", host, tok)
		if isTLS(r, cfg) {
			subURL = fmt.Sprintf("https://%s/api/subscribe/%s", host, tok)
		}
		writeJSON(w, map[string]any{
			"username": u.Username, "role": u.Role, "monthly_quota": u.MonthlyQuota,
			"token": tok, "subscribe_url": subURL,
			"traffic": map[string]any{"upload": up, "download": down, "total": u.MonthlyQuota},
		})
	}))

	// ---- 订阅分发端点: /api/subscribe/{token} (无登录, token 鉴权, UA 输出不同格式) ----
	// S6: 匿名端点限流（60 次/分钟/IP，短码枚举防护）
	mux.Handle("/api/subscribe/", auth.RateLimit(60, 60, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.URL.Path, "/api/subscribe/")
		if tok == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		username, err := store.ResolveToken(tok)
		if err != nil {
			w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
			w.Write([]byte(subscribe.InvalidTokenYAML))
			return
		}
		u, _, err := store.GetUser(username)
		if err != nil || !u.IsActive {
			w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
			w.Write([]byte(subscribe.InvalidTokenYAML))
			return
		}

		// M25: 配额生效 —— 月用量超限后返回带"配额已用尽"提示的合法配置
		used, _, _ := store.UserTrafficMonth(username)
		quotaExceeded := u.MonthlyQuota > 0 && used >= u.MonthlyQuota

		// 收集节点：用户自建 + 全局池(admin 导入与服务器同步的 owner='__global__')
		var nodes []*subparser.Node
		if !quotaExceeded {
			userNodes, _ := store.ListNodes(username)
			globalNodes, _ := store.ListNodes("__global__")
			for _, n := range append(userNodes, globalNodes...) {
				if !n.Enabled {
					continue
				}
				if pn, err := subparser.FromJSON(n.ParsedConfig); err == nil {
					nodes = append(nodes, pn)
				}
			}
		}

		client := subscribe.DetectClient(r.UserAgent())
		groupName := "🚀 节点选择"
		if quotaExceeded {
			groupName = "⛔ 配额已用尽"
		}
		body, ctype, err := subscribe.Generate(nodes, client, groupName)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		info, _ := subscribe.BuildTrafficInfo(store, username, nil)
		subscribe.SetHeaders(w, r.UserAgent(), info, username)
		w.Header().Set("Content-Type", ctype)
		w.Write(body)
	})))

	// ---- 服务器管理 (X 核心) ----
	mux.Handle("/api/admin/servers", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			servers, _ := store.ListServers()
			statuses, _ := store.ListServerStatuses()
			out := make([]map[string]any, 0, len(servers))
			for _, sv := range servers {
				st := statuses[sv.ID]
				item := map[string]any{
					"id": sv.ID, "name": sv.Name, "address": sv.Address, "region": sv.Region,
					"provider": sv.Provider, "notes": sv.Notes, "config_revision": sv.ConfigRevision,
					"created_at": sv.CreatedAt,
					"online":     st != nil && st.Online,
				}
				if st != nil {
					item["status"] = st
				}
				out = append(out, item)
			}
			writeJSON(w, out)
		case http.MethodPost:
			var p struct {
				Name     string `json:"name"`
				Address  string `json:"address"`
				Region   string `json:"region"`
				Provider string `json:"provider"`
				Notes    string `json:"notes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Name == "" {
				writeErr(w, 400, "缺少 name")
				return
			}
			sv, err := store.CreateServer(p.Name, p.Address, p.Region, p.Provider, p.Notes)
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, sv)
		default:
			writeErr(w, 405, "method not allowed")
		}
	}))
	mux.Handle("/api/admin/servers/", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/admin/servers/"), "/")
		id, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			writeErr(w, 400, "bad id")
			return
		}
		action := ""
		if len(parts) == 2 {
			action = parts[1]
		}
		switch action {
		case "":
			switch r.Method {
			case http.MethodGet:
				sv, err := store.GetServer(id)
				if err != nil {
					writeErr(w, 404, "not found")
					return
				}
				writeJSON(w, sv)
			case http.MethodDelete:
				if err := store.DeleteServer(id); err != nil {
					writeErr(w, 500, err.Error())
					return
				}
				writeJSON(w, map[string]string{"ok": "deleted"})
			default:
				writeErr(w, 405, "method not allowed")
			}
		case "token-reset":
			tok, err := store.ResetServerToken(id)
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]string{"token": tok})
		case "generate-node":
			// 在该 agent 机上生成节点：生成凭据 → 追加 inbound → 下发 → 同步到订阅
			var spec generateSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				writeErr(w, 400, "bad request")
				return
			}
			sv, err := store.GetServer(id)
			if err != nil {
				writeErr(w, 404, "server not found")
				return
			}
			ib, err := buildInbound(spec)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			// 合并进 desired config
			var cfgMap map[string]any
			if sv.DesiredConfig != "" && json.Unmarshal([]byte(sv.DesiredConfig), &cfgMap) != nil {
				writeErr(w, 500, "现有配置不是合法 JSON")
				return
			}
			if cfgMap == nil {
				cfgMap = map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}}}
			}
			inbounds, _ := cfgMap["inbounds"].([]any)
			// tag 查重
			for _, x := range inbounds {
				if m, ok := x.(map[string]any); ok && m["tag"] == ib["tag"] {
					writeErr(w, 400, "已存在同名入站: "+fmt.Sprint(m["tag"]))
					return
				}
			}
			cfgMap["inbounds"] = append(inbounds, ib)
			newCfg, _ := json.Marshal(cfgMap)
			rev, err := store.SaveDesiredConfig(id, string(newCfg))
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			if err := hub.PushConfig(id, rev, string(newCfg)); err != nil {
				log.Printf("[Master] 服务器 %d 离线，配置将在上线后拉取 (rev=%d)", id, rev)
			}
			// 同步到订阅节点池
			sv, _ = store.GetServer(id)
			n, serr := syncServerNodes(store, sv)
			writeJSON(w, map[string]any{
				"revision": rev, "inbound_tag": ib["tag"], "synced_nodes": n, "sync_error": errStr(serr),
			})
		case "sync-nodes":
			sv, err := store.GetServer(id)
			if err != nil {
				writeErr(w, 404, "server not found")
				return
			}
			n, err := syncServerNodes(store, sv)
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]any{"synced_nodes": n})
		case "status":
			st, err := store.GetServerStatus(id)
			if err != nil {
				writeErr(w, 404, "no status")
				return
			}
			writeJSON(w, st)
		case "traffic":
			days, _ := strconv.Atoi(r.URL.Query().Get("days"))
			if days <= 0 || days > 90 {
				days = 30
			}
			daily, _ := store.ServerTrafficDaily(id, days)
			writeJSON(w, daily)
		case "xray-config":
			switch r.Method {
			case http.MethodGet:
				sv, err := store.GetServer(id)
				if err != nil {
					writeErr(w, 404, "not found")
					return
				}
				writeJSON(w, map[string]any{"config": sv.DesiredConfig, "revision": sv.ConfigRevision})
			case http.MethodPut:
				var p struct {
					Config string `json:"config"`
				}
				if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Config == "" {
					writeErr(w, 400, "缺少 config")
					return
				}
				if !json.Valid([]byte(p.Config)) {
					writeErr(w, 400, "配置不是合法 JSON")
					return
				}
				rev, err := store.SaveDesiredConfig(id, p.Config)
				if err != nil {
					writeErr(w, 500, err.Error())
					return
				}
				// 在线则即时推送；离线等 agent 连上后按 revision 拉取
				if err := hub.PushConfig(id, rev, p.Config); err != nil {
					log.Printf("[Master] 服务器 %d 离线，配置将在上线后拉取 (rev=%d)", id, rev)
				}
				writeJSON(w, map[string]any{"revision": rev})
			default:
				writeErr(w, 405, "method not allowed")
			}
		case "rpc":
			// 通用反向 RPC 代理: {"method","path","query","body"}
			var p struct {
				Method string          `json:"method"`
				Path   string          `json:"path"`
				Query  string          `json:"query"`
				Body   json.RawMessage `json:"body"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				writeErr(w, 400, "bad request")
				return
			}
			if p.Method == "" {
				p.Method = http.MethodGet
			}
			reply, err := hub.Call(id, p.Method, p.Path, p.Query, p.Body, 30*time.Second)
			if err != nil {
				writeErr(w, http.StatusBadGateway, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(reply.Status)
			if reply.Body != nil {
				w.Write(reply.Body)
			}
		default:
			writeErr(w, 404, "unknown action")
		}
	}))

	// 主控公钥（agent 安装命令用）
	mux.Handle("/api/admin/master-pubkey", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"public_key": pubKey})
	}))

	// ---- SSL 设置（3X-UI 式域名证书模式）----
	mux.Handle("/api/admin/ssl", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s := resolveSSLSettings(store, cfg)
			out := map[string]any{
				"domain": s.Domain, "email": s.Email,
				"cert_file": s.CertFile, "key_file": s.KeyFile,
				"source": s.Source, "scheme": r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
				"panel_port": cfg.Port,
			}
			if exp, err := certExpiry(cfg.DataDir, s); err == nil {
				out["expires_at"] = exp
			}
			writeJSON(w, out)
		case http.MethodPost:
			var p struct {
				Domain   string `json:"domain"`
				Email    string `json:"email"`
				CertFile string `json:"cert_file"`
				KeyFile  string `json:"key_file"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				writeErr(w, 400, "bad request")
				return
			}
			// 手动证书模式要求两个路径成对
			if (p.CertFile == "") != (p.KeyFile == "") {
				writeErr(w, 400, "cert_file 与 key_file 必须成对填写")
				return
			}
			if p.CertFile != "" && p.Domain != "" {
				writeErr(w, 400, "手动证书与 ACME 域名二选一")
				return
			}
			_ = store.SetSetting("ssl_domain", p.Domain)
			_ = store.SetSetting("ssl_email", p.Email)
			_ = store.SetSetting("ssl_cert_file", p.CertFile)
			_ = store.SetSetting("ssl_key_file", p.KeyFile)
			writeJSON(w, map[string]string{"ok": "saved", "note": "已保存，重启服务后生效（systemd: systemctl restart miaowu）"})
		default:
			writeErr(w, 405, "method not allowed")
		}
	}))

	// agent 在线列表
	mux.Handle("/api/admin/agents/online", auth.Middleware(store, true, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, hub.OnlineIDs())
	}))

	// ---- 静态前端 ----
	dist, _ := fs.Sub(webFS, "web/dist")
	mux.Handle("/", http.FileServer(http.FS(dist)))

	addr := net.JoinHostPort("0.0.0.0", cfg.Port)

	// M14: 数据保留策略（启动清一次，此后每天一次）
	go func() {
		if err := store.CleanupExpired(); err != nil {
			log.Printf("[Master] 数据清理: %v", err)
		}
		for range time.Tick(24 * time.Hour) {
			if err := store.CleanupExpired(); err != nil {
				log.Printf("[Master] 数据清理: %v", err)
			}
		}
	}()

	// 启动时把已有服务器配置的入站同步进订阅节点池（幂等）
	go func() {
		servers, err := store.ListServers()
		if err != nil {
			return
		}
		for _, sv := range servers {
			if sv.DesiredConfig == "" {
				continue
			}
			if n, err := syncServerNodes(store, sv); err == nil && n > 0 {
				log.Printf("[Master] 服务器 %s 入站同步: %d 个节点", sv.Name, n)
			}
		}
	}()

	// ---- SSL：手动证书 / ACME 自动申请（域名模式），设置页可改、重启生效 ----
	ssl := resolveSSLSettings(store, cfg)
	var tlsConf *tls.Config
	scheme := "http"
	switch {
	case ssl.CertFile != "" && ssl.KeyFile != "":
		cert, err := tls.LoadX509KeyPair(ssl.CertFile, ssl.KeyFile)
		if err != nil {
			// M9: 加载失败降级为 HTTP 启动，保留面板可修复能力（否则 systemd 重启死循环）
			log.Printf("[SSL] 加载证书失败，降级为 HTTP 启动（请在面板/配置修复后重启）: %v", err)
			tlsConf = nil
			scheme = "http"
		} else {
			tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			scheme = "https"
			log.Printf("SSL 模式: 手动证书 (%s)", ssl.CertFile)
		}
	case ssl.Domain != "":
		m := &autocert.Manager{
			Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "certs")),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(ssl.Domain),
			Email:      ssl.Email,
		}
		tlsConf = m.TLSConfig()
		scheme = "https"
		log.Printf("SSL 模式: ACME 自动申请 (域名 %s, HTTP-01 需 80 端口可达; 首次访问时签发, 之后自动续期)", ssl.Domain)
		go func() {
			// 80 端口: ACME HTTP-01 质询 + 其余请求 301 到 https
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Printf("[SSL] 80 端口监听失败(HTTP-01 将不可用): %v", err)
			}
		}()
	default:
		log.Printf("SSL 模式: 关闭 (纯 HTTP) —— 可在面板「设置」或 config.yaml 配置证书/域名")
	}
	if scheme == "https" {
		if ssl.Domain != "" {
			log.Printf("面板地址: https://%s:%s", ssl.Domain, cfg.Port)
		} else {
			log.Printf("面板地址: https://<你的地址>:%s", cfg.Port)
		}
		_ = store.SetSetting("panel_scheme", "https")
	} else {
		_ = store.SetSetting("panel_scheme", "http")
	}

	log.Printf("miaowu master 启动: %s://%s  (数据目录 %s)", scheme, addr, cfg.DataDir)
	log.Printf("主控公钥: %s", pubKey)
	// M5: 慢连接防护。不设 WriteTimeout/ReadTimeout —— 会持久化到 hijacked 连接、
	// 干扰 WS 长连接的读写 deadline（由 websocket 库自行管理）
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if tlsConf != nil {
		log.Fatal(srv.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(srv.ListenAndServe())
	}
}

// sslSettings 生效中的 SSL 配置。config.yaml 为基础，网页设置页写入的 system_settings 优先。
type sslSettings struct {
	Domain   string `json:"domain"`
	Email    string `json:"email"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	Source   string `json:"source"` // db | config | none
}

func resolveSSLSettings(store *storage.Store, cfg Config) sslSettings {
	dbGet := func(k string) string { v, _ := store.GetSetting(k); return v }
	s := sslSettings{Source: "none"}

	// M9: 证书/私钥必须成对同源 —— 优先取 DB 配对，其次 config.yaml 配对，绝不跨源拼接
	dbCert, dbKey := dbGet("ssl_cert_file"), dbGet("ssl_key_file")
	dbDomain, dbEmail := dbGet("ssl_domain"), dbGet("ssl_email")

	switch {
	case dbCert != "" && dbKey != "":
		s.CertFile, s.KeyFile, s.Source = dbCert, dbKey, "db"
	case dbDomain != "":
		s.Domain, s.Source = dbDomain, "db"
		if dbEmail != "" {
			s.Email = dbEmail
		}
	case cfg.CertFile != "" && cfg.KeyFile != "":
		s.CertFile, s.KeyFile, s.Source = cfg.CertFile, cfg.KeyFile, "config"
	case cfg.Domain != "":
		s.Domain, s.Source = cfg.Domain, "config"
		s.Email = cfg.Email
	}
	// 单边配置（只有 cert 没有 key 等）给出告警并忽略
	if (s.CertFile == "") != (s.KeyFile == "") {
		log.Printf("[SSL] cert_file/key_file 只配置了一半，已忽略（必须成对）")
		s.CertFile, s.KeyFile = "", ""
		s.Source = "none"
	}
	if s.Domain != "" && s.CertFile != "" {
		log.Printf("[SSL] 域名与手动证书同时配置，以手动证书为准")
		s.Domain = ""
	}
	return s
}

// certExpiry 读取当前生效证书的到期时间（文件模式直接读文件；ACME 模式读本地缓存）。
func certExpiry(dataDir string, s sslSettings) (*time.Time, error) {
	var pemBytes []byte
	var err error
	if s.CertFile != "" && s.KeyFile != "" {
		pemBytes, err = os.ReadFile(s.CertFile)
	} else if s.Domain != "" {
		pemBytes, err = os.ReadFile(filepath.Join(dataDir, "certs", s.Domain))
	} else {
		return nil, fmt.Errorf("未配置 SSL")
	}
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, e := x509.ParseCertificate(block.Bytes); e == nil {
			return &cert.NotAfter, nil
		}
	}
	return nil, fmt.Errorf("证书文件中未找到证书")
}

// importNodes 批量导入节点 URI（多行 / 多 URL）。
func importNodes(store *storage.Store, owner, raw string, urls []string, tag string) (imported int, failed []string) {
	if tag == "" {
		tag = "手动输入"
	}
	lines := []string{}
	if raw != "" {
		lines = append(lines, strings.Split(raw, "\n")...)
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, err := subparser.Parse(line)
		if err != nil {
			failed = append(failed, line+" ("+err.Error()+")")
			continue
		}
		_, err = store.CreateNode(&storage.Node{
			Username: owner, RawURL: line, NodeName: n.Name, Protocol: n.Protocol,
			Server: n.Server, ParsedConfig: n.ToJSON(), Enabled: true, Tag: tag,
		})
		if err != nil {
			failed = append(failed, line+" ("+err.Error()+")")
			continue
		}
		imported++
	}
	return
}

// M3: 订阅链接主机名 —— 仅信任 public_base_url 配置，绝不信任客户端可控的
// X-Forwarded-Host（未配置时退回请求 Host）。
func requestHost(r *http.Request, cfg Config) string {
	if cfg.PublicBaseURL != "" {
		u, err := url.Parse(cfg.PublicBaseURL)
		if err == nil && u.Host != "" {
			return u.Host
		}
	}
	return r.Host
}

func isTLS(r *http.Request, cfg Config) bool {
	if cfg.PublicBaseURL != "" && strings.HasPrefix(cfg.PublicBaseURL, "https://") {
		return true
	}
	// 仅当直接 TLS 时为真；经可信反代的场景请配置 public_base_url
	return r.TLS != nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ==================== AGENT ====================

func runAgent(cfg Config) {
	mux := http.NewServeMux()
	client := agent.NewClient(agent.Config{
		MasterURL:     cfg.MasterServer,
		Token:         cfg.Token,
		MasterPubKey:  cfg.MasterPubKey,
		ListenPort:    cfg.ListenPort,
		XrayPath:      cfg.XrayPath,
		XrayConfigDir: cfg.XrayConfigDir,
		DataDir:       cfg.DataDir,
	}, mux)
	client.RegisterLocalHandlers(mux)

	// 本地管理端口（仅回环，排障用）
	if cfg.ListenPort > 0 {
		go func() {
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.ListenPort))
			log.Printf("miaowu agent 本地管理端口: http://%s", addr)
			if err := http.ListenAndServe(addr, mux); err != nil {
				log.Printf("本地管理端口失败: %v", err)
			}
		}()
	}

	log.Printf("miaowu agent 启动: master=%s", cfg.MasterServer)
	client.Start()
}
