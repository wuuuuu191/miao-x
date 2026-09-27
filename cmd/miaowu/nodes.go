// 节点生成与入站→订阅同步：主控面板一键在 agent 机上生成节点，并把入站自动转成订阅节点。
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"

	"miao-x/internal/master"
	"miao-x/internal/securechan"
	"miao-x/internal/storage"
	"miao-x/internal/subparser"
	"miao-x/internal/subscribe"
)

// generateSpec 生成节点的请求参数。
type generateSpec struct {
	Protocol string `json:"protocol"` // vless-reality | vless-ws | trojan | shadowsocks | hysteria2
	Name     string `json:"name"`     // 入站 tag / 节点名
	Port     int    `json:"port"`
	SNI      string `json:"sni"`   // reality/trojan/hy2 伪装域名；vless-ws 的 host
	Path     string `json:"path"`  // ws path
	Email    string `json:"email"` // 关联面板用户（流量归属），空则 auto@panel
}

var generateDefaults = map[string]struct {
	port  int
	proto string // xray inbound protocol
}{
	"vless-reality": {443, "vless"},
	"vless-ws":      {8443, "vless"},
	"trojan":        {443, "trojan"},
	"shadowsocks":   {8388, "shadowsocks"},
	"hysteria2":     {36712, "hysteria2"},
}

// buildInbound 按规格生成 xray inbound（含自动凭据）。返回 inbound 与保底元数据。
func buildInbound(spec generateSpec) (map[string]any, error) {
	def, ok := generateDefaults[spec.Protocol]
	if !ok {
		return nil, fmt.Errorf("不支持的协议: %s", spec.Protocol)
	}
	if spec.Name == "" {
		spec.Name = def.proto + "-" + randomHex(4)
	}
	if spec.Port <= 0 || spec.Port > 65535 {
		spec.Port = def.port
	}
	if spec.Email == "" {
		spec.Email = "auto-" + randomHex(3) + "@panel"
	} else if !strings.Contains(spec.Email, "@") {
		spec.Email += "@panel"
	}

	ib := map[string]any{
		"tag": spec.Name, "listen": "0.0.0.0", "port": spec.Port, "protocol": def.proto,
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": false},
	}
	stream := map[string]any{"network": "tcp", "security": "none"}

	switch spec.Protocol {
	case "vless-reality":
		if spec.SNI == "" {
			spec.SNI = "www.microsoft.com"
		}
		priv := realityKeypair()
		sid := randomHex(4)
		ib["settings"] = map[string]any{
			"clients":    []any{map[string]any{"id": uuidV4(), "email": spec.Email, "flow": "xtls-rprx-vision"}},
			"decryption": "none",
		}
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]any{
			"show": false, "dest": spec.SNI + ":443", "xver": 0,
			"serverNames": []string{spec.SNI}, "privateKey": priv, "shortIds": []string{sid},
		}
	case "vless-ws":
		if spec.Path == "" {
			spec.Path = "/" + randomHex(6)
		}
		ib["settings"] = map[string]any{
			"clients":    []any{map[string]any{"id": uuidV4(), "email": spec.Email}},
			"decryption": "none",
		}
		stream["network"] = "ws"
		ws := map[string]any{"path": spec.Path}
		if spec.SNI != "" {
			ws["headers"] = map[string]any{"Host": spec.SNI}
		}
		stream["wsSettings"] = ws
	case "trojan":
		if spec.SNI == "" {
			spec.SNI = "www.baidu.com"
		}
		ib["settings"] = map[string]any{
			"clients": []any{map[string]any{"password": randomHex(16), "email": spec.Email}},
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{"serverName": spec.SNI, "allowInsecure": false}
	case "shadowsocks":
		ib["settings"] = map[string]any{
			"method":   "aes-256-gcm",
			"password": randomHex(16),
			"network":  "tcp,udp",
		}
	case "hysteria2":
		if spec.SNI == "" {
			spec.SNI = "www.bing.com"
		}
		ib["settings"] = map[string]any{
			"clients": []any{map[string]any{"password": randomHex(12), "email": spec.Email}},
			"obfs":    map[string]any{"type": "none"},
		}
		stream["network"] = "udp"
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{"serverName": spec.SNI, "allowInsecure": false}
	}
	ib["streamSettings"] = stream
	return ib, nil
}

// realityKeypair 生成 Reality X25519 私钥（L4: 公钥不进配置，由同步器按需推导）。
func realityKeypair() string {
	priv, _, err := securechan.GenerateEphemeral()
	if err != nil {
		panic(err) // crypto/rand 失败即环境异常
	}
	return base64.RawStdEncoding.EncodeToString(priv)
}

// deriveRealityPub 从配置中的 privateKey 推导 publicKey（同步器用）。
func deriveRealityPub(privB64 string) string {
	priv, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(privB64, "="))
	if err != nil || len(priv) != 32 {
		return ""
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(pub)
}

func uuidV4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

// ---------- 入站客户端管理（单入站多用户） ----------

type inboundInfo struct {
	Tag      string   `json:"tag"`
	Protocol string   `json:"protocol"`
	Port     int      `json:"port"`
	Clients  []string `json:"clients"` // email 列表
}

// listInbounds 解析服务器配置中的入站与客户端。
func listInbounds(sv *storage.Server) []inboundInfo {
	if strings.TrimSpace(sv.DesiredConfig) == "" {
		return nil
	}
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if json.Unmarshal([]byte(sv.DesiredConfig), &cfg) != nil {
		return nil
	}
	out := []inboundInfo{}
	for _, ib := range cfg.Inbounds {
		proto, _ := ib["protocol"].(string)
		tag, _ := ib["tag"].(string)
		portF, _ := ib["port"].(float64)
		if proto == "dokodemo-door" {
			continue
		}
		info := inboundInfo{Tag: tag, Protocol: proto, Port: int(portF), Clients: []string{}}
		if settings, ok := ib["settings"].(map[string]any); ok {
			if cs, ok := settings["clients"].([]any); ok {
				for _, c := range cs {
					if m, ok := c.(map[string]any); ok {
						if em, _ := m["email"].(string); em != "" {
							info.Clients = append(info.Clients, em)
						}
					}
				}
			}
		}
		out = append(out, info)
	}
	return out
}

// addClientToInbound 给指定入站追加一个客户端（自动生成凭据）。
// 返回新 email 与更新后的完整配置 JSON。
func addClientToInbound(sv *storage.Server, tag, username string) (string, string, error) {
	if username == "" {
		return "", "", fmt.Errorf("用户名不能为空")
	}
	email := username + "@panel"
	var cfg map[string]any
	if sv.DesiredConfig == "" || json.Unmarshal([]byte(sv.DesiredConfig), &cfg) != nil {
		return "", "", fmt.Errorf("该服务器还没有配置")
	}
	inbounds, _ := cfg["inbounds"].([]any)
	for _, x := range inbounds {
		ib, ok := x.(map[string]any)
		if !ok || ib["tag"] != tag {
			continue
		}
		settings, _ := ib["settings"].(map[string]any)
		if settings == nil {
			return "", "", fmt.Errorf("入站 %s 缺少 settings", tag)
		}
		clients, _ := settings["clients"].([]any)
		for _, c := range clients {
			if m, ok := c.(map[string]any); ok && m["email"] == email {
				return "", "", fmt.Errorf("客户端已存在: %s", email)
			}
		}
		switch ib["protocol"] {
		case "vless":
			nc := map[string]any{"id": uuidV4(), "email": email}
			if len(clients) > 0 {
				if c0, ok := clients[0].(map[string]any); ok {
					if fl, _ := c0["flow"].(string); fl != "" {
						nc["flow"] = fl
					}
				}
			}
			clients = append(clients, nc)
		case "trojan", "hysteria2":
			clients = append(clients, map[string]any{"password": randomHex(12), "email": email})
		default:
			return "", "", fmt.Errorf("协议 %v 暂不支持多客户端", ib["protocol"])
		}
		settings["clients"] = clients
		newCfg, err := json.Marshal(cfg)
		if err != nil {
			return "", "", err
		}
		return email, string(newCfg), nil
	}
	return "", "", fmt.Errorf("入站不存在: %s", tag)
}

// removeClientFromInbound 从指定入站移除客户端。
// 返回被移除的 email 与更新后的完整配置 JSON。
func removeClientFromInbound(sv *storage.Server, tag, email string) (string, string, error) {
	var cfg map[string]any
	if sv.DesiredConfig == "" || json.Unmarshal([]byte(sv.DesiredConfig), &cfg) != nil {
		return "", "", fmt.Errorf("该服务器还没有配置")
	}
	inbounds, _ := cfg["inbounds"].([]any)
	for _, x := range inbounds {
		ib, ok := x.(map[string]any)
		if !ok || ib["tag"] != tag {
			continue
		}
		settings, _ := ib["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		out := []any{}
		removed := ""
		for _, c := range clients {
			if m, ok := c.(map[string]any); ok && m["email"] == email {
				removed = email
				continue
			}
			out = append(out, c)
		}
		if removed == "" {
			return "", "", fmt.Errorf("客户端不存在: %s", email)
		}
		if len(out) == 0 {
			return "", "", fmt.Errorf("至少保留一个客户端")
		}
		settings["clients"] = out
		newCfg, err := json.Marshal(cfg)
		if err != nil {
			return "", "", err
		}
		return removed, string(newCfg), nil
	}
	return "", "", fmt.Errorf("入站不存在: %s", tag)
}

// applyConfigChange 保存+推送配置并重新同步订阅节点（管理操作公共出口）。
func applyConfigChange(store *storage.Store, hub *master.Hub, sv *storage.Server, newConfig string) (int64, int, error) {
	rev, err := store.SaveDesiredConfig(sv.ID, newConfig)
	if err != nil {
		return 0, 0, err
	}
	if err := hub.PushConfig(sv.ID, rev, newConfig); err != nil {
		log.Printf("[Master] 服务器 %d 离线，配置将在上线后拉取 (rev=%d)", sv.ID, rev)
	}
	sv2, err := store.GetServer(sv.ID)
	if err != nil {
		return rev, 0, err
	}
	n, err := syncServerNodes(store, sv2)
	return rev, n, err
}

// syncServerNodes 把服务器 desired_config 的入站转成订阅节点（幂等 delete+insert）。
// 多用户入站：每个 client 生成一个节点，凭据归属各自面板用户（email 前缀匹配）；
// 无法匹配面板用户的 client 进入全局池。
func syncServerNodes(store *storage.Store, sv *storage.Server) (int, error) {
	if strings.TrimSpace(sv.DesiredConfig) == "" {
		store.ReplaceServerNodes(sv.ID, nil)
		return 0, nil
	}
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(sv.DesiredConfig), &cfg); err != nil {
		return 0, fmt.Errorf("解析服务器配置: %w", err)
	}

	host := publicHostOf(sv)
	var nodes []*storage.Node
	for _, ib := range cfg.Inbounds {
		nodes = append(nodes, inboundToNodes(ib, sv, host, store)...)
	}
	if err := store.ReplaceServerNodes(sv.ID, nodes); err != nil {
		return 0, err
	}
	return len(nodes), nil
}

// publicHostOf 订阅里节点的连接地址：优先服务器登记的地址，退化为服务器名。
func publicHostOf(sv *storage.Server) string {
	addr := sv.Address
	if i := strings.LastIndex(addr, ":"); i > 0 && !strings.Contains(addr[i:], "]") {
		// 去掉可能带的 :端口
		if _, err := strconv.Atoi(addr[i+1:]); err == nil {
			addr = addr[:i]
		}
	}
	if addr == "" {
		addr = sv.Name
	}
	return addr
}

// inboundToNodes 把一个 xray inbound 按客户端拆成订阅节点（每个 client 独立凭据）。
func inboundToNodes(ib map[string]any, sv *storage.Server, host string, store *storage.Store) []*storage.Node {
	proto, _ := ib["protocol"].(string)
	tag, _ := ib["tag"].(string)
	portF, _ := ib["port"].(float64)
	port := int(portF)

	settings, _ := ib["settings"].(map[string]any)
	stream, _ := ib["streamSettings"].(map[string]any)

	sec, _ := stream["security"].(string)
	net, _ := stream["network"].(string)

	// 提取全部客户端（ss 协议无 clients 列表，视为单匿名用户）
	type clientCred struct {
		email string
		cred  map[string]string
	}
	var clients []clientCred
	clientsA, _ := settings["clients"].([]any)
	for _, ca := range clientsA {
		c, ok := ca.(map[string]any)
		if !ok {
			continue
		}
		cc := clientCred{cred: map[string]string{}}
		cc.email, _ = c["email"].(string)
		for _, k := range []string{"id", "password", "flow"} {
			v, _ := c[k].(string)
			cc.cred[k] = v
		}
		clients = append(clients, cc)
	}
	if proto == "shadowsocks" {
		pw, _ := settings["password"].(string)
		clients = []clientCred{{cred: map[string]string{"password": pw}}}
	}
	if len(clients) == 0 {
		return nil // dokodemo/api 等非节点入站
	}

	multi := len(clients) > 1
	var nodes []*storage.Node
	for _, cc := range clients {
		n := &subparser.Node{Name: tag, Server: host, Port: port, Network: "tcp"}
		n.Network = net

		switch proto {
		case "vless":
			n.Protocol = "vless"
			n.UUID = cc.cred["id"]
			n.Flow = cc.cred["flow"]
		case "trojan":
			n.Protocol = "trojan"
			n.Password = cc.cred["password"]
			if sec == "" {
				sec = "tls"
			}
		case "shadowsocks":
			n.Protocol = "ss"
			n.Method, _ = settings["method"].(string)
			n.Password = cc.cred["password"]
		case "hysteria2":
			n.Protocol = "hysteria2"
			n.Password = cc.cred["password"]
			sec = "tls"
		default:
			continue
		}

		// TLS/Reality（与入站共享，凭据无关）
		switch sec {
		case "tls":
			n.Security = "tls"
			if ts, ok := stream["tlsSettings"].(map[string]any); ok {
				n.SNI, _ = ts["serverName"].(string)
				if insecure, _ := ts["allowInsecure"].(bool); insecure {
					n.SkipCert = true
				}
			}
		case "reality":
			n.Security = "reality"
			if rs, ok := stream["realitySettings"].(map[string]any); ok {
				if snis, _ := rs["serverNames"].([]any); len(snis) > 0 {
					n.SNI, _ = snis[0].(string)
				}
				if sids, _ := rs["shortIds"].([]any); len(sids) > 0 {
					n.Sid, _ = sids[0].(string)
				}
				priv, _ := rs["privateKey"].(string)
				n.Pbk = deriveRealityPub(priv)
				n.Fp = "chrome"
			}
			if n.Protocol == "vless" && n.Flow == "" {
				n.Flow = "xtls-rprx-vision"
			}
		}
		if net == "ws" {
			if ws, ok := stream["wsSettings"].(map[string]any); ok {
				n.Path, _ = ws["path"].(string)
				if hs, ok := ws["headers"].(map[string]any); ok {
					n.Host, _ = hs["Host"].(string)
				}
			}
		}
		if n.SNI == "" && n.Host != "" {
			n.SNI = n.Host
		}

		uri := subscribe.NodeURI(n)
		if uri == "" {
			continue
		}

		// 归属：email 前缀匹配面板用户 → 用户私有节点；否则全局池
		owner := "__global__"
		local := cc.email
		if i := strings.Index(cc.email, "@"); i > 0 {
			local = cc.email[:i]
		}
		if _, _, gerr := store.GetUser(local); gerr == nil {
			owner = local
		}
		name := tag
		if multi && local != "" {
			name = tag + " · " + local
		}
		nodes = append(nodes, &storage.Node{
			Username:     owner,
			RawURL:       uri,
			NodeName:     name,
			Protocol:     n.Protocol,
			Server:       host,
			ParsedConfig: n.ToJSON(),
			Enabled:      true,
			Tag:          sv.Name,
		})
	}
	return nodes
}
