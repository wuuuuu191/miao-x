// agent 的 xray 进程管理、统计采样与反向 RPC 分发。
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ---------- 反向 RPC：把主控的 HTTP 调用喂给本地 mux ----------

type rpcCallPayload struct {
	RequestID string          `json:"request_id"`
	Method    string          `json:"method"`
	Path      string          `json:"path"`
	Query     string          `json:"query,omitempty"`
	Body      json.RawMessage `json:"body,omitempty"`
	TimeoutMs int             `json:"timeout_ms,omitempty"`
	Stream    bool            `json:"stream,omitempty"`
}

type rpcReplyPayload struct {
	RequestID string          `json:"request_id"`
	Status    int             `json:"status"`
	Body      json.RawMessage `json:"body,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type bufferResponseWriter struct {
	mu      sync.Mutex
	headers http.Header
	body    bytes.Buffer
	status  int
}

func (w *bufferResponseWriter) Header() http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.headers
}
func (w *bufferResponseWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(b)
}
func (w *bufferResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = status
}

// handleRPCCall 与 X 的 ws_rpc.go 同构：本地 mux 共享同一份 handler 实例。
func (c *Client) handleRPCCall(ws *websocket.Conn, payload json.RawMessage) {
	var p rpcCallPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return
	}
	reply := rpcReplyPayload{RequestID: p.RequestID}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Agent] rpc handler panic: %v (path=%s)", r, p.Path)
			reply.Status = http.StatusInternalServerError
			reply.Error = "agent handler panic"
		}
		b, _ := json.Marshal(Envelope{Type: MsgRPCReply, Payload: mustMarshal(reply)})
		c.sendMu.Lock()
		bin, encErr := c.sess.Encrypt(b)
		if encErr == nil {
			_ = ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
			_ = ws.WriteMessage(websocket.BinaryMessage, bin)
		}
		c.sendMu.Unlock()
	}()

	u := &url.URL{Path: p.Path, RawQuery: p.Query}
	body := p.Body
	req, err := http.NewRequest(p.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		reply.Status = http.StatusBadRequest
		reply.Error = err.Error()
		return
	}
	req.Header.Set("X-WS-RPC", "1")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "ws-rpc"

	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	// S5: handler goroutine 可感知取消，超时后不再无限运行
	rpcCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req = req.WithContext(rpcCtx)

	w := &bufferResponseWriter{headers: make(http.Header), status: http.StatusOK}
	done := make(chan struct{})
	go func() {
		c.mux.ServeHTTP(w, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		cancel() // 通知可感知 ctx 的 handler 退出
		reply.Status = http.StatusGatewayTimeout
		reply.Error = "agent handler timeout"
		return
	}
	w.mu.Lock()
	reply.Status = w.status
	reply.Body = json.RawMessage(w.body.Bytes())
	w.mu.Unlock()
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ---------- 配置更新 ----------

type configUpdatePayload struct {
	Revision int64  `json:"revision"`
	Config   string `json:"config"` // xray config.json 全文
}

func (c *Client) handleConfigUpdate(ws *websocket.Conn, payload json.RawMessage) {
	var p configUpdatePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		log.Printf("[Agent] config_update 解析失败: %v", err)
		return
	}
	cfgPath := filepath.Join(c.cfg.XrayConfigDir, "config.json")
	// revision 语义 = 已应用版本：小于 applied 忽略；等于 applied 且本地已有配置 → 忽略重复；
	// 等于但本地无配置文件（全新 agent）→ 仍然应用（S1 补推场景）
	if p.Revision >= 0 {
		cur := c.lastRev.Load()
		_, haveFile := os.Stat(cfgPath)
		if p.Revision < cur || (p.Revision == cur && haveFile == nil) {
			log.Printf("[Agent] 忽略重复/旧配置 rev=%d（applied=%d, hasFile=%v）", p.Revision, cur, haveFile == nil)
			return
		}
	}
	if p.Config == "" {
		return
	}
	if err := os.MkdirAll(c.cfg.XrayConfigDir, 0755); err != nil {
		log.Printf("[Agent] 创建配置目录失败: %v", err)
		return
	}
	// 合并保底字段（stats/api inbound），与 X 的 xrayconf/merge 思路一致
	merged, err := mergeBaseConfig([]byte(p.Config))
	if err != nil {
		log.Printf("[Agent] 配置合并失败: %v", err)
		merged = []byte(p.Config)
	}
	// 剥离已下线用户的客户端（配额/禁用）
	merged = c.stripDisabledClients(merged)
	if err := os.WriteFile(cfgPath, merged, 0600); err != nil {
		log.Printf("[Agent] 写配置失败: %v", err)
		return
	}
	_ = os.Chmod(cfgPath, 0600) // 含 Reality 私钥与用户密码（M10）
	if p.Revision >= 0 {
		c.lastRev.Store(p.Revision) // 已应用
	}
	log.Printf("[Agent] 收到配置 rev=%d，已写入 %s，重启 xray", p.Revision, cfgPath)
	if err := c.RestartXray(); err != nil {
		log.Printf("[Agent] xray 重启失败: %v", err)
	}
	// S1 闭环：告知主控已应用到的 revision
	if ws != nil && p.Revision >= 0 {
		ackPayload, _ := json.Marshal(map[string]any{"revision": p.Revision})
		if err := c.send(ws, Envelope{Type: MsgConfigAck, Payload: ackPayload}); err != nil {
			log.Printf("[Agent] config_ack 发送失败: %v", err)
		}
	}
}

// ---------- 用户下线（配额/禁用） ----------

// loadDisabled 从 data_dir 读持久化的禁用名单（agent 重启后仍生效）。
func (c *Client) loadDisabled() {
	if c.cfg.DataDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(c.cfg.DataDir, "disabled.json"))
	if err != nil {
		return
	}
	var set map[string]bool
	if json.Unmarshal(data, &set) == nil {
		c.disabled = set
	}
}

// saveDisabled 持久化禁用名单。
func (c *Client) saveDisabled(set map[string]bool) {
	if c.cfg.DataDir == "" {
		return
	}
	data, _ := json.Marshal(set)
	_ = os.WriteFile(filepath.Join(c.cfg.DataDir, "disabled.json"), data, 0600)
}

// stripDisabledClients 从配置中移除已下线用户的客户端（vless/trojan/hy2 按 email）。
func (c *Client) stripDisabledClients(cfgBytes []byte) []byte {
	if len(c.disabled) == 0 {
		return cfgBytes
	}
	var cfg map[string]any
	if json.Unmarshal(cfgBytes, &cfg) != nil {
		return cfgBytes
	}
	inbounds, _ := cfg["inbounds"].([]any)
	changed := false
	for _, x := range inbounds {
		ib, ok := x.(map[string]any)
		if !ok {
			continue
		}
		settings, _ := ib["settings"].(map[string]any)
		if settings == nil {
			continue
		}
		clients, _ := settings["clients"].([]any)
		out := []any{}
		for _, cl := range clients {
			m, ok := cl.(map[string]any)
			if !ok {
				out = append(out, cl)
				continue
			}
			em, _ := m["email"].(string)
			if c.disabled[em] {
				changed = true
				log.Printf("[Agent] 客户端下线生效: %s", em)
				continue
			}
			out = append(out, cl)
		}
		settings["clients"] = out
	}
	if !changed {
		return cfgBytes
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return cfgBytes
	}
	return out
}

// handleUserSync 应用主控推送的下线名单：持久化 → 从当前生效配置剥离 → 重启 xray。
func (c *Client) handleUserSync(payload json.RawMessage) {
	var p struct {
		Disabled []string `json:"disabled"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return
	}
	set := map[string]bool{}
	for _, e := range p.Disabled {
		set[e] = true
	}
	c.disabledMu.Lock()
	c.disabled = set
	c.saveDisabled(set)
	c.disabledMu.Unlock()
	log.Printf("[Agent] user_sync: %d 个客户端下线", len(set))

	cfgPath := filepath.Join(c.cfg.XrayConfigDir, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}
	stripped := c.stripDisabledClients(data)
	if string(stripped) == string(data) {
		return // 配置无需变化
	}
	if err := os.WriteFile(cfgPath, stripped, 0600); err != nil {
		return
	}
	if err := c.RestartXray(); err != nil {
		log.Printf("[Agent] xray 重启失败: %v", err)
	}
}

// mergeBaseConfig 确保 stats 与 api inbound 存在（流量统计依赖）。
func mergeBaseConfig(user []byte) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(user, &cfg); err != nil {
		return nil, err
	}
	const apiPort = 15490
	const apiTag = "mmw-api"

	// stats: 流量统计依赖（total/inbound/user 三类 counter）
	if _, ok := cfg["stats"]; !ok {
		cfg["stats"] = map[string]any{}
	}
	// policy: 打开 inbound/user 级 counter（否则 statsquery 只有空结果）
	policy, _ := cfg["policy"].(map[string]any)
	if policy == nil {
		policy = map[string]any{}
	}
	levels, _ := policy["levels"].(map[string]any)
	if levels == nil {
		levels = map[string]any{}
	}
	l0, _ := levels["0"].(map[string]any)
	if l0 == nil {
		l0 = map[string]any{}
	}
	if _, ok := l0["statsUserUplink"]; !ok {
		l0["statsUserUplink"] = true
	}
	if _, ok := l0["statsUserDownlink"]; !ok {
		l0["statsUserDownlink"] = true
	}
	levels["0"] = l0
	policy["levels"] = levels
	sys, _ := policy["system"].(map[string]any)
	if sys == nil {
		sys = map[string]any{}
	}
	for _, k := range []string{"statsInboundUplink", "statsInboundDownlink", "statsOutboundUplink", "statsOutboundDownlink"} {
		if _, ok := sys[k]; !ok {
			sys[k] = true
		}
	}
	policy["system"] = sys
	cfg["policy"] = policy
	// api inbound
	inbounds, _ := cfg["inbounds"].([]any)
	hasAPI := false
	for _, ib := range inbounds {
		m, ok := ib.(map[string]any)
		if !ok {
			continue
		}
		if tag, _ := m["tag"].(string); tag == apiTag {
			hasAPI = true
		}
	}
	if !hasAPI {
		inbounds = append(inbounds, map[string]any{
			"tag":      apiTag,
			"listen":   "127.0.0.1",
			"port":     apiPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1"},
		})
		cfg["inbounds"] = inbounds
	}
	// routing: api → api inbound
	routing, _ := cfg["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	rules, _ := routing["rules"].([]any)
	hasAPIRule := false
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if ib, _ := m["inboundTag"].([]any); len(ib) > 0 {
			if s, _ := ib[0].(string); s == apiTag {
				hasAPIRule = true
			}
		}
	}
	if !hasAPIRule {
		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []string{apiTag},
			"outboundTag": "api",
		})
		routing["rules"] = rules
		cfg["routing"] = routing
	}
	// api service
	api, _ := cfg["api"].(map[string]any)
	if api == nil {
		cfg["api"] = map[string]any{"tag": "api", "services": []string{"HandlerService", "StatsService", "LoggerService"}}
	}
	_ = apiTag
	return json.Marshal(cfg)
}

// ---------- xray 进程管理 ----------

func (c *Client) xrayBin() string {
	if c.cfg.XrayPath != "" {
		return c.cfg.XrayPath
	}
	if runtime.GOOS == "windows" {
		return "xray.exe"
	}
	return "/usr/local/bin/xray"
}

func (c *Client) startXrayIfNeeded() {
	if c.xRunning.Load() {
		return
	}
	cfgPath := filepath.Join(c.cfg.XrayConfigDir, "config.json")
	if _, err := os.Stat(cfgPath); err != nil {
		log.Printf("[Agent] 尚无 xray 配置，等待主控下发")
		return
	}
	if err := c.startXray(); err != nil {
		log.Printf("[Agent] xray 启动失败: %v", err)
	}
}

func (c *Client) startXray() error {
	c.xMu.Lock()
	defer c.xMu.Unlock()
	if c.xRunning.Load() {
		return nil
	}
	cfgPath := filepath.Join(c.cfg.XrayConfigDir, "config.json")
	cmd := exec.Command(c.xrayBin(), "run", "-c", cfgPath, "-format", "json")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	c.xCmd = cmd
	c.xRunning.Store(true)
	// S4: 捕获 cmd 身份，仅当退出的是"当前进程"才清状态（防 RestartXray 竞态误清）
	go func(cmd *exec.Cmd) {
		_ = cmd.Wait()
		c.xMu.Lock()
		if c.xCmd == cmd {
			c.xCmd = nil
			c.xRunning.Store(false)
			log.Printf("[Agent] xray 进程退出")
		}
		c.xMu.Unlock()
	}(cmd)
	log.Printf("[Agent] xray 已启动 (pid=%d)", cmd.Process.Pid)
	return nil
}

// RestartXray 重启 xray 进程。
func (c *Client) RestartXray() error {
	c.xMu.Lock()
	if c.xCmd != nil {
		_ = c.xCmd.Process.Kill()
		_ = c.xCmd.Wait()
		c.xCmd = nil
	}
	c.xRunning.Store(false)
	c.xMu.Unlock()
	time.Sleep(500 * time.Millisecond)
	return c.startXray()
}

// ---------- 统计采样 ----------

type xrayStat struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

type statsQueryResult struct {
	Stat []xrayStat `json:"stat"`
}

// takeTrafficSnapshot 取走暂存增量并打包（M11：发送成功前数据在 inflight 里，失败可滚回）。
func (c *Client) takeTrafficSnapshot() trafficPayload {
	p := c.sampleTrafficCounters()

	c.xMu.Lock()
	defer c.xMu.Unlock()
	p.TotalUp += c.inflightTotal[0]
	p.TotalDown += c.inflightTotal[1]
	for email, up := range c.inflightUp {
		c.mergeUser(&p, email, up, 0)
	}
	for email, down := range c.inflightDown {
		c.mergeUser(&p, email, 0, down)
	}
	// 暂存 → 在途
	c.inflightUp = c.pendingUp
	c.inflightDown = c.pendingDown
	c.inflightTotal = [2]int64{p.TotalUp, p.TotalDown}
	c.pendingUp = map[string]int64{}
	c.pendingDown = map[string]int64{}
	return p
}

func (c *Client) mergeUser(p *trafficPayload, email string, up, down int64) {
	for i := range p.Users {
		if p.Users[i].Email == email {
			p.Users[i].Up += up
			p.Users[i].Down += down
			return
		}
	}
	p.Users = append(p.Users, userTrafficEntry{Email: email, Up: up, Down: down})
}

// restoreTraffic 发送失败：把在途增量合并回暂存，下轮重发。
func (c *Client) restoreTraffic(p trafficPayload) {
	c.xMu.Lock()
	defer c.xMu.Unlock()
	// 快照之后 pending 里又积累了新增量，直接在原 map 上合并回在途数据
	for email, u := range c.inflightUp {
		c.pendingUp[email] += u
	}
	for email, d := range c.inflightDown {
		c.pendingDown[email] += d
	}
	c.inflightUp = map[string]int64{}
	c.inflightDown = map[string]int64{}
	c.inflightTotal = [2]int64{}
	_ = p
}

// sampleTrafficCounters 通过 `xray api statsquery` 采集 counters（M12: 带超时）。
// 关注两类 counter:
//
//	user>>>EMAIL>>>traffic>>>uplink|downlink  → 按用户归集
//	inbound>>>TAG>>>traffic>>>uplink|downlink → 总量与入站
func (c *Client) sampleTrafficCounters() trafficPayload {
	p := trafficPayload{TS: time.Now().Unix()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.xrayBin(), "api", "statsquery",
		"--server=127.0.0.1:15490").Output()
	if err != nil {
		return p
	}
	var q statsQueryResult
	if err := json.Unmarshal(out, &q); err != nil {
		return p
	}

	c.xMu.Lock()
	defer c.xMu.Unlock()
	var totalUp, totalDown int64
	inbounds := map[string]*inboundEntry{}
	for _, st := range q.Stat {
		last, seen := c.lastCounters[st.Name]
		delta := st.Value
		if seen && st.Value >= last {
			delta = st.Value - last
		} // 否则(xray 重启计数器清零)取全量
		c.lastCounters[st.Name] = st.Value

		parts := strings.Split(st.Name, ">>>")
		if len(parts) < 4 || (parts[0] != "user" && parts[0] != "inbound") {
			continue
		}
		key := parts[1]
		isUp := parts[3] == "uplink"
		isDown := parts[3] == "downlink"
		if !isUp && !isDown {
			continue
		}
		if parts[0] == "user" {
			if isUp {
				c.pendingUp[key] += delta
			} else {
				c.pendingDown[key] += delta
			}
		} else {
			ie := inbounds[key]
			if ie == nil {
				ie = &inboundEntry{Tag: key}
				inbounds[key] = ie
			}
			if isUp {
				ie.Up += delta
				totalUp += delta
			} else {
				ie.Down += delta
				totalDown += delta
			}
		}
	}
	p.TotalUp, p.TotalDown = totalUp, totalDown
	for _, ie := range inbounds {
		p.Inbounds = append(p.Inbounds, *ie)
	}
	// pending 的取走在 takeTrafficSnapshot 中统一处理（支持发送失败滚回）
	return p
}
