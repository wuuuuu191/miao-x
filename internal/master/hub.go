// Package master 主控端 agent hub：注册、加密通道、心跳、RPC 转发、流量归集、配置下发。
// 协议与妙妙屋X mmw-agent 同构:
//   - agent 主动 WS 连入 /api/agent/ws (Authorization: Bearer <server-token>)
//   - 握手: agent 发 {type:key_exchange, eph_pub} → master 回 {type:key_exchange, eph_pub, sig}
//     (Ed25519 主控身份对临时公钥签名, agent 预置主控公钥验签防中间人)
//   - 此后所有帧为二进制信封(securechan) 包着 JSON {type, payload}
//   - register → register_ack；heartbeat/traffic/speed 周期帧；rpc_call 反向 RPC；config_update 下发
package master

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"miao-x/internal/securechan"
	"miao-x/internal/storage"
)

// WS 消息类型（对齐 X 的 WSMsgType 语义）。
const (
	MsgKeyExchange   = "key_exchange"
	MsgRegister      = "register"
	MsgRegisterAck   = "register_ack"
	MsgHeartbeat     = "heartbeat"
	MsgHeartbeatAck  = "heartbeat_ack"
	MsgTraffic       = "traffic"
	MsgSpeed         = "speed"
	MsgRPCCall       = "rpc_call"
	MsgRPCReply      = "rpc_reply"
	MsgRPCStreamData = "rpc_stream_data"
	MsgConfigUpdate  = "config_update"
	MsgConfigAck     = "config_ack"
	MsgTokenUpdate   = "token_update"
)

type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// Conn 一条已认证的 agent 连接。
type Conn struct {
	ServerID   int64
	ServerName string
	ws         *websocket.Conn
	session    *securechan.Session
	sendMu     sync.Mutex
	hub        *Hub
	closeCh    chan struct{}
	closeOnce  sync.Once
	pendingMu  sync.Mutex
	pending    map[string]chan *RPCReply
}

// Hub 管理所有在线 agent。
type Hub struct {
	mu    sync.RWMutex
	conns map[int64]*Conn // serverID -> conn
	store *storage.Store
	ident *securechan.Identity
	upgr  websocket.Upgrader
}

func NewHub(store *storage.Store, ident *securechan.Identity) *Hub {
	return &Hub{
		conns: map[int64]*Conn{},
		store: store,
		ident: ident,
		upgr: websocket.Upgrader{
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
}

func (h *Hub) IsOnline(serverID int64) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[serverID]
	return ok
}

func (h *Hub) OnlineIDs() []int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]int64, 0, len(h.conns))
	for id := range h.conns {
		out = append(out, id)
	}
	return out
}

// HandleAgentWS 处理 agent 连入：token 校验 → 握手 → 注册 → 消息循环。
func (h *Hub) HandleAgentWS(w http.ResponseWriter, r *http.Request) {
	token := bearerStrip(r.Header.Get("Authorization"))
	server, err := h.store.GetServerByToken(token)
	if err != nil {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	ws, err := h.upgr.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Hub] upgrade failed: %v", err)
		return
	}
	// M5: 限制单帧大小，防内存放大
	ws.SetReadLimit(1 << 20)
	conn := &Conn{
		ServerID:   server.ID,
		ServerName: server.Name,
		ws:         ws,
		hub:        h,
		closeCh:    make(chan struct{}),
		pending:    map[string]chan *RPCReply{},
	}

	// 密钥交换（明文帧 2 步）
	if err := conn.keyExchange(); err != nil {
		log.Printf("[Hub] %s key exchange failed: %v", server.Name, err)
		ws.Close()
		return
	}

	// 注册帧
	var reg RegisterPayload
	msg, err := conn.readEncrypted(30 * time.Second)
	if err != nil {
		log.Printf("[Hub] %s register read failed: %v", server.Name, err)
		ws.Close()
		return
	}
	if err := json.Unmarshal(msg.Payload, &reg); err != nil {
		ws.Close()
		return
	}

	// 挤掉旧连接（同一服务器只保留一条）
	h.mu.Lock()
	if old, ok := h.conns[server.ID]; ok {
		old.closeOnce.Do(func() { close(old.closeCh) })
		old.ws.Close()
	}
	h.conns[server.ID] = conn
	h.mu.Unlock()

	ack, _ := json.Marshal(map[string]any{
		"server_id":       server.ID,
		"name":            server.Name,
		"config_revision": server.ConfigRevision,
	})
	conn.sendEncrypted(Envelope{Type: MsgRegisterAck, Payload: ack})
	log.Printf("[Hub] agent connected: %s (%s/%s v%s) ip=%s", reg.Hostname, reg.OS, reg.Arch, reg.Version, r.RemoteAddr)

	// 注册在线状态
	h.store.UpsertServerStatus(&storage.ServerStatus{
		ServerID: server.ID, Online: true, LastSeen: time.Now(),
		Hostname: reg.Hostname, OS: reg.OS, Arch: reg.Arch, AgentVersion: reg.Version,
		ListenPort: reg.ListenPort, PublicIP: reg.PublicIP,
	})

	// S1: agent 上线即补推当前期望配置 —— 解决"下发时 agent 离线，配置永不投递"
	if server.DesiredConfig != "" {
		if err := conn.sendEncrypted(Envelope{Type: MsgConfigUpdate, Payload: mustJSON(map[string]any{
			"revision": server.ConfigRevision, "config": server.DesiredConfig,
		})}); err == nil {
			log.Printf("[Hub] 已向 %s 补推配置 rev=%d", server.Name, server.ConfigRevision)
		}
	}

	defer func() {
		// S3: 只有当前连接仍是自己时才删除并标记离线（防止重连后旧连接把新状态打回离线）
		h.mu.Lock()
		if h.conns[server.ID] == conn {
			delete(h.conns, server.ID)
			h.store.MarkServerOffline(server.ID)
		}
		h.mu.Unlock()
		conn.closeOnce.Do(func() { close(conn.closeCh) })
		conn.failAllPending("agent offline")
		ws.Close()
		log.Printf("[Hub] agent disconnected: %s", server.Name)
	}()

	conn.run()
}

// ---------- 连接读写 ----------

type RegisterPayload struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Version      string `json:"version"`
	ListenPort   int    `json:"listen_port"`
	PublicIP     string `json:"public_ip"`
	Capabilities struct {
		RPC bool `json:"rpc"`
	} `json:"capabilities"`
}

type HeartbeatPayload struct {
	TS          int64   `json:"ts"`
	XrayRunning bool    `json:"xray_running"`
	CPUPct      float64 `json:"cpu_pct"`
	MemUsed     int64   `json:"mem_used"`
	MemTotal    int64   `json:"mem_total"`
	Uptime      int64   `json:"uptime"`
}

type TrafficPayload struct {
	TS        int64               `json:"ts"`
	TotalUp   int64               `json:"total_up"`
	TotalDown int64               `json:"total_down"`
	Users     []UserTrafficReport `json:"users"`
	Inbounds  []InboundTraffic    `json:"inbounds"`
}

type UserTrafficReport struct {
	Email string `json:"email"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
}

type InboundTraffic struct {
	Tag  string `json:"tag"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type SpeedPayload struct {
	UpBps   int64 `json:"up_bps"`
	DownBps int64 `json:"down_bps"`
}

type RPCCall struct {
	RequestID string          `json:"request_id"`
	Method    string          `json:"method"`
	Path      string          `json:"path"`
	Query     string          `json:"query,omitempty"`
	Body      json.RawMessage `json:"body,omitempty"`
	TimeoutMs int             `json:"timeout_ms,omitempty"`
	Stream    bool            `json:"stream,omitempty"`
}

type RPCReply struct {
	RequestID string          `json:"request_id"`
	Status    int             `json:"status"`
	Body      json.RawMessage `json:"body,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// sendEncrypted 线程安全发送。
func (c *Conn) sendEncrypted(env Envelope) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	plain, err := json.Marshal(env)
	if err != nil {
		return err
	}
	bin, err := c.session.Encrypt(plain)
	if err != nil {
		return err
	}
	_ = c.ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return c.ws.WriteMessage(websocket.BinaryMessage, bin)
}

func (c *Conn) readEncrypted(timeout time.Duration) (Envelope, error) {
	var env Envelope
	_ = c.ws.SetReadDeadline(time.Now().Add(timeout))
	mt, data, err := c.ws.ReadMessage()
	if err != nil {
		return env, err
	}
	if mt != websocket.BinaryMessage {
		return env, errEnvelope{msg: "expect binary frame"}
	}
	plain, err := c.session.Decrypt(data)
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(plain, &env)
	return env, err
}

type errEnvelope struct{ msg string }

func (e errEnvelope) Error() string { return e.msg }

// keyExchange 主控侧握手：agent 先发临时公钥（agent 主动，消除消息顺序歧义），
// 主控回签名过的临时公钥 → 派生会话。
func (c *Conn) keyExchange() error {
	mPriv, mPub, err := securechan.GenerateEphemeral()
	if err != nil {
		return err
	}

	_ = c.ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, data, err := c.ws.ReadMessage()
	if err != nil {
		return err
	}
	var agentKE struct {
		EphPub string `json:"eph_pub"`
	}
	if err := json.Unmarshal(data, &agentKE); err != nil {
		return err
	}
	aPub, err := decodeB64(agentKE.EphPub)
	if err != nil {
		return err
	}

	mPubB64 := encodeB64(mPub)
	sig := securechan.Sign(c.hub.ident.PrivateKey, mPub)
	resp, _ := json.Marshal(map[string]any{"eph_pub": mPubB64, "sig": encodeB64(sig)})
	_ = c.ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := c.ws.WriteMessage(websocket.TextMessage, resp); err != nil {
		return err
	}

	shared, err := securechan.ComputeSharedSecret(mPriv, aPub)
	if err != nil {
		return err
	}
	sess, err := securechan.DeriveSession(shared, aPub, mPub, true)
	if err != nil {
		return err
	}
	c.session = sess
	return nil
}

// run 消息循环：分发 heartbeat/traffic/speed/rpc_reply/config_ack。
func (c *Conn) run() {
	for {
		env, err := c.readEncrypted(120 * time.Second)
		if err != nil {
			return
		}
		switch env.Type {
		case MsgHeartbeat:
			var hb HeartbeatPayload
			if json.Unmarshal(env.Payload, &hb) == nil {
				c.hub.store.UpdateServerDynamicStatus(c.ServerID, true, hb.XrayRunning, hb.CPUPct, hb.MemUsed, hb.MemTotal)
				ack, _ := json.Marshal(map[string]any{"ts": time.Now().Unix()})
				c.sendEncrypted(Envelope{Type: MsgHeartbeatAck, Payload: ack})
			}
		case MsgTraffic:
			var tr TrafficPayload
			if json.Unmarshal(env.Payload, &tr) == nil {
				c.handleTraffic(&tr)
			}
		case MsgSpeed:
			var sp SpeedPayload
			if json.Unmarshal(env.Payload, &sp) == nil {
				c.hub.store.UpdateServerSpeed(c.ServerID, sp.UpBps, sp.DownBps)
			}
		case MsgRPCReply:
			var reply RPCReply
			if json.Unmarshal(env.Payload, &reply) == nil {
				c.resolvePending(&reply)
			}
		case MsgConfigAck:
			// 配置应用确认，暂仅日志
			log.Printf("[Hub] %s config ack", c.ServerName)
		default:
			log.Printf("[Hub] %s unknown msg type: %s", c.ServerName, env.Type)
		}
	}
}

// handleTraffic 流量归集：服务器总流量入库；email 前缀映射面板用户；入站流量挂到同步节点。
func (c *Conn) handleTraffic(tr *TrafficPayload) {
	_ = c.hub.store.AddServerTraffic(c.ServerID, tr.TotalUp, tr.TotalDown)
	for _, u := range tr.Users {
		name := userEmailToUsername(u.Email)
		if name == "" {
			continue
		}
		_ = c.hub.store.AddUserTraffic(name, u.Up, u.Down)
	}
	for _, ib := range tr.Inbounds {
		_ = c.hub.store.AddNodeTraffic(c.ServerID, ib.Tag, ib.Up, ib.Down)
	}
}

// userEmailToUsername agent 上报的 email 形如 "alice@panel"，映射为面板用户名 alice。
func userEmailToUsername(email string) string {
	for i := 0; i < len(email); i++ {
		if email[i] == '@' {
			return email[:i]
		}
	}
	return email
}

// ---------- 对外 RPC 调用 ----------

// Call 向在线 agent 发起反向 RPC（HTTP 语义转发），阻塞等待回复。
func (h *Hub) Call(serverID int64, method, path, query string, body []byte, timeout time.Duration) (*RPCReply, error) {
	h.mu.RLock()
	conn, ok := h.conns[serverID]
	h.mu.RUnlock()
	if !ok {
		return nil, errAgentOffline
	}

	reqID := nextReqID()
	ch := make(chan *RPCReply, 1)
	conn.pendingMu.Lock()
	conn.pending[reqID] = ch
	conn.pendingMu.Unlock()

	payload, _ := json.Marshal(RPCCall{
		RequestID: reqID, Method: method, Path: path, Query: query,
		Body: body, TimeoutMs: int(timeout.Milliseconds()),
	})
	if err := conn.sendEncrypted(Envelope{Type: MsgRPCCall, Payload: payload}); err != nil {
		conn.pendingMu.Lock()
		delete(conn.pending, reqID)
		conn.pendingMu.Unlock()
		return nil, err
	}

	select {
	case reply := <-ch:
		return reply, nil
	case <-time.After(timeout):
		conn.pendingMu.Lock()
		delete(conn.pending, reqID)
		conn.pendingMu.Unlock()
		return nil, errRPCTimeout
	case <-conn.closeCh:
		return nil, errAgentOffline
	}
}

func (c *Conn) resolvePending(reply *RPCReply) {
	c.pendingMu.Lock()
	ch, ok := c.pending[reply.RequestID]
	if ok {
		delete(c.pending, reply.RequestID)
	}
	c.pendingMu.Unlock()
	if ok {
		select {
		case ch <- reply:
		default:
		}
	}
}

func (c *Conn) failAllPending(reason string) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	for id, ch := range c.pending {
		select {
		case ch <- &RPCReply{RequestID: id, Status: http.StatusServiceUnavailable, Error: reason}:
		default:
		}
		delete(c.pending, id)
	}
}

func nextReqID() string {
	return time.Now().Format("150405.000000") + "-" + randSuffix()
}

// PushConfig 把期望配置推给在线 agent（不在线则等 agent 连上后拉取）。
func (h *Hub) PushConfig(serverID int64, revision int64, config string) error {
	h.mu.RLock()
	conn, ok := h.conns[serverID]
	h.mu.RUnlock()
	if !ok {
		return errAgentOffline
	}
	payload, _ := json.Marshal(map[string]any{
		"revision": revision,
		"config":   config,
	})
	return conn.sendEncrypted(Envelope{Type: MsgConfigUpdate, Payload: payload})
}

var (
	errAgentOffline = errSimple{"agent 离线"}
	errRPCTimeout   = errSimple{"agent 响应超时"}
)

type errSimple struct{ s string }

func (e errSimple) Error() string { return e.s }

// ---------- 小工具 ----------

// bearerStrip 剥掉 "Bearer " 前缀。
func bearerStrip(h string) string {
	if len(h) > 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	return h
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func randSuffix() string {
	buf := make([]byte, 4)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}
