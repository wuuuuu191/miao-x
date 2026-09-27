// Package agent 子节点端：主动连接主控，加密通道，反向 RPC，xray 管理，流量/指标上报。
package agent

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"

	"miao-x/internal/securechan"
)

const Version = "0.1.0"

const (
	MsgKeyExchange  = "key_exchange"
	MsgRegister     = "register"
	MsgRegisterAck  = "register_ack"
	MsgHeartbeat    = "heartbeat"
	MsgHeartbeatAck = "heartbeat_ack"
	MsgTraffic      = "traffic"
	MsgSpeed        = "speed"
	MsgRPCCall      = "rpc_call"
	MsgRPCReply     = "rpc_reply"
	MsgConfigUpdate = "config_update"
	MsgConfigAck    = "config_ack"
	MsgTokenUpdate  = "token_update"
)

type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type Config struct {
	MasterURL     string // 如 http(s)://1.2.3.4:12889 或 ws(s)://
	Token         string
	MasterPubKey  string // base64 Ed25519 主控公钥（防中间人）
	ListenPort    int    // agent 本地管理端口(0=仅WS RPC)
	XrayPath      string // xray 二进制路径
	XrayConfigDir string // xray 配置目录
	DataDir       string
	AllowInsecure bool // 允许对非内网地址使用明文 ws://（S2 防护开关）
}

type Client struct {
	cfg    Config
	mux    *http.ServeMux // 反向 RPC 用的本地 handler（与本地 HTTP 端口共享）
	conn   *websocket.Conn
	sendMu sync.Mutex
	sess   *securechan.Session

	// xray 进程管理
	xCmd     *exec.Cmd
	xMu      sync.Mutex
	xRunning atomic.Bool

	// 统计采样: statName -> 上次 counter 值; 采样周期内增量暂存
	lastCounters  map[string]int64
	pendingUp     map[string]int64 // email -> bytes（待发送）
	pendingDown   map[string]int64
	inflightUp    map[string]int64 // 已打包未确认（M11: 发送失败滚回）
	inflightDown  map[string]int64
	inflightTotal [2]int64

	lastRev atomic.Int64 // 已应用的最大配置 revision（防旧配置乱序覆盖）

	lastNetSample struct {
		rx, tx int64
		at     time.Time
	}

	stopCh chan struct{}
	once   sync.Once
}

func NewClient(cfg Config, mux *http.ServeMux) *Client {
	return &Client{
		cfg:          cfg,
		mux:          mux,
		stopCh:       make(chan struct{}),
		lastCounters: map[string]int64{},
		pendingUp:    map[string]int64{},
		pendingDown:  map[string]int64{},
		inflightUp:   map[string]int64{},
		inflightDown: map[string]int64{},
	}
}

func (c *Client) Stop() { c.once.Do(func() { close(c.stopCh) }) }

// Start 阻塞运行（内部自动重连，指数退避 5s→300s）。
func (c *Client) Start() {
	backoff := 5 * time.Second
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}
		err := c.connectAndRun()
		if err != nil && err != errAuthInvalid {
			log.Printf("[Agent] 连接断开: %v, %v 后重连", err, backoff)
		} else if err == errAuthInvalid {
			log.Printf("[Agent] token 无效，60s 后重试")
			backoff = 60 * time.Second
		}
		select {
		case <-c.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 300*time.Second {
			backoff *= 2
			if backoff > 300*time.Second {
				backoff = 300 * time.Second
			}
		}
	}
}

var errAuthInvalid = fmt.Errorf("auth invalid")

func (c *Client) connectAndRun() error {
	u := c.cfg.MasterURL
	if len(u) > 4 && u[:4] == "http" {
		// http(s):// → ws(s)://
		if u[4] == 's' {
			u = "wss" + u[5:]
		} else {
			u = "ws" + u[4:]
		}
	}
	// S2: 明文 ws:// 只允许内网/回环地址，公网地址必须 https/wss 或显式 allow_insecure
	if err := ensureSecureTransport(u); err != nil {
		if !c.cfg.AllowInsecure {
			return fmt.Errorf("%w（如确要明文传输，配置 allow_insecure: true）", err)
		}
		log.Printf("[Agent] 警告: allow_insecure 已开启，token 将明文传输: %v", err)
	}

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+c.cfg.Token)
	hdr.Set("User-Agent", "miaowu-agent/"+Version)

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ws, _, err := dialer.Dial(u+"/api/agent/ws", hdr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = ws
	defer ws.Close()

	if err := c.keyExchange(ws); err != nil {
		return fmt.Errorf("key exchange: %w", err)
	}
	if err := c.register(ws); err != nil {
		return err
	}
	log.Printf("[Agent] 已连接主控 %s", c.cfg.MasterURL)
	defer log.Printf("[Agent] 与主控断开")

	go c.startXrayIfNeeded()

	return c.messageLoop(ws)
}

// keyExchange agent 侧握手：发临时公钥 → 收主控临时公钥+签名 → 用预置主控公钥验签 → 派生会话。
func (c *Client) keyExchange(ws *websocket.Conn) error {
	aPriv, aPub, err := securechan.GenerateEphemeral()
	if err != nil {
		return err
	}
	req, _ := json.Marshal(map[string]any{"eph_pub": b64(aPub)})
	_ = ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := ws.WriteMessage(websocket.TextMessage, req); err != nil {
		return err
	}

	_ = ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		return err
	}
	var resp struct {
		EphPub string `json:"eph_pub"`
		Sig    string `json:"sig"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}

	mPub, err := securechan.ParsePublicKey(c.cfg.MasterPubKey)
	if err != nil {
		return fmt.Errorf("master_pub_key 配置无效: %w", err)
	}
	mPubEph, err := base64.StdEncoding.DecodeString(resp.EphPub)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Sig)
	if err != nil {
		return err
	}
	if !securechan.Verify(mPub, mPubEph, sig) {
		return fmt.Errorf("主控签名校验失败（可能的中间人）")
	}

	shared, err := securechan.ComputeSharedSecret(aPriv, mPubEph)
	if err != nil {
		return err
	}
	sess, err := securechan.DeriveSession(shared, aPub, mPubEph, false)
	if err != nil {
		return err
	}
	c.sess = sess
	return nil
}

type registerPayload struct {
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

func (c *Client) register(ws *websocket.Conn) error {
	host, _ := os.Hostname()
	p := registerPayload{
		Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Version: Version,
		ListenPort: c.cfg.ListenPort, PublicIP: detectPublicIP(),
	}
	p.Capabilities.RPC = true
	b, _ := json.Marshal(p)
	return c.send(ws, Envelope{Type: MsgRegister, Payload: b})
}

func (c *Client) send(ws *websocket.Conn, env Envelope) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	plain, err := json.Marshal(env)
	if err != nil {
		return err
	}
	bin, err := c.sess.Encrypt(plain)
	if err != nil {
		return err
	}
	_ = ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return ws.WriteMessage(websocket.BinaryMessage, bin)
}

func (c *Client) readEnvelope(ws *websocket.Conn, timeout time.Duration) (Envelope, error) {
	var env Envelope
	_ = ws.SetReadDeadline(time.Now().Add(timeout))
	mt, data, err := ws.ReadMessage()
	if err != nil {
		return env, err
	}
	if mt != websocket.BinaryMessage {
		return env, fmt.Errorf("expect binary frame")
	}
	plain, err := c.sess.Decrypt(data)
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(plain, &env)
	return env, err
}

// messageLoop 主循环：读消息 + 周期上报。
func (c *Client) messageLoop(ws *websocket.Conn) error {
	heartbeat := time.NewTicker(15 * time.Second)
	speedTick := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	defer speedTick.Stop()

	// M12: 流量采样放独立 goroutine（xray api 调用带超时），经 channel 交给主循环发送
	trafficCh := make(chan trafficPayload, 1)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				p := c.takeTrafficSnapshot()
				select {
				case trafficCh <- p:
				default: // 上一包还没发出去，丢弃本次（增量化下无需补发）
				}
			}
		}
	}()

	msgCh := make(chan Envelope, 16)
	errCh := make(chan error, 1)
	go func() {
		for {
			env, err := c.readEnvelope(ws, 120*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- env
		}
	}()

	c.sendHeartbeat(ws)
	c.sendSpeed(ws)
	c.sampleNet()

	for {
		select {
		case <-c.stopCh:
			return nil
		case err := <-errCh:
			return err
		case env := <-msgCh:
			switch env.Type {
			case MsgHeartbeatAck:
			case MsgRegisterAck:
				log.Printf("[Agent] 注册成功")
				var p struct {
					ConfigRevision int64 `json:"config_revision"`
				}
				if json.Unmarshal(env.Payload, &p) == nil && p.ConfigRevision >= 0 {
					c.lastRev.Store(p.ConfigRevision)
				}
			case MsgTokenUpdate:
				var p struct {
					Token string `json:"token"`
				}
				if json.Unmarshal(env.Payload, &p) == nil && p.Token != "" {
					c.cfg.Token = p.Token
					c.persistToken(p.Token)
					return errAuthInvalid // 触发用新 token 重连
				}
			case MsgConfigUpdate:
				go c.handleConfigUpdate(ws, env.Payload)
			case MsgRPCCall:
				go c.handleRPCCall(ws, env.Payload)
			default:
				log.Printf("[Agent] 未知消息: %s", env.Type)
			}
		case <-heartbeat.C:
			if err := c.sendHeartbeat(ws); err != nil {
				return err
			}
		case p := <-trafficCh:
			if err := c.sendTraffic(ws, p); err != nil {
				c.restoreTraffic(p) // M11: 发送失败把增量滚回暂存，下轮合并重发
				return err
			}
		case <-speedTick.C:
			if err := c.sendSpeed(ws); err != nil {
				return err
			}
		}
	}
}

type heartbeatPayload struct {
	TS          int64   `json:"ts"`
	XrayRunning bool    `json:"xray_running"`
	CPUPct      float64 `json:"cpu_pct"`
	MemUsed     int64   `json:"mem_used"`
	MemTotal    int64   `json:"mem_total"`
	Uptime      int64   `json:"uptime"`
}

var procStart = time.Now()

func (c *Client) sendHeartbeat(ws *websocket.Conn) error {
	cpu, memUsed, memTotal := systemMetrics()
	b, _ := json.Marshal(heartbeatPayload{
		TS: time.Now().Unix(), XrayRunning: c.xRunning.Load(),
		CPUPct: cpu, MemUsed: memUsed, MemTotal: memTotal,
		Uptime: int64(time.Since(procStart).Seconds()),
	})
	return c.send(ws, Envelope{Type: MsgHeartbeat, Payload: b})
}

type trafficPayload struct {
	TS        int64              `json:"ts"`
	TotalUp   int64              `json:"total_up"`
	TotalDown int64              `json:"total_down"`
	Users     []userTrafficEntry `json:"users"`
	Inbounds  []inboundEntry     `json:"inbounds"`
}

type userTrafficEntry struct {
	Email string `json:"email"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
}

type inboundEntry struct {
	Tag  string `json:"tag"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

// sendTraffic 发送采样好的流量包（M11: 失败由调用方 restoreTraffic 滚回）。
func (c *Client) sendTraffic(ws *websocket.Conn, p trafficPayload) error {
	b, _ := json.Marshal(p)
	return c.send(ws, Envelope{Type: MsgTraffic, Payload: b})
}

func (c *Client) sendSpeed(ws *websocket.Conn) error {
	rx, tx := netCounters()
	now := time.Now()
	c.xMu.Lock()
	prev := c.lastNetSample
	c.lastNetSample.rx, c.lastNetSample.tx, c.lastNetSample.at = rx, tx, now
	c.xMu.Unlock()
	var upBps, downBps int64
	if !prev.at.IsZero() {
		dt := now.Sub(prev.at).Seconds()
		if dt > 0 {
			upBps = int64(float64(tx-prev.tx) / dt)
			downBps = int64(float64(rx-prev.rx) / dt)
			if upBps < 0 {
				upBps = 0
			}
			if downBps < 0 {
				downBps = 0
			}
		}
	}
	b, _ := json.Marshal(map[string]int64{"up_bps": upBps, "down_bps": downBps})
	return c.send(ws, Envelope{Type: MsgSpeed, Payload: b})
}

func (c *Client) sampleNet() {
	rx, tx := netCounters()
	c.lastNetSample = struct {
		rx, tx int64
		at     time.Time
	}{rx: rx, tx: tx, at: time.Now()}
}

// persistToken 主控轮换 token 后写回配置文件（L18: 用 yaml 重写而非行替换）。
func (c *Client) persistToken(tok string) {
	if c.cfg.DataDir == "" {
		log.Printf("[Agent] data_dir 未配置，新 token 无法持久化")
		return
	}
	path := filepath.Join(c.cfg.DataDir, "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("[Agent] 配置解析失败，新 token 无法持久化: %v", err)
		return
	}
	cfg["token"] = tok
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, out, 0600)
	log.Printf("[Agent] 新 token 已写入 %s", path)
}

// ---------- 小工具 ----------

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func detectPublicIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
