// 节点生成与入站→订阅同步：主控面板一键在 agent 机上生成节点，并把入站自动转成订阅节点。
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"

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
	return base64.StdEncoding.EncodeToString(priv)
}

// deriveRealityPub 从配置中的 privateKey 推导 publicKey（同步器用）。
func deriveRealityPub(privB64 string) string {
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(priv) != 32 {
		return ""
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
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

// ---------- 入站 → 订阅节点 同步器 ----------

// syncServerNodes 把服务器 desired_config 的入站转成订阅节点（全局池），delete+insert 幂等。
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
		node, err := inboundToNode(ib, sv, host)
		if err != nil {
			continue // dokodemo/api 等非节点入站
		}
		nodes = append(nodes, node)
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

// inboundToNode 把一个 xray inbound 转成订阅节点（生成分享 URI）。
func inboundToNode(ib map[string]any, sv *storage.Server, host string) (*storage.Node, error) {
	proto, _ := ib["protocol"].(string)
	tag, _ := ib["tag"].(string)
	portF, _ := ib["port"].(float64)
	port := int(portF)

	settings, _ := ib["settings"].(map[string]any)
	stream, _ := ib["streamSettings"].(map[string]any)

	n := &subparser.Node{Name: tag, Server: host, Port: port, Network: "tcp"}

	getClient := func(key string) string {
		if settings == nil {
			return ""
		}
		clients, _ := settings["clients"].([]any)
		if len(clients) == 0 {
			return ""
		}
		c, _ := clients[0].(map[string]any)
		v, _ := c[key].(string)
		return v
	}

	sec, _ := stream["security"].(string)
	net, _ := stream["network"].(string)
	n.Network = net

	switch proto {
	case "vless":
		n.Protocol = "vless"
		n.UUID = getClient("id")
		n.Flow = getClient("flow")
	case "trojan":
		n.Protocol = "trojan"
		n.Password = getClient("password")
		if sec == "" {
			sec = "tls"
		}
	case "shadowsocks":
		n.Protocol = "ss"
		method, _ := settings["method"].(string)
		n.Method = method
		n.Password, _ = settings["password"].(string)
	case "hysteria2":
		n.Protocol = "hysteria2"
		n.Password = getClient("password")
		sec = "tls"
	default:
		return nil, fmt.Errorf("跳过协议 %s", proto)
	}

	// TLS/Reality
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

	// WS 传输
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
		return nil, fmt.Errorf("无法生成分享链接")
	}
	return &storage.Node{
		Username:     "__global__",
		RawURL:       uri,
		NodeName:     tag,
		Protocol:     n.Protocol,
		Server:       host,
		ParsedConfig: n.ToJSON(),
		Enabled:      true,
		Tag:          sv.Name, // 标签=来源服务器名
	}, nil
}
