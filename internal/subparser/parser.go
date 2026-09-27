// Package subparser 节点 URI 解析与统一结构。
// 支持: ss / vmess / vless / trojan / hysteria2(hy2) / tuic / anytls
package subparser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Node 统一节点结构（存 parsed_config JSON）。
type Node struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Server   string            `json:"server"`
	Port     int               `json:"port"`
	UUID     string            `json:"uuid,omitempty"`
	Password string            `json:"password,omitempty"`
	Method   string            `json:"method,omitempty"`   // ss cipher
	Network  string            `json:"network,omitempty"`  // tcp/ws/grpc/h2
	Security string            `json:"security,omitempty"` // tls/reality/none
	SNI      string            `json:"sni,omitempty"`
	Host     string            `json:"host,omitempty"` // ws host
	Path     string            `json:"path,omitempty"` // ws path
	Flow     string            `json:"flow,omitempty"` // xtls-rprx-vision
	ALPN     []string          `json:"alpn,omitempty"`
	Fp       string            `json:"fp,omitempty"`
	Pbk      string            `json:"pbk,omitempty"` // reality public key
	Sid      string            `json:"sid,omitempty"` // reality short id
	SkipCert bool              `json:"skip_cert_verify,omitempty"`
	WSOpts   map[string]string `json:"-"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// Parse 解析一条分享链接。
func Parse(raw string) (*Node, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "ss://"):
		return parseSS(raw)
	case strings.HasPrefix(raw, "vmess://"):
		return parseVmess(raw)
	case strings.HasPrefix(raw, "vless://"):
		return parseUserHostURI(raw[8:], "vless")
	case strings.HasPrefix(raw, "trojan://"):
		n, err := parseUserHostURI(raw[9:], "trojan")
		if err != nil {
			return nil, err
		}
		SetTrojan(n)
		return n, nil
	case strings.HasPrefix(raw, "hysteria2://"), strings.HasPrefix(raw, "hy2://"):
		u := strings.TrimPrefix(strings.TrimPrefix(raw, "hysteria2://"), "hy2://")
		return parseGeneric(u, "hysteria2")
	case strings.HasPrefix(raw, "tuic://"):
		return parseGeneric(raw[7:], "tuic")
	case strings.HasPrefix(raw, "anytls://"):
		return parseGeneric(raw[9:], "anytls")
	default:
		return nil, fmt.Errorf("不支持的协议前缀: %s", prefixOf(raw))
	}
}

func prefixOf(s string) string {
	if i := strings.Index(s, "://"); i > 0 {
		return s[:i+3]
	}
	return s
}

func parseGeneric(rest, proto string) (*Node, error) {
	u, err := url.Parse("scheme://" + rest)
	if err != nil {
		return nil, fmt.Errorf("URI 解析失败: %w", err)
	}
	port, _ := strconv.Atoi(u.Port())
	if u.User == nil {
		return nil, fmt.Errorf("缺少凭据")
	}
	n := &Node{
		Name:     u.Fragment,
		Protocol: proto,
		Server:   u.Hostname(),
		Port:     port,
		UUID:     u.User.Username(),
	}
	if pw, ok := u.User.Password(); ok {
		n.Password = pw
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s-%s:%d", proto, n.Server, n.Port)
	}
	applyQuery(n, u.Query())
	if proto == "hysteria2" && n.Password == "" {
		n.Password = n.UUID
	}
	if proto == "tuic" && n.UUID != "" && n.Password == "" {
		// tuic v5: uuid:password 已分离
	}
	if proto == "anytls" && n.Password == "" {
		n.Password = n.UUID
	}
	return n, nil
}

func applyQuery(n *Node, q url.Values) {
	if v := q.Get("security"); v != "" {
		n.Security = v
	}
	if n.Security == "" && (q.Get("sni") != "" || q.Get("pbk") != "") {
		n.Security = "tls"
	}
	if v := q.Get("sni"); v != "" {
		n.SNI = v
	}
	if v := q.Get("host"); v != "" {
		n.Host = v
	}
	if v := q.Get("path"); v != "" {
		n.Path = v
	}
	if v := q.Get("type"); v != "" {
		n.Network = v
	}
	if v := q.Get("flow"); v != "" {
		n.Flow = v
	}
	if v := q.Get("fp"); v != "" {
		n.Fp = v
	}
	if v := q.Get("pbk"); v != "" {
		n.Pbk = v
	}
	if v := q.Get("sid"); v != "" {
		n.Sid = v
	}
	if v := q.Get("alpn"); v != "" {
		n.ALPN = strings.Split(v, ",")
	}
	if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
		n.SkipCert = true
	}
	if v := q.Get("serviceName"); v != "" && n.Network == "grpc" {
		n.Path = v
	}
}

// parseUserHostURI: scheme://uuid[:pass]@host:port?params#name —— vless/trojan 同构
func parseUserHostURI(rest, proto string) (*Node, error) {
	u, err := url.Parse("scheme://" + rest)
	if err != nil {
		return nil, err
	}
	// M17: 与 parseGeneric 一致，缺凭据显式报错（Go 的 nil Userinfo 静默返回 ""，会产出空凭据节点）
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("缺少凭据（uuid/password）")
	}
	port, _ := strconv.Atoi(u.Port())
	n := &Node{
		Name:     u.Fragment,
		Protocol: proto,
		Server:   u.Hostname(),
		Port:     port,
		UUID:     u.User.Username(),
	}
	if pw, ok := u.User.Password(); ok {
		n.Extra = map[string]string{"second": pw}
	}
	if n.Name == "" {
		n.Name = n.Server + ":" + strconv.Itoa(n.Port)
	}
	applyQuery(n, u.Query())
	if n.Network == "" {
		n.Network = "tcp"
	}
	return n, nil
}

// SetTrojan 修正协议名（trojan URI 与 vless 同构）。
func SetTrojan(n *Node) {
	n.Protocol = "trojan"
	if n.Password == "" {
		n.Password = n.UUID
		n.UUID = ""
	}
	if n.Security == "" {
		n.Security = "tls"
	}
}

// parseVmess: vmess://base64(JSON)
func parseVmess(raw string) (*Node, error) {
	payload := raw[8:]
	b, err := base64Decode(payload)
	if err != nil {
		// 尝试 URL-safe
		b, err = base64.RawURLEncoding.DecodeString(payload + strings.Repeat("=", (4-len(payload)%4)%4))
		if err != nil {
			return nil, fmt.Errorf("vmess base64 解码失败: %w", err)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("vmess JSON 解析失败: %w", err)
	}
	get := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return strconv.Itoa(int(v))
		}
		return ""
	}
	port, _ := strconv.Atoi(get("port"))
	n := &Node{
		Name:     get("ps"),
		Protocol: "vmess",
		Server:   get("add"),
		Port:     port,
		UUID:     get("id"),
		Network:  get("net"),
		Security: get("tls"),
		SNI:      get("sni"),
		Host:     get("host"),
		Path:     get("path"),
	}
	if n.Network == "" {
		n.Network = "tcp"
	}
	if n.Security == "" && (n.SNI != "" || n.Host != "") {
		n.Security = "tls" // L17: vmess JSON 只给 tls 标志位的归一化
	}
	return n, nil
}

// parseSS: ss://base64(method:password)@host:port#name 或 ss://base64(method:password@host:port)#name
func parseSS(raw string) (*Node, error) {
	body := raw[5:]
	frag := ""
	if i := strings.LastIndex(body, "#"); i >= 0 {
		frag = body[i+1:]
		body = body[:i]
	}
	name, _ := url.QueryUnescape(frag)

	// 形式1: 整体 base64
	if !strings.Contains(body, "@") {
		b, err := base64Decode(body)
		if err != nil {
			return nil, fmt.Errorf("ss base64 解码失败: %w", err)
		}
		body = string(b)
		if i := strings.LastIndex(body, "#"); i >= 0 {
			if n2, _ := url.QueryUnescape(body[i+1:]); n2 != "" {
				name = n2
			}
			body = body[:i]
		}
	}
	// user-info@host
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return nil, fmt.Errorf("ss URI 缺少 @")
	}
	userPart := body[:at]
	hostPart := body[at+1:]
	// userPart 可能是 base64(method:password)
	decoded, err := base64Decode(userPart)
	if err == nil && !strings.Contains(userPart, ":") {
		userPart = string(decoded)
	}
	cipher, password, ok := strings.Cut(userPart, ":")
	if !ok {
		return nil, fmt.Errorf("ss URI 缺少 cipher:password")
	}
	host, portS, err := splitHostPort(hostPart)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portS)
	if name == "" {
		name = host + ":" + portS
	}
	return &Node{Name: name, Protocol: "ss", Server: host, Port: port, Method: cipher, Password: password}, nil
}

func splitHostPort(s string) (string, string, error) {
	s = strings.Trim(s, "[]")
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("缺少端口: %s", s)
	}
	return s[:i], strings.TrimSuffix(s[i+1:], "/"), nil
}

func base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.StdEncoding.DecodeString(s)
}

// ToClash 把统一结构转为 Clash proxy YAML 片段的 map（由上层 yaml 序列化）。
func (n *Node) ToClash() map[string]any {
	m := map[string]any{
		"name":   n.Name,
		"type":   clashType(n.Protocol),
		"server": n.Server,
		"port":   n.Port,
	}
	switch n.Protocol {
	case "ss":
		m["cipher"] = n.Method
		m["password"] = n.Password
	case "vmess":
		m["uuid"] = n.UUID
		m["alterId"] = 0
		m["cipher"] = "auto"
		fillTransport(m, n)
	case "vless":
		m["uuid"] = n.UUID
		if n.Flow != "" {
			m["flow"] = n.Flow
		}
		fillTransport(m, n)
	case "trojan":
		m["password"] = n.Password
		fillTransport(m, n)
	case "hysteria2":
		m["password"] = n.Password
		if n.SNI != "" {
			m["sni"] = n.SNI
		}
		if n.SkipCert {
			m["skip-cert-verify"] = true
		}
		if len(n.ALPN) > 0 {
			m["alpn"] = n.ALPN
		}
	case "tuic":
		m["uuid"] = n.UUID
		m["password"] = n.Password
		if n.SNI != "" {
			m["sni"] = n.SNI
		}
		m["congestion-controller"] = "bbr"
		m["udp-relay"] = true
		m["reduce-rtt"] = true
	case "anytls":
		m["password"] = n.Password
		if n.SNI != "" {
			m["sni"] = n.SNI
		}
		if n.SkipCert {
			m["skip-cert-verify"] = true
		}
	}
	return m
}

func clashType(proto string) string {
	if proto == "hysteria2" {
		return "hysteria2"
	}
	return proto
}

func fillTransport(m map[string]any, n *Node) {
	if n.Security == "tls" || n.Security == "reality" {
		tls := map[string]any{"enabled": true}
		if n.SNI != "" {
			tls["server-name"] = n.SNI
		} else if n.Host != "" {
			tls["server-name"] = n.Host
		}
		if n.SkipCert {
			tls["skip-cert-verify"] = true
		}
		if n.Fp != "" {
			tls["client-fingerprint"] = n.Fp
		}
		if len(n.ALPN) > 0 {
			tls["alpn"] = n.ALPN
		}
		if n.Security == "reality" {
			tls["reality-opts"] = map[string]any{"public-key": n.Pbk, "short-id": n.Sid}
		}
		m["tls"] = true
		m["servername"] = tls["server-name"]
		if n.SkipCert {
			m["skip-cert-verify"] = true
		}
		if n.Fp != "" {
			m["client-fingerprint"] = n.Fp
		}
		if n.Security == "reality" {
			m["reality-opts"] = tls["reality-opts"]
		}
		_ = tls
	}
	switch n.Network {
	case "ws":
		m["network"] = "ws"
		ws := map[string]any{}
		if n.Path != "" {
			ws["path"] = n.Path
		}
		if n.Host != "" {
			ws["headers"] = map[string]any{"Host": n.Host}
		}
		m["ws-opts"] = ws
	case "grpc":
		m["network"] = "grpc"
		if n.Path != "" {
			m["grpc-opts"] = map[string]any{"grpc-service-name": n.Path}
		}
	}
}

// ToSingBoxOutbound 生成 sing-box outbound 对象（v1.11+ 字段风格）。
func (n *Node) ToSingBoxOutbound() map[string]any {
	tag := n.Name
	var ob map[string]any
	switch n.Protocol {
	case "ss":
		ob = map[string]any{"type": "shadowsocks", "tag": tag, "server": n.Server, "server_port": n.Port,
			"method": n.Method, "password": n.Password}
	case "vmess":
		ob = map[string]any{"type": "vmess", "tag": tag, "server": n.Server, "server_port": n.Port,
			"uuid": n.UUID, "security": "auto", "alter_id": 0}
		fillSingBoxTransport(ob, n)
	case "vless":
		ob = map[string]any{"type": "vless", "tag": tag, "server": n.Server, "server_port": n.Port, "uuid": n.UUID}
		if n.Flow != "" {
			ob["flow"] = n.Flow
		}
		fillSingBoxTransport(ob, n)
	case "trojan":
		ob = map[string]any{"type": "trojan", "tag": tag, "server": n.Server, "server_port": n.Port, "password": n.Password}
		fillSingBoxTransport(ob, n)
	case "hysteria2":
		ob = map[string]any{"type": "hysteria2", "tag": tag, "server": n.Server, "server_port": n.Port, "password": n.Password}
		fillSingBoxTLS(ob, n, false)
	case "tuic":
		ob = map[string]any{"type": "tuic", "tag": tag, "server": n.Server, "server_port": n.Port,
			"uuid": n.UUID, "password": n.Password, "congestion_control": "bbr", "udp_relay": true}
		fillSingBoxTLS(ob, n, false)
	case "anytls":
		ob = map[string]any{"type": "anytls", "tag": tag, "server": n.Server, "server_port": n.Port, "password": n.Password}
		fillSingBoxTLS(ob, n, false)
	default:
		return nil
	}
	return ob
}

func fillSingBoxTransport(ob map[string]any, n *Node) {
	fillSingBoxTLS(ob, n, n.Protocol == "trojan" || n.Protocol == "vless" || n.Protocol == "vmess")
	switch n.Network {
	case "ws":
		ws := map[string]any{}
		if n.Path != "" {
			ws["path"] = n.Path
		}
		if n.Host != "" {
			ws["headers"] = map[string]any{"Host": n.Host}
		}
		ob["transport"] = map[string]any{"type": "ws", "path": ws["path"], "headers": ws["headers"]}
	}
}

func fillSingBoxTLS(ob map[string]any, n *Node, needTLS bool) {
	if !needTLS && n.Security != "tls" && n.Security != "reality" {
		return
	}
	tls := map[string]any{"enabled": true}
	if n.SNI != "" {
		tls["server_name"] = n.SNI
	} else if n.Host != "" {
		tls["server_name"] = n.Host
	}
	if n.SkipCert {
		tls["insecure"] = true
	}
	if n.Fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": n.Fp}
	}
	if n.Security == "reality" {
		tls["reality"] = map[string]any{"enabled": true, "public_key": n.Pbk, "short_id": n.Sid}
	}
	if len(n.ALPN) > 0 {
		tls["alpn"] = n.ALPN
	}
	ob["tls"] = tls
}

// ToJSON 供 storage 存 parsed_config。
func (n *Node) ToJSON() string {
	b, _ := json.Marshal(n)
	return string(b)
}

// FromJSON 从 stored JSON 恢复。
func FromJSON(s string) (*Node, error) {
	n := &Node{}
	err := json.Unmarshal([]byte(s), n)
	return n, err
}
