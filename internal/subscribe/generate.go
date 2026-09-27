// Package subscribe 订阅生成：UA 识别 + 格式转换 + 流量头注入。
// 与妙妙屋一致的行为：
//   - profile-update-interval: 24
//   - subscription-userinfo: upload=..; download=..; total=..; expire=..
//   - 非浏览器才带 content-disposition
//   - token 失效输出合法 YAML（含"订阅已过期"提示节点）
package subscribe

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"miao-x/internal/storage"
	"miao-x/internal/subparser"
)

type ClientType int

const (
	ClientClash ClientType = iota
	ClientSingBox
	ClientV2Ray
	ClientUnknown
)

// DetectClient 按 UA 识别客户端类型（对齐妙妙屋 UA 表的核心子集）。
func DetectClient(ua string) ClientType {
	u := strings.ToLower(ua)
	// M20: v2rayn 是 v2rayng 的子串，必须先判长的
	switch {
	case strings.Contains(u, "sing-box"), strings.Contains(u, "singbox"), strings.Contains(u, "karing"):
		return ClientSingBox
	case strings.Contains(u, "v2rayng"), strings.Contains(u, "v2rayn"):
		return ClientV2Ray
	case strings.Contains(u, "clash"), strings.Contains(u, "mihomo"), strings.Contains(u, "stash"),
		strings.Contains(u, "surge"), strings.Contains(u, "loon"), strings.Contains(u, "quantumult"),
		strings.Contains(u, "shadowrocket"), strings.Contains(u, "surfboard"), strings.Contains(u, "egern"),
		strings.Contains(u, "hiddify"):
		return ClientClash
	default:
		return ClientUnknown
	}
}

func isBrowser(ua string) bool {
	u := strings.ToLower(ua)
	return strings.Contains(u, "mozilla") && strings.Contains(u, "applewebkit")
}

// TrafficInfo 用于注入 subscription-userinfo。
type TrafficInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   time.Time // 零值表示无到期
}

// Generate 根据客户端类型生成订阅正文。
func Generate(nodes []*subparser.Node, client ClientType, groupName string) ([]byte, string, error) {
	switch client {
	case ClientSingBox:
		b, err := generateSingBox(nodes)
		return b, "application/json; charset=utf-8", err
	case ClientV2Ray:
		return generateV2Ray(nodes), "text/plain; charset=utf-8", nil
	default:
		b, err := generateClash(nodes, groupName)
		return b, "text/yaml; charset=utf-8", err
	}
}

// generateClash 生成完整 Clash 配置（与原版结构一致: port/socks-port/mode/dns 简化 + proxies + proxy-groups + rules）。
func generateClash(nodes []*subparser.Node, groupName string) ([]byte, error) {
	proxies := make([]any, 0, len(nodes))
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		m := n.ToClash()
		proxies = append(proxies, m)
		names = append(names, n.Name)
	}
	if groupName == "" {
		groupName = "🚀 节点选择"
	}
	cfg := map[string]any{
		"mixed-port":                7890,
		"allow-lan":                 false,
		"mode":                      "rule",
		"log-level":                 "info",
		"unified-delay":             true,
		"tcp-concurrent":            true,
		"find-process-mode":         "strict",
		"global-client-fingerprint": "chrome",
		"dns": map[string]any{
			"enable":        true,
			"enhanced-mode": "fake-ip",
			"nameserver":    []string{"https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"},
			"fallback":      []string{"https://dns.cloudflare.com/dns-query", "https://dns.google/dns-query"},
		},
		"proxies": proxies,
		"proxy-groups": []any{
			map[string]any{"name": groupName, "type": "select", "proxies": append([]string{"自动选择", "DIRECT"}, names...)},
			map[string]any{"name": "自动选择", "type": "url-test", "proxies": names,
				"url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
		},
		"rules": []string{
			"GEOIP,LAN,DIRECT,no-resolve",
			"GEOIP,CN,DIRECT",
			"MATCH," + groupName,
		},
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// generateV2Ray base64 的 URI 列表（v2ray 系客户端通用）。
func generateV2Ray(nodes []*subparser.Node) []byte {
	lines := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if u := nodeURI(n); u != "" {
			lines = append(lines, u)
		}
	}
	raw := strings.Join(lines, "\n")
	return []byte(base64.StdEncoding.EncodeToString([]byte(raw)))
}

// nodeURI 反向生成分享链接（M18: 全字段经 url.URL/Values 转义，特殊字符安全）。
func nodeURI(n *subparser.Node) string {
	switch n.Protocol {
	case "ss":
		u := url.URL{
			Scheme:   "ss",
			User:     url.User(base64.RawURLEncoding.EncodeToString([]byte(n.Method + ":" + n.Password))),
			Host:     fmt.Sprintf("%s:%d", n.Server, n.Port),
			Fragment: n.Name,
		}
		return u.String()
	case "trojan":
		q := url.Values{}
		q.Set("security", orDefault(n.Security, "tls"))
		q.Set("type", orDefault(n.Network, "tcp"))
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		u := url.URL{Scheme: "trojan", User: url.User(n.Password),
			Host: fmt.Sprintf("%s:%d", n.Server, n.Port), RawQuery: q.Encode(), Fragment: n.Name}
		return u.String()
	case "vless":
		q := url.Values{}
		q.Set("security", orDefault(n.Security, "none"))
		q.Set("type", orDefault(n.Network, "tcp"))
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		if n.Flow != "" {
			q.Set("flow", n.Flow)
		}
		if n.Pbk != "" {
			q.Set("pbk", n.Pbk)
			q.Set("sid", n.Sid)
			q.Set("fp", n.Fp)
		}
		if n.Path != "" {
			q.Set("path", n.Path)
		}
		if n.Host != "" {
			q.Set("host", n.Host)
		}
		u := url.URL{Scheme: "vless", User: url.User(n.UUID),
			Host: fmt.Sprintf("%s:%d", n.Server, n.Port), RawQuery: q.Encode(), Fragment: n.Name}
		return u.String()
	case "vmess":
		m := map[string]any{
			"v": "2", "ps": n.Name, "add": n.Server, "port": n.Port, "id": n.UUID,
			"aid": 0, "net": n.Network, "type": "none", "host": n.Host, "path": n.Path,
			"tls": n.Security, "sni": n.SNI, "scy": "auto",
		}
		b, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "hysteria2":
		q := url.Values{} // M19: 统一组装，杜绝 insecure 重复/覆盖
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		if n.SkipCert {
			q.Set("insecure", "1")
		}
		u := url.URL{Scheme: "hysteria2", User: url.User(n.Password),
			Host: fmt.Sprintf("%s:%d", n.Server, n.Port), RawQuery: q.Encode(), Fragment: n.Name}
		return u.String()
	default:
		return ""
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// NodeURI 生成节点的分享链接（供入站→节点同步器复用）。
func NodeURI(n *subparser.Node) string { return nodeURI(n) }

// generateSingBox 输出 sing-box 1.8+ 配置。
func generateSingBox(nodes []*subparser.Node) ([]byte, error) {
	outbounds := []any{
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "block", "tag": "block"},
		map[string]any{"type": "dns", "tag": "dns-out"},
	}
	tags := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if ob := n.ToSingBoxOutbound(); ob != nil {
			outbounds = append(outbounds, ob)
			tags = append(tags, n.Name)
		}
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "info"},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "remote", "address": "https://8.8.8.8/dns-query", "detour": "Proxy"},
				map[string]any{"tag": "local", "address": "https://223.5.5.5/dns-query", "detour": "direct"},
			},
			"rules": []any{
				map[string]any{"outbound": "any", "server": "local"},
				map[string]any{"rule_set": []string{"geosite-cn"}, "server": "local"},
			},
			"final": "remote",
		},
		"inbounds": []any{
			map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30"}, "auto_route": true},
		},
		"outbounds": append([]any{
			map[string]any{"type": "selector", "tag": "Proxy", "outbounds": append([]string{"auto"}, append(tags, "direct")...)},
			map[string]any{"type": "urltest", "tag": "auto", "outbounds": tags,
				"url": "http://www.gstatic.com/generate_204", "interval": "5m"},
		}, outbounds...),
		"route": map[string]any{
			"rules": []any{
				map[string]any{"protocol": "dns", "outbound": "dns-out"},
				map[string]any{"rule_set": []string{"geoip-cn"}, "outbound": "direct"},
				map[string]any{"rule_set": []string{"geosite-cn"}, "outbound": "direct"},
			},
			"rule_set": []any{
				map[string]any{"type": "remote", "tag": "geosite-cn", "format": "binary",
					"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "direct"},
				map[string]any{"type": "remote", "tag": "geoip-cn", "format": "binary",
					"url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "direct"},
			},
			"final":                 "Proxy",
			"auto_detect_interface": true,
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// SetHeaders 注入标准订阅响应头。
func SetHeaders(w http.ResponseWriter, ua string, info *TrafficInfo, filename string) {
	w.Header().Set("profile-update-interval", "24")
	if info != nil && (info.Upload > 0 || info.Download > 0 || info.Total > 0) {
		expire := "0"
		if !info.Expire.IsZero() {
			expire = fmt.Sprint(info.Expire.Unix())
		}
		w.Header().Set("subscription-userinfo",
			fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%s", info.Upload, info.Download, info.Total, expire))
	}
	if !isBrowser(ua) && filename != "" {
		// M2: 文件名走 PathEscape，防头注入/截断
		w.Header().Set("content-disposition",
			"attachment;filename*=UTF-8''"+url.PathEscape(filename))
	}
}

// InvalidTokenYAML token 失效/过期时的合法 YAML（沿用原版设计：可导入，节点名提示管理员）。
const InvalidTokenYAML = `allow-lan: false
mode: rule
log-level: info
proxies:
  - name: "⚠️ 订阅已过期，请联系管理员"
    type: ss
    server: 127.0.0.1
    port: 443
    password: miaowu-invalid-token
    cipher: aes-128-gcm
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - "⚠️ 订阅已过期，请联系管理员"
rules:
  - MATCH,DIRECT
`

// BuildTrafficInfo 组装某用户的流量信息（月度累计/配额/订阅到期）。
func BuildTrafficInfo(store *storage.Store, username string, expireAt *time.Time) (*TrafficInfo, error) {
	up, down, err := store.UserTrafficMonth(username)
	if err != nil {
		return nil, err
	}
	total := int64(0)
	if u, _, err := store.GetUser(username); err == nil {
		total = u.MonthlyQuota
	}
	info := &TrafficInfo{Upload: up, Download: down, Total: total}
	if expireAt != nil {
		info.Expire = *expireAt
	}
	return info, nil
}
