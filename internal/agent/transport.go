// S2: 传输安全检查 —— 明文 ws:// 仅允许回环/内网地址。
package agent

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

var errPlainTransport = fmt.Errorf("明文 ws:// 传输会把 server token 暴露在链路上")

// ensureSecureTransport 校验 ws(s) URL：明文 ws 仅允许回环与私有网段。
func ensureSecureTransport(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("master_url 解析失败: %w", err)
	}
	if parsed.Scheme == "wss" || parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("%w: URL 缺少主机", errPlainTransport)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "::1" {
		return nil
	}
	ips := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		resolved, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("%w: 无法解析主机 %s（按公网处理）", errPlainTransport, host)
		}
		ips = resolved
	}
	for _, ip := range ips {
		if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			return fmt.Errorf("%w: %s 是公网地址", errPlainTransport, host)
		}
	}
	return nil
}
