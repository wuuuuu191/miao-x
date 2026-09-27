// agent 本地管理 API —— 本地 HTTP 端口与 WS 反向 RPC 共享同一份 handler。
// 主控经 rpc_call 调用这些 endpoint 管理入站/出站；本地访问便于排障。
package agent

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

// RegisterLocalHandlers 把管理 API 注册到 mux（主控 RPC 与本地端口共用）。
func (c *Client) RegisterLocalHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/child/status", c.handleStatus)
	mux.HandleFunc("/api/child/config", c.handleConfig)
	mux.HandleFunc("/api/child/restart", c.handleRestart)
	mux.HandleFunc("/api/child/stats", c.handleStats)
}

func writeOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeFail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (c *Client) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfgPath := filepath.Join(c.cfg.XrayConfigDir, "config.json")
	_, cfgErr := os.Stat(cfgPath)
	host, _ := os.Hostname()
	writeOK(w, map[string]any{
		"agent_version": Version,
		"hostname":      host,
		"xray_running":  c.xRunning.Load(),
		"xray_path":     c.xrayBin(),
		"config_exists": cfgErr == nil,
		"listen_port":   c.cfg.ListenPort,
	})
}

func (c *Client) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfgPath := filepath.Join(c.cfg.XrayConfigDir, "config.json")
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			writeFail(w, http.StatusNotFound, "配置不存在")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case http.MethodPut:
		var p struct {
			Config string `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Config == "" {
			writeFail(w, http.StatusBadRequest, "缺少 config 字段")
			return
		}
		go c.handleConfigUpdate(nil, mustMarshal(configUpdatePayload{Revision: -1, Config: p.Config}))
		writeOK(w, map[string]string{"ok": "accepted"})
	default:
		writeFail(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (c *Client) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeFail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := c.RestartXray(); err != nil {
		writeFail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]string{"ok": "restarted"})
}

func (c *Client) handleStats(w http.ResponseWriter, r *http.Request) {
	p := c.takeTrafficSnapshot()
	writeOK(w, p)
}
