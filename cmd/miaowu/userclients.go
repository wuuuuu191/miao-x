// 删除用户时，从所有服务器配置剥离其客户端并重推。
package main

import (
	"encoding/json"
	"log"
	"strings"

	"miao-x/internal/master"
	"miao-x/internal/storage"
)

func removeUserClientsFromAllServers(store *storage.Store, hub *master.Hub, username string) {
	email := username + "@panel"
	servers, err := store.ListServers()
	if err != nil {
		return
	}
	for _, sv := range servers {
		if !strings.Contains(sv.DesiredConfig, email) {
			continue
		}
		var cfg struct {
			Inbounds []map[string]any `json:"inbounds"`
		}
		if json.Unmarshal([]byte(sv.DesiredConfig), &cfg) != nil {
			continue
		}
		changed := false
		for _, ib := range cfg.Inbounds {
			settings, _ := ib["settings"].(map[string]any)
			if settings == nil {
				continue
			}
			clients, _ := settings["clients"].([]any)
			out := []any{}
			for _, c := range clients {
				if m, ok := c.(map[string]any); ok && m["email"] == email {
					changed = true
					continue
				}
				out = append(out, c)
			}
			settings["clients"] = out
		}
		if !changed {
			continue
		}
		newCfg, err := json.Marshal(cfg)
		if err != nil {
			continue
		}
		if _, _, err := applyConfigChange(store, hub, sv, string(newCfg)); err != nil {
			log.Printf("[Master] remove clients of %s failed (server %d): %v", username, sv.ID, err)
		}
	}
}
