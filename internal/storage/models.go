package storage

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"
)

// ---------- nodes ----------

type Node struct {
	ID             int64     `json:"id"`
	Username       string    `json:"username"`
	RawURL         string    `json:"raw_url"`
	NodeName       string    `json:"node_name"`
	Protocol       string    `json:"protocol"`
	Server         string    `json:"server"`
	ParsedConfig   string    `json:"parsed_config"`
	Enabled        bool      `json:"enabled"`
	Tag            string    `json:"tag"`
	OriginServerID int64     `json:"origin_server_id"` // >0: 由服务器入站同步生成
	CreatedAt      time.Time `json:"created_at"`
}

func (s *Store) CreateNode(n *Node) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO nodes(username,raw_url,node_name,protocol,server,parsed_config,enabled,tag,origin_server_id)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		n.Username, n.RawURL, n.NodeName, n.Protocol, n.Server, n.ParsedConfig, boolInt(n.Enabled), n.Tag, n.OriginServerID)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

// ReplaceServerNodes 用服务器当前入站重建其同步节点（delete+insert，幂等）。
func (s *Store) ReplaceServerNodes(serverID int64, nodes []*Node) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM nodes WHERE origin_server_id=?`, serverID); err != nil {
		return err
	}
	for _, n := range nodes {
		n.OriginServerID = serverID
		if _, err := tx.Exec(`INSERT INTO nodes(username,raw_url,node_name,protocol,server,parsed_config,enabled,tag,origin_server_id)
			VALUES(?,?,?,?,?,?,?,?,?)`,
			n.Username, n.RawURL, n.NodeName, n.Protocol, n.Server, n.ParsedConfig, boolInt(n.Enabled), n.Tag, serverID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListNodes(username string) ([]*Node, error) {
	rows, err := s.db.Query(`SELECT id,username,raw_url,node_name,protocol,server,parsed_config,enabled,tag,created_at,origin_server_id
		FROM nodes WHERE username=? ORDER BY id`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func (s *Store) ListAllNodes() ([]*Node, error) {
	rows, err := s.db.Query(`SELECT id,username,raw_url,node_name,protocol,server,parsed_config,enabled,tag,created_at,origin_server_id
		FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func scanNodes(rows *sql.Rows) ([]*Node, error) {
	var out []*Node
	for rows.Next() {
		n := &Node{}
		var enabled int
		if err := rows.Scan(&n.ID, &n.Username, &n.RawURL, &n.NodeName, &n.Protocol, &n.Server, &n.ParsedConfig, &enabled, &n.Tag, &n.CreatedAt, &n.OriginServerID); err != nil {
			return nil, err
		}
		n.Enabled = enabled == 1
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) GetNode(id int64) (*Node, error) {
	n := &Node{}
	var enabled int
	err := s.db.QueryRow(`SELECT id,username,raw_url,node_name,protocol,server,parsed_config,enabled,tag,created_at,origin_server_id
		FROM nodes WHERE id=?`, id).
		Scan(&n.ID, &n.Username, &n.RawURL, &n.NodeName, &n.Protocol, &n.Server, &n.ParsedConfig, &enabled, &n.Tag, &n.CreatedAt, &n.OriginServerID)
	if err != nil {
		return nil, err
	}
	n.Enabled = enabled == 1
	return n, nil
}

func (s *Store) UpdateNode(n *Node) error {
	_, err := s.db.Exec(`UPDATE nodes SET raw_url=?,node_name=?,protocol=?,server=?,parsed_config=?,enabled=?,tag=? WHERE id=?`,
		n.RawURL, n.NodeName, n.Protocol, n.Server, n.ParsedConfig, boolInt(n.Enabled), n.Tag, n.ID)
	return err
}

func (s *Store) DeleteNode(id int64) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE id=?`, id)
	return err
}

// ---------- subscribe_files ----------

type Subscription struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Filename    string     `json:"filename"`
	Owner       string     `json:"owner"`
	ExpireAt    *time.Time `json:"expire_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (s *Store) CreateSubscription(sub *Subscription) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO subscribe_files(name,description,filename,owner,expire_at) VALUES(?,?,?,?,?)`,
		sub.Name, sub.Description, sub.Filename, sub.Owner, sub.ExpireAt)
	if err != nil {
		return 0, err
	}
	id, _ := r.LastInsertId()
	// owner 自动绑定该订阅
	if sub.Owner != "" {
		s.db.Exec(`INSERT OR IGNORE INTO user_subscriptions(username,subscription_id) VALUES(?,?)`, sub.Owner, id)
	}
	return id, nil
}

func (s *Store) ListSubscriptions() ([]*Subscription, error) {
	rows, err := s.db.Query(`SELECT id,name,description,filename,owner,expire_at,created_at FROM subscribe_files ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Subscription
	for rows.Next() {
		sub := &Subscription{}
		if err := rows.Scan(&sub.ID, &sub.Name, &sub.Description, &sub.Filename, &sub.Owner, &sub.ExpireAt, &sub.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

func (s *Store) GetSubscription(id int64) (*Subscription, error) {
	sub := &Subscription{}
	err := s.db.QueryRow(`SELECT id,name,description,filename,owner,expire_at,created_at FROM subscribe_files WHERE id=?`, id).
		Scan(&sub.ID, &sub.Name, &sub.Description, &sub.Filename, &sub.Owner, &sub.ExpireAt, &sub.CreatedAt)
	return sub, err
}

func (s *Store) UpdateSubscription(sub *Subscription) error {
	_, err := s.db.Exec(`UPDATE subscribe_files SET name=?,description=?,owner=?,expire_at=? WHERE id=?`,
		sub.Name, sub.Description, sub.Owner, sub.ExpireAt, sub.ID)
	return err
}

func (s *Store) DeleteSubscription(id int64) error {
	s.db.Exec(`DELETE FROM user_subscriptions WHERE subscription_id=?`, id)
	_, err := s.db.Exec(`DELETE FROM subscribe_files WHERE id=?`, id)
	return err
}

func (s *Store) BindSubscription(username string, subID int64, bind bool) error {
	if bind {
		_, err := s.db.Exec(`INSERT OR IGNORE INTO user_subscriptions(username,subscription_id) VALUES(?,?)`, username, subID)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM user_subscriptions WHERE username=? AND subscription_id=?`, username, subID)
	return err
}

func (s *Store) UserSubscriptionIDs(username string) ([]int64, error) {
	rows, err := s.db.Query(`SELECT subscription_id FROM user_subscriptions WHERE username=?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---------- servers (X 核心) ----------

type Server struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Token          string    `json:"token,omitempty"`
	Address        string    `json:"address"`
	Region         string    `json:"region"`
	Provider       string    `json:"provider"`
	Notes          string    `json:"notes"`
	DesiredConfig  string    `json:"desired_config"`
	ConfigRevision int64     `json:"config_revision"`
	CreatedAt      time.Time `json:"created_at"`
}

func (s *Store) CreateServer(name, address, region, provider, notes string) (*Server, error) {
	tok := "mw" + randHex(24)
	r, err := s.db.Exec(`INSERT INTO servers(name,token,address,region,provider,notes) VALUES(?,?,?,?,?,?)`,
		name, tok, address, region, provider, notes)
	if err != nil {
		return nil, err
	}
	id, _ := r.LastInsertId()
	return s.GetServer(id)
}

func (s *Store) GetServer(id int64) (*Server, error) {
	sv := &Server{}
	err := s.db.QueryRow(`SELECT id,name,token,address,region,provider,notes,desired_config,config_revision,created_at
		FROM servers WHERE id=?`, id).
		Scan(&sv.ID, &sv.Name, &sv.Token, &sv.Address, &sv.Region, &sv.Provider, &sv.Notes, &sv.DesiredConfig, &sv.ConfigRevision, &sv.CreatedAt)
	return sv, err
}

func (s *Store) ListServers() ([]*Server, error) {
	rows, err := s.db.Query(`SELECT id,name,token,address,region,provider,notes,desired_config,config_revision,created_at
		FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Server
	for rows.Next() {
		sv := &Server{}
		if err := rows.Scan(&sv.ID, &sv.Name, &sv.Token, &sv.Address, &sv.Region, &sv.Provider, &sv.Notes, &sv.DesiredConfig, &sv.ConfigRevision, &sv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

func (s *Store) GetServerByToken(token string) (*Server, error) {
	sv := &Server{}
	err := s.db.QueryRow(`SELECT id,name,token,address,region,provider,notes,desired_config,config_revision,created_at
		FROM servers WHERE token=?`, token).
		Scan(&sv.ID, &sv.Name, &sv.Token, &sv.Address, &sv.Region, &sv.Provider, &sv.Notes, &sv.DesiredConfig, &sv.ConfigRevision, &sv.CreatedAt)
	return sv, err
}

func (s *Store) UpdateServer(sv *Server) error {
	_, err := s.db.Exec(`UPDATE servers SET name=?,address=?,region=?,provider=?,notes=? WHERE id=?`,
		sv.Name, sv.Address, sv.Region, sv.Provider, sv.Notes, sv.ID)
	return err
}

func (s *Store) ResetServerToken(id int64) (string, error) {
	tok := "mw" + randHex(24)
	_, err := s.db.Exec(`UPDATE servers SET token=? WHERE id=?`, tok, id)
	return tok, err
}

func (s *Store) DeleteServer(id int64) error {
	s.db.Exec(`DELETE FROM server_status WHERE server_id=?`, id)
	s.db.Exec(`DELETE FROM server_traffic WHERE server_id=?`, id)
	s.db.Exec(`DELETE FROM agent_users WHERE server_id=?`, id)
	s.db.Exec(`DELETE FROM nodes WHERE origin_server_id=?`, id) // 同步节点一并清理
	_, err := s.db.Exec(`DELETE FROM servers WHERE id=?`, id)
	return err
}

func (s *Store) SaveDesiredConfig(id int64, config string) (int64, error) {
	var rev int64
	err := s.db.QueryRow(`SELECT config_revision FROM servers WHERE id=?`, id).Scan(&rev)
	if err != nil {
		return 0, err
	}
	rev++
	_, err = s.db.Exec(`UPDATE servers SET desired_config=?, config_revision=? WHERE id=?`, config, rev, id)
	return rev, err
}

// ---------- server_status ----------

type ServerStatus struct {
	ServerID     int64     `json:"server_id"`
	Online       bool      `json:"online"`
	LastSeen     time.Time `json:"last_seen"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	AgentVersion string    `json:"agent_version"`
	PublicIP     string    `json:"public_ip"`
	ListenPort   int       `json:"listen_port"`
	XrayRunning  bool      `json:"xray_running"`
	CPUPct       float64   `json:"cpu_pct"`
	MemUsed      int64     `json:"mem_used"`
	MemTotal     int64     `json:"mem_total"`
	UpBps        int64     `json:"up_bps"`
	DownBps      int64     `json:"down_bps"`
}

func (s *Store) UpsertServerStatus(st *ServerStatus) error {
	_, err := s.db.Exec(`INSERT INTO server_status(server_id,online,last_seen,hostname,os,arch,agent_version,public_ip,listen_port,xray_running,cpu_pct,mem_used,mem_total,up_bps,down_bps)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(server_id) DO UPDATE SET online=excluded.online,last_seen=excluded.last_seen,hostname=excluded.hostname,
		os=excluded.os,arch=excluded.arch,agent_version=excluded.agent_version,public_ip=excluded.public_ip,
		listen_port=excluded.listen_port,xray_running=excluded.xray_running,cpu_pct=excluded.cpu_pct,
		mem_used=excluded.mem_used,mem_total=excluded.mem_total,up_bps=excluded.up_bps,down_bps=excluded.down_bps`,
		st.ServerID, boolInt(st.Online), st.LastSeen, st.Hostname, st.OS, st.Arch, st.AgentVersion, st.PublicIP,
		st.ListenPort, boolInt(st.XrayRunning), st.CPUPct, st.MemUsed, st.MemTotal, st.UpBps, st.DownBps)
	return err
}

func (s *Store) MarkServerOffline(id int64) error {
	_, err := s.db.Exec(`UPDATE server_status SET online=0 WHERE server_id=?`, id)
	return err
}

// UpdateServerDynamicStatus 心跳/速度上报只更新动态字段，不覆盖注册时的静态信息。
func (s *Store) UpdateServerDynamicStatus(serverID int64, online bool, xrayRunning bool, cpuPct float64, memUsed, memTotal int64) error {
	_, err := s.db.Exec(`INSERT INTO server_status(server_id,online,last_seen,xray_running,cpu_pct,mem_used,mem_total)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(server_id) DO UPDATE SET online=excluded.online,last_seen=excluded.last_seen,
		xray_running=excluded.xray_running,cpu_pct=excluded.cpu_pct,mem_used=excluded.mem_used,mem_total=excluded.mem_total`,
		serverID, boolInt(online), time.Now(), boolInt(xrayRunning), cpuPct, memUsed, memTotal)
	return err
}

// UpdateServerSpeed 只更新实时速度。
func (s *Store) UpdateServerSpeed(serverID int64, upBps, downBps int64) error {
	_, err := s.db.Exec(`INSERT INTO server_status(server_id,online,last_seen,up_bps,down_bps) VALUES(?,?,?, ?,?)
		ON CONFLICT(server_id) DO UPDATE SET online=excluded.online,last_seen=excluded.last_seen,
		up_bps=excluded.up_bps,down_bps=excluded.down_bps`,
		serverID, 1, time.Now(), upBps, downBps)
	return err
}

func (s *Store) GetServerStatus(id int64) (*ServerStatus, error) {
	st := &ServerStatus{}
	var online, xray int
	err := s.db.QueryRow(`SELECT server_id,online,last_seen,hostname,os,arch,agent_version,public_ip,listen_port,xray_running,cpu_pct,mem_used,mem_total,up_bps,down_bps
		FROM server_status WHERE server_id=?`, id).
		Scan(&st.ServerID, &online, &st.LastSeen, &st.Hostname, &st.OS, &st.Arch, &st.AgentVersion, &st.PublicIP, &st.ListenPort, &xray, &st.CPUPct, &st.MemUsed, &st.MemTotal, &st.UpBps, &st.DownBps)
	if err != nil {
		return nil, err
	}
	st.Online = online == 1
	st.XrayRunning = xray == 1
	return st, nil
}

func (s *Store) ListServerStatuses() (map[int64]*ServerStatus, error) {
	rows, err := s.db.Query(`SELECT server_id,online,last_seen,hostname,os,arch,agent_version,public_ip,listen_port,xray_running,cpu_pct,mem_used,mem_total,up_bps,down_bps FROM server_status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*ServerStatus{}
	for rows.Next() {
		st := &ServerStatus{}
		var online, xray int
		if err := rows.Scan(&st.ServerID, &online, &st.LastSeen, &st.Hostname, &st.OS, &st.Arch, &st.AgentVersion, &st.PublicIP, &st.ListenPort, &xray, &st.CPUPct, &st.MemUsed, &st.MemTotal, &st.UpBps, &st.DownBps); err != nil {
			return nil, err
		}
		st.Online = online == 1
		st.XrayRunning = xray == 1
		out[st.ServerID] = st
	}
	return out, rows.Err()
}

// ---------- traffic ----------

// AddServerTraffic 记录一次上报的增量流量。
func (s *Store) AddServerTraffic(serverID int64, up, down int64) error {
	_, err := s.db.Exec(`INSERT INTO server_traffic(server_id,ts,up_bytes,down_bytes) VALUES(?,?,?,?)`,
		serverID, time.Now(), up, down)
	return err
}

func (s *Store) ServerTrafficSummary(serverID int64, since time.Time) (up, down int64, err error) {
	err = s.db.QueryRow(`SELECT COALESCE(SUM(up_bytes),0), COALESCE(SUM(down_bytes),0)
		FROM server_traffic WHERE server_id=? AND ts>=?`, serverID, since).Scan(&up, &down)
	return
}

func (s *Store) ServerTrafficDaily(serverID int64, days int) ([]map[string]any, error) {
	since := time.Now().AddDate(0, 0, -days)
	rows, err := s.db.Query(`SELECT date(ts), SUM(up_bytes), SUM(down_bytes) FROM server_traffic
		WHERE server_id=? AND ts>=? GROUP BY date(ts) ORDER BY 1`, serverID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var d string
		var up, down int64
		if err := rows.Scan(&d, &up, &down); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"date": d, "up": up, "down": down, "total": up + down})
	}
	return out, rows.Err()
}

// AddUserTraffic 累加某用户当天流量（email 前缀映射为面板用户名）。
func (s *Store) AddUserTraffic(username string, up, down int64) error {
	if username == "" || (up == 0 && down == 0) {
		return nil
	}
	date := time.Now().Format("2006-01-02")
	_, err := s.db.Exec(`INSERT INTO user_traffic(date,username,up,down) VALUES(?,?,?,?)
		ON CONFLICT(date,username) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`,
		date, username, up, down)
	return err
}

// monthRange 当前自然月的 [起, 止) 日期（M16: 范围条件可走主键索引，LIKE 前缀不行）。
func monthRange() (string, string) {
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	end := start.AddDate(0, 1, 0)
	return start.Format("2006-01-02"), end.Format("2006-01-02")
}

// UserTrafficMonth 当前自然月累计。
func (s *Store) UserTrafficMonth(username string) (up, down int64, err error) {
	start, end := monthRange()
	err = s.db.QueryRow(`SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0)
		FROM user_traffic WHERE username=? AND date>=? AND date<?`, username, start, end).Scan(&up, &down)
	return
}

// ---------- node_traffic（入站级流量） ----------

// AddNodeTraffic 累加某服务器某入站当天的上下行增量。
func (s *Store) AddNodeTraffic(serverID int64, tag string, up, down int64) error {
	if tag == "" || (up == 0 && down == 0) {
		return nil
	}
	date := time.Now().Format("2006-01-02")
	_, err := s.db.Exec(`INSERT INTO node_traffic(date,server_id,tag,up,down) VALUES(?,?,?,?,?)
		ON CONFLICT(date,server_id,tag) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`,
		date, serverID, tag, up, down)
	return err
}

// NodeTrafficMonth 本月各 (server_id,tag) 的流量合计。
func (s *Store) NodeTrafficMonth() (map[string][2]int64, error) {
	start, end := monthRange()
	rows, err := s.db.Query(`SELECT server_id, tag, COALESCE(SUM(up),0), COALESCE(SUM(down),0)
		FROM node_traffic WHERE date>=? AND date<? GROUP BY server_id, tag`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var sid int64
		var tag string
		var up, down int64
		if err := rows.Scan(&sid, &tag, &up, &down); err != nil {
			return nil, err
		}
		out[fmt.Sprintf("%d|%s", sid, tag)] = [2]int64{up, down}
	}
	return out, rows.Err()
}

// DisabledEmails 需要在被控机上下线的用户集合：
//  1. 被管理员禁用（is_active=0）的用户
//  2. 月配额非零且当月用量已达配额的用户
//
// 返回 email 形式（username@panel），与 xray client email 对应。
func (s *Store) DisabledEmails() ([]string, error) {
	users, err := s.ListUsers()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, u := range users {
		if !u.IsActive {
			out = append(out, u.Username+"@panel")
			continue
		}
		if u.MonthlyQuota > 0 {
			up, down, err := s.UserTrafficMonth(u.Username)
			if err == nil && up+down >= u.MonthlyQuota {
				out = append(out, u.Username+"@panel")
			}
		}
	}
	return out, nil
}

// ---------- agent_users ----------

func (s *Store) SetAgentUsers(serverID int64, emails []string) error {
	s.db.Exec(`DELETE FROM agent_users WHERE server_id=?`, serverID)
	for _, e := range emails {
		s.db.Exec(`INSERT OR IGNORE INTO agent_users(server_id,email,quota) VALUES(?,?,0)`, serverID, e)
	}
	return nil
}

func (s *Store) ListAgentUsers(serverID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT email FROM agent_users WHERE server_id=?`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func randHex(n int) string {
	buf := make([]byte, n)
	rand.Read(buf)
	return hexEncode(buf)
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
