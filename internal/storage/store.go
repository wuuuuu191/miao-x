// Package storage SQLite 持久层。schema 与妙妙屋(原版)同构，按 X 的场景增补 servers/server 相关表。
package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// M15: WAL 支持一写多读，多连接 + busy_timeout 兼顾并发读与写串行化
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// L16: 数据库文件收紧权限（含用户哈希/token/流量数据）
	_ = os.Chmod(path, 0600)
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS system_settings (
			key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			is_active INTEGER NOT NULL DEFAULT 1,
			remark TEXT NOT NULL DEFAULT '',
			monthly_quota INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS user_tokens (
			username TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			user_short_code TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_ut_short ON user_tokens(user_short_code) WHERE user_short_code != ''`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			raw_url TEXT NOT NULL,
			node_name TEXT NOT NULL,
			protocol TEXT NOT NULL,
			server TEXT NOT NULL DEFAULT '',
			parsed_config TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			tag TEXT NOT NULL DEFAULT '手动输入',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_username ON nodes(username)`,
		`CREATE TABLE IF NOT EXISTS subscribe_files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			filename TEXT NOT NULL,
			owner TEXT NOT NULL DEFAULT '',
			expire_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(name))`,
		`CREATE TABLE IF NOT EXISTS user_subscriptions (
			username TEXT NOT NULL,
			subscription_id INTEGER NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (username, subscription_id))`,
		// ---- X 新增: 远程服务器 ----
		`CREATE TABLE IF NOT EXISTS servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			address TEXT NOT NULL DEFAULT '',
			region TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT '',
			desired_config TEXT NOT NULL DEFAULT '',
			config_revision INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS server_status (
			server_id INTEGER PRIMARY KEY,
			online INTEGER NOT NULL DEFAULT 0,
			last_seen TIMESTAMP,
			hostname TEXT NOT NULL DEFAULT '',
			os TEXT NOT NULL DEFAULT '',
			arch TEXT NOT NULL DEFAULT '',
			agent_version TEXT NOT NULL DEFAULT '',
			public_ip TEXT NOT NULL DEFAULT '',
			listen_port INTEGER NOT NULL DEFAULT 0,
			xray_running INTEGER NOT NULL DEFAULT 0,
			cpu_pct REAL NOT NULL DEFAULT 0,
			mem_used INTEGER NOT NULL DEFAULT 0,
			mem_total INTEGER NOT NULL DEFAULT 0,
			up_bps INTEGER NOT NULL DEFAULT 0,
			down_bps INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS server_traffic (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			ts TIMESTAMP NOT NULL,
			up_bytes INTEGER NOT NULL DEFAULT 0,
			down_bytes INTEGER NOT NULL DEFAULT 0)`,
		`CREATE INDEX IF NOT EXISTS idx_st_server_ts ON server_traffic(server_id, ts)`,
		`CREATE TABLE IF NOT EXISTS user_traffic (
			date TEXT NOT NULL,
			username TEXT NOT NULL,
			up INTEGER NOT NULL DEFAULT 0,
			down INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (date, username))`,
		`CREATE TABLE IF NOT EXISTS agent_users (
			server_id INTEGER NOT NULL,
			email TEXT NOT NULL,
			quota INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (server_id, email))`,
		// 节点级流量（来自 agent 入站 counter，按服务器+入站tag归集）
		`CREATE TABLE IF NOT EXISTS node_traffic (
			date TEXT NOT NULL,
			server_id INTEGER NOT NULL,
			tag TEXT NOT NULL,
			up INTEGER NOT NULL DEFAULT 0,
			down INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (date, server_id, tag))`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w (stmt: %.60s)", err, stmt)
		}
	}
	// nodes.origin_server_id: >0 表示由该服务器的入站自动同步而来
	if err := s.ensureColumn("nodes", "origin_server_id", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

// ensureColumn 给已有表补列（已存在则忽略）。
func (s *Store) ensureColumn(table, col, ddl string) error {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('` + table + `')`)
	if err != nil {
		return err
	}
	exists := false
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil && name == col {
			exists = true
		}
	}
	rows.Close()
	if exists {
		return nil
	}
	if _, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + ddl); err != nil {
		return err
	}
	return nil
}

// ---------- system_settings ----------

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM system_settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO system_settings(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now())
	return err
}

// CleanupExpired M14: 数据保留策略 —— 过期会话与超龄明细定期清理。
func (s *Store) CleanupExpired() error {
	steps := []string{
		`DELETE FROM sessions WHERE expires_at < ?`,
		`DELETE FROM server_traffic WHERE ts < ?`,
		`DELETE FROM user_traffic WHERE date < ?`,
		`DELETE FROM node_traffic WHERE date < ?`,
	}
	now := time.Now()
	day := func(d int) string { return now.AddDate(0, 0, -d).Format("2006-01-02") }
	args := []any{now, now.AddDate(0, 0, -90), day(180), day(90)}
	for i, stmt := range steps {
		if _, err := s.db.Exec(stmt, args[i]); err != nil {
			return fmt.Errorf("cleanup step %d: %w", i, err)
		}
	}
	return nil
}

// ---------- users ----------

type User struct {
	Username      string    `json:"username"`
	Role          string    `json:"role"`
	IsActive      bool      `json:"is_active"`
	Remark        string    `json:"remark"`
	MonthlyQuota  int64     `json:"monthly_quota"`
	CreatedAt     time.Time `json:"created_at"`
	PasswordHash  string    `json:"-"`
	passwordPlain string
}

func (s *Store) CreateUser(u *User, passwordHash string) error {
	_, err := s.db.Exec(`INSERT INTO users(username,password_hash,role,is_active,remark,monthly_quota) VALUES(?,?,?,?,?,?)`,
		u.Username, passwordHash, u.Role, boolInt(u.IsActive), u.Remark, u.MonthlyQuota)
	return err
}

func (s *Store) GetUser(name string) (*User, string, error) {
	u := &User{}
	var active int
	var hash string
	err := s.db.QueryRow(`SELECT username,password_hash,role,is_active,remark,monthly_quota,created_at FROM users WHERE username=?`, name).
		Scan(&u.Username, &hash, &u.Role, &active, &u.Remark, &u.MonthlyQuota, &u.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	u.IsActive = active == 1
	return u, hash, nil
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT username,password_hash,role,is_active,remark,monthly_quota,created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		var active int
		if err := rows.Scan(&u.Username, &u.PasswordHash, &u.Role, &active, &u.Remark, &u.MonthlyQuota, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.IsActive = active == 1
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUserPassword(name, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=?, updated_at=? WHERE username=?`, hash, time.Now(), name)
	return err
}

func (s *Store) UpdateUserFields(name string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+1)
	for k, v := range fields {
		sets = append(sets, k+"=?")
		args = append(args, v)
	}
	args = append(args, time.Now(), name)
	_, err := s.db.Exec(`UPDATE users SET `+strings.Join(sets, ",")+`, updated_at=? WHERE username=?`, args...)
	return err
}

func (s *Store) DeleteUser(name string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE username=?`, name)
	return err
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ---------- sessions ----------

func (s *Store) CreateSession(username string, ttl time.Duration) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	_, err := s.db.Exec(`INSERT INTO sessions(token,username,expires_at) VALUES(?,?,?)`, tok, username, time.Now().Add(ttl))
	return tok, err
}

func (s *Store) GetSession(token string) (string, error) {
	var username string
	err := s.db.QueryRow(`SELECT username FROM sessions WHERE token=? AND expires_at>?`, token, time.Now()).Scan(&username)
	return username, err
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

// ---------- user_tokens (订阅token) ----------

func (s *Store) GetUserToken(username string) (string, error) {
	var tok string
	err := s.db.QueryRow(`SELECT token FROM user_tokens WHERE username=?`, username).Scan(&tok)
	if err == sql.ErrNoRows {
		buf := make([]byte, 16)
		rand.Read(buf)
		tok = hex.EncodeToString(buf)
		_, err = s.db.Exec(`INSERT INTO user_tokens(username,token,user_short_code) VALUES(?,?,?)`, username, tok, shortCode())
		if err != nil {
			return "", err
		}
		return tok, nil
	}
	return tok, err
}

func (s *Store) ResetUserToken(username string) (string, error) {
	tok := "mw" + randHex(16)
	// M1: 占位符与参数对齐；L10: 保留原短码
	_, err := s.db.Exec(`INSERT INTO user_tokens(username,token,updated_at) VALUES(?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(username) DO UPDATE SET token=excluded.token, updated_at=CURRENT_TIMESTAMP`,
		username, tok)
	return tok, err
}

// ResolveToken 把订阅 token 解析为用户名（支持完整 token 与短码；短码已扩到 10 位）。
func (s *Store) ResolveToken(tok string) (string, error) {
	var username string
	err := s.db.QueryRow(`SELECT username FROM user_tokens WHERE token=?`, tok).Scan(&username)
	if err == sql.ErrNoRows && len(tok) > 0 {
		err = s.db.QueryRow(`SELECT username FROM user_tokens WHERE user_short_code=? OR user_short_code=?`,
			tok, strings.ToLower(tok)).Scan(&username)
	}
	return username, err
}

func shortCode() string {
	// S6/L6: 10 位（31^10 ≈ 8.2e14）且用 crypto/rand.Int 消除取模偏置
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]byte, 10)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic("crypto/rand 不可用: " + err.Error())
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
