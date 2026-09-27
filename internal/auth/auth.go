// Package auth 密码哈希与会话中间件。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"miao-x/internal/storage"
)

const (
	sessionTTL  = 7 * 24 * time.Hour
	argonTime   = 1
	argonMemory = 64 * 1024
	argonThread = 4
	argonKeyLen = 32
)

// HashPassword 生成 argon2id 哈希: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
func HashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThread, argonKeyLen)
	var b strings.Builder
	fmt.Fprintf(&b, "$argon2id$v=19$m=%d,t=%d,p=%d$", argonMemory, argonTime, argonThread)
	b.WriteString(base64.RawStdEncoding.EncodeToString(salt))
	b.WriteString("$")
	b.WriteString(base64.RawStdEncoding.EncodeToString(key))
	return b.String()
}

// VerifyPassword 校验密码（常数时间比较）。
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

type ctxKey string

const userKey ctxKey = "user"

// CurrentUser 从请求上下文取当前用户名。
func CurrentUser(r *http.Request) string {
	u, _ := r.Context().Value(userKey).(string)
	return u
}

func withUser(r *http.Request, username string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey, username))
}

type jsonHandler func(w http.ResponseWriter, r *http.Request)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Middleware 返回会话校验中间件（要求登录；adminOnly 时要求管理员）。
func Middleware(store *storage.Store, adminOnly bool, next jsonHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		username, err := store.GetSession(tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "会话已失效")
			return
		}
		if adminOnly {
			u, _, err := store.GetUser(username)
			if err != nil || u.Role != "admin" || !u.IsActive {
				writeErr(w, http.StatusForbidden, "需要管理员权限")
				return
			}
		} else {
			u, _, err := store.GetUser(username)
			if err != nil || !u.IsActive {
				writeErr(w, http.StatusUnauthorized, "账号已禁用")
				return
			}
		}
		next(w, withUser(r, username))
	})
}

func bearerToken(r *http.Request) string {
	// M7: 仅接受 Authorization 头 —— query 参数会进访问日志/Referer，扩大泄露面
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}
