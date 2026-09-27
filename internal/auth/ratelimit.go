// S6: 按 IP 的令牌桶限流（登录爆破 / 匿名订阅枚举防护）。
package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	lastSeen map[string]time.Time
	r        rate.Limit
	burst    int
}

func newIPLimiter(r rate.Limit, burst int) *ipLimiter {
	l := &ipLimiter{limiters: map[string]*rate.Limiter{}, lastSeen: map[string]time.Time{}, r: r, burst: burst}
	go func() { // 简单回收，防 map 无界增长
		for range time.Tick(10 * time.Minute) {
			l.mu.Lock()
			for k, t := range l.lastSeen {
				if time.Since(t) > time.Hour {
					delete(l.limiters, k)
					delete(l.lastSeen, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.limiters[ip]
	if !ok {
		lim = rate.NewLimiter(l.r, l.burst)
		l.limiters[ip] = lim
	}
	l.lastSeen[ip] = time.Now()
	return lim.Allow()
}

// RateLimit 中间件：超限返回 429。
func RateLimit(eventsPerMin, burst int, next http.Handler) http.Handler {
	l := newIPLimiter(rate.Every(time.Minute/time.Duration(eventsPerMin)), burst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !l.allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"请求过于频繁"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
