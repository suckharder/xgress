package api

import (
	"sync"
	"time"
)

// loginLimiter is a small in-memory per-source throttle for the login endpoint:
// after maxFails failed attempts from a key within the window, further attempts are
// refused until the window elapses. State resets on restart (fine for a brute-force
// brake) and on a successful login. bcrypt already slows guessing; this caps it.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
	maxFails int
	window   time.Duration
}

type loginAttempt struct {
	fails int
	until time.Time // window/lockout expiry
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: map[string]*loginAttempt{}, maxFails: 10, window: 5 * time.Minute}
}

// allowed reports whether key may attempt a login now.
func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[key]
	if a == nil || time.Now().After(a.until) {
		return true
	}
	return a.fails < l.maxFails
}

// fail records a failed attempt and (re)arms the window.
func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.attempts[key]
	if a == nil || now.After(a.until) {
		a = &loginAttempt{}
		l.attempts[key] = a
	}
	a.fails++
	a.until = now.Add(l.window)
	// Opportunistic cleanup so the map can't grow unbounded with attacker IPs.
	if len(l.attempts) > 4096 {
		for k, v := range l.attempts {
			if now.After(v.until) {
				delete(l.attempts, k)
			}
		}
	}
}

// success clears any throttle for key.
func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}
