//go:build integration

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe buffer for capturing a subprocess's combined
// output while assertions read it concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// discardLogger silences xgress's internal logging during the test.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// postJSON POSTs a JSON body and returns the status code (body closed).
func postJSON(t *testing.T, client *http.Client, url, body string) int {
	t.Helper()
	resp, err := client.Post(url, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// freePorts reserves n distinct free TCP ports on loopback and releases them, so
// the static config can name fixed ports before Traefik binds. All listeners are
// held open simultaneously so the returned ports are guaranteed distinct.
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve free port: %v", err)
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	return ports
}

// eventually retries fn until it returns nil or the timeout elapses, failing the
// test with the last error. Used for the inherently-asynchronous Traefik poll loop.
func eventually(t *testing.T, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = fn(); lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %v", timeout, lastErr)
}

// waitReady polls url until it returns 200 or the timeout elapses.
func waitReady(url string, timeout time.Duration) error {
	return waitReadyWith(&http.Client{Timeout: time.Second}, url, timeout)
}

// waitReadyWith is waitReady with a caller-supplied client (e.g. one that trusts a
// not-yet-known TLS CA during bootstrap).
func waitReadyWith(client *http.Client, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = errStatus(resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

// waitReachable polls url until the server responds at all (any status — for
// services whose endpoints are non-GET, like challtestsrv's POST-only mgmt API).
func waitReachable(client *http.Client, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

// httpGetHost issues GET rawurl while presenting hostHeader as the HTTP Host, so
// Traefik routes by its Host(...) rule. Redirects are not followed.
func httpGetHost(rawurl, hostHeader string) (body string, status int, err error) {
	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		return "", 0, err
	}
	req.Host = hostHeader
	client := &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, nil
}

// routerInfo is the subset of Traefik's /api/http/routers entries we assert on.
type routerInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Rule   string `json:"rule"`
}

// traefikRouters reads the live HTTP routers from Traefik's read-only API.
func traefikRouters(apiBase string) ([]routerInfo, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(apiBase + "/api/http/routers")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errStatus(resp.StatusCode)
	}
	var rs []routerInfo
	if err := json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return nil, err
	}
	return rs, nil
}

type errStatus int

func (e errStatus) Error() string { return "unexpected status " + itoa(int(e)) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
