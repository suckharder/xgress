package ssrfguard

import (
	"strings"
	"testing"
)

// S6: CheckAddr runs on the already-resolved dial address (ip:port) so it closes the
// DNS-rebinding gap CheckHost can't. It must block loopback/link-local/metadata and
// fail closed on a non-IP address.
func TestCheckAddr(t *testing.T) {
	blocked := []string{"127.0.0.1:80", "[::1]:443", "169.254.169.254:80", "0.0.0.0:25"}
	for _, a := range blocked {
		if err := CheckAddr(a); err == nil {
			t.Errorf("CheckAddr(%q) = nil, want blocked", a)
		}
	}
	allowed := []string{"8.8.8.8:443", "10.0.0.5:80", "172.16.0.1:587", "[2606:4700:4700::1111]:443"}
	for _, a := range allowed {
		if err := CheckAddr(a); err != nil {
			t.Errorf("CheckAddr(%q) = %v, want allowed", a, err)
		}
	}
	// Control always receives a resolved IP; a non-IP host here is unexpected → fail closed.
	if err := CheckAddr("example.com:80"); err == nil {
		t.Error("CheckAddr with a non-IP host should fail closed")
	}
	// DialControl is the net.Dialer.Control wrapper.
	if err := DialControl("tcp", "127.0.0.1:80", nil); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("DialControl(loopback) = %v, want blocked", err)
	}
}

func TestCheckHost(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "169.254.169.254", "169.254.0.1", "0.0.0.0", "[::1]"}
	for _, h := range blocked {
		if err := CheckHost(h); err == nil {
			t.Errorf("CheckHost(%q) = nil, want blocked", h)
		}
	}
	// Private + public IP literals are allowed (legit internal/external targets).
	allowed := []string{"10.0.0.5", "192.168.1.1", "172.16.0.1", "8.8.8.8"}
	for _, h := range allowed {
		if err := CheckHost(h); err != nil {
			t.Errorf("CheckHost(%q) = %v, want allowed", h, err)
		}
	}
}

func TestCheckURL(t *testing.T) {
	for _, u := range []string{
		"http://127.0.0.1:9000/api/provider",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8088/",
	} {
		if err := CheckURL(u); err == nil {
			t.Errorf("CheckURL(%q) = nil, want blocked", u)
		}
	}
	// Private target allowed.
	if err := CheckURL("http://10.1.2.3:8080/hook"); err != nil {
		t.Errorf("CheckURL(private) = %v, want allowed", err)
	}
	// Missing host → error.
	if err := CheckURL("http:///path"); err == nil {
		t.Error("CheckURL(no host) = nil, want error")
	}
}
