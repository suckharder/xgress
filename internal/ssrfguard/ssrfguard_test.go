package ssrfguard

import "testing"

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
