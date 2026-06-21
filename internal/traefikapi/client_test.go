package traefikapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDisabledClient(t *testing.T) {
	c := New("")
	if c.Enabled() {
		t.Fatal("empty addr should be disabled")
	}
	if _, err := c.Raw(context.Background(), "/api/overview"); !errors.Is(err, ErrDisabled) {
		t.Errorf("Raw on disabled client = %v, want ErrDisabled", err)
	}
}

func TestRawAndStatusErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/overview":
			w.Write([]byte(`{"ok":true}`))
		case "/api/missing":
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	c := New(strings.TrimPrefix(ts.URL, "http://"))
	if !c.Enabled() {
		t.Fatal("client should be enabled")
	}
	body, err := c.Raw(context.Background(), "/api/overview")
	if err != nil || !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("Raw overview: %v / %s", err, body)
	}
	if _, err := c.Raw(context.Background(), "/api/missing"); err == nil {
		t.Error("Raw on a 404 should return an error")
	}
}

func TestRoutersAndServicesParsing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/http/routers":
			w.Write([]byte(`[
				{"name":"r1@docker","rule":"Host(` + "`a.com`" + `)","service":"s1","status":"enabled","provider":"docker","entryPoints":["web"]},
				{"name":"r2@file","rule":"Host(` + "`b.com`" + `)","service":"s2","status":"enabled","provider":"file"}
			]`))
		case "/api/http/services":
			w.Write([]byte(`[
				{"name":"s1@docker","provider":"docker","type":"loadbalancer","loadBalancer":{"servers":[{"url":"http://10.0.0.1:80"}]}}
			]`))
		}
	}))
	defer ts.Close()
	c := New(strings.TrimPrefix(ts.URL, "http://"))

	routers, err := c.Routers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(routers) != 2 || routers[0].Name != "r1@docker" || routers[0].Provider != "docker" {
		t.Fatalf("routers parse mismatch: %+v", routers)
	}
	if routers[0].EntryPoints[0] != "web" {
		t.Errorf("entrypoints not parsed: %+v", routers[0].EntryPoints)
	}

	services, err := c.Services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].Name != "s1@docker" {
		t.Fatalf("services parse mismatch: %+v", services)
	}
	servers, _ := services[0].LoadBalancer["servers"].([]any)
	if len(servers) != 1 {
		t.Errorf("loadBalancer servers not parsed: %+v", services[0].LoadBalancer)
	}
}
