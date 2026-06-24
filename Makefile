VERSION ?= 0.10.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
  -X github.com/suckharder/xgress/internal/version.Version=$(VERSION) \
  -X github.com/suckharder/xgress/internal/version.Commit=$(COMMIT) \
  -X github.com/suckharder/xgress/internal/version.Date=$(DATE)

.PHONY: all web build run test integration smoke vet tidy docker clean dev

all: web build

web:
	cd web && npm install && npm run build

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/xgress ./cmd/xgress

run: build
	XGRESS_DATA_DIR=./_data XGRESS_TRAEFIK_MANAGED=false XGRESS_ADMIN_LISTEN=127.0.0.1:8088 XGRESS_DEV=true ./bin/xgress

test:
	go test ./...

# End-to-end Tier A (config-contract). Runs xgress's engine/store/provider in-process
# and drives a real pinned Traefik against it. Needs network on first run to fetch
# the Traefik binary (cached under test/e2e/.cache thereafter). -count=1: never cache
# (external process). On macOS runs native; the Linux/container runner lands later.
integration:
	go test -tags integration -count=1 -timeout 120s ./test/e2e/...

# End-to-end Tier C (compose smoke). Builds the real image and drives it via docker
# compose across ALL 8 shipped deployment variants (single/external x sqlite/postgres
# x memory/redis): setup -> login -> create host -> proxy reaches whoami -> disable ->
# hot-reload 404, plus the hardening + (single-container redis) a cache HIT from
# Redis. Needs Docker. One variant: `go test -tags smoke -run TestSmoke/<name> ./test/smoke/...`.
smoke:
	docker build -t xgress:test .
	go test -tags smoke -count=1 -timeout 900s ./test/smoke/...

vet:
	go vet ./...

tidy:
	go mod tidy

docker:
	docker build -t xgress:$(VERSION) --build-arg VERSION=$(VERSION) .

dev:
	cd web && npm run dev

clean:
	rm -rf bin _data web/dist/assets
