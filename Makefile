.PHONY: test race fuzz soak bench demo android ios lint
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -X github.com/ameerhamza2/tunnelcore/mobile.version=$(VERSION)

test:
	go vet ./...
	go test -race -count=1 ./...

FUZZTIME ?= 30s

# One target at a time: -fuzz accepts a single target per package run.
fuzz:
	go test -run=^$$ -fuzz=^FuzzParse$$ -fuzztime=$(FUZZTIME) ./packet/
	go test -run=^$$ -fuzz=^FuzzParseDNSQuestion$$ -fuzztime=$(FUZZTIME) ./packet/
	go test -run=^$$ -fuzz=^FuzzBuildUDPRoundTrip$$ -fuzztime=$(FUZZTIME) ./packet/
	go test -run=^$$ -fuzz=^FuzzFindSNI$$ -fuzztime=$(FUZZTIME) ./transport/obfs/
	go test -run=^$$ -fuzz=^FuzzTLSFragmentWrite$$ -fuzztime=$(FUZZTIME) ./transport/obfs/
	go test -run=^$$ -fuzz=^FuzzHandleQuery$$ -fuzztime=$(FUZZTIME) ./dnsproxy/
	go test -run=^$$ -fuzz=^FuzzResponseTTL$$ -fuzztime=$(FUZZTIME) ./dnsproxy/
	go test -run=^$$ -fuzz=^FuzzStackDeliverInbound$$ -fuzztime=$(FUZZTIME) ./netstack/
	go test -run=^$$ -fuzz=^FuzzNewTunnel$$ -fuzztime=$(FUZZTIME) ./mobile/

# Soak and leak tests live behind the `soak` build tag so `make test` stays
# fast. Add -race for a slower, stricter run: make soak SOAKFLAGS=-race
SOAKFLAGS ?=
soak:
	go test -tags soak -run Soak -count=1 -timeout 30m -v $(SOAKFLAGS) ./...

bench:
	go test -run=^$$ -bench=. -benchmem ./packet/ ./transport/... ./netstack/ ./dnsproxy/

demo:
	go run ./cmd/tun-harness demo

android:
	mkdir -p build && gomobile bind -target=android -androidapi 24 -ldflags "$(LDFLAGS)" -o build/tunnelcore.aar ./mobile

ios:
	mkdir -p build && gomobile bind -target=ios,iossimulator -ldflags "$(LDFLAGS)" -o build/Tunnelcore.xcframework ./mobile
