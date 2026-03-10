GO ?= go

.PHONY: fmt test test-fast bench lint run-cli demo-bitcoin demo-rollup demo-light-client demo-bridge-exit tidy

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

test-fast:
	$(GO) test ./internal/... ./cmd/... ./examples/...

bench:
	$(GO) test -bench=. -benchmem ./internal/...

lint:
	$(GO) vet ./...

run-cli:
	$(GO) run ./cmd/zkp-merkle-demo --help

demo-bitcoin:
	$(GO) run ./examples/bitcoin-p2mr

demo-rollup:
	$(GO) run ./examples/zk-rollup

demo-light-client:
	$(GO) run ./examples/light-client-spv

demo-bridge-exit:
	$(GO) run ./examples/bridge-exit

tidy:
	$(GO) mod tidy
