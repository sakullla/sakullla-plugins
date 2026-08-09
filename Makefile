GO ?= go
CARGO ?= cargo

.PHONY: test test-go test-rust ci clean-test

test: test-go test-rust

test-go:
	$(GO) test ./...

test-rust:
	$(CARGO) test --workspace --locked

ci: test
	$(GO) run ./cmd/nre-ci repository --root .

clean-test:
	$(GO) run ./cmd/nre-ci reproducible --root . -- $(MAKE) test
