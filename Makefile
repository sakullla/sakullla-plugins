GO ?= go
CARGO ?= cargo
ARTIFACTS_DIR ?= dist/bin

.PHONY: test test-go test-rust artifacts ci clean-test sdk-check

test: test-go test-rust

test-go:
	$(GO) test ./...

test-rust:
	$(CARGO) test --workspace --locked

artifacts:
	mkdir -p $(ARTIFACTS_DIR)
	$(GO) build -trimpath -buildvcs=false -ldflags='-buildid=' -o $(ARTIFACTS_DIR)/nre-ci ./cmd/nre-ci
	$(GO) build -trimpath -buildvcs=false -ldflags='-buildid=' -o $(ARTIFACTS_DIR)/nre-package ./cmd/nre-package
	$(GO) build -trimpath -buildvcs=false -ldflags='-buildid=' -o $(ARTIFACTS_DIR)/nre-market ./cmd/nre-market

ci: sdk-check test clean-test
	$(GO) run ./cmd/nre-ci repository --root .

sdk-check:
	$(GO) run ./cmd/nre-ci sdk --require-host-capabilities

clean-test:
	$(GO) run ./cmd/nre-ci reproducible --root . --output target/reproducible-dist -- $(MAKE) artifacts ARTIFACTS_DIR=target/reproducible-dist/bin SHELL=$(SHELL)
