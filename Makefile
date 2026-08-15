GO ?= go
CARGO ?= cargo

.PHONY: test test-go test-rust artifacts ci clean-test sdk-check

test: test-go test-rust

test-go:
	$(GO) test ./...

test-rust:
	$(CARGO) test --workspace --locked

artifacts:
	mkdir -p dist/bin
	$(GO) build -trimpath -buildvcs=false -ldflags='-buildid=' -o dist/bin/nre-ci ./cmd/nre-ci
	$(GO) build -trimpath -buildvcs=false -ldflags='-buildid=' -o dist/bin/nre-package ./cmd/nre-package
	$(GO) build -trimpath -buildvcs=false -ldflags='-buildid=' -o dist/bin/nre-market ./cmd/nre-market

ci: sdk-check test clean-test
	$(GO) run ./cmd/nre-ci repository --root .

sdk-check:
	$(GO) run ./cmd/nre-ci sdk --require-host-capabilities

clean-test:
	$(GO) run ./cmd/nre-ci reproducible --root . --output dist -- $(MAKE) artifacts
