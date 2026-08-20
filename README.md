# Sakullla official plugins

This repository owns the source, tests, packaging tools, and market projection for
Sakullla's official plugins. The host ABI, validator, authorization model, and
core resource owners remain in the main product repository and are consumed only
through a pinned public SDK contract.

## Toolchains

- Go is pinned by `go.mod` (`1.27.0`).
- Rust is pinned by `rust-toolchain.toml` (`1.97.1`) and the workspace discovers
  policy guests through `plugins/*`.
- CI pins protoc to `32.0` before running generated-code checks.

The repository tools create task-specific temporary caches; they do not read a
sibling main-product checkout. Build outputs, private keys, runtime data, and
GeoLite databases are ignored.

## Common commands

```sh
make test
make ci
make clean-test
```

`make test` runs the Go and Rust workspaces. `make ci` additionally checks
generated drift, dependency license declarations, secret-like material, and two
independent clean builds of the declared `dist` output. On Windows, the equivalent commands can be run through
`go run ./cmd/nre-ci ...` plus `cargo test --workspace --locked`.

## Packaging boundary

During development, `go.mod` replaces the canonical `plugin-sdk` module root
with `../nginx-reverse-emby/plugin-sdk`; production code imports only its public
`plugin-sdk/go` packages. Release candidates remove the local replacement and
pin the committed upstream pseudo-version.

`nre-package` assembles a closed package tree, emits deterministic file metadata,
SPDX JSON and NOTICE data, asks an external signer provider to sign the payload
digest, and invokes the pinned validator. Official signing is command-provider
only: signing secrets are never accepted as command-line flags or stored in this
repository. Tests inject an in-memory fake signer through the Go interface and
cannot be selected by the production CLI.

`nre-market` consumes JSON release records and writes canonical UTF-8 YAML with a
fixed field order, LF line endings, and one final newline. Generated market and
package data should never be edited by hand.
