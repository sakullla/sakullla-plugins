# Repository Guidelines

## Project Structure & Module Organization

This repository contains Go RPC plugins and Rust policy guests. Command-line entry points live in `cmd/` (`nre-ci`, `nre-package`, `nre-market`, and signing tools), while shared Go implementation code is under `internal/`. Each component belongs in `plugins/<name>/`; reusable Rust guest code lives in `crates/nre-policy-guest/`. Cross-component fixtures and suites are organized under `testing/`, including `integration/`, `hostfixture/`, `policychain/`, `performance/`, `sdkfixture/`, and `corpus/`. Keep plugin manifests and schemas beside their plugin (`plugin.yaml`, `config.schema.json`, `ui.schema.json`).

## Build, Test, and Development Commands

- `make test` runs `go test ./...` and `cargo test --workspace --locked`.
- `make ci` runs the full local CI path: tests, reproducible clean builds, generated-file drift checks, license checks, and secret-material checks.
- `make clean-test` performs two independent package builds and compares them for reproducibility; it is not a cleanup command.
- `go generate ./...` refreshes generated Go outputs. Review the resulting diff and never hand-edit generated market, package, SDK projection, NOTICE, SBOM, or lock artifacts.

Use Go 1.27.0 and the pinned Rust 1.97.1 toolchain. Preserve LF line endings as configured by `.gitattributes`.

## Coding Style & Naming Conventions

Format Go with `gofmt`; use idiomatic exported `PascalCase` names and unexported `camelCase` names. Format Rust with `cargo fmt`; use `snake_case` for modules, functions, and tests, and `PascalCase` for types. Follow existing package boundaries and keep plugin-specific logic within its plugin directory. Treat checked-in generated files as outputs, not source.

## Testing Guidelines

Place Go tests in `*_test.go`, name them `TestXxx`, and use table-driven `t.Run` cases where appropriate. Rust integration tests belong in `tests/*.rs` and use `#[test]` with descriptive `snake_case` names. Add deterministic fixtures under `testing/corpus/<plugin>/` for contract behavior. Run `make test` during development and `make ci` before opening a pull request. No repository-wide coverage threshold is currently defined.

## Commit & Pull Request Guidelines

Recent history generally follows Conventional Commit-style subjects: `fix(release): correct provenance`, `feat(waf): add rule support`, or `ci: tighten checks`. Use an imperative, focused summary and include a scope when useful. Pull requests should explain behavior changes, list affected plugins, link relevant issues, and include test evidence. Include screenshots only for UI schema or rendered interface changes. Ensure the required CI workflow passes before requesting review.
