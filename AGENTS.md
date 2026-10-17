# Repository Guidelines

## Project Structure & Module Organization

This repository contains Go RPC plugins and Rust policy guests. Command-line entry points live in `cmd/` (`nre-ci`, `nre-package`, `nre-market`, and signing tools), while shared Go implementation code is under `internal/`. Each component belongs in `plugins/<name>/`; reusable Rust guest code lives in `crates/nre-policy-guest/`. Cross-component fixtures and suites are organized under `testing/`, including `integration/`, `hostfixture/`, `policychain/`, `performance/`, `sdkfixture/`, and `corpus/`. Keep plugin manifests and schemas beside their plugin (`plugin.yaml`, `config.schema.json`, `ui.schema.json`).

## Build, Test, and Development Commands

- `make test` runs `go test ./...` and `cargo test --workspace --locked`.
- `make ci` runs the full local CI path: tests, reproducible clean builds, generated-file drift checks, license checks, and secret-material checks.
- `make clean-test` performs two independent package builds and compares them for reproducibility; it is not a cleanup command.
- `go generate ./...` refreshes generated Go outputs. Review the resulting diff and never hand-edit generated market, package, SDK projection, NOTICE, SBOM, or lock artifacts.

Use Go 1.27.0 and the pinned Rust 1.97.1 toolchain. Preserve LF line endings as configured by `.gitattributes`.

## Plugin Development & Release Workflow

1. Make the behavior change inside `plugins/<id>/`, keeping manifests, schemas, package assets, fixtures, and tests with their owner. RPC plugins must use the public SDK lifecycle, entrypoint, transport, UI, and generation helpers instead of adding package-local copies. Manifest `assets` paths must be canonical paths below `assets/`.
2. Format and run the smallest useful feedback loop while developing:
   - Go: `gofmt -w <changed-go-files>` followed by `go test ./plugins/<id> ./testing/integration/<id>` where that integration package exists.
   - Rust: `cargo fmt --all -- --check` followed by `cargo test -p <package> --locked`; for policy artifacts also build the pinned `wasm32-unknown-unknown` release target.
   - Build/validate one official plugin with `go run ./cmd/nre-ci plugin --id <id>`.
3. Refresh generated outputs only through their owners. Use `go generate ./...` for Go projections and `go run ./cmd/nre-ci license --update` after a dependency-version change. Review every generated diff; do not manually patch SDK locks, legal inventories, market files, SBOMs, package indexes, or generated ABI projections.
4. When changing the upstream SDK in `nginx-reverse-emby/plugin-sdk`, complete this order:
   - Commit and test only the SDK-owned paths in the upstream repository.
   - Publish a new immutable `plugin-sdk/vX.Y.Z` tag; never move or recreate a published tag.
   - In this repository run `go run ./cmd/nre-ci sdk --update --tag plugin-sdk/vX.Y.Z` and then `go run ./cmd/nre-ci license --update`.
   - Verify with `go run ./cmd/nre-ci sdk --require-host-capabilities`. Never commit a local filesystem `replace` or `go.work` dependency.
5. Run `make test`, inspect `git diff --check`, and commit all intended source and generated changes. Use a focused Conventional Commit subject. Reproducibility and release checks rebuild the committed `HEAD`, not uncommitted working-tree changes.
6. Run `make ci` on the committed candidate. It must pass repository/generated checks, SDK capability verification, legal and secret checks, clean reproducibility builds, and all Go/Rust tests before release.
7. Prepare an official release only on Linux amd64 with the official signer provider configured through secrets/environment variables. Follow `.github/workflows/release.yml` to build `nre-signing-provider` and set the JSON `NRE_OFFICIAL_SIGNER` provider configuration; never print, persist, or commit the private key. Then run:

   ```sh
   go run ./cmd/nre-ci release --verify-reproducible --signer env:NRE_OFFICIAL_SIGNER
   ```

8. Treat `dist/release-candidate/`, its content-addressed `.nrepkg` blobs, provenance, signatures, and generated market projection as outputs. The `official-release-candidate` GitHub workflow is the canonical publisher: it uploads immutable blobs and publishes the verified `official-market` branch only after the release command succeeds. Do not hand-edit or replace published artifacts.

## Coding Style & Naming Conventions

Format Go with `gofmt`; use idiomatic exported `PascalCase` names and unexported `camelCase` names. Format Rust with `cargo fmt`; use `snake_case` for modules, functions, and tests, and `PascalCase` for types. Follow existing package boundaries and keep plugin-specific logic within its plugin directory. Treat checked-in generated files as outputs, not source.

## Testing Guidelines

Place Go tests in `*_test.go`, name them `TestXxx`, and use table-driven `t.Run` cases where appropriate. Rust integration tests belong in `tests/*.rs` and use `#[test]` with descriptive `snake_case` names. Add deterministic fixtures under `testing/corpus/<plugin>/` for contract behavior. Run `make test` during development and `make ci` before opening a pull request. No repository-wide coverage threshold is currently defined.

## UI Capture

`node testing/ui/capture.mjs` captures registered plugin pages for layout inspection. The pictures are not product acceptance.

- All plugins and scenes: `node testing/ui/capture.mjs`
- One plugin: `node testing/ui/capture.mjs --plugin <id>`
- One scene: `node testing/ui/capture.mjs --only <scene>`

`--plugin` takes a comma-separated plugin list. `--only` filters scene names and accepts `*` and `?`. When both are set, the run keeps their intersection. `node testing/ui/capture.mjs --list` prints the plugins and scenes those filters would capture.

`--theme` is `all` (the default, both light and dark), `light`, or `dark`. `--size` is a comma-separated list of viewport widths; the default is `1440,768,390`, and each width must be an integer from 280 to 3840. The default output directory is `dist/ui-capture/`. `--out` selects another directory. Each run deletes that directory before writing, so a narrower plugin or scene run replaces the gallery already stored there. The directory then contains `index.html`, `README.md`, `capture-ui-manifest.json`, and the PNG files.

## Commit & Pull Request Guidelines

Recent history generally follows Conventional Commit-style subjects: `fix(release): correct provenance`, `feat(waf): add rule support`, or `ci: tighten checks`. Use an imperative, focused summary and include a scope when useful. Pull requests should explain behavior changes, list affected plugins, link relevant issues, and include test evidence. Include screenshots only for UI schema or rendered interface changes. Ensure the required CI workflow passes before requesting review.
