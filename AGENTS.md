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

`--theme` is `all` (the default, both light and dark), `light`, `dark`, `host` (the five host themes), one of the host theme ids `fresh-green`, `sakura-day`, `sakura-night`, `neko-dark`, or `business`, or a comma-separated combination of those values. `--list` prints the available themes with the plugins and scenes.

Each capture writes the requested theme to the page's own `localStorage` key before navigation and then reads `data-theme` from the document root; it never injects `data-theme` after load. A capture fails when the resolved root theme or the declared theme mode does not match the requested value. The manifest records the requested `theme`, `themeMode`, `themeKey`, `expectedTheme`, `resolvedTheme`, and `themeFamily` for each image.

Six host pages (`cloudflare-dns`, `docker-app`, `ip-policy`, `reverse-l4`, `shadowsocks-server`, `waf`) follow the same-origin `localStorage.theme` and the five host themes. Three standalone pages (`accelerator-sources`, `doh`, `webdav`) follow the system preference or their own `<plugin>.theme` key and only resolve `light`/`dark`; a host theme id requested for a standalone page is checked as its light/dark family. Use `node testing/ui/theme-probe.mjs` to verify a top-level host page with only `localStorage.theme` prepared; it reads the root theme and fails on a mismatch. `node testing/ui/contrast.mjs` audits the canonical kit token pairs for every theme. Text pairs must reach 4.5:1: body, secondary, tertiary and status text; links, eyebrows and selected tabs using `--ui-primary` on `--ui-bg` and `--ui-surface`; link hover using `--ui-primary-hover` on the same two surfaces; tab and ghost-button hover text `--ui-text` on `--ui-hover`; the default badge's `--ui-text-secondary` on `--ui-subtle`; the info badge's `--ui-primary` on `--ui-primary-soft`; table headers' `--ui-text-tertiary` on `--ui-sunken`; the primary button's `--ui-on-primary` on `--ui-primary` with its hover/active states; the danger button's `--ui-on-danger` on `--ui-danger-button`; and the danger badge's `--ui-danger-text` on `--ui-danger-soft`. Non-text pairs must reach 3:1: the `--ui-border` and `--ui-border-strong` control boundaries, the danger indicator, and the error-state icon's `--ui-danger` on `--ui-danger-soft`. A failing required pair exits non-zero; only the decorative toast accent stripes stay advisory and warn, and they fail solely with `--strict`. `--file` audits another kit copy.

`--size` is a comma-separated list of viewport widths; the default is `1440,768,390`, and each width must be an integer from 280 to 3840. The default output directory is `dist/ui-capture/`. `--out` selects another directory. Each run deletes that directory before writing, so a narrower plugin or scene run replaces the gallery already stored there. The directory then contains `index.html`, `README.md`, `capture-ui-manifest.json`, and the PNG files.

Successful PNGs include content already displayed below the first screen. The layout viewport stays 900 pixels tall, and a taller document produces a taller image. Content that is only inside a nested scroll container is kept as that container shows it. If the document is taller than the viewport but the PNG is not, that capture fails.

### UI component and keyboard evidence

`node testing/ui/component-consistency.mjs` opens the nine R6 pages (accelerator-sources, cloudflare-dns, docker-app, doh, ip-policy, reverse-l4, shadowsocks-server, waf, webdav) with their capture fixtures and writes `testing/ui/component-consistency.md`: the primary button, input, table, badge, dialog and empty state per page, with whether each uses the kit class and `--ui-*` tokens and whether the component differences are eliminated. `node testing/ui/keyboard-checks.mjs` presses real Tab/Enter/Escape keys over the same pages and writes `testing/ui/keyboard-checks.md`: page, scene, element, operation, focus visibility, Enter result, and Escape close/focus return.

Both scripts have `--check`, which re-runs the audit against the current pages and fails when the committed report is stale or a difference remains. `node --test testing/ui/capture.test.mjs` runs both `--check` commands, so regenerate the reports with the same scripts after a page change. These reports are delivery evidence for R6, not product acceptance.

## Commit & Pull Request Guidelines

Recent history generally follows Conventional Commit-style subjects: `fix(release): correct provenance`, `feat(waf): add rule support`, or `ci: tighten checks`. Use an imperative, focused summary and include a scope when useful. Pull requests should explain behavior changes, list affected plugins, link relevant issues, and include test evidence. Include screenshots only for UI schema or rendered interface changes. Ensure the required CI workflow passes before requesting review.
