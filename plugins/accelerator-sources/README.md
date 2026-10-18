# Accelerator Sources

Accelerator Sources is an Agent-scoped, zero-configuration HTTP backend
provider. The `default` provider serves Docker Registry-compatible endpoints,
Docker Hub catalog and offline image export APIs, GitHub and Hugging Face
proxies, script rewriting, and the embedded web interface.

The plugin runs entirely in its own process. The Host owns the private provider
socket, generation credential, readiness checks, and request authority. The
plugin owns generation-local DNS, token and manifest caches, upstream
connection pools, and closes them after the Host drains the generation.

All upstream access uses the shared in-process upstream manager. No Docker
daemon, container runtime, virtual machine, database, sidecar, or external
helper application is required.

## Visitor interface

`web/static/` is embedded into the binary and served on `/`. It is fully
self-contained (no external requests, production CSP `default-src 'self'`).

- The header states the accelerator endpoint as a copyable monospace host, so the
  value a visitor needs most never has to be retyped from the address bar.
- **用法** — one smart input (`/` focuses it, a clipboard button fills it) turns
  GitHub / Hugging Face links (web `blob` URLs become raw / resolve downloads,
  repositories become `git clone`) and Docker image references
  (`docker pull <host>/<ref>`) into an accelerated address. The result sits
  beside the input with link / curl / wget / pull formats, an `Enter`-to-copy
  action and a one-click open. Below it, always-visible Docker, GitHub and
  Hugging Face cards carry the copy-ready commands, including `HF_ENDPOINT` and
  Git LFS clone.
- **镜像** — search Docker Hub, pick tags, and build an offline pack of up to
  16 images. Selected references are mirrored as a removable list beside the
  textarea. Before offering the download, the page `HEAD`s the prepared URL
  (HEAD does not consume the one-time token) and names any image that cannot
  be resolved. A `curl` command for headless servers is generated live.
- Light/dark follows the system unless the visitor toggles it; copy works on
  plain-HTTP deployments through a selection fallback.

## UI capture tool

`testing/ui/capture.mjs` renders this plugin's scenes in headless Chrome, Edge,
or Chromium against a deterministic mock of the catalog and offline APIs
(served with the same CSP as `web/handler.go`). It needs Node 22+ and a local
browser. Set `NRE_UI_BROWSER` to choose the browser binary.

```sh
node testing/ui/capture.mjs --plugin accelerator-sources
node testing/ui/capture.mjs --list
node testing/ui/capture.mjs --plugin accelerator-sources --only usage --theme dark --size 390
```

The run writes `index.html`, `README.md`, `capture-ui-manifest.json`, and png
files to `dist/ui-capture/` (override with `--out`). Successful images include
content already displayed below the first screen; a nested scroll area stays
as it is shown. It exits non-zero when a scene does not finish, visible
content overflows horizontally, the page raises an error, or that
below-the-fold content is missing from the image. In the mock, search terms
starting with `hold` stay loading, and terms or image references starting
with `fail` return upstream errors.
