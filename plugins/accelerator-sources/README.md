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

- **用法** — one smart input converts GitHub / Hugging Face links (web `blob`
  URLs become raw / resolve downloads, repositories become `git clone`) and
  Docker image references (`docker pull <host>/<ref>`), with link / curl /
  wget / pull formats, plus copy-ready Docker, `daemon.json`, script and clone
  examples.
- **镜像** — search Docker Hub, pick tags, and build an offline pack of up to
  16 images. Before offering the download, the page `HEAD`s the prepared URL
  (HEAD does not consume the one-time token) and names any image that cannot
  be resolved. A `curl` command for headless servers is generated live.
- Light/dark follows the system unless the visitor toggles it; copy works on
  plain-HTTP deployments through a selection fallback.

## UI capture tool

`testing/ui/capture.mjs` renders the page in headless Chrome/Edge against a
deterministic mock of the catalog and offline APIs (served with the same CSP
as `web/handler.go`) and captures every scene in light and dark themes at
several widths. It needs only Node 22+ and a local Chromium-family browser.

```sh
node plugins/accelerator-sources/testing/ui/capture.mjs                 # all scenes, light+dark, 1440/768/390
node plugins/accelerator-sources/testing/ui/capture.mjs --list          # list scenes
node plugins/accelerator-sources/testing/ui/capture.mjs --scenes mirrors-browse --themes dark --widths 390 --scale 2
node plugins/accelerator-sources/testing/ui/capture.mjs --serve         # interactive preview on 127.0.0.1:4180
```

Screenshots, `report.json`, and a browsable `index.html` contact sheet are
written to `dist/accelerator-sources-ui/` (override with `--out`). The run
exits non-zero when any capture has horizontal overflow, script errors, CSP
violations, or requests leaving the page origin. Set `NRE_UI_BROWSER` to use a
specific browser binary. In the mock, search terms starting with `hold` stay
loading and terms or image references starting with `fail` return upstream
errors.
