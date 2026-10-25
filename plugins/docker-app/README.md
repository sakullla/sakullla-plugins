# Docker App plugin

This package owns bounded compose-application configuration, discovery
projections, risk previews, rollout state, redacted audit records, and cleanup
decisions. Overlay apps persist compose YAML; image and published ports are
derived from that document. Configuration and controller snapshots contain
bounded opaque `secret_refs` only, never secret material. Future material
access must be transient through a generation-owned typed secret handle.
Rollout recovery likewise depends on a durable versioned CAS store with
monotonic fencing and persisted transition intents; the included map store is
a test model only. Admission is a prepared transaction: controller-owned
Commit runs only after registration, and its non-blocking Abort compensates
generation revoke or deadline failure.

The plugin declares `ui.route` and `resource.group` in `plugin.yaml`, with
`host_scope: control-plane` for the management face and `host_scopes`
including `agent` for the execution face. The management face runs on the control plane; Agent execution uses the SDK
explicit target allowlist. Empty instance targets do not select all remote Agents.
Signed metadata `rpc.execution-scope.v1: agent` makes the Agent face explicit to
the Host, so the runtime does not infer it from endpoint presence.
The UI offers only remote Agents present in deployed instance targets; it does
not configure itself onto a selected node. The host mounts the page at
`/panel-api/plugins/<ui_route_id>/` and lists the resource group from
`resource_group_id` plus `resource.group.*` metadata. Instance
`resource_group_ref` is host-injected and must match `resource.group.ref`.
This plugin does not declare `http.backend-provider`,
`http_backend_providers`, or `ui.schema.json`. Compose YAML is edited on
the resource-group page, not on the generic config form.

The canonical `nre:rpc/v1` manifest and executable support a CI handshake
self-check. The plugin requires `http.rule`, `ui.dynamic`, `storage.read`,
`storage.write`, and a `service.revocable-resource-handle` scoped to
`docker-compose:managed`. That scoped generation grant activates the Agent's
private, allowlisted Compose command proxy; no node-local Docker host, socket,
API key, or per-Agent plugin configuration is required.

The control-plane management face reaches the Agent execution face through
the generic host runtime `plugin.call` (`engine.report`, `compose`, `image`)
and keeps HTTP ingress on `http.rule`. It does not emit `agent.engine.report`,
`agent.compose`, or `agent.image`. The Agent execution face runs local
`docker compose` CLI, engine probes, and image inspect; it does not expose
Docker as a network service. Missing or unsupported handles fail closed; they
never fall back to the control-plane `docker.socket` or `/var/run/docker.sock`.
Offline or missing reports are not treated as ready. The resource-group page
lists Agents, shows a copy-only official install command when the engine is
missing, and deploys compose only after that Agent is online and ready. This
plugin is not configured onto the selected Agent as an HTTP backend. No
private Host wire contract substitutes for the remaining public grants.

## UI validation

For an interactive local preview, run:

```sh
node plugins/docker-app/testing/ui/preview.mjs --port 4173
```

Open `http://127.0.0.1:4173/?agent_id=node-a`. The preview reads the current UI
assets on each request and uses in-memory fixtures for application operations,
files, logs, and HTTP entries. It never connects to Docker or a production host.
The preview-only controls switch light/night themes and reset sample data.
Stop the server with Ctrl+C.

The plugin package includes its original AI-generated companion artwork,
`companion.js`, and neutral/blink/wink WebP frames. Each frame is below the
1 MiB response budget. The page loads these package-local assets directly
and only after the assistant is expanded, so the first screen never requests a
frame image; there is no dependency on `dist/`, a preview server, a model CDN,
or an image API. The image CSP permits same-origin assets and validated
in-memory blob images, so loaded expressions continue working through a
connection outage.
The companion uses aligned raster expression frames; it is not a completed
Cubism mesh model. Full Live2D mesh/deformer binding and `.moc3` export remain
outstanding. Artwork provenance is recorded in `assets/companion-art.json`.

For local art experiments, add `&companion=portrait` to use
`dist/docker-app-live2d-preview/reference/character.webp` and its optional
expression metadata. To prepare a reference, run
`python plugins/docker-app/testing/ui/prepare-portrait.py /path/to/reference.jpg`
with Pillow, NumPy, and ONNX Runtime installed. The reference stays local;
the script downloads the Apache-2.0 anime segmentation model from SkyTNT.
For the separate Live2D runtime evaluation, run
`node plugins/docker-app/testing/ui/prepare-live2d.mjs` and open the preview
with `&companion=live2d`. This downloads the official Hiyori Momose sample and
pinned renderer dependencies into ignored `dist/` storage. These third-party
sample assets and runtimes are not included in official plugin packages.
This evaluation uses sample data owned and copyrighted by Live2D Inc.; the
sample is subject to the [sample terms](https://www.live2d.com/en/learn/sample/model-terms/)
and [Free Material License](https://www.live2d.com/eula/live2d-free-material-license-agreement_en.html).
`node plugins/docker-app/testing/ui/run.mjs --suite companion` checks the
running local preview, actual sample-model idle-frame changes, motion pause,
mobile placement, and the packaged companion's expression animation.

Docker Hub metadata checks use the Agent Docker daemon's effective
`RegistryConfig.Mirrors`, including standard Registry tag endpoints and the
`accelerator-sources` `/api/tags` catalog. Pagination stays on the configured
mirror. If mirrors are configured, a failed lookup does not silently bypass
them; only a daemon without mirrors queries Docker Hub directly. Private
registry images retain their own registry. Manifest reads preserve the original
image reference and do not pull or recreate containers. Failed digest checks
remain unavailable rather than being reported as an up-to-date image.

Version detection reads the release line of a repository, not only the digest of
one tag. A pinned tag such as `fatedier/frpc:v0.71.1` is compared with the
repository's newest release, so the page can state "已是最新版本 v0.71.1" or
offer `v0.71.1` as the next candidate. A moving tag such as
`xream/sub-store:latest` is matched against the release it currently points at
using the digest the registry publishes for each tag, so the page can report
"当前 2.42.6" and offer the concrete release as a pin. When a registry only
publishes tag names, the node is asked for the digest of the newest release in
the background so the same answer is still available. Suffix variants such as
`2.42.6-http-meta` stay a separate release line, and a `v`-prefixed tag family
such as `v0.71.1` is handled like any other semantic version. The release line
is read from the same configured mirror as the tag list, and a repository with
over a thousand tags is read completely instead of being truncated.

Detail pages share a one-second foreground image-check budget while background
checks continue. The page refreshes pending image results without discarding an
open editor. Agent Docker proxy support for `docker info` and formatted
`docker image inspect` is required; update the Agent alongside this plugin.

The management page is a working console rather than a list beside an empty
column. A sticky command bar carries the brand, the target-node picker with its
live engine badge and refresh, and the only primary deployment entry. A compact
status band counts all, running, updatable and stopped applications and doubles
as the status filter. The inventory column below the band keeps search (the `/`
shortcut focuses it), the status filter and the application rows visible while
a detail is open. Every row uses one structure: monogram and name, inline status
and update badges, published ports with the service count, one line per service
image, the ingress domain link, and a `详情` link. The whole row opens the
detail view and is keyboard focusable, and rows carry no inline primary action,
so running, stopped and updatable applications never show different button
sets. Selecting nothing leaves an actionable work area instead of blank space:
it lists the applications that need attention, the node facts (node, engine
version, application count) and quick starts for deploying or cleaning up.
Empty inventories, unmatched searches and offline nodes replace the previous
content instead of leaving stale rows behind.

The work area keeps a sticky identity header with the monogram, title, status,
node/application context and domain link, followed by a six-tab section bar
(overview, Compose, files, logs, HTTP ingress, backups). The header holds at
most one filled primary action (opening the application); stop uses a secondary
danger style and delete exists only in the closing danger zone. The overview
pairs a compact fact strip (state, services, published ports, HTTP ingress) with
service-image rows, the HTTP ingress entry, storage, the backup summary and run
parameters. A service-image row is the only image-update entry: version policy
and update live on each service row, the block header offers the image update
and rollback for the application, and an update still passes the existing risk
confirmation. Compose and workspace files use titled editor windows; logs use a
dark terminal with a themed toolbar and keep their four-second polling, pause
and copy/download controls. Image names and ingress domains can be copied from
the overview and ingress sections. Below 1024px the inventory and work area
become a single pane: opening an application hides the inventory, the back
control restores it together with the selected row and focus, and controls keep
a 44px target without horizontal overflow. Operation feedback floats above the
page rather than pushing it: a status toast appears and disappears without
reflowing the content and without intercepting a click.

Every capability from the earlier layout stays reachable: node selection and
engine state in the command bar, deployment from the command bar or the empty
inventory, start/stop/restart in the identity header, image update and rollback
from the overview's service-image block, version policy from each service row,
Compose and workspace files from their sections, logs from the log section,
HTTP ingress from its section, backup records, runs, restore, delete and
destination settings from the backup section, and disk cleanup from the
inventory header. Drafts keep their navigation and unload protection, and the
companion assistant stays on its own floating control.

The detail page also carries a backup section. It lists this application's
backup records (application, time, size, destination) with per-record restore
and delete entries, starts backups against a chosen destination (S3, or a
managed node when that destination is enabled), and edits the host-injected
destination settings: the S3 endpoint/bucket/prefix form plus the node
destination switch. Destination settings are written through the host
`instance.config` operation and re-injected by the lifecycle; S3 credentials
go to the host scoped-secret store (create/rotate) and only the returned
reference is persisted in `backup.s3.credentials_secret`. Restore and delete
reuse the page's confirmation dialog and the server-side confirm token (the
application id): an unconfirmed overwrite or deletion is rejected with zero
side effects. The node destination stays off by default and its entries are
not rendered while it is off; the server-side gate remains authoritative.

An optional read-only field diagnostic accepts image names at runtime through
`NRE_DOCKER_APP_LIVE_IMAGES` (space-separated). Run `TestLiveDockerImageMetadata`
from a compiled Go test binary on the Agent to verify real tag enumeration,
local/remote digests, and update projection. This test is skipped when the
variable is unset; ordinary test suites remain offline.

The UI remains native HTML/CSS/JavaScript. Node 22 or newer and a runnable
Chromium, Chrome, or Edge installation are required for the browser suites.
`NRE_UI_BROWSER` can name an explicit browser executable. The runner uses Node
built-ins and Chrome DevTools Protocol; no npm install or product build step is
needed.

```sh
go test ./plugins/docker-app ./testing/integration/docker-app
node plugins/docker-app/testing/ui/run.mjs --suite all
```

`all` runs `workspace`, `compose`, `operations`, `resources`, and `experience`.
Each suite must actually execute and produce passing evidence for the current
asset fingerprint. Missing browsers, skipped suites, stale evidence, and failed
assertions result in a nonzero exit. These suites use controlled fixture APIs;
their screenshots are labelled separately from actual host acceptance.

Screenshots come from the shared capture runner:

```sh
node testing/ui/capture.mjs --plugin docker-app --theme light,dark --size 1440,768,390 --out dist/ui-capture
node testing/ui/capture.mjs --plugin docker-app --theme host --size 1440,768,390 --out dist/ui-capture-host
```

Its eight scenes cover the inventory, the deployment drawer, the detail
overview, Compose, workspace files, logs, HTTP ingress and backups. Each scene
waits for an anchor of the current interface (the inventory status band, the
identity header's fact strip, the section panels) before the capture, so a page
that fails to render records a failing gallery entry instead of a stale image,
and the requested theme must match the page root or the run fails.

Theme resolution is owned by the shared kit. The page declares host theme mode,
so it reads the host's `theme` preference (`localStorage.theme`) before the
first paint and supports the five host themes — fresh-green, sakura-day,
sakura-night, neko-dark and business — plus the host's light and dark aliases
and its legacy theme ids. The kit writes `data-theme` and
`data-theme-family` on the page root, follows cross-tab `storage` changes, and
falls back to the system light or dark family for unknown or unreadable
values. The page is served as a top-level route whose CSP keeps
`frame-ancestors 'none'`, so theme resolution never reads a parent frame.
Credentials and Compose `.env` contents are not part of theme storage. Drafts
remain only in the current document; navigation asks before discarding them,
and browser unload confirmation is used where supported.

## Actual host acceptance

Run this only with a dedicated, disposable Agent. The suite deploys an
application, edits its Compose and files, starts/stops/restarts it, updates and
rolls back its running image, creates and visits HTTP ingress, deletes the
application, and performs node image/cache cleanup. It also creates a small
dangling image as explicit test preparation so cleanup remains testable on a
subsequent run. The host and Agent must already run the candidate package with
the required grants and explicit instance target allowlist.

Provide a public JSON configuration outside tracked source, for example:

```json
{
  "hostURL": "http://127.0.0.1:18080",
  "agentID": "explicit-test-agent-id",
  "agentContainer": "explicit-disposable-agent-container",
  "packageDigest": "installed-candidate-package-sha256",
  "tokenContainer": { "name": "explicit-host-container", "env": "API_TOKEN" },
  "disposableAgent": true,
  "appPrefix": "ui-acceptance",
  "baseImage": "nginx:1.27-alpine",
  "updateTag": "1.30.4-alpine",
  "publishedPort": 18081,
  "httpDomain": "http://127.0.0.1:15080",
  "hostSourceCommit": "full-host-source-commit",
  "compatibilityPatch": "describe any actual isolated-host adaptation"
}
```

Use `tokenEnv` with an environment-variable name instead of `tokenContainer`
when the token comes from a secret provider. Never put the token value in this
JSON. Container references are explicit; the runner does not scan unrelated
containers. Authentication uses the host's normal bootstrap credentials in a
fresh incognito browser context that is disposed at the end. Tokens are kept
out of console output, reports, and persistent browser profiles.

```sh
NRE_UI_HOST_CONFIG=/absolute/path/public-host.json \
  node plugins/docker-app/testing/ui/run.mjs --suite host
```

In PowerShell, set `$env:NRE_UI_HOST_CONFIG` to the absolute JSON path before
running the same Node command. Configuration can live outside an isolated
verification checkout. Optional metadata references such as
`productionFingerprint` or `packageMetadata` are informational; acceptance
compares the configured active package digest, the Agent's package digest,
and the actual served bytes of all three UI assets against the checkout from
which the runner is executing.

The selected update tag must be offered by the real registry metadata and
should be pre-pulled on the test Agent to avoid a registry delay consuming the
Agent operation deadline. `publishedPort` is the container's published backend
port; it must differ from the NRE ingress listener port in `httpDomain`. The
host's current UI route is a standalone page with `frame-ancestors 'none'`;
the suite opens it through the real host plugin-management link and changes
themes through the real host ThemeSelector in another tab.

Reports and screenshots are written under `dist/docker-app-ui-validation/`.
Host evidence includes host/Agent identity, package digest, asset fingerprint,
viewport, actual theme, executed scenes, cancellation/failure observations,
and runtime image identities. Required scenes and light/dark/narrow screenshots
must all exist before `host` can pass. On failure the named test application is
retained for investigation; resolve that explicitly before rerunning. The
runner refuses to start with pre-existing managed applications on the dedicated
Agent. Fixture results cannot substitute for missing host scenes.

The acceptance environment for this redesign uses an isolated export of host
commit `398ea1d9a3f51e6435ad812ed59447369d8b0ffc`. Its
`controlPlaneRuntimePlan` reuses the existing package-bound validator to load
the private custom-signed test candidate, with signature verification enabled.
The upstream repository is unchanged. The report records this environment
condition; the result applies to that adapted test host and explicit Agent.
