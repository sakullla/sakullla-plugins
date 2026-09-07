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

Docker Hub metadata checks use the Agent Docker daemon's effective
`RegistryConfig.Mirrors`, including standard Registry tag endpoints and the
`accelerator-sources` `/api/tags` catalog. Pagination stays on the configured
mirror. If mirrors are configured, a failed lookup does not silently bypass
them; only a daemon without mirrors queries Docker Hub directly. Private
registry images retain their own registry. Manifest reads preserve the original
image reference and do not pull or recreate containers. Failed digest checks
remain unavailable rather than being reported as an up-to-date image.

Detail pages share a one-second foreground image-check budget while background
checks continue. The page refreshes pending image results without discarding an
open editor. Agent Docker proxy support for `docker info` and formatted
`docker image inspect` is required; update the Agent alongside this plugin.

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

The page follows the host's supported light/dark theme aliases. In a same-origin
frame it observes the parent document's `data-theme`; as a standalone hosted
page it uses the host's `theme` preference and receives cross-tab storage
changes. Unknown or inaccessible host themes fall back to light. Credentials
and Compose `.env` contents are not part of theme storage. Drafts remain only
in the current document; navigation asks before discarding them, and browser
unload confirmation is used where supported.

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
