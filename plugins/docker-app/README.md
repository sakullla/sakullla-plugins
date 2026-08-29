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
including `agent` for the execution face. That dual-face runtime is the SDK
`RuntimeImplicitRemoteAgentExecution` contract: empty instance targets deliver
the Agent execution face to every remote Agent; the plugin does not list
Agents in TargetJSON or configure itself onto a selected node. The host mounts the page at
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
