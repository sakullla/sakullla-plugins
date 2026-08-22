# Docker App plugin

This package owns bounded compose-application configuration, discovery
projections, risk previews, rollout state, redacted audit records, and cleanup
decisions. Overlay apps persist compose YAML; image and published ports are
derived from that document. It never opens the Docker socket, executes Docker
or Compose commands, or owns HTTP routing resources. All effects remain behind
broker adapters that can only be implemented by future typed public SDK handles.

Configuration and controller snapshots contain bounded opaque `secret_refs`
only, never secret material. Future material access must be transient through a
generation-owned typed secret handle. Rollout recovery likewise depends on a
durable versioned CAS store with monotonic fencing and persisted transition
intents; the included map store is a test model only. Admission is a prepared
transaction: controller-owned Commit runs only after registration, and its
non-blocking Abort compensates generation revoke or deadline failure.

The plugin declares `ui.route` and `resource.group` in `plugin.yaml`, with
`host_scope: control-plane`. The host mounts the page at
`/panel-api/plugins/<ui_route_id>/` and lists the resource group from
`resource_group_id` plus `resource.group.*` metadata. Instance
`resource_group_ref` is host-injected and must match `resource.group.ref`.
This plugin does not declare `http.backend-provider`,
`http_backend_providers`, or `ui.schema.json`. Compose YAML is edited on
the resource-group page, not on the generic config form.

The canonical `nre:rpc/v1` manifest and executable support a CI handshake
self-check. Required grants are `http.rule` and `ui.dynamic`. Docker/Compose
API is not a plugin permission: Handshake and Activate do not require
`container.compose`, and install/deploy overlays have no Docker host, socket,
or API key fields. Engine readiness is consumed from the generic host runtime
(`agent.engine.report`: `online`, `installed`, `version`) and is not a
connection form. Compose apply/start/stop/restart/logs/remove are dispatched
through the same host runtime (`agent.compose`) with the target `agent_id`.
Missing or unsupported handles fail closed; they never fall back to the
control-plane `docker.socket` or `/var/run/docker.sock`. Offline or missing
reports are not treated as ready. The resource-group page lists Agents, shows
a copy-only official install command when the engine is missing, and deploys
compose only after that Agent is online and ready. This plugin is not
configured onto the selected Agent. No private Host wire contract substitutes
for the remaining public grants.
