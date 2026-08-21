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

The plugin declares `ui.route` with `ui_route_id: docker-app`. The host
mounts the page at `/panel-api/plugins/<ui_route_id>/` from plugin nav
metadata; this plugin does not declare `resource.group` or `ui.schema.json`.
Compose YAML is edited on that page, not on the generic config form.

The canonical `nre:rpc/v1` manifest and executable support a CI handshake
self-check. Required grants are `http.rule` and `ui.dynamic`. Docker/Compose
API is not a plugin permission: Handshake and Activate do not require
`container.compose`, and install/deploy overlays have no Docker host, socket,
or API key fields. Local engine readiness is observed separately and is not a
connection form. No private Host wire contract substitutes for the remaining
public grants.
