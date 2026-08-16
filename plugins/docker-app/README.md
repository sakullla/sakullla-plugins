# Docker App plugin

This package owns bounded application configuration, discovery projections,
risk previews, rollout state, redacted audit records, and cleanup decisions.
It never opens the Docker socket, executes Docker or Compose commands, or owns
HTTP routing resources. All effects remain behind broker adapters that can only
be implemented by future typed public SDK handles.

Configuration and controller snapshots contain bounded opaque `secret_refs`
only, never secret material. Future material access must be transient through a
generation-owned typed secret handle. Rollout recovery likewise depends on a
durable versioned CAS store with monotonic fencing and persisted transition
intents; the included map store is a test model only. Admission is a prepared
transaction: controller-owned Commit runs only after registration, and its
non-blocking Abort compensates generation revoke or deadline failure.

The canonical `nre:rpc/v1` manifest and executable support a CI handshake
self-check. Permissions and required grants are the public handle names
`container.compose`, `http.rule`, and `ui.dynamic`. Normal startup and
operational actions fail closed when those handles are not granted; no private
Host wire contract substitutes for them.
