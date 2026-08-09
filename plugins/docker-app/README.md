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
self-check. Normal startup fails closed because the public SDK currently lacks
typed Docker, Compose, HTTP-rule, and dynamic UI handles; no private Host wire
contract substitutes for them.
