# Docker App plugin

This package owns bounded application configuration, discovery projections,
risk previews, rollout state, redacted audit records, and cleanup decisions.
It never opens the Docker socket, executes Docker or Compose commands, or owns
HTTP routing resources. All effects remain behind broker adapters that can only
be implemented by future typed public SDK handles.

The canonical `nre:rpc/v1` manifest and executable support a CI handshake
self-check. Normal startup fails closed because the public SDK currently lacks
typed Docker, Compose, HTTP-rule, and dynamic UI handles; no private Host wire
contract substitutes for them.
