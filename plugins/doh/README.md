# DoH plugin

This agent-scoped Go RPC plugin models RFC 8484 GET/POST handling, token and
shared IP-policy admission, deterministic upstream failover, trusted DNS TTL
caching, and redacted aggregate logs.

The plugin never opens a listener or network connection itself. Production
activation requires canonical generation-owned listener, network, Secret,
monotonic clock, cache, IP-policy, log, and audit handles. The current public
SDK does not expose those typed handles, so the default entrypoint fails closed.
