# DoH plugin

DoH is an Agent-scoped, zero-configuration HTTP backend provider. The `default`
provider serves RFC 8484 DNS over HTTPS at `/dns-query`. GET `/` returns a
Chinese setup page that copies the current origin plus `/dns-query`. Optional
`upstreams` override the built-in Google DNS-over-HTTPS resolver.

The plugin runs entirely in its own process. The Host owns the private provider
socket, generation credential, readiness checks, request authority, and the
public HTTP+TLS listener. The plugin does not open a public HTTP or TLS port.
