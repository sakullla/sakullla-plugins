# Reverse L4 plugin

This directory currently contains the plugin-owned mapping, reconnect, mTLS
session status, generation admission, and drain state machine for reverse TCP
and UDP mappings.

It deliberately contains no listener, tunnel, relay, traffic implementation,
certificate/key handling, Agent identity, frp protocol, or direct network
dialer. Those resources must be supplied as revocable typed handles by the
canonical public SDK. The current SDK does not publish those types, so
`AdmitRuntime` always fails closed and no package manifest or executable is
produced. A capability string alone cannot enable startup.
