# Reverse L4 plugin

This directory currently contains the plugin-owned mapping, reconnect, mTLS
session status, generation admission, and drain state machine for reverse TCP
and UDP mappings.

It deliberately contains no listener, tunnel, relay, traffic implementation,
certificate/key handling, Agent identity, frp protocol, or direct network
dialer. Those resources must be supplied as revocable typed handles by the
canonical public SDK. The current SDK does not publish those types, so
`AdmitRuntime` always fails closed and a capability string alone cannot enable
startup. The package manifest and Go RPC executable declare only canonical
`nre:rpc/v1`; the executable exposes a CI-only public-SDK handshake self-check,
not a replacement Host transport or resource wire contract.
