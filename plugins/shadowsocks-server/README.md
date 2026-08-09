# Shadowsocks Server

This Go RPC plugin models regulated TCP and UDP Shadowsocks admission. Listener,
secret verification and rotation, replay protection, monotonic time,
traffic accounting, and audit are exclusively brokered through typed adapters.
It never registers an HTTP or generic L4 egress provider.

The current public SDK does not expose these typed service handles, so the
production entrypoint intentionally fails closed. Integration tests inject the
business adapters without defining another Host RPC or wire ABI. The Host starts
the RPC plugin itself; there is deliberately no business-level child-process
callback and no Host-owned Shadowsocks implementation.

Transport cryptography and wire framing are implemented in this repository with
the Go standard library. Supported methods are `aes-128-gcm`, `aes-256-gcm`,
`2022-blake3-aes-128-gcm`, and `2022-blake3-aes-256-gcm`. The implementation
includes the legacy password KDF and HKDF-SHA1 session keys, the SS2022 BLAKE3
derive-key mode, TCP and UDP framing, SOCKS addresses, AEAD authentication,
timestamp validation, and replay tokens. Shadowsocks 2022 accepts canonical
standard-base64 PSKs of exactly 16 or 32 bytes and never uses the legacy password
KDF. Packaging still fails closed until canonical typed listener, secret,
traffic, and replay handles are published by the SDK.
