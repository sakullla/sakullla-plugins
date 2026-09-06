# Shadowsocks Server

This Go RPC plugin provides regulated TCP and UDP Shadowsocks admission. Production
listeners, accepted flows, direct outbound connections, and source admission use
the public Host managed-network runtime. Host admission completes before encrypted
client bytes reach the plugin. Secret creation, delivery, rotation, and revocation
use scoped Host storage; normal plugin state contains references only.
Replay protection, monotonic time, traffic accounting, and audit use typed adapters.
It never registers an HTTP or generic L4 egress provider.

Administrators manage accounts from the plugin's simple panel: generate a
traditional SS or SS2022 account, list enabled and disabled users, disable or
re-enable one account, rotate that account's client key, optionally rotate the
instance SS2022 server PSK, and copy a SIP002 URI or show the matching QR.
The panel lets administrators set the client-facing share host (domain or
public IP) used in SIP002 URIs. The default follows the Host node snapshot
(configured DDNS, then heartbeat IPv4, then IPv6). A saved override is
per-agent and is not replaced by later heartbeats; clearing it restores the
automatic address. Sharing uses the instance's own TCP+UDP listen;
generating and sharing do not require opening the L4 rules page or filling a
backend. There is no subscription URL and no SIP003 plugin parameter.

The host may mount this page because `plugin.yaml` declares `ui.route` and
`resource.group` with id `shadowsocks-server`. `host_scope: control-plane` plus
`host_scopes: [agent]` is the SDK `RuntimeImplicitRemoteAgentExecution`
contract: empty instance targets deliver the Agent execution face to every
remote Agent; this plugin does not list Agents in TargetJSON or configure
itself onto a selected node. Control-plane `ServeHTTP` serves canonical files
from `assets/ui/`; the Agent face does not serve the management page. This
plugin does not declare `ui.schema.json`, `tunnel.provider`, or
`http.backend-provider`.

Production startup uses the canonical SDK runtime lifecycle and requires the
Host-authored runtime instance identity plus managed-network and scoped-secret
features. The control-plane face sends only listener and secret references to the
Agent face. A previous `secrets` state record is imported once into scoped Host
storage; listener references are committed before that legacy value is cleared.
Migration failure preserves the prior listener catalog and material for retry.
The native socket binder remains an explicit test fixture and is never selected
by the production entrypoint. The Host owns sockets and admission, while the
plugin continues to own Shadowsocks framing and cryptography.

Transport cryptography and wire framing are implemented in this repository with
the Go standard library. Supported methods are `aes-128-gcm`, `aes-256-gcm`,
`2022-blake3-aes-128-gcm`, and `2022-blake3-aes-256-gcm`. The implementation
includes the legacy password KDF and HKDF-SHA1 session keys, the SS2022 BLAKE3
derive-key mode, TCP and UDP framing, SOCKS addresses, AEAD authentication,
timestamp validation, and replay tokens. Shadowsocks 2022 accepts canonical
standard-base64 PSKs of exactly 16 or 32 bytes and never uses the legacy password
KDF. Missing Host runtime endpoints fail closed at SDK validation.

## Dataset routing

The management page stores up to 16 scoped-secret upstreams and 64 ordered
rules. Each rule selects one Host-managed dataset source and classification,
including GeoSite attributes such as `category-ai` with `!cn`, then chooses
`direct`, `reject`, or one upstream. The first match wins and the explicit
default action applies after ordinary non-matches. A missing classification,
unavailable dataset, disabled or protocol-incompatible upstream, failed dial,
or failed upstream authentication stops the flow without a direct fallback.

The Agent resolves immutable dataset references when applying a listener
snapshot. TCP sessions retain that snapshot for their lifetime. Each UDP input
uses one bounded 500 ms outbound association and may return multiple datagrams;
separate inputs remain isolated and protocol replay checks remain active.
Upstream endpoints are dialed directly and are never routed recursively.
Diagnostics expose rule, source, classification, immutable version, selected
exit, and stable failure codes. They never expose upstream secret material.

When a TCP request names only an IP target, routing may inspect at most 16 KiB
for 250 ms before dialing. It recognizes HTTP/1.0 or HTTP/1.1 `Host` and clear
TLS 1.2/1.3 ClientHello SNI across Shadowsocks chunks and TLS records. The
original domain always wins. The original IP and port are never rewritten, and
all bytes consumed during inspection are replayed exactly. HTTP/2 prior
knowledge, ECH, conflicting or malformed headers, timeout, over-limit input and
server-first protocols use the IP/default route. UDP is never sniffed.
