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

Signed metadata `rpc.execution-scope.v1: agent` opts the Agent face into the
Host-authored execution scope. The control-plane face remains compatible with
the SDK's legacy host-endpoint selection and does not require the optional
execution-scope feature in its handshake.

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
including GeoSite classifications such as `category-ai-!cn`, then chooses
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

The "刷新数据集" action (`POST /api/routing/refresh`, optionally scoped by
`source_id`) asks the control plane to issue the `dataset.control` refresh
operation for every source referenced by the rules. That call requires the
`dataset.manage` grant. When the refresh succeeds the panel re-applies routing
to every listening agent so each agent re-resolves the newest Host-prepared
immutable reference; the response reports the before/after version digest per
source (`updated`, `latest`, or `unresolved`) and `routing_applied` /
`routing_error` per node. A failed refresh control never re-applies, so the
last working version keeps serving. When `dataset.manage` is not granted the
action degrades to re-apply only, the report says so, and no new version is
silently selected. In-flight sessions keep their established immutable
snapshot either way.

The "远程规则集" section registers additional public HTTPS dataset sources
through the `dataset.source-register` runtime grant (`POST
/api/dataset-sources`). Each source has an id, a format (`geosite`, `geoip`,
`community`, `cidr`, or `geo-mmdb`), an optional refresh interval, and a
retrieval mode: `pinned` requires a revision plus a `sha256:` expected digest,
while `rolling-sha256` requires an HTTPS checksum URL the Host polls for
updated content. Only public `https://` addresses are accepted — no userinfo,
fragments, or private-network literals — and authenticated subscription URLs
with credentials are unsupported in this phase; nothing in the request,
registry, or UI stores or echoes credentials. The Host performs every fetch,
checksum validation, and version preparation; the plugin only keeps a bounded
registry record of the registration parameters. Registered ids appear in the
rule dialog's source-id suggestions alongside `geosite` and `geoip`, and the
panel lists each source's retrieval parameters plus the current version digest
and last-fetch time when the Host catalog exposes them (they stay blank when
the catalog does not report them). Per-source and bulk refresh reuse the same
`dataset.control` refresh channel described above; removal issues the Host
`delete-source` operation (`POST /api/dataset-sources/{id}/delete`). If the
Host refuses deletion — for example because consumers still reference the
source — the readable error is shown and the registry entry is kept. If
deletion succeeds while rules still reference the id, those rules stay in
place and fail closed with `dataset-unavailable`; they never silently rebind
to another source or fall back to direct.

Upstreams use separate host, port, method, and password fields, not an Xray
outbound JSON object. For SS2022 multi-user upstreams, the password field holds
the complete `serverPSK:userPSK` pair. An upstream can be edited in place
without breaking rule references: endpoint, method, and protocol fields apply
directly, a new password rotates its scoped secret, and a blank password keeps
the existing credential. Select a classification present in the source catalog;
`category-ai-!cn` is a literal classification name, not the `!cn` attribute on
a different classification. Bind the dataset to each target node before
applying the rule.

The "测试" action (`POST /api/upstreams/{id}/test`, with `agent_id` in the
request body or query) asks the selected Agent to run a read-only
connectivity probe through the `upstream.test` plugin call. The Agent dials
the saved endpoint over Host-managed networking, performs a Shadowsocks TCP
handshake with the locally resolved scoped credential, and reports
reachability, an optional round-trip time, and a stable failure code such as
`upstream-auth-failed`, `upstream-timeout`, `upstream-connection-failed`,
`upstream-protocol-error`, `upstream-unavailable`, `tcp-unsupported`,
`agent-offline`, or `probe-failed`. UDP-only upstreams report
`tcp-unsupported` and disabled upstreams stay testable. The probe never
mutates saved routing, sessions, or listeners, and the request and result
carry only the opaque secret reference, never key material.

The "导出配置" action (`GET /api/routing/export`) downloads the routing
configuration as a JSON document: the ordered rules, the default action,
and each upstream's non-secret fields (id, host, port, method, enabled,
tcp, udp). The file never carries secret references, secret versions, or
key material, so it is safe to keep as a backup or move between
instances. The "导入配置" action (`POST /api/routing/import`) validates
the whole file — document version, field shapes, the 16-upstream and
64-rule limits, and every rule's upstream reference — before replacing
the current configuration through the same `replaceRouting` commit and
per-node apply path. Each imported upstream needs its connection
password re-entered, except that a same-ID existing upstream may reuse
its stored scoped credential when that material still fits the imported
method. A missing or incompatible credential fails with a readable
per-upstream message and leaves the running configuration untouched;
secrets minted for a rejected attempt are revoked, and secrets orphaned
by a successful import are revoked after commit.

Saving routing commits the desired configuration independently of node
availability. A failed or removed node cannot roll back healthy nodes. The
reconciler compares routing digests as well as bound ports and retries pending
nodes. The routing API reports `routing_applied` and `routing_error` for the
requested node; saved configuration alone is not evidence of application.
Consecutive compatible rules use one bounded dataset query while retaining
first-match order and fail-closed behavior. No cross-generation decision cache
can hide revoked dataset access. TCP upstream reads and writes proceed
independently; closing the socket wakes reads before clearing session keys.

When a TCP request names only an IP target, routing may inspect at most 16 KiB
for 250 ms before dialing. It recognizes HTTP/1.0 or HTTP/1.1 `Host` and clear
TLS 1.2/1.3 ClientHello SNI across Shadowsocks chunks and TLS records. The
original domain always wins. The original IP and port are never rewritten, and
all bytes consumed during inspection are replayed exactly. HTTP/2 prior
knowledge, ECH, conflicting or malformed headers, timeout, over-limit input and
server-first protocols use the IP/default route. UDP is never sniffed.
