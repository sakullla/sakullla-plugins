# Cloudflare DNS plugin

This control-plane Go RPC plugin owns domain-suffix to Vault `secret_ref`
mappings and answers which Cloudflare DNS Token a caller should use for a
domain. Query names and configured suffixes are normalized (lowercased, trailing
dot stripped) and the longest matching suffix wins. Callers ask `ResolveToken`
with the involved domain and an optional per-call fallback Token; a mapping hit
never falls back, and a miss with no fallback fails as that domain having no
available Token.

Token material is written once into the host Vault on create or rotate and is
not stored in plugin state. Lists, status, errors, UI projections, and audit
records expose only suffixes and metadata.

The plugin serves a dedicated mapping page for authorized administrators to
create, rename, rotate, and delete suffix mappings. Unauthorized callers
receive an explicit denial instead of a blank page, write controls are hidden
without enroll/rotate permission, and saved Token values are never prefilled.
Delete and rotate require an object confirmation; cancel leaves state unchanged.
Each write mints a unique operation key so a second rotate stores the new Token
instead of replaying the previous Vault outcome. The last successful save is
reloaded when the service is reconstructed or a new generation activates
against the same Vault catalog. The host may mount this page; this plugin does
not declare `ui.schema.json`.

The plugin declares `ui.route` and `resource.group` in `plugin.yaml`. The host
mounts the page at `/panel-api/plugins/<ui_route_id>/` and lists the resource
group from `resource_group_id` plus `resource.group.*` metadata. Instance
`resource_group_ref` must match `resource.group.ref`.

Production activation uses the SDK host-runtime client. Vault writes, durable
operation outcomes, instance state, and audit events stay in generic host
capabilities; Cloudflare request and response semantics stay in this plugin.
Secret-backed HTTP is restricted by the granted `http.outbound` resource to
`api.cloudflare.com`.

Cloudflare list operations consume all validated result pages within the plugin
bounds. DNS mutations forward stable operation IDs to the durable host journal;
404 delete is idempotent, while timeouts, 5xx responses, and malformed success
responses remain inspectable as unknown instead of being repeated. The token
verification endpoint confirms that a token is active and zone listing confirms
Zone read access. Cloudflare does not return token policy permissions from that
endpoint, so `DNS:Edit` is the plugin's required policy and Cloudflare remains
the authority on every write request.
