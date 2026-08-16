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

Existing zone-scoped DNS record adapters remain for injected test brokers. They
are not the product face of this plugin.

The current public SDK does not publish typed host handles, so production
activation fails closed. Injectable adapters exist only for deterministic
business tests and do not define a Host wire protocol.
