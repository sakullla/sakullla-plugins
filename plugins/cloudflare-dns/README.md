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

Existing zone-scoped DNS record adapters remain for injected test brokers. They
are not the product face of this plugin.

The current public SDK does not publish typed host handles, so production
activation fails closed. Injectable adapters exist only for deterministic
business tests and do not define a Host wire protocol.
