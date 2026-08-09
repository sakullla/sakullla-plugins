# Cloudflare DNS plugin

This control-plane Go RPC plugin owns only Cloudflare DNS workflow state and UI
projection. Token material remains in the host Vault and DNS operations are
performed only by a zone-scoped broker handle after actor, resource-group,
secret-version, permission, and zone authorization is revalidated.

The current public SDK does not publish those typed handles, so production
activation fails closed. Injectable adapters exist only for deterministic
business tests and do not define a Host wire protocol.
