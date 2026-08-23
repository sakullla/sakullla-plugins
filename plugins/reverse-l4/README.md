# Reverse L4 plugin

A control-plane management plugin for reverse layer-4 tunnel mappings. One
mapping publishes an internal TCP or UDP service through two host-owned
effects:

- the entry side is an ordinary host L4 rule on the publicly reachable entry
  agent (created through the generic `l4.rule` host capability), so mappings
  inherit host L4 features and appear in the host rule list with plugin
  attribution;
- the exit side is a host-managed reverse channel (generic `channel.reverse`
  capability): the outbound-only exit agent dials the entry agent, traffic
  accepted by the rule is bridged back over that channel, and the exit agent
  forwards it to the mapping backend. Identity and encryption are enforced by
  the host PKI; there is no plaintext or unauthenticated option.

The plugin owns only the mapping catalog and its orchestration. Mapping
records live in durable plugin state (`state.get`/`state.put`), are created
from the management page with zero plugin configuration, and every mutation
drives the host effects with idempotent operation ids derived from the mapping
revision, so retries converge without orphan rules or channels. Disabling a
mapping disables its rule and tears the channel down but keeps the record;
enabling re-ensures the channel and re-points the rule; deleting removes all
of them. A mapping may optionally reference user-managed relay listeners to
route the channel through a relay chain; without a reference the exit agent
dials the entry agent directly.

## Management page

The plugin declares the generic `ui.route` extension point with `ui.nav`
metadata, so an installed and enabled plugin gets a panel navigation entry
mounted at `/panel-api/plugins/reverse-l4/`. The page is served from canonical
`assets/` paths by the plugin process itself on the host-provisioned private
UI endpoint and carries the full mapping lifecycle: create, update, enable,
disable, and confirmed delete. Every card lists the entry agent, exit agent,
protocol, listen port, enabled state, and the live reverse-channel
connectivity projected from the host (`online`, `offline`, or `unknown`), so an
offline exit side is distinguishable at a glance. Management RPC calls are
authenticated by the actor / resource-group / operation-key headers the panel
injects; calls without an actor identity are rejected.
