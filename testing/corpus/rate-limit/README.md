# Rate-limit corpus

The cases are repository-authored deterministic contract fixtures derived from
the T05 requirements. They do not contain production traffic or identifiers.
Each JSON document declares the admission kind, monotonic timestamps, bounded
bucket configuration, and stable expected reason/action.

- `http-source-limit.json`: a source bucket denies independently with HTTP 429.
- `http-global-limit.json`: distinct sources share the rule-global bucket.
- `l4-existing-session.json`: an established session never consumes admission.
- `l4-new-connection.json`: only a new connection consumes L4 source capacity.
- `generation-reset.json`: a new generation cannot reuse old counter state.
- `capabilities-unavailable.json`: missing monotonic clock or atomic state blocks activation.

All identifiers are opaque stable test values. Durations are nanoseconds from a
Host monotonic clock, never wall-clock timestamps.
