# Sakullla WAF

Official dual-face package: a control-plane `rpc-service` dedicated management page (`ui.route`) plus a nested Agent `nre:policy/v1` wasm policy (`http.request`). Operators install one plugin. The host auto-attaches that policy instance to HTTP entries; the management page is the only operator path.

The wasm guest defaults to observe. A host evaluate overlay of `{"mode":"observe"}` or `{"mode":"deny"}` overrides that mode when present; missing overlay keeps the instance default. Managed rules are compiled at build time into deterministic bounded bytecode covering path traversal, injection, XSS, and dangerous request features. Custom rules use literal ASCII matching only; this release does not claim complete OWASP CRS or PCRE compatibility.

The guest consumes host-normalized HTTP fields and the shared bounded body window. It never reads the request stream. Missing trusted-source capability and truncated/unavailable body windows produce stable visible reasons. Events expose the existing SDK's site, rule, source digest, disposition and reason fields.

## Management workflow

- **防护概览** shows configured coverage and counts within the recent records returned by the existing SDK. It does not claim full-history statistics or collection health.
- **安全事件** searches and pages those returned records. Existing event data does not include time or request path. A confirmed false positive can prefill the rule ID; the operator must enter the exact path prefix.
- **防护策略** lists compiled literal checks, custom rules, and exclusions. Removing a custom rule also removes its associated exclusions.
- **防护范围** controls each HTTP entry. Detection records matches while allowing requests; blocking rejects matching requests. Bulk changes affect only the selected node and preserve the instance default.

This plugin uses the public SDK's existing HTTP catalog, instance configuration and event-list capabilities. It does not require host-specific WAF routes, tables, heartbeat fields or retention jobs. Pagination is bounded by the records the existing host API returns; it cannot retrieve older records outside that window. No new audit store, event reporting pipeline or cleanup worker is introduced.

## Ownership and uninstall

The manifest declares instances, config, owned_data and grants as delete. Configuration uses host-managed instance storage. Stopping a generation revokes its UI handle and releases in-memory configuration; the generic host uninstall path owns deletion of the plugin's instance data and grants. This UI introduces no external files or background workers.

Any future plugin-owned persistence must use managed plugin storage, and any worker must be bound to the plugin generation's stop/drain lifecycle. Its uninstall tests must cover stopping work and removing owned data. Shared platform resources and platform audit history remain governed by the host's existing policy; the plugin must not delete another owner's data.

## UI verification

Run `node --test plugins/waf/testing/ui/agents.test.mjs` and `node plugins/waf/testing/ui/run.mjs` from the repository root. The browser runner uses an isolated headless Chromium/Chrome/Edge profile and fixture APIs, and writes screenshots under `dist/waf-ui-validation/`. Set `NRE_UI_BROWSER` if the browser is not in a standard location.
