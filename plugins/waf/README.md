# Sakullla WAF

Native `nre:policy/v1` no-std WAF. Instance config and the uninitialized guest default to observe. A host evaluate overlay of `{"mode":"observe"}` or `{"mode":"deny"}` overrides that mode when present; missing overlay keeps the instance default. Managed rules are compiled at build time into deterministic bounded bytecode covering path traversal, injection, XSS, and dangerous request features. Custom rules use literal ASCII matching only; this release does not claim complete OWASP CRS or PCRE compatibility.

The guest consumes host-normalized HTTP fields and the shared bounded body window. It never reads the request stream. Missing trusted-source capability and truncated/unavailable body windows produce stable visible reasons. Events contain only site, rule, source digest, and disposition—never request or body content.
