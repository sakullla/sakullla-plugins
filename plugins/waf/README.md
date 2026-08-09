# Sakullla WAF

Native `nre:policy/v1` no-std WAF. Managed rules are compiled at build time into deterministic bounded bytecode. Custom rules use literal ASCII matching only; this release does not claim complete OWASP CRS or PCRE compatibility.

The guest consumes host-normalized HTTP fields and the shared bounded body window. It never reads the request stream. Missing trusted-source capability and truncated/unavailable body windows produce stable visible reasons. Events contain only site, rule, source digest, and disposition—never request or body content.
