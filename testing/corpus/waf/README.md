# WAF corpus

Small deterministic fixtures for the supported literal managed-rule subset.
They cover path traversal, injection, XSS, and dangerous request features as
ASCII/substring inputs, not a claim of full OWASP CRS or PCRE compatibility.

`truncated-upload.txt` represents only the shared host body window; bytes after
the marker remain in the upstream request stream and are never consumed by the
guest.
