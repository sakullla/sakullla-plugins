# 文件共享 (webdav)

WebDAV is an Agent-scoped HTTP backend provider. The `default` provider is
published on the Host-owned ingress domain. The plugin does not declare
`ui.route` or `resource.group`.

The Host owns the private provider socket, generation credential, readiness
checks, request authority, and the public HTTP+TLS listener. The plugin
serves generation-local HTTP after Activate and returns 503 after Stop.

A shared `password` is required at Prepare. Page, file API, and `/dav/`
requests accept either HTTP Basic or `Authorization: Bearer <password>`.
Every valid Basic username selects its own automatically created directory;
this includes the conventional `webdav` username. Bearer has no user identity
and accesses the configured shared root. Missing or empty passwords fail
Prepare, so the ingress does not list files.

The default share root is an instance-owned `share/` directory, not the Agent
filesystem root. An absolute `root_path` switches the share to that directory.
Close and Stop do not delete files in either location. Webpage APIs and
WebDAV both resolve paths inside the authenticated request root and reject
escapes, including attempts by one Basic user to reach another namespace.
The manifest scopes `storage.write` to `config-path:/root_path`; a compatible
Agent resolves that JSON Pointer and mounts only the configured Host directory
into the sandbox at the same absolute path.
