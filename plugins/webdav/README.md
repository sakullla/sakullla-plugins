# 文件共享 (webdav)

WebDAV is an Agent-scoped HTTP backend provider. The `default` provider is
published on the Host-owned ingress domain. The plugin does not declare
`ui.route` or `resource.group`.

The Host owns the private provider socket, generation credential, readiness
checks, request authority, and the public HTTP+TLS listener. The plugin
serves generation-local HTTP after Activate and returns 503 after Stop.

The default share root is an instance-owned `share/` directory, not the Agent
filesystem root. Close and Stop do not delete files in that directory.
