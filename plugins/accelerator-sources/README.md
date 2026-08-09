# Accelerator Sources

This package is a control-plane business model for Docker and GitHub
accelerator sources. It stores only canonical HTTPS source configuration and
host-attested probe status. It generates copyable output and never applies
host configuration, proxies content, resolves DNS, or opens network sockets.

All probing, scheduling, dynamic UI, and audit operations require future
canonical typed public SDK handles. The production entrypoint therefore fails
closed while those handles are absent. The injected adapter interfaces in this
package are process-local business seams for deterministic tests; they are not
a Host RPC or wire contract.

