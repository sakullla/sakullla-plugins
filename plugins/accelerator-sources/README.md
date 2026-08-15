# Accelerator Sources

Accelerator Sources is an Agent-scoped, zero-configuration HTTP backend
provider. The `default` provider serves Docker Registry-compatible endpoints,
Docker Hub catalog and offline image export APIs, GitHub and Hugging Face
proxies, script rewriting, and the embedded web interface.

The plugin runs entirely in its own process. The Host owns the private provider
socket, generation credential, readiness checks, and request authority. The
plugin owns generation-local DNS, token and manifest caches, upstream
connection pools, and closes them after the Host drains the generation.

All upstream access uses the shared in-process upstream manager. No Docker
daemon, container runtime, virtual machine, database, sidecar, or external
helper application is required.
