# IP policy and Shadowsocks candidate verification

`verify-candidate.ps1` verifies the exact clean plugin and Host commits printed
at startup. It requires Linux amd64 and a working Docker daemon. Missing tools,
processes, pinned source data, or test dependencies fail the selected suite.
Set `NRE_DATASET_SOURCE_CACHE` to a local directory containing the pinned source
files. The e2e suite requires `dlc.dat` and `loyalsoldier-geoip.dat`; the
performance suite requires all seven files selected by the Host source test.

The `e2e` suite first builds the official IP policy WASM candidate. Focused
plugin tests cover fresh IP installation, province policy, dataset failure
retention, direct and upstream TCP/UDP, bounded HTTP/TLS domain sniffing,
credential migration, rotation and revocation. It then runs the exact combined
Host process test with the built IP artifact, pinned GeoSite/GeoIP indexes, two
real Shadowsocks processes, managed admission and observable direct/upstream
TCP exits. `plugins-ci` and `host-ci` delegate to the repositories' canonical CI
and `TESTING.md` commands.

`performance` first runs the Host's pinned seven-source import/index integration
against the required cache. It then enables performance sampling in that same
combined Host/IP/SS workload. The wrapper requires and emits the workload's 20
raw latency samples, throughput, p95, p99 and actual plugin-process RSS; the Host
test enforces its RSS bound. Docker tests use the pinned Go 1.27.0 trixie image
and privileged sandbox support required by the real Host process fixture.
