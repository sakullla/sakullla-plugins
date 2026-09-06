# IP policy and Shadowsocks candidate verification

`verify-candidate.ps1` verifies the exact clean plugin and Host commits printed
at startup. It requires Linux or Windows x64 and a working Docker daemon.
Missing tools, processes, pinned source data, or test dependencies fail the
selected suite. `-DatasetCache` optionally selects the persistent download
cache; its default is `$env:TEMP/nre-dataset-source-cache`. Missing files are
downloaded from the Host test's fixed URLs, while every downloaded or reused
file is checked for size and SHA-256. The e2e suite prepares `dlc.dat` and
`loyalsoldier-geoip.dat`; the performance suite prepares all seven sources.

The `e2e` suite first builds the official IP policy WASM candidate. Focused
plugin tests cover fresh IP installation, province policy, dataset failure
retention, direct and upstream TCP/UDP, bounded HTTP/TLS domain sniffing,
credential migration, rotation and revocation. It then runs the exact combined
Host process test with the built IP artifact, pinned GeoSite/GeoIP indexes, two
real Shadowsocks processes, managed admission and observable direct/upstream
TCP exits. On Linux, `plugins-ci` delegates to `make ci`. On Windows it runs the
same SDK, Go, Rust, reproducibility and repository checks, using the small
`build-artifacts.ps1` equivalent of the Makefile's three artifact builds.
`host-ci` runs local Go/frontend checks and the Host image build on both systems;
on Windows its Linux integration tier runs in the pinned Docker image.

`performance` first runs the Host's pinned seven-source import/index integration
against the required cache. It then enables performance sampling in that same
combined Host/IP/SS workload. The wrapper requires and emits the workload's 20
raw latency samples, throughput, p95, p99 and actual plugin-process RSS; the Host
test enforces its RSS bound. Docker tests use the pinned Go 1.27.0 trixie image
and privileged sandbox support required by the real Host process fixture.
