# AnyTLS / Shadowsocks performance verification

Measured on 2026-11-15. Baseline sources: plugins `76f2bac`, host
`nginx-reverse-emby` `d47a1ba1`. Changes span this plugin and the host's
`go-agent/internal/plugins/network` and `go-agent/internal/plugins/rpc` packages.

## Changes

- AnyTLS transfers ownership of received frames and forwards them through
  `io.WriterTo`, avoiding another payload copy and a 32 KiB copy buffer per
  relay. A 4 KiB session reader coalesces small frames and header reads.
- AnyTLS frame writes and Shadowsocks response/upstream writes borrow sized
  buffers only for the duration of a write. Buffers are cleared before reuse;
  public sealing methods still return independently owned results.
- Host TCP and terminated TLS reads start with at most 4 KiB, grow when full,
  and reset after an empty read. The caller's maximum remains an upper bound;
  UDP packet sizing is unchanged.

## Allocation measurements

Go 1.27.0, Windows amd64, Intel i7-9700F, default GOMAXPROCS=8. Each benchmark
ran three times with `-benchmem`. Frame/response payloads are 32 KiB; host
read benchmarks request 64 KiB and receive a small response. These isolate
allocation costs with in-memory I/O, not TLS encryption or network throughput.

| Benchmark | Before B/op | After B/op | Before allocs/op | After allocs/op |
| --- | ---: | ---: | ---: | ---: |
| AnyTLSWriteFrame | 40,960 | 0 | 1 | 0 |
| AnyTLSReceiveRelay | 98,553 | 33,032 | 7 | 5 |
| ShadowsocksResponseWrite | 40,960 | 0 | 1 | 0 |
| ManagedSmallRead (host) | 66,256 | 4,816 | 13 | 13 |
| TerminatedSmallRead (host) | 65,736 | 4,296 | 7 | 7 |

Zero allocations describes the steady-state benchmark. Pool misses and GC can
still allocate. These values do not represent whole-process resident memory.
Timing was sensitive to concurrent local test work, so it is not used as a
network speedup claim.

```sh
# Plugin repository
GOTOOLCHAIN=go1.27.0 go test ./plugins/shadowsocks-server -run '^$' \
  -bench 'Benchmark(AnyTLS|ShadowsocksResponse)' -benchmem -count=3

# Main repository, from go-agent/
GOTOOLCHAIN=go1.27.0 go test ./internal/plugins/network ./internal/plugins/rpc \
  -run '^$' -bench 'Benchmark(ManagedSmallRead|TerminatedSmallRead)' -benchmem -count=3
```

## Real managed-process capacity

Linux amd64 under WSL Debian, static Go binaries, isolated privileged sandbox.
Both baseline and changed sources passed the existing 3000-connection SS2022
fixture: three bidirectional rounds including an idle-poll rollover, an
11,010,048-byte transfer with SHA-256 verification, new connections after close,
and host socket reclamation. Baseline production sources were supplied through
a Go overlay; the corrected test permissions were identical in both runs.

| Single-run peak RSS | Baseline MiB | Changed MiB |
| --- | ---: | ---: |
| Host | 554.5 | 568.3 |
| Plugin process tree | 408.3 | 408.5 |

This workload did **not** demonstrate lower total RSS. The measurements above
support reduced allocation/copy costs, not an overall memory-reduction
percentage. The capacity fixture is for Shadowsocks; it is not an AnyTLS
capacity or public-network throughput benchmark.

```sh
# Main repository, from go-agent/; run separately from other test suites.
CGO_ENABLED=0 NRE_SS_PLUGIN_ROOT=/path/to/sakullla-plugins NRE_SS_CAPACITY=3000 \
  go test -exec 'sudo -n -E --' -tags=integration,ssplugin -count=1 -timeout=5m \
  -run '^TestIntegrationRealShadowsocksManagedHostProcess$' -v ./internal/plugins/rpc
```

## Test reliability and coverage

- Listener reconciliation uses `testing/synctest` and the real 15-second
  interval. It advances 45 seconds of virtual time instead of changing a
  process-wide variable and spending at least 100 ms in polling/sleeps.
  Controller test cleanup now stops the reconciler.
- AnyTLS fixtures configure dependencies before serving; injected TLS failure
  uses an atomic flag rather than replacing a callback during a connection.
- Host overload coverage waits for all 128 requests to enter a controlled
  redeemer before probing admission. The old concurrent probe could reject a
  fixture request and leave the test waiting for saturation that never occurred.
- SS process fixtures include the public-certificate permissions added for
  AnyTLS. Missing permissions previously prevented the capacity test handshake.
- Windows dual-protocol test ports are selected by UDP first, avoiding the
  observed consecutive TCP allocations inside UDP excluded ranges.
- Regression coverage includes partial reads and short writes, multiplexed
  frame ordering, padding/buffer reuse, every supported Shadowsocks cipher in
  both directions, stream close under backpressure, and host read ownership,
  maximum-size bounds, growth, and reset.

Validation passed: plugin `go test ./...`, `cargo test --workspace --locked`,
the Shadowsocks plugin build/validation command, Linux `-race` for the plugin
and host network/RPC packages, and the managed-process capacity fixture.
The overload and reconciliation regressions also passed ten repeated runs.
The canonical host fast suite from the main repository's `TESTING.md` passed
when run separately from capacity and repository-wide test workloads.

The separate dataset-sniff/IP-policy process suite requires the pinned
`NRE_DATASET_SOURCE_CACHE` and `NRE_IP_POLICY_WASM` fixtures and was not completed
in this run. Release signing, publication, and the committed-candidate `make ci`
release gate are outside this verification.
