# nre-ci prewarm performance

Date: 2026-08-22

## Scope and measurement method

This report covers only the two local commands named by the performance requirement:

```text
go run ./cmd/nre-ci reproducible --output target/nre-ci/ip-policy/plugin.wasm -- go run ./cmd/nre-ci plugin --id ip-policy
go run ./cmd/nre-ci sdk --require-host-capabilities
```

Wall-clock time is measured around the complete command process in PowerShell with
`System.Diagnostics.Stopwatch`. A sample is valid only when the command exits with
status 0. The prewarm acceptance sequence is one successful, unmeasured warmup
followed by three unchanged invocations of the original command. The 10-second
target applies to each of those three samples, not to cold starts.

## Measurement host

- OS: Microsoft Windows 11 Pro, version 10.0.26200, build 26200, 64-bit
- Machine: System manufacturer / System Product Name
- CPU: Intel Core i7-9700F at 3.00 GHz, 8 cores / 8 logical processors
- Memory: 34,291,494,912 bytes (approximately 31.9 GiB)
- Go: `go1.27.0 windows/amd64`
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`

## Baseline before optimization

The baseline was captured against the pre-optimization implementation. That
implementation made two source copies with separate Go and Cargo build caches for
the reproducibility command and performed the complete SDK verification on every
invocation.

| Command | Exit status | Wall-clock |
| --- | ---: | ---: |
| IP Policy reproducible build | 0 | 290.696 s |
| SDK capability verification | 0 | 64.937 s |

## Optimized prewarm results

Pending implementation and the required successful warmup plus three measured
invocations for each command.

## Interpretation and exclusions

The acceptance result will describe local prewarmed execution only. It does not
make a 10-second claim for cold dependency downloads, an empty toolchain cache,
deleted reusable resources, other plugins or subcommands, repository-wide builds,
or plugin runtime throughput and latency.
