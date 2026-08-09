# nre-policy-guest

`no_std` support for guests implementing the canonical `nre:policy/v1`
WebAssembly ABI. The crate provides bounded protobuf cursors and encoders,
fixed-size Host-call buffers, call/resource budgets, and stable action, status,
error, and reason types.

ABI names, import/export strings, protobuf field numbers, enum values, and
resource ceilings live only in `src/abi_generated.rs`. That file is generated
from the public Go SDK's `pluginsdk` contract and canonical `protoschema`
descriptor. It must not be edited independently. The repository SDK drift
generator owns refreshes when the pinned upstream SDK changes.

The library has no allocator, filesystem, network, clock, random, WASI, or host
implementation dependency. On `wasm32`, `WasmHost` binds only the six canonical
Host imports. Native tests inject a `HostTransport` fake.
