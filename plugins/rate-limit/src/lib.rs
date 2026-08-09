#![cfg_attr(target_arch = "wasm32", no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Bounded, node-local GCRA admission logic.
//!
//! Time and atomic mutation are explicit inputs. The production artifact does
//! not derive time from a wall clock or emulate compare-and-swap with StateGet
//! and StatePut when the canonical Host lacks those capabilities.

mod gcra;
mod limiter;

#[cfg(target_arch = "wasm32")]
mod wasm;

pub use gcra::{BucketSpec, ConfigError, GcraState, Preview};
pub use limiter::{
    Admission, AdmissionKind, CounterKey, DecisionReason, LocalLimiter, MonotonicInstant, StableId,
};
