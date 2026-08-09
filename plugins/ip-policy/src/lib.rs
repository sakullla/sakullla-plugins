#![cfg_attr(target_arch = "wasm32", no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Allocation-free HTTP/L4 IP policy engine.
//!
//! Trusted connection provenance and MMDB results are Host-owned inputs. Raw
//! forwarded headers and GeoLite databases are deliberately outside this crate.

mod geo;
mod policy;
mod trie;

#[cfg(target_arch = "wasm32")]
mod wasm;

pub use geo::{GeoFailurePolicy, GeoHandle, GeoLookup, GeoProvider, GeoRecord, GeoRule, GeoStatus};
pub use policy::{
    Decision, DecisionReason, IpPolicy, RuleEffect, SourceAuthentication, TrustedSource,
};
pub use trie::{Cidr, ConfigError, IpAddress, PolicySet};
