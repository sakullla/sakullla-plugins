#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Bounded guest-side support for the canonical `nre:policy/v1` ABI.
//!
//! This crate intentionally contains no allocator-backed state. Callers select
//! all frame and Host-response capacities with const generics, while runtime
//! budgets cap fields, Host calls, and the first response attempt.

mod abi_generated;
mod budget;
mod host;
mod message;
mod reason;
mod wire;

pub use abi_generated::{
    ABI_MAJOR_VERSION, AbiStatus, CANONICAL_DESCRIPTOR_SET_SHA256, EXPORT_ALLOCATE,
    EXPORT_EVALUATE, EXPORT_FREE, EXPORT_INIT, EXPORT_MEMORY, EXPORT_RESET, EXPORT_VERSION,
    POLICY_ABI_V1, PolicyAction, RuntimeErrorCode,
};
pub use budget::{BudgetDimension, PolicyResourceBudget, WireLimits};
#[cfg(target_arch = "wasm32")]
pub use host::WasmHost;
pub use host::{HostClient, HostImport, HostLimits, HostTransport};
pub use message::{
    BytesResponse, EvaluateRequest, GrantedScopes, InitRequest, encode_evaluate_error,
    encode_evaluate_success,
};
pub use reason::{GuestError, ReasonCode};
pub use wire::{Field, FieldValue, FrameWriter, WireCursor, WireType};

/// Pack the guest-owned evaluate response allocation as required by the ABI.
#[inline]
pub const fn pack_policy_buffer(pointer: u32, length: u32) -> u64 {
    ((pointer as u64) << 32) | length as u64
}

/// Unpack the guest-owned evaluate response allocation.
#[inline]
pub const fn unpack_policy_buffer(value: u64) -> (u32, u32) {
    ((value >> 32) as u32, value as u32)
}

/// Pack a Host status and written/required response length.
#[inline]
pub const fn pack_host_result(status: AbiStatus, length: u32) -> u64 {
    ((status as u64) << 32) | length as u64
}

/// Unpack a raw Host result without accepting an unknown status value.
#[inline]
pub fn unpack_host_result(value: u64) -> Result<(AbiStatus, u32), GuestError> {
    let raw = (value >> 32) as u32;
    match AbiStatus::from_u32(raw) {
        Some(status) => Ok((status, value as u32)),
        None => Err(GuestError::new(
            AbiStatus::Internal,
            ReasonCode::UnknownHostStatus,
        )),
    }
}
