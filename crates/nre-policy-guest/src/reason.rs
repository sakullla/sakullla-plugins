use crate::AbiStatus;

/// Stable, non-sensitive reason codes emitted by guest support operations.
///
/// These are crate-level diagnostics rather than protobuf enum values. Their
/// numeric representation is stable so policy implementations can aggregate
/// failures without persisting request bodies, tokens, keys, or messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReasonCode {
    InvalidWire = 1,
    NonCanonicalWire = 2,
    InvalidUtf8 = 3,
    DuplicateField = 4,
    MissingResult = 5,
    ConflictingResult = 6,
    InputBudgetExceeded = 7,
    OutputBudgetExceeded = 8,
    FieldBudgetExceeded = 9,
    HostCallBudgetExceeded = 10,
    HostResponseBudgetExceeded = 11,
    UnknownHostStatus = 12,
    HostInvalidArgument = 13,
    HostPermissionDenied = 14,
    HostResourceExhausted = 15,
    HostDeadlineExceeded = 16,
    HostUnavailable = 17,
    HostIncompatibleAbi = 18,
    HostInternal = 19,
    InvalidAction = 20,
    InvalidRuntimeError = 21,
    InvalidResourceBudget = 22,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestError {
    pub status: AbiStatus,
    pub reason: ReasonCode,
}

impl GuestError {
    pub const fn new(status: AbiStatus, reason: ReasonCode) -> Self {
        Self { status, reason }
    }
}

impl core::fmt::Display for GuestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "guest error {:?}/{:?}", self.status, self.reason)
    }
}

impl core::error::Error for GuestError {}
