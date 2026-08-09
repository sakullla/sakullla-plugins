use crate::abi_generated;
use crate::{AbiStatus, GuestError, ReasonCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetDimension {
    Input,
    Output,
    Memory,
    Concurrency,
    Deadline,
    State,
}

impl BudgetDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Input => abi_generated::BUDGET_INPUT,
            Self::Output => abi_generated::BUDGET_OUTPUT,
            Self::Memory => abi_generated::BUDGET_MEMORY,
            Self::Concurrency => abi_generated::BUDGET_CONCURRENCY,
            Self::Deadline => abi_generated::BUDGET_DEADLINE,
            Self::State => abi_generated::BUDGET_STATE,
        }
    }
}

/// Canonical manifest admission budget for `nre:policy/v1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyResourceBudget {
    pub timeout_milliseconds: u32,
    pub memory_bytes: u64,
    pub concurrency: u32,
    pub input_frame_bytes: usize,
    pub output_frame_bytes: usize,
}

impl PolicyResourceBudget {
    pub const fn validate(self) -> Result<Self, GuestError> {
        if self.timeout_milliseconds == 0
            || self.timeout_milliseconds > abi_generated::MAX_TIMEOUT_MILLISECONDS
            || self.memory_bytes < abi_generated::MIN_MEMORY_BYTES
            || self.memory_bytes > abi_generated::MAX_MEMORY_BYTES
            || self.concurrency == 0
            || self.concurrency > abi_generated::MAX_CONCURRENCY
            || self.input_frame_bytes < abi_generated::MIN_INPUT_FRAME_BYTES
            || self.input_frame_bytes > abi_generated::MAX_INPUT_FRAME_BYTES
            || self.output_frame_bytes < abi_generated::MIN_OUTPUT_FRAME_BYTES
            || self.output_frame_bytes > abi_generated::MAX_OUTPUT_FRAME_BYTES
        {
            return Err(GuestError::new(
                AbiStatus::InvalidArgument,
                ReasonCode::InvalidResourceBudget,
            ));
        }
        Ok(self)
    }
}

/// Limits one protobuf cursor independently of its backing storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireLimits {
    pub max_frame_bytes: usize,
    pub max_fields: u16,
}

impl WireLimits {
    pub const POLICY_INPUT: Self = Self {
        max_frame_bytes: abi_generated::MAX_INPUT_FRAME_BYTES,
        max_fields: 256,
    };
    pub const POLICY_OUTPUT: Self = Self {
        max_frame_bytes: abi_generated::MAX_OUTPUT_FRAME_BYTES,
        max_fields: 64,
    };

    pub const fn new(max_frame_bytes: usize, max_fields: u16) -> Self {
        Self {
            max_frame_bytes,
            max_fields,
        }
    }
}
