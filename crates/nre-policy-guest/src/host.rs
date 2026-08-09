use crate::abi_generated::{self, field};
use crate::{
    AbiStatus, BytesResponse, FrameWriter, GuestError, ReasonCode, WireLimits, unpack_host_result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostImport {
    ReadField,
    ReadBodyWindow,
    StateGet,
    StatePut,
    EmitEvent,
    AddMetric,
}

impl HostImport {
    pub const fn module(self) -> &'static str {
        abi_generated::HOST_MODULE
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadField => abi_generated::HOST_READ_FIELD,
            Self::ReadBodyWindow => abi_generated::HOST_READ_BODY_WINDOW,
            Self::StateGet => abi_generated::HOST_STATE_GET,
            Self::StatePut => abi_generated::HOST_STATE_PUT,
            Self::EmitEvent => abi_generated::HOST_EMIT_EVENT,
            Self::AddMetric => abi_generated::HOST_ADD_METRIC,
        }
    }
}

/// Injectable transport for the canonical four-pointer Host-call convention.
pub trait HostTransport {
    fn call(&mut self, import: HostImport, request: &[u8], response: &mut [u8]) -> u64;
}

#[cfg(target_arch = "wasm32")]
#[derive(Default)]
pub struct WasmHost;

#[cfg(target_arch = "wasm32")]
impl HostTransport for WasmHost {
    fn call(&mut self, import: HostImport, request: &[u8], response: &mut [u8]) -> u64 {
        let request_ptr = request.as_ptr() as u32;
        let request_len = request.len() as u32;
        let response_ptr = response.as_mut_ptr() as u32;
        let response_capacity = response.len() as u32;
        // SAFETY: the canonical Host ABI reads only the request range and writes
        // at most response_capacity bytes to the caller-owned response range.
        unsafe {
            match import {
                HostImport::ReadField => abi_generated::nre_host_read_field(
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_capacity,
                ),
                HostImport::ReadBodyWindow => abi_generated::nre_host_read_body_window(
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_capacity,
                ),
                HostImport::StateGet => abi_generated::nre_host_state_get(
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_capacity,
                ),
                HostImport::StatePut => abi_generated::nre_host_state_put(
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_capacity,
                ),
                HostImport::EmitEvent => abi_generated::nre_host_emit_event(
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_capacity,
                ),
                HostImport::AddMetric => abi_generated::nre_host_add_metric(
                    request_ptr,
                    request_len,
                    response_ptr,
                    response_capacity,
                ),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostLimits {
    pub max_calls: u16,
    pub initial_response_bytes: usize,
    pub response_wire: WireLimits,
}

impl HostLimits {
    pub const fn new(max_calls: u16, initial_response_bytes: usize) -> Self {
        Self {
            max_calls,
            initial_response_bytes,
            response_wire: WireLimits::POLICY_OUTPUT,
        }
    }
}

/// Host-call facade with compile-time fixed request and response buffers.
pub struct HostClient<H, const REQUEST_BYTES: usize, const RESPONSE_BYTES: usize> {
    transport: H,
    request: [u8; REQUEST_BYTES],
    response: [u8; RESPONSE_BYTES],
    limits: HostLimits,
    calls: u16,
}

impl<H, const REQUEST_BYTES: usize, const RESPONSE_BYTES: usize>
    HostClient<H, REQUEST_BYTES, RESPONSE_BYTES>
where
    H: HostTransport,
{
    pub fn new(transport: H, limits: HostLimits) -> Result<Self, GuestError> {
        if REQUEST_BYTES == 0
            || RESPONSE_BYTES == 0
            || REQUEST_BYTES > abi_generated::MAX_INPUT_FRAME_BYTES
            || RESPONSE_BYTES > abi_generated::MAX_OUTPUT_FRAME_BYTES
            || limits.max_calls == 0
            || limits.initial_response_bytes == 0
            || limits.initial_response_bytes > RESPONSE_BYTES
            || RESPONSE_BYTES > limits.response_wire.max_frame_bytes
        {
            return Err(GuestError::new(
                AbiStatus::InvalidArgument,
                ReasonCode::InvalidResourceBudget,
            ));
        }
        Ok(Self {
            transport,
            request: [0; REQUEST_BYTES],
            response: [0; RESPONSE_BYTES],
            limits,
            calls: 0,
        })
    }

    pub const fn calls_used(&self) -> u16 {
        self.calls
    }

    pub fn into_transport(self) -> H {
        self.transport
    }

    pub fn read_field(&mut self, name: &str) -> Result<BytesResponse<'_>, GuestError> {
        let length = encode_one_string(&mut self.request, field::read_field_request::NAME, name)?;
        let response_length = self.invoke(HostImport::ReadField, length)?;
        BytesResponse::decode(&self.response[..response_length], self.limits.response_wire)
    }

    pub fn read_body_window(
        &mut self,
        offset: u32,
        length: u32,
    ) -> Result<BytesResponse<'_>, GuestError> {
        let mut writer = FrameWriter::new(&mut self.request);
        writer.write_varint_field(field::read_body_window_request::OFFSET, offset as u64)?;
        writer.write_varint_field(field::read_body_window_request::LENGTH, length as u64)?;
        let request_length = writer.len();
        let response_length = self.invoke(HostImport::ReadBodyWindow, request_length)?;
        BytesResponse::decode(&self.response[..response_length], self.limits.response_wire)
    }

    pub fn state_get(&mut self, key: &str) -> Result<BytesResponse<'_>, GuestError> {
        let length = encode_one_string(&mut self.request, field::state_get_request::KEY, key)?;
        let response_length = self.invoke(HostImport::StateGet, length)?;
        BytesResponse::decode(&self.response[..response_length], self.limits.response_wire)
    }

    pub fn state_put(&mut self, key: &str, value: &[u8]) -> Result<(), GuestError> {
        let mut writer = FrameWriter::new(&mut self.request);
        writer.write_string_field(field::state_put_request::KEY, key)?;
        writer.write_bytes_field(field::state_put_request::VALUE, value)?;
        let request_length = writer.len();
        self.invoke_empty(HostImport::StatePut, request_length)
    }

    pub fn emit_event(&mut self, kind: &str, payload: &[u8]) -> Result<(), GuestError> {
        let mut writer = FrameWriter::new(&mut self.request);
        writer.write_string_field(field::emit_event_request::KIND, kind)?;
        writer.write_bytes_field(field::emit_event_request::PAYLOAD, payload)?;
        let request_length = writer.len();
        self.invoke_empty(HostImport::EmitEvent, request_length)
    }

    pub fn add_metric(&mut self, name: &str, delta: i64) -> Result<(), GuestError> {
        let mut writer = FrameWriter::new(&mut self.request);
        writer.write_string_field(field::add_metric_request::NAME, name)?;
        writer.write_sint64_field(field::add_metric_request::DELTA, delta)?;
        let request_length = writer.len();
        self.invoke_empty(HostImport::AddMetric, request_length)
    }

    fn invoke_empty(
        &mut self,
        import: HostImport,
        request_length: usize,
    ) -> Result<(), GuestError> {
        let response_length = self.invoke(import, request_length)?;
        if response_length != 0 {
            return Err(GuestError::new(
                AbiStatus::InvalidArgument,
                ReasonCode::InvalidWire,
            ));
        }
        Ok(())
    }

    fn invoke(&mut self, import: HostImport, request_length: usize) -> Result<usize, GuestError> {
        let first_capacity = self.limits.initial_response_bytes;
        let (mut status, mut length) = self.call_once(import, request_length, first_capacity)?;
        if status == AbiStatus::ResourceExhausted && length as usize > first_capacity {
            let required = length as usize;
            if required > RESPONSE_BYTES || required > self.limits.response_wire.max_frame_bytes {
                return Err(GuestError::new(
                    AbiStatus::ResourceExhausted,
                    ReasonCode::HostResponseBudgetExceeded,
                ));
            }
            (status, length) = self.call_once(import, request_length, required)?;
        }
        if status != AbiStatus::Ok {
            return Err(host_status_error(status));
        }
        let written = length as usize;
        if written > RESPONSE_BYTES {
            return Err(GuestError::new(
                AbiStatus::ResourceExhausted,
                ReasonCode::HostResponseBudgetExceeded,
            ));
        }
        Ok(written)
    }

    fn call_once(
        &mut self,
        import: HostImport,
        request_length: usize,
        response_capacity: usize,
    ) -> Result<(AbiStatus, u32), GuestError> {
        if self.calls >= self.limits.max_calls {
            return Err(GuestError::new(
                AbiStatus::ResourceExhausted,
                ReasonCode::HostCallBudgetExceeded,
            ));
        }
        self.calls += 1;
        let packed = self.transport.call(
            import,
            &self.request[..request_length],
            &mut self.response[..response_capacity],
        );
        let (status, length) = unpack_host_result(packed)?;
        if status == AbiStatus::Ok && length as usize > response_capacity {
            return Err(GuestError::new(
                AbiStatus::ResourceExhausted,
                ReasonCode::HostResponseBudgetExceeded,
            ));
        }
        Ok((status, length))
    }
}

fn encode_one_string(buffer: &mut [u8], field: u32, value: &str) -> Result<usize, GuestError> {
    let mut writer = FrameWriter::new(buffer);
    writer.write_string_field(field, value)?;
    Ok(writer.len())
}

const fn host_status_error(status: AbiStatus) -> GuestError {
    let reason = match status {
        AbiStatus::Ok => ReasonCode::HostInternal,
        AbiStatus::InvalidArgument => ReasonCode::HostInvalidArgument,
        AbiStatus::PermissionDenied => ReasonCode::HostPermissionDenied,
        AbiStatus::ResourceExhausted => ReasonCode::HostResourceExhausted,
        AbiStatus::DeadlineExceeded => ReasonCode::HostDeadlineExceeded,
        AbiStatus::Unavailable => ReasonCode::HostUnavailable,
        AbiStatus::IncompatibleAbi => ReasonCode::HostIncompatibleAbi,
        AbiStatus::Internal => ReasonCode::HostInternal,
    };
    GuestError::new(status, reason)
}
