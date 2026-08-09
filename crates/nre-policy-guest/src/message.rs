use crate::abi_generated::field;
use crate::wire::{bytes_field_len, invalid_wire, varint_field_len};
use crate::{
    AbiStatus, FieldValue, FrameWriter, GuestError, PolicyAction, ReasonCode, RuntimeErrorCode,
    WireCursor, WireLimits,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluateRequest<'a> {
    pub extension_point: &'a str,
    pub request_id: &'a str,
    pub payload: &'a [u8],
}

impl<'a> EvaluateRequest<'a> {
    pub fn decode(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        let mut cursor = WireCursor::new(frame, limits)?;
        let mut extension_point = None;
        let mut request_id = None;
        let mut payload = None;
        while let Some(current) = cursor.next_field()? {
            match current.number {
                field::evaluate_request::EXTENSION_POINT => {
                    set_once(&mut extension_point, as_str(current.value)?)?
                }
                field::evaluate_request::REQUEST_ID => {
                    set_once(&mut request_id, as_str(current.value)?)?
                }
                field::evaluate_request::PAYLOAD => {
                    set_once(&mut payload, as_bytes(current.value)?)?
                }
                _ => {}
            }
        }
        Ok(Self {
            extension_point: extension_point.unwrap_or(""),
            request_id: request_id.unwrap_or(""),
            payload: payload.unwrap_or(&[]),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitRequest<'a> {
    pub config: &'a [u8],
    pub granted_scopes: GrantedScopes<'a>,
    pub generation: &'a str,
}

impl<'a> InitRequest<'a> {
    pub fn decode(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        let mut cursor = WireCursor::new(frame, limits)?;
        let mut config = None;
        let mut generation = None;
        while let Some(current) = cursor.next_field()? {
            match current.number {
                field::init_request::CONFIG => set_once(&mut config, as_bytes(current.value)?)?,
                field::init_request::GRANTED_SCOPES => {
                    let _ = as_str(current.value)?;
                }
                field::init_request::GENERATION => {
                    set_once(&mut generation, as_str(current.value)?)?
                }
                _ => {}
            }
        }
        Ok(Self {
            config: config.unwrap_or(&[]),
            granted_scopes: GrantedScopes::new(frame, limits),
            generation: generation.unwrap_or(""),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantedScopes<'a> {
    frame: &'a [u8],
    limits: WireLimits,
}

impl<'a> GrantedScopes<'a> {
    const fn new(frame: &'a [u8], limits: WireLimits) -> Self {
        Self { frame, limits }
    }

    pub fn iter(self) -> GrantedScopesIter<'a> {
        GrantedScopesIter {
            cursor: WireCursor::new(self.frame, self.limits).ok(),
            failed: false,
        }
    }

    pub fn contains(self, expected: &str) -> Result<bool, GuestError> {
        for scope in self.iter() {
            if scope? == expected {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub struct GrantedScopesIter<'a> {
    cursor: Option<WireCursor<'a>>,
    failed: bool,
}

impl<'a> Iterator for GrantedScopesIter<'a> {
    type Item = Result<&'a str, GuestError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let cursor = self.cursor.as_mut()?;
        loop {
            match cursor.next_field() {
                Ok(Some(current)) if current.number == field::init_request::GRANTED_SCOPES => {
                    return Some(as_str(current.value));
                }
                Ok(Some(_)) => {}
                Ok(None) => return None,
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BytesResponse<'a> {
    pub value: &'a [u8],
    pub found: bool,
}

impl<'a> BytesResponse<'a> {
    pub fn decode(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        let mut cursor = WireCursor::new(frame, limits)?;
        let mut value = None;
        let mut found = None;
        while let Some(current) = cursor.next_field()? {
            match current.number {
                field::bytes_response::VALUE => set_once(&mut value, as_bytes(current.value)?)?,
                field::bytes_response::FOUND => {
                    let raw = as_varint(current.value)?;
                    if raw > 1 {
                        return Err(invalid_wire());
                    }
                    set_once(&mut found, raw == 1)?;
                }
                _ => {}
            }
        }
        Ok(Self {
            value: value.unwrap_or(&[]),
            found: found.unwrap_or(false),
        })
    }
}

pub fn encode_evaluate_success<'a>(
    output: &'a mut [u8],
    action: PolicyAction,
    payload: &[u8],
) -> Result<&'a [u8], GuestError> {
    if !action.is_decision() {
        return Err(GuestError::new(
            AbiStatus::InvalidArgument,
            ReasonCode::InvalidAction,
        ));
    }
    let nested_length = varint_field_len(field::evaluate_success::ACTION, action as u64)
        + bytes_field_len(field::evaluate_success::PAYLOAD, payload.len());
    let mut writer = FrameWriter::new(output);
    writer.write_message_header(field::evaluate_response::SUCCESS, nested_length)?;
    writer.write_varint_field(field::evaluate_success::ACTION, action as u64)?;
    writer.write_bytes_field(field::evaluate_success::PAYLOAD, payload)?;
    Ok(writer.finish())
}

pub fn encode_evaluate_error<'a>(
    output: &'a mut [u8],
    code: RuntimeErrorCode,
    message: &str,
    retryable: bool,
) -> Result<&'a [u8], GuestError> {
    if !code.is_failure() {
        return Err(GuestError::new(
            AbiStatus::InvalidArgument,
            ReasonCode::InvalidRuntimeError,
        ));
    }
    let nested_length = varint_field_len(field::runtime_error::CODE, code as u64)
        + bytes_field_len(field::runtime_error::MESSAGE, message.len())
        + varint_field_len(field::runtime_error::RETRYABLE, retryable as u64);
    let mut writer = FrameWriter::new(output);
    writer.write_message_header(field::evaluate_response::ERROR, nested_length)?;
    writer.write_varint_field(field::runtime_error::CODE, code as u64)?;
    writer.write_string_field(field::runtime_error::MESSAGE, message)?;
    writer.write_varint_field(field::runtime_error::RETRYABLE, retryable as u64)?;
    Ok(writer.finish())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), GuestError> {
    if slot.is_some() {
        return Err(GuestError::new(
            AbiStatus::InvalidArgument,
            ReasonCode::DuplicateField,
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn as_bytes(value: FieldValue<'_>) -> Result<&[u8], GuestError> {
    match value {
        FieldValue::Bytes(value) => Ok(value),
        _ => Err(invalid_wire()),
    }
}

fn as_str(value: FieldValue<'_>) -> Result<&str, GuestError> {
    core::str::from_utf8(as_bytes(value)?)
        .map_err(|_| GuestError::new(AbiStatus::InvalidArgument, ReasonCode::InvalidUtf8))
}

fn as_varint(value: FieldValue<'_>) -> Result<u64, GuestError> {
    match value {
        FieldValue::Varint(value) => Ok(value),
        _ => Err(invalid_wire()),
    }
}
