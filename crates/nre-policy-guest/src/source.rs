use crate::abi_generated::field;
use crate::dataset::RuntimeFailure;
use crate::wire::invalid_wire;
use crate::{
    AbiStatus, FieldValue, GuestError, ReasonCode, TrustedSourceAuthority, WireCursor, WireLimits,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyTrustedSource<'a> {
    pub instance_id: &'a str,
    pub generation: &'a str,
    pub entry_id: &'a str,
    pub peer_address: &'a [u8],
    pub source_address: &'a [u8],
    pub authority: TrustedSourceAuthority,
}

impl PolicyTrustedSource<'_> {
    pub fn validate(&self) -> Result<(), GuestError> {
        if !valid_identity(self.instance_id)
            || !valid_identity(self.generation)
            || !valid_identity(self.entry_id)
            || !valid_address(self.peer_address)
            || !valid_address(self.source_address)
            || (self.authority == TrustedSourceAuthority::Socket
                && self.peer_address != self.source_address)
        {
            return Err(invalid_wire());
        }
        Ok(())
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_whitespace())
        && !value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_whitespace())
        && !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyTrustedSourceResponse<'a> {
    pub source: Option<PolicyTrustedSource<'a>>,
    pub error: Option<RuntimeFailure<'a>>,
}

impl<'a> PolicyTrustedSourceResponse<'a> {
    pub fn decode(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        let mut cursor = WireCursor::new(frame, limits)?;
        let mut source = None;
        let mut error = None;
        while let Some(field) = cursor.next_field()? {
            match field.number {
                field::trusted_source_response::SOURCE => {
                    set_once(&mut source, decode_source(as_bytes(field.value)?, limits)?)?
                }
                field::trusted_source_response::ERROR => set_once(
                    &mut error,
                    RuntimeFailure::decode(as_bytes(field.value)?, limits)?,
                )?,
                _ => return Err(invalid_wire()),
            }
        }
        if source.is_some() == error.is_some() {
            return Err(invalid_wire());
        }
        Ok(Self { source, error })
    }
}

fn decode_source(frame: &[u8], limits: WireLimits) -> Result<PolicyTrustedSource<'_>, GuestError> {
    let mut cursor = WireCursor::new(frame, limits)?;
    let mut instance_id = None;
    let mut generation = None;
    let mut entry_id = None;
    let mut peer_address = None;
    let mut source_address = None;
    let mut authority = None;
    while let Some(field) = cursor.next_field()? {
        match field.number {
            field::trusted_source::INSTANCE_ID => set_once(&mut instance_id, as_str(field.value)?)?,
            field::trusted_source::GENERATION => set_once(&mut generation, as_str(field.value)?)?,
            field::trusted_source::ENTRY_ID => set_once(&mut entry_id, as_str(field.value)?)?,
            field::trusted_source::PEER_ADDRESS => {
                set_once(&mut peer_address, as_bytes(field.value)?)?
            }
            field::trusted_source::SOURCE_ADDRESS => {
                set_once(&mut source_address, as_bytes(field.value)?)?
            }
            field::trusted_source::AUTHORITY => set_once(
                &mut authority,
                TrustedSourceAuthority::from_u32(
                    u32::try_from(as_varint(field.value)?).map_err(|_| invalid_wire())?,
                )
                .filter(|authority| *authority != TrustedSourceAuthority::Unspecified)
                .ok_or_else(invalid_wire)?,
            )?,
            _ => return Err(invalid_wire()),
        }
    }
    let source = PolicyTrustedSource {
        instance_id: instance_id.ok_or_else(invalid_wire)?,
        generation: generation.ok_or_else(invalid_wire)?,
        entry_id: entry_id.ok_or_else(invalid_wire)?,
        peer_address: peer_address.ok_or_else(invalid_wire)?,
        source_address: source_address.ok_or_else(invalid_wire)?,
        authority: authority.ok_or_else(invalid_wire)?,
    };
    source.validate()?;
    Ok(source)
}

fn valid_address(value: &[u8]) -> bool {
    match value {
        [0, 0, 0, 0] => false,
        [first, ..] if value.len() == 4 && (224..=239).contains(first) => false,
        [first, ..] if value.len() == 16 && *first == 0xff => false,
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ..] => false,
        value if value.len() == 16 && value.iter().all(|byte| *byte == 0) => false,
        value => matches!(value.len(), 4 | 16),
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), GuestError> {
    if slot.replace(value).is_some() {
        return Err(GuestError::new(
            AbiStatus::InvalidArgument,
            ReasonCode::DuplicateField,
        ));
    }
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
