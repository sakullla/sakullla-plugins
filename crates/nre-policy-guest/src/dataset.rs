use crate::abi_generated::field;
use crate::wire::{bytes_field_len, invalid_wire, varint_field_len};
use crate::{
    AbiStatus, DatasetClassificationKind, DatasetMatchCoverage, DatasetQueryStatus, FieldValue,
    FrameWriter, GuestError, ReasonCode, RuntimeErrorCode, WireCursor, WireLimits,
};

const MAX_QUERY_CLASSIFICATIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetReference<'a> {
    pub handle: &'a str,
    pub instance_id: &'a str,
    pub generation: &'a str,
    pub source_id: &'a str,
    pub version_digest: &'a str,
}

impl DatasetReference<'_> {
    pub fn validate(&self) -> Result<(), GuestError> {
        if self.handle.len() < 32
            || self.handle.len() > 256
            || !self
                .handle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !valid_identity(self.instance_id)
            || !valid_identity(self.generation)
            || self.source_id.is_empty()
            || self.source_id.len() > 128
            || self.version_digest.len() != 71
            || self.version_digest.as_bytes().get(..7) != Some(b"sha256:")
            || !self
                .version_digest
                .as_bytes()
                .get(7..)
                .is_some_and(|digest| {
                    digest
                        .iter()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                })
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
pub struct DatasetClassification<'a> {
    pub name: &'a str,
    pub kind: DatasetClassificationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetResolveRequest<'a> {
    pub source_id: &'a str,
    pub max_duration_micros: u32,
    pub max_response_bytes: u32,
}

impl DatasetResolveRequest<'_> {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, GuestError> {
        if self.source_id.is_empty()
            || self.max_duration_micros == 0
            || self.max_duration_micros > 2000
            || self.max_response_bytes == 0
            || self.max_response_bytes > 4096
        {
            return Err(invalid_wire());
        }
        let mut writer = FrameWriter::new(output);
        writer.write_string_field(field::dataset_resolve_request::SOURCE_ID, self.source_id)?;
        writer.write_varint_field(
            field::dataset_resolve_request::MAX_DURATION_MICROS,
            self.max_duration_micros as u64,
        )?;
        writer.write_varint_field(
            field::dataset_resolve_request::MAX_RESPONSE_BYTES,
            self.max_response_bytes as u64,
        )?;
        Ok(writer.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetResolveResponse<'a> {
    pub reference: Option<DatasetReference<'a>>,
    pub error: Option<RuntimeFailure<'a>>,
}

impl<'a> DatasetResolveResponse<'a> {
    pub fn decode(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        let mut cursor = WireCursor::new(frame, limits)?;
        let mut reference = None;
        let mut error = None;
        while let Some(field) = cursor.next_field()? {
            match field.number {
                field::dataset_resolve_response::REFERENCE => set_once(
                    &mut reference,
                    decode_reference(as_bytes(field.value)?, limits)?,
                )?,
                field::dataset_resolve_response::ERROR => set_once(
                    &mut error,
                    RuntimeFailure::decode(as_bytes(field.value)?, limits)?,
                )?,
                _ => return Err(invalid_wire()),
            }
        }
        if reference.is_some() == error.is_some() {
            return Err(invalid_wire());
        }
        Ok(Self { reference, error })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetQueryRequest<'a> {
    pub reference: DatasetReference<'a>,
    pub classifications: &'a [DatasetClassification<'a>],
    pub max_duration_micros: u32,
    pub max_response_bytes: u32,
}

impl DatasetQueryRequest<'_> {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, GuestError> {
        self.reference.validate()?;
        if self.classifications.is_empty()
            || self.classifications.len() > MAX_QUERY_CLASSIFICATIONS
            || self.max_duration_micros == 0
            || self.max_duration_micros > 2000
            || self.max_response_bytes == 0
            || self.max_response_bytes > 4096
        {
            return Err(invalid_wire());
        }
        for (index, classification) in self.classifications.iter().enumerate() {
            if classification.name.is_empty()
                || self
                    .classifications
                    .iter()
                    .take(index)
                    .any(|seen| seen == classification)
            {
                return Err(invalid_wire());
            }
        }

        let reference_len = reference_encoded_len(self.reference);
        let mut writer = FrameWriter::new(output);
        writer.write_message_header(field::dataset_query_request::REFERENCE, reference_len)?;
        write_reference(&mut writer, self.reference)?;
        for classification in self.classifications {
            let length = bytes_field_len(
                field::dataset_classification::NAME,
                classification.name.len(),
            ) + varint_field_len(
                field::dataset_classification::KIND,
                classification.kind as u64,
            );
            writer.write_message_header(field::dataset_query_request::CLASSIFICATIONS, length)?;
            writer.write_string_field(field::dataset_classification::NAME, classification.name)?;
            writer.write_varint_field(
                field::dataset_classification::KIND,
                classification.kind as u64,
            )?;
        }
        writer.write_varint_field(
            field::dataset_query_request::MAX_DURATION_MICROS,
            self.max_duration_micros as u64,
        )?;
        writer.write_varint_field(
            field::dataset_query_request::MAX_RESPONSE_BYTES,
            self.max_response_bytes as u64,
        )?;
        Ok(writer.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetMatch {
    pub index: u32,
    pub matched: bool,
    pub coverage: DatasetMatchCoverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetQueryResponse<'a> {
    pub reference: DatasetReference<'a>,
    pub status: DatasetQueryStatus,
    frame: &'a [u8],
    limits: WireLimits,
    match_count: u8,
}

impl<'a> DatasetQueryResponse<'a> {
    pub fn decode(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        let mut cursor = WireCursor::new(frame, limits)?;
        let mut reference = None;
        let mut status = None;
        let mut match_count = 0usize;
        while let Some(field) = cursor.next_field()? {
            match field.number {
                field::dataset_query_response::REFERENCE => set_once(
                    &mut reference,
                    decode_reference(as_bytes(field.value)?, limits)?,
                )?,
                field::dataset_query_response::STATUS => set_once(
                    &mut status,
                    DatasetQueryStatus::from_u32(
                        u32::try_from(as_varint(field.value)?).map_err(|_| invalid_wire())?,
                    )
                    .filter(|status| *status != DatasetQueryStatus::Unspecified)
                    .ok_or_else(invalid_wire)?,
                )?,
                field::dataset_query_response::MATCHES => {
                    decode_match(as_bytes(field.value)?, limits, match_count)?;
                    match_count += 1;
                    if match_count > MAX_QUERY_CLASSIFICATIONS {
                        return Err(invalid_wire());
                    }
                }
                _ => return Err(invalid_wire()),
            }
        }
        let reference = reference.ok_or_else(invalid_wire)?;
        let status = status.ok_or_else(invalid_wire)?;
        if (status == DatasetQueryStatus::Ok) != (match_count != 0) {
            return Err(invalid_wire());
        }
        Ok(Self {
            reference,
            status,
            frame,
            limits,
            match_count: match_count as u8,
        })
    }

    pub fn validate_for(self, request: DatasetQueryRequest<'_>) -> Result<Self, GuestError> {
        if self.reference != request.reference
            || (self.status == DatasetQueryStatus::Ok
                && self.match_count as usize != request.classifications.len())
        {
            return Err(invalid_wire());
        }
        Ok(self)
    }

    pub fn matches(self) -> DatasetMatches<'a> {
        DatasetMatches {
            cursor: WireCursor::new(self.frame, self.limits).ok(),
            next_index: 0,
            failed: false,
        }
    }
}

pub struct DatasetMatches<'a> {
    cursor: Option<WireCursor<'a>>,
    next_index: usize,
    failed: bool,
}

impl<'a> Iterator for DatasetMatches<'a> {
    type Item = Result<DatasetMatch, GuestError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let cursor = self.cursor.as_mut()?;
        loop {
            match cursor.next_field() {
                Ok(Some(field)) if field.number == field::dataset_query_response::MATCHES => {
                    let result = as_bytes(field.value)
                        .and_then(|value| decode_match(value, cursor.limits(), self.next_index));
                    match result {
                        Ok(value) => {
                            self.next_index += 1;
                            return Some(Ok(value));
                        }
                        Err(error) => {
                            self.failed = true;
                            return Some(Err(error));
                        }
                    }
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
pub struct RuntimeFailure<'a> {
    pub code: RuntimeErrorCode,
    pub message: &'a str,
    pub retryable: bool,
}

impl<'a> RuntimeFailure<'a> {
    pub(crate) fn decode(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        let mut cursor = WireCursor::new(frame, limits)?;
        let mut code = None;
        let mut message = None;
        let mut retryable = None;
        while let Some(field) = cursor.next_field()? {
            match field.number {
                field::runtime_error::CODE => set_once(
                    &mut code,
                    RuntimeErrorCode::from_u32(
                        u32::try_from(as_varint(field.value)?).map_err(|_| invalid_wire())?,
                    )
                    .filter(|value| value.is_failure())
                    .ok_or_else(invalid_wire)?,
                )?,
                field::runtime_error::MESSAGE => set_once(&mut message, as_str(field.value)?)?,
                field::runtime_error::RETRYABLE => set_once(&mut retryable, as_bool(field.value)?)?,
                _ => return Err(invalid_wire()),
            }
        }
        Ok(Self {
            code: code.ok_or_else(invalid_wire)?,
            message: message.unwrap_or(""),
            retryable: retryable.unwrap_or(false),
        })
    }
}

fn decode_reference(frame: &[u8], limits: WireLimits) -> Result<DatasetReference<'_>, GuestError> {
    let mut cursor = WireCursor::new(frame, limits)?;
    let mut fields = [None; 5];
    while let Some(field) = cursor.next_field()? {
        let index = usize::try_from(
            field
                .number
                .checked_sub(field::dataset_reference::HANDLE)
                .ok_or_else(invalid_wire)?,
        )
        .map_err(|_| invalid_wire())?;
        let slot = fields.get_mut(index).ok_or_else(invalid_wire)?;
        set_once(slot, as_str(field.value)?)?;
    }
    let reference = DatasetReference {
        handle: fields.first().copied().flatten().ok_or_else(invalid_wire)?,
        instance_id: fields.get(1).copied().flatten().ok_or_else(invalid_wire)?,
        generation: fields.get(2).copied().flatten().ok_or_else(invalid_wire)?,
        source_id: fields.get(3).copied().flatten().ok_or_else(invalid_wire)?,
        version_digest: fields.get(4).copied().flatten().ok_or_else(invalid_wire)?,
    };
    reference.validate()?;
    Ok(reference)
}

fn write_reference(
    writer: &mut FrameWriter<'_>,
    reference: DatasetReference<'_>,
) -> Result<(), GuestError> {
    writer.write_string_field(field::dataset_reference::HANDLE, reference.handle)?;
    writer.write_string_field(field::dataset_reference::INSTANCE_ID, reference.instance_id)?;
    writer.write_string_field(field::dataset_reference::GENERATION, reference.generation)?;
    writer.write_string_field(field::dataset_reference::SOURCE_ID, reference.source_id)?;
    writer.write_string_field(
        field::dataset_reference::VERSION_DIGEST,
        reference.version_digest,
    )
}

fn reference_encoded_len(reference: DatasetReference<'_>) -> usize {
    bytes_field_len(1, reference.handle.len())
        + bytes_field_len(2, reference.instance_id.len())
        + bytes_field_len(3, reference.generation.len())
        + bytes_field_len(4, reference.source_id.len())
        + bytes_field_len(5, reference.version_digest.len())
}

fn decode_match(
    frame: &[u8],
    limits: WireLimits,
    expected_index: usize,
) -> Result<DatasetMatch, GuestError> {
    let mut cursor = WireCursor::new(frame, limits)?;
    let mut index = None;
    let mut matched = None;
    let mut coverage = None;
    while let Some(field) = cursor.next_field()? {
        match field.number {
            field::dataset_match::INDEX => set_once(
                &mut index,
                u32::try_from(as_varint(field.value)?).map_err(|_| invalid_wire())?,
            )?,
            field::dataset_match::MATCHED => set_once(&mut matched, as_bool(field.value)?)?,
            field::dataset_match::COVERAGE => set_once(
                &mut coverage,
                DatasetMatchCoverage::from_u32(
                    u32::try_from(as_varint(field.value)?).map_err(|_| invalid_wire())?,
                )
                .filter(|coverage| *coverage != DatasetMatchCoverage::Unspecified)
                .ok_or_else(invalid_wire)?,
            )?,
            _ => return Err(invalid_wire()),
        }
    }
    let result = DatasetMatch {
        index: index.unwrap_or(0),
        matched: matched.unwrap_or(false),
        coverage: coverage.ok_or_else(invalid_wire)?,
    };
    if result.index as usize != expected_index
        || (result.coverage != DatasetMatchCoverage::Covered && result.matched)
    {
        return Err(invalid_wire());
    }
    Ok(result)
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

fn as_bool(value: FieldValue<'_>) -> Result<bool, GuestError> {
    match as_varint(value)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_wire()),
    }
}
