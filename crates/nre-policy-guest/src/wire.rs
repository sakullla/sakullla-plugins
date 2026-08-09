use crate::{AbiStatus, GuestError, ReasonCode, WireLimits};

const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WireType {
    Varint = 0,
    Fixed64 = 1,
    Bytes = 2,
    Fixed32 = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldValue<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    Bytes(&'a [u8]),
    Fixed32([u8; 4]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field<'a> {
    pub number: u32,
    pub value: FieldValue<'a>,
}

impl Field<'_> {
    pub const fn wire_type(&self) -> WireType {
        match self.value {
            FieldValue::Varint(_) => WireType::Varint,
            FieldValue::Fixed64(_) => WireType::Fixed64,
            FieldValue::Bytes(_) => WireType::Bytes,
            FieldValue::Fixed32(_) => WireType::Fixed32,
        }
    }
}

/// Strict, allocation-free protobuf cursor with frame and field-count bounds.
pub struct WireCursor<'a> {
    frame: &'a [u8],
    offset: usize,
    fields: u16,
    limits: WireLimits,
}

impl<'a> WireCursor<'a> {
    pub fn new(frame: &'a [u8], limits: WireLimits) -> Result<Self, GuestError> {
        if frame.len() > limits.max_frame_bytes {
            return Err(GuestError::new(
                AbiStatus::ResourceExhausted,
                ReasonCode::InputBudgetExceeded,
            ));
        }
        Ok(Self {
            frame,
            offset: 0,
            fields: 0,
            limits,
        })
    }

    pub const fn remaining(&self) -> usize {
        self.frame.len() - self.offset
    }

    pub fn next_field(&mut self) -> Result<Option<Field<'a>>, GuestError> {
        if self.offset == self.frame.len() {
            return Ok(None);
        }
        if self.fields >= self.limits.max_fields {
            return Err(GuestError::new(
                AbiStatus::ResourceExhausted,
                ReasonCode::FieldBudgetExceeded,
            ));
        }
        self.fields += 1;

        let tag = self.read_varint()?;
        let number = u32::try_from(tag >> 3).map_err(|_| invalid_wire())?;
        if number == 0 || number > MAX_FIELD_NUMBER {
            return Err(invalid_wire());
        }
        let value = match (tag & 7) as u8 {
            0 => FieldValue::Varint(self.read_varint()?),
            1 => FieldValue::Fixed64(self.read_array::<8>()?),
            2 => {
                let length = self.read_varint()?;
                let length = usize::try_from(length).map_err(|_| invalid_wire())?;
                FieldValue::Bytes(self.read_slice(length)?)
            }
            5 => FieldValue::Fixed32(self.read_array::<4>()?),
            _ => return Err(invalid_wire()),
        };
        Ok(Some(Field { number, value }))
    }

    fn read_varint(&mut self) -> Result<u64, GuestError> {
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = *self.frame.get(self.offset).ok_or_else(invalid_wire)?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(invalid_wire());
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && byte == 0 {
                    return Err(GuestError::new(
                        AbiStatus::InvalidArgument,
                        ReasonCode::NonCanonicalWire,
                    ));
                }
                return Ok(value);
            }
        }
        Err(invalid_wire())
    }

    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], GuestError> {
        let end = self.offset.checked_add(length).ok_or_else(invalid_wire)?;
        let value = self.frame.get(self.offset..end).ok_or_else(invalid_wire)?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], GuestError> {
        let bytes = self.read_slice(N)?;
        let mut value = [0; N];
        // SAFETY: read_slice returned exactly N bytes and the arrays do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), value.as_mut_ptr(), N) };
        Ok(value)
    }
}

/// Allocation-free deterministic protobuf writer over a caller-owned buffer.
pub struct FrameWriter<'a> {
    buffer: &'a mut [u8],
    length: usize,
}

impl<'a> FrameWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, length: 0 }
    }

    pub const fn len(&self) -> usize {
        self.length
    }

    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn finish(self) -> &'a [u8] {
        // SAFETY: every writer operation increments length only after a
        // successful bounds-checked write.
        unsafe { self.buffer.get_unchecked(..self.length) }
    }

    pub fn write_varint_field(&mut self, number: u32, value: u64) -> Result<(), GuestError> {
        self.write_tag(number, WireType::Varint)?;
        self.write_varint(value)
    }

    pub fn write_sint64_field(&mut self, number: u32, value: i64) -> Result<(), GuestError> {
        let zigzag = ((value << 1) ^ (value >> 63)) as u64;
        self.write_varint_field(number, zigzag)
    }

    pub fn write_bytes_field(&mut self, number: u32, value: &[u8]) -> Result<(), GuestError> {
        self.write_message_header(number, value.len())?;
        self.write_bytes(value)
    }

    pub fn write_string_field(&mut self, number: u32, value: &str) -> Result<(), GuestError> {
        self.write_bytes_field(number, value.as_bytes())
    }

    pub fn write_message_header(&mut self, number: u32, length: usize) -> Result<(), GuestError> {
        self.write_tag(number, WireType::Bytes)?;
        self.write_varint(length as u64)
    }

    fn write_tag(&mut self, number: u32, wire_type: WireType) -> Result<(), GuestError> {
        if number == 0 || number > MAX_FIELD_NUMBER {
            return Err(invalid_wire());
        }
        self.write_varint((u64::from(number) << 3) | wire_type as u64)
    }

    fn write_varint(&mut self, mut value: u64) -> Result<(), GuestError> {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.write_byte(byte)?;
            if value == 0 {
                return Ok(());
            }
        }
    }

    fn write_byte(&mut self, value: u8) -> Result<(), GuestError> {
        let slot = self
            .buffer
            .get_mut(self.length)
            .ok_or_else(output_exhausted)?;
        *slot = value;
        self.length += 1;
        Ok(())
    }

    fn write_bytes(&mut self, value: &[u8]) -> Result<(), GuestError> {
        let end = self
            .length
            .checked_add(value.len())
            .ok_or_else(output_exhausted)?;
        let target = self
            .buffer
            .get_mut(self.length..end)
            .ok_or_else(output_exhausted)?;
        // SAFETY: target was bounds checked and has value.len() bytes.
        unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), target.as_mut_ptr(), value.len()) };
        self.length = end;
        Ok(())
    }
}

pub(crate) const fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

pub(crate) const fn field_key_len(number: u32) -> usize {
    varint_len((number as u64) << 3)
}

pub(crate) const fn bytes_field_len(number: u32, length: usize) -> usize {
    field_key_len(number) + varint_len(length as u64) + length
}

pub(crate) const fn varint_field_len(number: u32, value: u64) -> usize {
    field_key_len(number) + varint_len(value)
}

pub(crate) const fn invalid_wire() -> GuestError {
    GuestError::new(AbiStatus::InvalidArgument, ReasonCode::InvalidWire)
}

pub(crate) const fn output_exhausted() -> GuestError {
    GuestError::new(
        AbiStatus::ResourceExhausted,
        ReasonCode::OutputBudgetExceeded,
    )
}
