#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidAddress,
    InvalidPrefixLength,
    DuplicatePrefix,
    CapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpAddress {
    octets: [u8; 16],
    bits: u8,
}

impl IpAddress {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        if value.as_bytes().contains(&b':') {
            parse_ipv6(value)
        } else {
            let address = parse_ipv4(value)?;
            let mut octets = [0; 16];
            for (target, source) in octets.iter_mut().zip(address) {
                *target = source;
            }
            Ok(Self { octets, bits: 32 })
        }
    }

    pub fn parse_strict(value: &str) -> Result<Self, ConfigError> {
        let address = Self::parse(value)?;
        let mut canonical = CanonicalText::new();
        canonical.write_address(address)?;
        if canonical.as_str() != value {
            return Err(ConfigError::InvalidAddress);
        }
        Ok(address)
    }

    pub const fn is_ipv4(self) -> bool {
        self.bits == 32
    }

    pub const fn octets(self) -> [u8; 16] {
        self.octets
    }

    pub fn from_network_bytes(value: &[u8]) -> Result<Self, ConfigError> {
        match value.len() {
            4 => {
                let mut octets = [0; 16];
                for (target, source) in octets.iter_mut().zip(value) {
                    *target = *source;
                }
                Ok(Self { octets, bits: 32 })
            }
            16 if !matches!(value, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ..]) => {
                let mut octets = [0; 16];
                for (target, source) in octets.iter_mut().zip(value) {
                    *target = *source;
                }
                Ok(Self { octets, bits: 128 })
            }
            _ => Err(ConfigError::InvalidAddress),
        }
    }

    fn bit(self, index: u8) -> usize {
        ((self.octets.get(index as usize / 8).copied().unwrap_or(0) >> (7 - index % 8)) & 1)
            as usize
    }
}

fn parse_ipv4(value: &str) -> Result<[u8; 4], ConfigError> {
    let bytes = value.as_bytes();
    let mut result = [0u8; 4];
    let mut part = 0usize;
    let mut start = 0usize;
    let mut index = 0usize;
    while index <= bytes.len() {
        if index == bytes.len() || bytes.get(index).copied() == Some(b'.') {
            if part >= 4
                || start == index
                || (index - start > 1 && bytes.get(start).copied() == Some(b'0'))
            {
                return Err(ConfigError::InvalidAddress);
            }
            let mut number = 0u16;
            for byte in bytes.get(start..index).ok_or(ConfigError::InvalidAddress)? {
                if !byte.is_ascii_digit() {
                    return Err(ConfigError::InvalidAddress);
                }
                number = number * 10 + u16::from(*byte - b'0');
                if number > 255 {
                    return Err(ConfigError::InvalidAddress);
                }
            }
            *result.get_mut(part).ok_or(ConfigError::InvalidAddress)? = number as u8;
            part += 1;
            start = index + 1;
        }
        index += 1;
    }
    if part == 4 {
        Ok(result)
    } else {
        Err(ConfigError::InvalidAddress)
    }
}

fn parse_ipv6(value: &str) -> Result<IpAddress, ConfigError> {
    if value.is_empty() || value.as_bytes().contains(&b'.') {
        return Err(ConfigError::InvalidAddress);
    }
    let mut groups = [0u16; 8];
    if let Some(split) = find_double_colon(value.as_bytes()) {
        let left = value.get(..split).ok_or(ConfigError::InvalidAddress)?;
        let right = value.get(split + 2..).ok_or(ConfigError::InvalidAddress)?;
        if find_double_colon(right.as_bytes()).is_some() {
            return Err(ConfigError::InvalidAddress);
        }
        let left_count = parse_ipv6_groups(left, &mut groups)?;
        let mut tail = [0u16; 8];
        let right_count = parse_ipv6_groups(right, &mut tail)?;
        if left_count + right_count >= 8 {
            return Err(ConfigError::InvalidAddress);
        }
        for index in 0..right_count {
            *groups
                .get_mut(8 - right_count + index)
                .ok_or(ConfigError::InvalidAddress)? = tail
                .get(index)
                .copied()
                .ok_or(ConfigError::InvalidAddress)?;
        }
    } else {
        let count = parse_ipv6_groups(value, &mut groups)?;
        if count != 8 {
            return Err(ConfigError::InvalidAddress);
        }
    }
    let mut octets = [0u8; 16];
    for (index, group) in groups.iter().copied().enumerate() {
        *octets
            .get_mut(index * 2)
            .ok_or(ConfigError::InvalidAddress)? = (group >> 8) as u8;
        *octets
            .get_mut(index * 2 + 1)
            .ok_or(ConfigError::InvalidAddress)? = group as u8;
    }
    if matches!(octets, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ..]) {
        return Err(ConfigError::InvalidAddress);
    }
    Ok(IpAddress { octets, bits: 128 })
}

fn find_double_colon(value: &[u8]) -> Option<usize> {
    let mut index = 0usize;
    while index + 1 < value.len() {
        if value.get(index).copied() == Some(b':') && value.get(index + 1).copied() == Some(b':') {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn parse_ipv6_groups(value: &str, output: &mut [u16; 8]) -> Result<usize, ConfigError> {
    if value.is_empty() {
        return Ok(0);
    }
    let bytes = value.as_bytes();
    let mut count = 0usize;
    let mut start = 0usize;
    let mut index = 0usize;
    while index <= bytes.len() {
        if index == bytes.len() || bytes.get(index).copied() == Some(b':') {
            if start == index || count >= 8 || index - start > 4 {
                return Err(ConfigError::InvalidAddress);
            }
            let mut number = 0u16;
            for byte in bytes.get(start..index).ok_or(ConfigError::InvalidAddress)? {
                let digit = match byte {
                    b'0'..=b'9' => u16::from(*byte - b'0'),
                    b'a'..=b'f' => u16::from(*byte - b'a') + 10,
                    b'A'..=b'F' => u16::from(*byte - b'A') + 10,
                    _ => return Err(ConfigError::InvalidAddress),
                };
                number = (number << 4) | digit;
            }
            *output.get_mut(count).ok_or(ConfigError::InvalidAddress)? = number;
            count += 1;
            start = index + 1;
        }
        index += 1;
    }
    Ok(count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cidr {
    network: IpAddress,
    prefix_bits: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let (address, prefix) = split_once_byte(value, b'/')?;
        let mut network = IpAddress::parse(address)?;
        let prefix_bits = parse_prefix(prefix)?;
        if prefix_bits > network.bits {
            return Err(ConfigError::InvalidPrefixLength);
        }
        mask_host_bits(&mut network.octets, prefix_bits, network.bits);
        Ok(Self {
            network,
            prefix_bits,
        })
    }

    pub const fn network(self) -> IpAddress {
        self.network
    }

    pub const fn prefix_bits(self) -> u8 {
        self.prefix_bits
    }

    pub fn parse_strict(value: &str) -> Result<Self, ConfigError> {
        let (address, prefix_text) = split_once_byte(value, b'/')?;
        let original = IpAddress::parse_strict(address)?;
        if prefix_text.len() > 1 && prefix_text.as_bytes().first().copied() == Some(b'0') {
            return Err(ConfigError::InvalidPrefixLength);
        }
        let prefix = Self::parse(value)?;
        if original != prefix.network {
            return Err(ConfigError::InvalidAddress);
        }
        Ok(prefix)
    }

    pub fn contains(self, address: IpAddress) -> bool {
        if self.network.bits != address.bits {
            return false;
        }
        (0..self.prefix_bits).all(|index| self.network.bit(index) == address.bit(index))
    }
}

fn split_once_byte(value: &str, separator: u8) -> Result<(&str, &str), ConfigError> {
    let mut found = None;
    for (index, byte) in value.bytes().enumerate() {
        if byte == separator {
            if found.is_some() {
                return Err(ConfigError::InvalidPrefixLength);
            }
            found = Some(index);
        }
    }
    let index = found.ok_or(ConfigError::InvalidPrefixLength)?;
    Ok((
        value.get(..index).ok_or(ConfigError::InvalidPrefixLength)?,
        value
            .get(index + 1..)
            .ok_or(ConfigError::InvalidPrefixLength)?,
    ))
}

fn parse_prefix(value: &str) -> Result<u8, ConfigError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(ConfigError::InvalidPrefixLength);
    }
    let mut result = 0u16;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return Err(ConfigError::InvalidPrefixLength);
        }
        result = result * 10 + u16::from(byte - b'0');
        if result > 128 {
            return Err(ConfigError::InvalidPrefixLength);
        }
    }
    Ok(result as u8)
}

struct CanonicalText {
    bytes: [u8; 64],
    len: usize,
}

impl CanonicalText {
    const fn new() -> Self {
        Self {
            bytes: [0; 64],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        // IP formatting emits ASCII only.
        let bytes = self.bytes.get(..self.len).unwrap_or(&[]);
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }

    fn write_address(&mut self, address: IpAddress) -> Result<(), ConfigError> {
        if address.is_ipv4() {
            for (index, octet) in address.octets.iter().copied().take(4).enumerate() {
                if index != 0 {
                    self.push(b'.')?;
                }
                self.decimal(octet)?;
            }
        } else {
            let mut groups = [0u16; 8];
            for (group, pair) in groups.iter_mut().zip(address.octets.chunks_exact(2)) {
                *group = u16::from_be_bytes([
                    pair.first().copied().unwrap_or(0),
                    pair.get(1).copied().unwrap_or(0),
                ]);
            }
            let (zero_start, zero_len) = longest_zero_run(groups);
            let mut index = 0usize;
            while index < groups.len() {
                if index == zero_start {
                    self.push(b':')?;
                    self.push(b':')?;
                    index += zero_len;
                    continue;
                }
                if self.len != 0 && self.bytes.get(self.len - 1).copied().unwrap_or(0) != b':' {
                    self.push(b':')?;
                }
                self.hex(
                    groups
                        .get(index)
                        .copied()
                        .ok_or(ConfigError::InvalidAddress)?,
                )?;
                index += 1;
            }
        }
        Ok(())
    }

    fn push(&mut self, value: u8) -> Result<(), ConfigError> {
        let slot = self
            .bytes
            .get_mut(self.len)
            .ok_or(ConfigError::InvalidAddress)?;
        *slot = value;
        self.len += 1;
        Ok(())
    }

    fn decimal(&mut self, value: u8) -> Result<(), ConfigError> {
        if value >= 100 {
            self.push(b'0' + value / 100)?;
            self.push(b'0' + (value / 10) % 10)?;
        } else if value >= 10 {
            self.push(b'0' + value / 10)?;
        }
        self.push(b'0' + value % 10)
    }

    fn hex(&mut self, value: u16) -> Result<(), ConfigError> {
        let digits = *b"0123456789abcdef";
        let mut started = false;
        for shift in [12, 8, 4, 0] {
            let nibble = ((value >> shift) & 0x0f) as usize;
            if nibble != 0 || started || shift == 0 {
                self.push(
                    digits
                        .get(nibble)
                        .copied()
                        .ok_or(ConfigError::InvalidAddress)?,
                )?;
                started = true;
            }
        }
        Ok(())
    }
}

fn longest_zero_run(groups: [u16; 8]) -> (usize, usize) {
    let mut best_start = usize::MAX;
    let mut best_len = 0usize;
    let mut index = 0usize;
    while index < groups.len() {
        if groups.get(index).copied().unwrap_or(0) != 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < groups.len() && groups.get(index).copied().unwrap_or(1) == 0 {
            index += 1;
        }
        let length = index - start;
        if length >= 2 && length > best_len {
            best_start = start;
            best_len = length;
        }
    }
    (best_start, best_len)
}

fn mask_host_bits(octets: &mut [u8; 16], prefix: u8, address_bits: u8) {
    for bit in prefix..address_bits {
        let byte = bit as usize / 8;
        if let Some(value) = octets.get_mut(byte) {
            *value &= !(1 << (7 - bit % 8));
        }
    }
    if address_bits == 32 {
        if let Some(tail) = octets.get_mut(4..) {
            tail.fill(0);
        }
    }
}

const NONE: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Node {
    child: [u16; 2],
    allow: bool,
    deny: bool,
}

impl Node {
    const EMPTY: Self = Self {
        child: [NONE; 2],
        allow: false,
        deny: false,
    };
}

/// A bounded, normalized IPv4/IPv6 binary prefix trie.
#[derive(Clone)]
pub struct PolicySet<const MAX_NODES: usize> {
    nodes: [Node; MAX_NODES],
    used: u16,
}

impl<const MAX_NODES: usize> PolicySet<MAX_NODES> {
    pub const fn new() -> Self {
        Self {
            nodes: [Node::EMPTY; MAX_NODES],
            used: if MAX_NODES >= 2 { 2 } else { 0 },
        }
    }

    pub fn insert(&mut self, prefix: Cidr, effect: crate::RuleEffect) -> Result<(), ConfigError> {
        if MAX_NODES < 2 || self.used < 2 {
            return Err(ConfigError::CapacityExceeded);
        }
        let mut current = if prefix.network.is_ipv4() { 0 } else { 1 };
        for index in 0..prefix.prefix_bits {
            let branch = prefix.network.bit(index);
            let next = self
                .nodes
                .get(current)
                .and_then(|node| node.child.get(branch))
                .copied()
                .ok_or(ConfigError::CapacityExceeded)?;
            current = if next == NONE {
                let allocated = self.allocate()?;
                *self
                    .nodes
                    .get_mut(current)
                    .and_then(|node| node.child.get_mut(branch))
                    .ok_or(ConfigError::CapacityExceeded)? = allocated as u16;
                allocated
            } else {
                next as usize
            };
        }
        let node = self
            .nodes
            .get_mut(current)
            .ok_or(ConfigError::CapacityExceeded)?;
        let occupied = match effect {
            crate::RuleEffect::Allow => node.allow,
            crate::RuleEffect::Deny => node.deny,
        };
        if occupied {
            return Err(ConfigError::DuplicatePrefix);
        }
        match effect {
            crate::RuleEffect::Allow => node.allow = true,
            crate::RuleEffect::Deny => node.deny = true,
        }
        Ok(())
    }

    pub fn contains(&self, address: IpAddress, effect: crate::RuleEffect) -> bool {
        if self.used < 2 {
            return false;
        }
        let mut current = if address.is_ipv4() { 0 } else { 1 };
        if self.node_matches(current, effect) {
            return true;
        }
        for index in 0..address.bits {
            let next = self
                .nodes
                .get(current)
                .and_then(|node| node.child.get(address.bit(index)))
                .copied()
                .unwrap_or(NONE);
            if next == NONE {
                return false;
            }
            current = next as usize;
            if self.node_matches(current, effect) {
                return true;
            }
        }
        false
    }

    pub const fn node_count(&self) -> usize {
        self.used as usize
    }

    fn node_matches(&self, index: usize, effect: crate::RuleEffect) -> bool {
        match effect {
            crate::RuleEffect::Allow => self.nodes.get(index).is_some_and(|node| node.allow),
            crate::RuleEffect::Deny => self.nodes.get(index).is_some_and(|node| node.deny),
        }
    }

    fn allocate(&mut self) -> Result<usize, ConfigError> {
        let index = self.used as usize;
        if index >= MAX_NODES || index >= NONE as usize {
            return Err(ConfigError::CapacityExceeded);
        }
        *self
            .nodes
            .get_mut(index)
            .ok_or(ConfigError::CapacityExceeded)? = Node::EMPTY;
        self.used += 1;
        Ok(index)
    }
}

impl<const MAX_NODES: usize> Default for PolicySet<MAX_NODES> {
    fn default() -> Self {
        Self::new()
    }
}
