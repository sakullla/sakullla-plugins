use core::net::IpAddr;
use core::str::FromStr;

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
        match IpAddr::from_str(value).map_err(|_| ConfigError::InvalidAddress)? {
            IpAddr::V4(address) => {
                let mut octets = [0; 16];
                octets[..4].copy_from_slice(&address.octets());
                Ok(Self { octets, bits: 32 })
            }
            IpAddr::V6(address) => Ok(Self {
                octets: address.octets(),
                bits: 128,
            }),
        }
    }

    pub const fn is_ipv4(self) -> bool {
        self.bits == 32
    }

    pub const fn octets(self) -> [u8; 16] {
        self.octets
    }

    const fn bit(self, index: u8) -> usize {
        ((self.octets[index as usize / 8] >> (7 - index % 8)) & 1) as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cidr {
    network: IpAddress,
    prefix_bits: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or(ConfigError::InvalidPrefixLength)?;
        let mut network = IpAddress::parse(address)?;
        let prefix_bits = prefix
            .parse::<u8>()
            .map_err(|_| ConfigError::InvalidPrefixLength)?;
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
}

fn mask_host_bits(octets: &mut [u8; 16], prefix: u8, address_bits: u8) {
    for bit in prefix..address_bits {
        let byte = bit as usize / 8;
        octets[byte] &= !(1 << (7 - bit % 8));
    }
    if address_bits == 32 {
        octets[4..].fill(0);
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
            let next = self.nodes[current].child[branch];
            current = if next == NONE {
                let allocated = self.allocate()?;
                self.nodes[current].child[branch] = allocated as u16;
                allocated
            } else {
                next as usize
            };
        }
        let node = &mut self.nodes[current];
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
            let next = self.nodes[current].child[address.bit(index)];
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
            crate::RuleEffect::Allow => self.nodes[index].allow,
            crate::RuleEffect::Deny => self.nodes[index].deny,
        }
    }

    fn allocate(&mut self) -> Result<usize, ConfigError> {
        let index = self.used as usize;
        if index >= MAX_NODES || index >= NONE as usize {
            return Err(ConfigError::CapacityExceeded);
        }
        self.nodes[index] = Node::EMPTY;
        self.used += 1;
        Ok(index)
    }
}

impl<const MAX_NODES: usize> Default for PolicySet<MAX_NODES> {
    fn default() -> Self {
        Self::new()
    }
}
