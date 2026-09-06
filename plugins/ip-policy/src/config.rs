use crate::{Cidr, IpAddress, RuleEffect};
use nre_policy_guest::DatasetClassificationKind;

pub const MAX_DATASETS: usize = 4;
pub const MAX_CLASSIFICATIONS: usize = 256;
pub const MAX_RULES: usize = 256;
pub const MAX_OVERLAY_RULES: usize = 64;
pub const MAX_PROVINCES: usize = 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidJson,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidValue,
    DuplicateId,
    MissingReference,
    CapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedStr<const N: usize> {
    bytes: [u8; N],
    len: u16,
}

impl<const N: usize> FixedStr<N> {
    pub const EMPTY: Self = Self {
        bytes: [0; N],
        len: 0,
    };

    pub fn set(&mut self, value: &str) -> Result<(), ParseError> {
        if value.is_empty() || value.len() > N || value.len() > u16::MAX as usize {
            return Err(ParseError::InvalidValue);
        }
        for (target, source) in self.bytes.iter_mut().zip(value.as_bytes()) {
            *target = *source;
        }
        self.len = value.len() as u16;
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        // Values enter through a validated UTF-8 JSON string.
        let bytes = self.bytes.get(..self.len as usize).unwrap_or(&[]);
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dataset {
    pub id: FixedStr<32>,
    pub source_id: FixedStr<32>,
    pub classification_start: u16,
    pub classification_len: u16,
}

impl Dataset {
    const EMPTY: Self = Self {
        id: FixedStr::EMPTY,
        source_id: FixedStr::EMPTY,
        classification_start: 0,
        classification_len: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Classification {
    pub id: FixedStr<32>,
    pub name: FixedStr<128>,
    pub kind: DatasetClassificationKind,
    pub dataset: u8,
    pub index_in_dataset: u8,
}

impl Classification {
    const EMPTY: Self = Self {
        id: FixedStr::EMPTY,
        name: FixedStr::EMPTY,
        kind: DatasetClassificationKind::Cidr,
        dataset: 0,
        index_in_dataset: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selector {
    Ip(IpAddress),
    Cidr(Cidr),
    Classification(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule {
    pub id: FixedStr<32>,
    pub action: RuleEffect,
    pub selector: Selector,
}

impl Rule {
    const EMPTY: Self = Self {
        id: FixedStr::EMPTY,
        action: RuleEffect::Deny,
        selector: Selector::Classification(0),
    };

    pub fn matches_local(self, address: IpAddress) -> bool {
        match self.selector {
            Selector::Ip(expected) => expected == address,
            Selector::Cidr(cidr) => cidr.contains(address),
            Selector::Classification(_) => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub default_action: RuleEffect,
    pub datasets: [Dataset; MAX_DATASETS],
    pub dataset_len: u8,
    pub classifications: [Classification; MAX_CLASSIFICATIONS],
    pub classification_len: u16,
    pub province_whitelist: [u16; MAX_PROVINCES],
    pub province_len: u8,
    pub rules: [Rule; MAX_RULES],
    pub rule_len: u16,
}

impl Config {
    const EMPTY: Self = Self {
        default_action: RuleEffect::Deny,
        datasets: [Dataset::EMPTY; MAX_DATASETS],
        dataset_len: 0,
        classifications: [Classification::EMPTY; MAX_CLASSIFICATIONS],
        classification_len: 0,
        province_whitelist: [0; MAX_PROVINCES],
        province_len: 0,
        rules: [Rule::EMPTY; MAX_RULES],
        rule_len: 0,
    };

    pub fn parse(frame: &[u8]) -> Result<Self, ParseError> {
        if frame.is_empty() || frame.len() > 64 * 1024 {
            return Err(ParseError::CapacityExceeded);
        }
        let mut parser = Parser::new(frame);
        let mut raw = RawConfig::EMPTY;
        parser.config(&mut raw)?;
        parser.end()?;
        raw.resolve()
    }

    pub fn rules(&self) -> &[Rule] {
        self.rules.get(..self.rule_len as usize).unwrap_or(&[])
    }

    pub fn classifications(&self) -> &[Classification] {
        self.classifications
            .get(..self.classification_len as usize)
            .unwrap_or(&[])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Overlay {
    pub rules: [Rule; MAX_OVERLAY_RULES],
    pub len: u8,
}

impl Overlay {
    pub fn parse(frame: &[u8], config: &Config) -> Result<Self, ParseError> {
        if frame.is_empty() || frame.len() > 16 * 1024 {
            return Err(ParseError::CapacityExceeded);
        }
        let mut parser = Parser::new(frame);
        let mut raw = RawOverlay::EMPTY;
        parser.overlay(&mut raw)?;
        parser.end()?;
        raw.resolve(config)
    }

    pub fn rules(&self) -> &[Rule] {
        self.rules.get(..self.len as usize).unwrap_or(&[])
    }
}

#[derive(Clone, Copy)]
struct RawReference {
    dataset_id: FixedStr<32>,
    classification_id: FixedStr<32>,
}

impl RawReference {
    const EMPTY: Self = Self {
        dataset_id: FixedStr::EMPTY,
        classification_id: FixedStr::EMPTY,
    };
}

#[derive(Clone, Copy)]
enum RawSelectorKind {
    Missing,
    Ip,
    Cidr,
    Classification,
}

#[derive(Clone, Copy)]
struct RawRule {
    id: FixedStr<32>,
    action: RuleEffect,
    selector_kind: RawSelectorKind,
    value: FixedStr<64>,
    reference: RawReference,
}

impl RawRule {
    const EMPTY: Self = Self {
        id: FixedStr::EMPTY,
        action: RuleEffect::Deny,
        selector_kind: RawSelectorKind::Missing,
        value: FixedStr::EMPTY,
        reference: RawReference::EMPTY,
    };

    fn resolve(self, config: &Config) -> Result<Rule, ParseError> {
        let selector = match self.selector_kind {
            RawSelectorKind::Ip => Selector::Ip(
                IpAddress::parse_strict(self.value.as_str())
                    .map_err(|_| ParseError::InvalidValue)?,
            ),
            RawSelectorKind::Cidr => Selector::Cidr(
                Cidr::parse_strict(self.value.as_str()).map_err(|_| ParseError::InvalidValue)?,
            ),
            RawSelectorKind::Classification => Selector::Classification(
                u8::try_from(resolve_classification(config, self.reference)?)
                    .map_err(|_| ParseError::CapacityExceeded)?,
            ),
            RawSelectorKind::Missing => return Err(ParseError::MissingField),
        };
        Ok(Rule {
            id: self.id,
            action: self.action,
            selector,
        })
    }
}

#[derive(Clone)]
struct RawConfig {
    config: Config,
    provinces: [RawReference; MAX_PROVINCES],
    raw_rules: [RawRule; MAX_RULES],
}

impl RawConfig {
    const EMPTY: Self = Self {
        config: Config::EMPTY,
        provinces: [RawReference::EMPTY; MAX_PROVINCES],
        raw_rules: [RawRule::EMPTY; MAX_RULES],
    };

    fn resolve(mut self) -> Result<Config, ParseError> {
        for index in 0..self.config.province_len as usize {
            let reference = self
                .provinces
                .get(index)
                .copied()
                .ok_or(ParseError::CapacityExceeded)?;
            let classification = resolve_classification(&self.config, reference)?;
            let candidate = self
                .config
                .classifications
                .get(classification)
                .copied()
                .ok_or(ParseError::CapacityExceeded)?;
            if candidate.kind != DatasetClassificationKind::Region
                || !is_cn_province(candidate.name.as_str())
                || self
                    .config
                    .province_whitelist
                    .get(..index)
                    .unwrap_or(&[])
                    .contains(&(classification as u16))
            {
                return Err(ParseError::InvalidValue);
            }
            *self
                .config
                .province_whitelist
                .get_mut(index)
                .ok_or(ParseError::CapacityExceeded)? = classification as u16;
        }
        for index in 0..self.config.rule_len as usize {
            let raw = self
                .raw_rules
                .get(index)
                .copied()
                .ok_or(ParseError::CapacityExceeded)?;
            let resolved = raw.resolve(&self.config)?;
            if self
                .config
                .rules
                .get(..index)
                .unwrap_or(&[])
                .iter()
                .any(|rule| rule.id == resolved.id)
            {
                return Err(ParseError::DuplicateId);
            }
            *self
                .config
                .rules
                .get_mut(index)
                .ok_or(ParseError::CapacityExceeded)? = resolved;
        }
        Ok(self.config)
    }
}

#[derive(Clone)]
struct RawOverlay {
    rules: [RawRule; MAX_OVERLAY_RULES],
    len: u8,
}

impl RawOverlay {
    const EMPTY: Self = Self {
        rules: [RawRule::EMPTY; MAX_OVERLAY_RULES],
        len: 0,
    };

    fn resolve(self, config: &Config) -> Result<Overlay, ParseError> {
        let mut overlay = Overlay {
            rules: [Rule::EMPTY; MAX_OVERLAY_RULES],
            len: self.len,
        };
        for index in 0..self.len as usize {
            let resolved = self
                .rules
                .get(index)
                .copied()
                .ok_or(ParseError::CapacityExceeded)?
                .resolve(config)?;
            if config.rules().iter().any(|rule| rule.id == resolved.id)
                || overlay
                    .rules
                    .get(..index)
                    .unwrap_or(&[])
                    .iter()
                    .any(|rule| rule.id == resolved.id)
            {
                return Err(ParseError::DuplicateId);
            }
            *overlay
                .rules
                .get_mut(index)
                .ok_or(ParseError::CapacityExceeded)? = resolved;
        }
        Ok(overlay)
    }
}

fn resolve_classification(config: &Config, reference: RawReference) -> Result<usize, ParseError> {
    let dataset = config
        .datasets
        .get(..config.dataset_len as usize)
        .unwrap_or(&[])
        .iter()
        .position(|dataset| dataset.id == reference.dataset_id)
        .ok_or(ParseError::MissingReference)?;
    let entry = config
        .datasets
        .get(dataset)
        .copied()
        .ok_or(ParseError::MissingReference)?;
    let start = entry.classification_start as usize;
    let end = start + entry.classification_len as usize;
    config
        .classifications
        .get(start..end)
        .ok_or(ParseError::MissingReference)?
        .iter()
        .position(|classification| classification.id == reference.classification_id)
        .map(|offset| start + offset)
        .ok_or(ParseError::MissingReference)
}

fn is_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_classification_name(value: &str) -> bool {
    value.len() <= 128
        && value != "."
        && value != ".."
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index != 0 && matches!(byte, b'_' | b'.' | b'!' | b'@' | b'+' | b'-'))
        })
}

fn is_cn_province(value: &str) -> bool {
    matches!(
        value,
        "cn-11"
            | "cn-12"
            | "cn-13"
            | "cn-14"
            | "cn-15"
            | "cn-21"
            | "cn-22"
            | "cn-23"
            | "cn-31"
            | "cn-32"
            | "cn-33"
            | "cn-34"
            | "cn-35"
            | "cn-36"
            | "cn-37"
            | "cn-41"
            | "cn-42"
            | "cn-43"
            | "cn-44"
            | "cn-45"
            | "cn-46"
            | "cn-50"
            | "cn-51"
            | "cn-52"
            | "cn-53"
            | "cn-54"
            | "cn-61"
            | "cn-62"
            | "cn-63"
            | "cn-64"
            | "cn-65"
    )
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn config(&mut self, raw: &mut RawConfig) -> Result<(), ParseError> {
        self.object_start()?;
        let mut seen = 0u8;
        while !self.object_end()? {
            let key = self.string(false)?;
            self.colon()?;
            let bit = match key {
                "schema" => {
                    if self.string(false)? != "sakullla.ip-policy/v1" {
                        return Err(ParseError::InvalidValue);
                    }
                    1
                }
                "default_action" => {
                    raw.config.default_action = self.action()?;
                    2
                }
                "datasets" => {
                    self.datasets(&mut raw.config)?;
                    4
                }
                "province_whitelist" => {
                    raw.config.province_len = self.references(&mut raw.provinces)? as u8;
                    8
                }
                "rules" => {
                    raw.config.rule_len = self.rules(&mut raw.raw_rules)? as u16;
                    16
                }
                _ => return Err(ParseError::UnknownField),
            };
            if seen & bit != 0 {
                return Err(ParseError::DuplicateField);
            }
            seen |= bit;
            self.member_end()?;
        }
        if seen != 31 {
            return Err(ParseError::MissingField);
        }
        Ok(())
    }

    fn overlay(&mut self, raw: &mut RawOverlay) -> Result<(), ParseError> {
        self.object_start()?;
        let mut seen = 0u8;
        while !self.object_end()? {
            let key = self.string(false)?;
            self.colon()?;
            let bit = match key {
                "schema" => {
                    if self.string(false)? != "sakullla.ip-policy-overlay/v1" {
                        return Err(ParseError::InvalidValue);
                    }
                    1
                }
                "rules" => {
                    raw.len = self.rules(&mut raw.rules)? as u8;
                    2
                }
                _ => return Err(ParseError::UnknownField),
            };
            if seen & bit != 0 {
                return Err(ParseError::DuplicateField);
            }
            seen |= bit;
            self.member_end()?;
        }
        if seen != 3 {
            return Err(ParseError::MissingField);
        }
        Ok(())
    }

    fn datasets(&mut self, config: &mut Config) -> Result<(), ParseError> {
        self.array_start()?;
        while !self.array_end()? {
            let index = config.dataset_len as usize;
            if index >= MAX_DATASETS {
                return Err(ParseError::CapacityExceeded);
            }
            let start = config.classification_len;
            let mut dataset = Dataset::EMPTY;
            self.dataset(&mut dataset, config)?;
            dataset.classification_start = start;
            dataset.classification_len = config.classification_len - start;
            if dataset.classification_len == 0
                || config
                    .datasets
                    .get(..index)
                    .unwrap_or(&[])
                    .iter()
                    .any(|existing| existing.id == dataset.id)
            {
                return Err(ParseError::DuplicateId);
            }
            *config
                .datasets
                .get_mut(index)
                .ok_or(ParseError::CapacityExceeded)? = dataset;
            config.dataset_len += 1;
            self.element_end()?;
        }
        Ok(())
    }

    fn dataset(&mut self, dataset: &mut Dataset, config: &mut Config) -> Result<(), ParseError> {
        self.object_start()?;
        let mut seen = 0u8;
        while !self.object_end()? {
            let key = self.string(false)?;
            self.colon()?;
            let bit = match key {
                "id" => {
                    let value = self.string(false)?;
                    if !is_id(value) {
                        return Err(ParseError::InvalidValue);
                    }
                    dataset.id.set(value)?;
                    1
                }
                "source_id" => {
                    let value = self.string(false)?;
                    if !is_id(value) {
                        return Err(ParseError::InvalidValue);
                    }
                    dataset.source_id.set(value)?;
                    2
                }
                "classifications" => {
                    self.classifications(config, config.dataset_len)?;
                    4
                }
                _ => return Err(ParseError::UnknownField),
            };
            if seen & bit != 0 {
                return Err(ParseError::DuplicateField);
            }
            seen |= bit;
            self.member_end()?;
        }
        if seen != 7 {
            return Err(ParseError::MissingField);
        }
        Ok(())
    }

    fn classifications(&mut self, config: &mut Config, dataset: u8) -> Result<(), ParseError> {
        self.array_start()?;
        let start = config.classification_len as usize;
        while !self.array_end()? {
            let index = config.classification_len as usize;
            if index >= MAX_CLASSIFICATIONS || index - start >= 64 {
                return Err(ParseError::CapacityExceeded);
            }
            let mut value = Classification::EMPTY;
            value.dataset = dataset;
            value.index_in_dataset = (index - start) as u8;
            self.classification(&mut value)?;
            if config
                .classifications
                .get(start..index)
                .unwrap_or(&[])
                .iter()
                .any(|existing| {
                    existing.id == value.id
                        || (existing.name == value.name && existing.kind == value.kind)
                })
            {
                return Err(ParseError::DuplicateId);
            }
            *config
                .classifications
                .get_mut(index)
                .ok_or(ParseError::CapacityExceeded)? = value;
            config.classification_len += 1;
            self.element_end()?;
        }
        Ok(())
    }

    fn classification(&mut self, value: &mut Classification) -> Result<(), ParseError> {
        self.object_start()?;
        let mut seen = 0u8;
        while !self.object_end()? {
            let key = self.string(false)?;
            self.colon()?;
            let bit = match key {
                "id" => {
                    let field = self.string(false)?;
                    if !is_id(field) {
                        return Err(ParseError::InvalidValue);
                    }
                    value.id.set(field)?;
                    1
                }
                "name" => {
                    let field = self.string(false)?;
                    if !is_classification_name(field) {
                        return Err(ParseError::InvalidValue);
                    }
                    value.name.set(field)?;
                    2
                }
                "kind" => {
                    value.kind = match self.string(false)? {
                        "country" => DatasetClassificationKind::Country,
                        "region" => DatasetClassificationKind::Region,
                        "cidr" => DatasetClassificationKind::Cidr,
                        _ => return Err(ParseError::InvalidValue),
                    };
                    4
                }
                _ => return Err(ParseError::UnknownField),
            };
            if seen & bit != 0 {
                return Err(ParseError::DuplicateField);
            }
            seen |= bit;
            self.member_end()?;
        }
        if seen != 7 {
            return Err(ParseError::MissingField);
        }
        Ok(())
    }

    fn references<const N: usize>(
        &mut self,
        output: &mut [RawReference; N],
    ) -> Result<usize, ParseError> {
        self.array_start()?;
        let mut length = 0usize;
        while !self.array_end()? {
            if length >= N {
                return Err(ParseError::CapacityExceeded);
            }
            *output.get_mut(length).ok_or(ParseError::CapacityExceeded)? = self.reference()?;
            length += 1;
            self.element_end()?;
        }
        Ok(length)
    }

    fn reference(&mut self) -> Result<RawReference, ParseError> {
        self.object_start()?;
        let mut value = RawReference::EMPTY;
        let mut seen = 0u8;
        while !self.object_end()? {
            let key = self.string(false)?;
            self.colon()?;
            let field = self.string(false)?;
            if !is_id(field) {
                return Err(ParseError::InvalidValue);
            }
            let bit = match key {
                "dataset_id" => {
                    value.dataset_id.set(field)?;
                    1
                }
                "classification_id" => {
                    value.classification_id.set(field)?;
                    2
                }
                _ => return Err(ParseError::UnknownField),
            };
            if seen & bit != 0 {
                return Err(ParseError::DuplicateField);
            }
            seen |= bit;
            self.member_end()?;
        }
        if seen != 3 {
            return Err(ParseError::MissingField);
        }
        Ok(value)
    }

    fn rules<const N: usize>(&mut self, output: &mut [RawRule; N]) -> Result<usize, ParseError> {
        self.array_start()?;
        let mut length = 0usize;
        while !self.array_end()? {
            if length >= N {
                return Err(ParseError::CapacityExceeded);
            }
            let rule = self.rule()?;
            *output.get_mut(length).ok_or(ParseError::CapacityExceeded)? = rule;
            if output
                .get(..length)
                .unwrap_or(&[])
                .iter()
                .any(|existing| existing.id == rule.id)
            {
                return Err(ParseError::DuplicateId);
            }
            length += 1;
            self.element_end()?;
        }
        Ok(length)
    }

    fn rule(&mut self) -> Result<RawRule, ParseError> {
        self.object_start()?;
        let mut value = RawRule::EMPTY;
        let mut seen = 0u8;
        while !self.object_end()? {
            let key = self.string(false)?;
            self.colon()?;
            let bit = match key {
                "id" => {
                    let field = self.string(false)?;
                    if !is_id(field) {
                        return Err(ParseError::InvalidValue);
                    }
                    value.id.set(field)?;
                    1
                }
                "action" => {
                    value.action = self.action()?;
                    2
                }
                "selector" => {
                    self.selector(&mut value)?;
                    4
                }
                _ => return Err(ParseError::UnknownField),
            };
            if seen & bit != 0 {
                return Err(ParseError::DuplicateField);
            }
            seen |= bit;
            self.member_end()?;
        }
        if seen != 7 {
            return Err(ParseError::MissingField);
        }
        Ok(value)
    }

    fn selector(&mut self, value: &mut RawRule) -> Result<(), ParseError> {
        self.object_start()?;
        let mut seen = 0u8;
        while !self.object_end()? {
            let key = self.string(false)?;
            self.colon()?;
            let bit = match key {
                "type" => {
                    value.selector_kind = match self.string(false)? {
                        "ip" => RawSelectorKind::Ip,
                        "cidr" => RawSelectorKind::Cidr,
                        "classification" => RawSelectorKind::Classification,
                        _ => return Err(ParseError::InvalidValue),
                    };
                    1
                }
                "value" => {
                    value.value.set(self.string(false)?)?;
                    2
                }
                "dataset_id" => {
                    let field = self.string(false)?;
                    if !is_id(field) {
                        return Err(ParseError::InvalidValue);
                    }
                    value.reference.dataset_id.set(field)?;
                    4
                }
                "classification_id" => {
                    let field = self.string(false)?;
                    if !is_id(field) {
                        return Err(ParseError::InvalidValue);
                    }
                    value.reference.classification_id.set(field)?;
                    8
                }
                _ => return Err(ParseError::UnknownField),
            };
            if seen & bit != 0 {
                return Err(ParseError::DuplicateField);
            }
            seen |= bit;
            self.member_end()?;
        }
        match value.selector_kind {
            RawSelectorKind::Ip | RawSelectorKind::Cidr if seen == 3 => Ok(()),
            RawSelectorKind::Classification if seen == 13 => Ok(()),
            _ => Err(ParseError::InvalidValue),
        }
    }

    fn action(&mut self) -> Result<RuleEffect, ParseError> {
        match self.string(false)? {
            "allow" => Ok(RuleEffect::Allow),
            "deny" => Ok(RuleEffect::Deny),
            _ => Err(ParseError::InvalidValue),
        }
    }

    fn string(&mut self, allow_escape: bool) -> Result<&'a str, ParseError> {
        self.ws();
        if self.take() != Some(b'"') {
            return Err(ParseError::InvalidJson);
        }
        let start = self.offset;
        while let Some(byte) = self.take() {
            match byte {
                b'"' => {
                    let value = self
                        .input
                        .get(start..self.offset - 1)
                        .ok_or(ParseError::InvalidJson)?;
                    return core::str::from_utf8(value).map_err(|_| ParseError::InvalidJson);
                }
                b'\\' if !allow_escape => return Err(ParseError::InvalidValue),
                b'\\' => {
                    let escaped = self.take().ok_or(ParseError::InvalidJson)?;
                    if !matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        return Err(ParseError::InvalidJson);
                    }
                }
                0..=0x1f => return Err(ParseError::InvalidJson),
                _ => {}
            }
        }
        Err(ParseError::InvalidJson)
    }

    fn object_start(&mut self) -> Result<(), ParseError> {
        self.expect(b'{')
    }

    fn object_end(&mut self) -> Result<bool, ParseError> {
        self.ws();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn array_start(&mut self) -> Result<(), ParseError> {
        self.expect(b'[')
    }

    fn array_end(&mut self) -> Result<bool, ParseError> {
        self.ws();
        if self.peek() == Some(b']') {
            self.offset += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn colon(&mut self) -> Result<(), ParseError> {
        self.expect(b':')
    }

    fn member_end(&mut self) -> Result<(), ParseError> {
        self.ws();
        match self.peek() {
            Some(b',') => {
                self.offset += 1;
                self.ws();
                if self.peek() == Some(b'}') {
                    Err(ParseError::InvalidJson)
                } else {
                    Ok(())
                }
            }
            Some(b'}') => Ok(()),
            _ => Err(ParseError::InvalidJson),
        }
    }

    fn element_end(&mut self) -> Result<(), ParseError> {
        self.ws();
        match self.peek() {
            Some(b',') => {
                self.offset += 1;
                self.ws();
                if self.peek() == Some(b']') {
                    Err(ParseError::InvalidJson)
                } else {
                    Ok(())
                }
            }
            Some(b']') => Ok(()),
            _ => Err(ParseError::InvalidJson),
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), ParseError> {
        self.ws();
        if self.take() == Some(expected) {
            Ok(())
        } else {
            Err(ParseError::InvalidJson)
        }
    }

    fn end(&mut self) -> Result<(), ParseError> {
        self.ws();
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ParseError::InvalidJson)
        }
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.offset += 1;
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &[u8] = br#"{
      "schema":"sakullla.ip-policy/v1",
      "default_action":"allow",
      "datasets":[{"id":"geo","source_id":"geoip","classifications":[
        {"id":"cn","name":"cn","kind":"country"},
        {"id":"guangdong","name":"cn-44","kind":"region"}
      ]}],
      "province_whitelist":[{"dataset_id":"geo","classification_id":"guangdong"}],
      "rules":[
        {"id":"deny-lan","action":"deny","selector":{"type":"cidr","value":"10.0.0.0/8"}},
        {"id":"allow-cn","action":"allow","selector":{"type":"classification","dataset_id":"geo","classification_id":"cn"}}
      ]
    }"#;

    #[test]
    fn parses_strict_contract_and_resolves_references() {
        let config = Config::parse(CONFIG).unwrap();
        assert_eq!(config.default_action, RuleEffect::Allow);
        assert_eq!(config.dataset_len, 1);
        assert_eq!(config.classification_len, 2);
        assert_eq!(config.province_whitelist[0], 1);
        assert_eq!(config.rule_len, 2);
        assert!(matches!(
            config.rules[1].selector,
            Selector::Classification(0)
        ));

        let overlay = Overlay::parse(
            br#"{"schema":"sakullla.ip-policy-overlay/v1","rules":[{"id":"entry-deny","action":"deny","selector":{"type":"ip","value":"192.0.2.1"}}]}"#,
            &config,
        )
        .unwrap();
        assert_eq!(overlay.len, 1);
    }

    #[test]
    fn rejects_unknown_fields_duplicate_ids_and_noncanonical_cidr() {
        let mut unknown = CONFIG.to_vec();
        let end = unknown.iter().rposition(|byte| *byte == b'}').unwrap();
        unknown.splice(end..end, b",\"mode\":\"observe\"".iter().copied());
        assert_eq!(Config::parse(&unknown), Err(ParseError::UnknownField));

        let bad = core::str::from_utf8(CONFIG)
            .unwrap()
            .replace("10.0.0.0/8", "10.1.0.0/8");
        assert_eq!(Config::parse(bad.as_bytes()), Err(ParseError::InvalidValue));
    }

    #[test]
    fn province_gate_requires_one_of_the_31_region_codes() {
        let bad = core::str::from_utf8(CONFIG)
            .unwrap()
            .replace("cn-44", "cn-99");
        assert_eq!(Config::parse(bad.as_bytes()), Err(ParseError::InvalidValue));
    }
}
