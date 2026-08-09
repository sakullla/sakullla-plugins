use crate::{
    ConfigError, CustomRule, Exclusion, PreparedConfig, Target, WafConfig, WafMode, prepare_config,
};

const MAX_RULES: usize = 16;
const MAX_EXCLUSIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigDecodeError {
    InvalidJson,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidValue,
    Prepare(ConfigError),
}

#[derive(Clone, Copy)]
struct OwnedRule {
    id: [u8; 32],
    id_len: usize,
    target: Target,
    needle: [u8; 64],
    needle_len: usize,
}

impl OwnedRule {
    const EMPTY: Self = Self {
        id: [0; 32],
        id_len: 0,
        target: Target::Path,
        needle: [0; 64],
        needle_len: 0,
    };
}

#[derive(Clone, Copy)]
struct OwnedExclusion {
    rule_id: [u8; 32],
    rule_id_len: usize,
    path_prefix: [u8; 96],
    path_prefix_len: usize,
}

impl OwnedExclusion {
    const EMPTY: Self = Self {
        rule_id: [0; 32],
        rule_id_len: 0,
        path_prefix: [0; 96],
        path_prefix_len: 0,
    };
}

struct OwnedConfig {
    mode: WafMode,
    rules: [OwnedRule; MAX_RULES],
    rule_count: usize,
    exclusions: [OwnedExclusion; MAX_EXCLUSIONS],
    exclusion_count: usize,
}

impl OwnedConfig {
    fn prepare(&self) -> Result<PreparedConfig, ConfigDecodeError> {
        let empty_rule = CustomRule {
            id: "a",
            target: Target::Path,
            needle: b"aa",
        };
        let mut rules = [empty_rule; MAX_RULES];
        for (index, owned) in self.rules.iter().take(self.rule_count).enumerate() {
            let id = core::str::from_utf8(owned.id.get(..owned.id_len).unwrap_or(&[]))
                .map_err(|_| ConfigDecodeError::InvalidValue)?;
            let needle = owned
                .needle
                .get(..owned.needle_len)
                .ok_or(ConfigDecodeError::InvalidValue)?;
            if let Some(rule) = rules.get_mut(index) {
                *rule = CustomRule {
                    id,
                    target: owned.target,
                    needle,
                };
            }
        }
        let empty_exclusion = Exclusion {
            rule_id: "a",
            path_prefix: b"/",
        };
        let mut exclusions = [empty_exclusion; MAX_EXCLUSIONS];
        for (index, owned) in self
            .exclusions
            .iter()
            .take(self.exclusion_count)
            .enumerate()
        {
            let rule_id =
                core::str::from_utf8(owned.rule_id.get(..owned.rule_id_len).unwrap_or(&[]))
                    .map_err(|_| ConfigDecodeError::InvalidValue)?;
            let path_prefix = owned
                .path_prefix
                .get(..owned.path_prefix_len)
                .ok_or(ConfigDecodeError::InvalidValue)?;
            if let Some(exclusion) = exclusions.get_mut(index) {
                *exclusion = Exclusion {
                    rule_id,
                    path_prefix,
                };
            }
        }
        let rules = rules
            .get(..self.rule_count)
            .ok_or(ConfigDecodeError::InvalidValue)?;
        let exclusions = exclusions
            .get(..self.exclusion_count)
            .ok_or(ConfigDecodeError::InvalidValue)?;
        prepare_config(WafConfig {
            mode: self.mode,
            custom_rules: rules,
            exclusions,
        })
        .map_err(ConfigDecodeError::Prepare)
    }
}

pub fn decode_config(input: &[u8]) -> Result<PreparedConfig, ConfigDecodeError> {
    let mut parser = Parser { input, offset: 0 };
    let mut config = OwnedConfig {
        mode: WafMode::Deny,
        rules: [OwnedRule::EMPTY; MAX_RULES],
        rule_count: 0,
        exclusions: [OwnedExclusion::EMPTY; MAX_EXCLUSIONS],
        exclusion_count: 0,
    };
    let mut seen_mode = false;
    let mut seen_rules = false;
    let mut seen_exclusions = false;
    parser.expect(b'{')?;
    if !parser.consume(b'}') {
        loop {
            let mut key = [0; 24];
            let key_len = parser.string_into(&mut key)?;
            parser.expect(b':')?;
            match key.get(..key_len).ok_or(ConfigDecodeError::InvalidJson)? {
                b"mode" => {
                    if seen_mode {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_mode = true;
                    let mut value = [0; 8];
                    let length = parser.string_into(&mut value)?;
                    config.mode = match value.get(..length) {
                        Some(b"deny") => WafMode::Deny,
                        Some(b"observe") => WafMode::Observe,
                        _ => return Err(ConfigDecodeError::InvalidValue),
                    };
                }
                b"custom_rules" => {
                    if seen_rules {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_rules = true;
                    config.rule_count = parser.rules(&mut config.rules)?;
                }
                b"exclusions" => {
                    if seen_exclusions {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_exclusions = true;
                    config.exclusion_count = parser.exclusions(&mut config.exclusions)?;
                }
                _ => return Err(ConfigDecodeError::UnknownField),
            }
            if parser.consume(b'}') {
                break;
            }
            parser.expect(b',')?;
        }
    }
    parser.space();
    if parser.offset != input.len() {
        return Err(ConfigDecodeError::InvalidJson);
    }
    if !seen_mode {
        return Err(ConfigDecodeError::MissingField);
    }
    config.prepare()
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl Parser<'_> {
    fn rules(&mut self, output: &mut [OwnedRule; MAX_RULES]) -> Result<usize, ConfigDecodeError> {
        self.expect(b'[')?;
        let mut count = 0;
        if self.consume(b']') {
            return Ok(0);
        }
        loop {
            let slot = output
                .get_mut(count)
                .ok_or(ConfigDecodeError::InvalidValue)?;
            self.rule(slot)?;
            count += 1;
            if self.consume(b']') {
                return Ok(count);
            }
            self.expect(b',')?;
        }
    }

    fn rule(&mut self, output: &mut OwnedRule) -> Result<(), ConfigDecodeError> {
        self.expect(b'{')?;
        let mut seen_id = false;
        let mut seen_target = false;
        let mut seen_needle = false;
        if self.consume(b'}') {
            return Err(ConfigDecodeError::MissingField);
        }
        loop {
            let mut key = [0; 16];
            let length = self.string_into(&mut key)?;
            self.expect(b':')?;
            match key.get(..length) {
                Some(b"id") => {
                    if seen_id {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_id = true;
                    output.id_len = self.string_into(&mut output.id)?;
                }
                Some(b"target") => {
                    if seen_target {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_target = true;
                    let mut target = [0; 8];
                    let length = self.string_into(&mut target)?;
                    output.target = match target.get(..length) {
                        Some(b"path") => Target::Path,
                        Some(b"query") => Target::Query,
                        Some(b"headers") => Target::Headers,
                        Some(b"body") => Target::Body,
                        _ => return Err(ConfigDecodeError::InvalidValue),
                    };
                }
                Some(b"needle") => {
                    if seen_needle {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_needle = true;
                    output.needle_len = self.string_into(&mut output.needle)?;
                }
                _ => return Err(ConfigDecodeError::UnknownField),
            }
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        if !seen_id || !seen_target || !seen_needle {
            return Err(ConfigDecodeError::MissingField);
        }
        Ok(())
    }

    fn exclusions(
        &mut self,
        output: &mut [OwnedExclusion; MAX_EXCLUSIONS],
    ) -> Result<usize, ConfigDecodeError> {
        self.expect(b'[')?;
        let mut count = 0;
        if self.consume(b']') {
            return Ok(0);
        }
        loop {
            let slot = output
                .get_mut(count)
                .ok_or(ConfigDecodeError::InvalidValue)?;
            self.exclusion(slot)?;
            count += 1;
            if self.consume(b']') {
                return Ok(count);
            }
            self.expect(b',')?;
        }
    }

    fn exclusion(&mut self, output: &mut OwnedExclusion) -> Result<(), ConfigDecodeError> {
        self.expect(b'{')?;
        let mut seen_rule = false;
        let mut seen_prefix = false;
        if self.consume(b'}') {
            return Err(ConfigDecodeError::MissingField);
        }
        loop {
            let mut key = [0; 16];
            let length = self.string_into(&mut key)?;
            self.expect(b':')?;
            match key.get(..length) {
                Some(b"rule_id") => {
                    if seen_rule {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_rule = true;
                    output.rule_id_len = self.string_into(&mut output.rule_id)?;
                }
                Some(b"path_prefix") => {
                    if seen_prefix {
                        return Err(ConfigDecodeError::DuplicateField);
                    }
                    seen_prefix = true;
                    output.path_prefix_len = self.string_into(&mut output.path_prefix)?;
                }
                _ => return Err(ConfigDecodeError::UnknownField),
            }
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        if !seen_rule || !seen_prefix {
            return Err(ConfigDecodeError::MissingField);
        }
        Ok(())
    }

    fn string_into(&mut self, output: &mut [u8]) -> Result<usize, ConfigDecodeError> {
        self.space();
        if self.take() != Some(b'"') {
            return Err(ConfigDecodeError::InvalidJson);
        }
        let mut length = 0;
        loop {
            let value = match self.take() {
                Some(b'"') => return Ok(length),
                Some(b'\\') => self.escape()?,
                Some(value @ 0x20..=0x7e) => value,
                _ => return Err(ConfigDecodeError::InvalidValue),
            };
            let slot = output
                .get_mut(length)
                .ok_or(ConfigDecodeError::InvalidValue)?;
            *slot = value;
            length += 1;
        }
    }

    fn escape(&mut self) -> Result<u8, ConfigDecodeError> {
        match self.take() {
            Some(b'"') => Ok(b'"'),
            Some(b'\\') => Ok(b'\\'),
            Some(b'/') => Ok(b'/'),
            Some(b'b') => Ok(0x08),
            Some(b'f') => Ok(0x0c),
            Some(b'n') => Ok(b'\n'),
            Some(b'r') => Ok(b'\r'),
            Some(b't') => Ok(b'\t'),
            Some(b'u') => {
                let a = hex(self.take().ok_or(ConfigDecodeError::InvalidJson)?)?;
                let b = hex(self.take().ok_or(ConfigDecodeError::InvalidJson)?)?;
                let c = hex(self.take().ok_or(ConfigDecodeError::InvalidJson)?)?;
                let d = hex(self.take().ok_or(ConfigDecodeError::InvalidJson)?)?;
                if a != 0 || b != 0 {
                    return Err(ConfigDecodeError::InvalidValue);
                }
                Ok((c << 4) | d)
            }
            _ => Err(ConfigDecodeError::InvalidJson),
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), ConfigDecodeError> {
        self.space();
        if self.take() == Some(expected) {
            Ok(())
        } else {
            Err(ConfigDecodeError::InvalidJson)
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        self.space();
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn space(&mut self) {
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

fn hex(value: u8) -> Result<u8, ConfigDecodeError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ConfigDecodeError::InvalidJson),
    }
}
