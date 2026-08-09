use nre_policy_guest::PolicyAction;

pub const MAX_CUSTOM_RULES: usize = 16;
pub const MAX_EXCLUSIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WafMode {
    Deny,
    Observe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Path,
    Query,
    Headers,
    Body,
}

#[derive(Clone, Copy, Debug)]
pub struct CustomRule<'a> {
    pub id: &'a str,
    pub target: Target,
    pub needle: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct Exclusion<'a> {
    pub rule_id: &'a str,
    pub path_prefix: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct WafConfig<'a> {
    pub mode: WafMode,
    pub custom_rules: &'a [CustomRule<'a>],
    pub exclusions: &'a [Exclusion<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    TooManyRules,
    TooManyExclusions,
    InvalidRuleId,
    InvalidNeedle,
    InvalidPathPrefix,
    DuplicateRuleId,
    UnknownExcludedRule,
}

#[derive(Clone, Copy, Debug)]
struct FixedBytes<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> FixedBytes<N> {
    const EMPTY: Self = Self {
        bytes: [0; N],
        len: 0,
    };

    fn new(value: &[u8]) -> Option<Self> {
        if value.is_empty() || value.len() > N {
            return None;
        }
        let mut fixed = Self::EMPTY;
        copy_bounded(&mut fixed.bytes, value)?;
        fixed.len = value.len() as u8;
        Some(fixed)
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len as usize).unwrap_or(&[])
    }
}

#[derive(Clone, Copy)]
struct PreparedRule {
    id: FixedBytes<32>,
    target: Target,
    needle: FixedBytes<64>,
}

#[derive(Clone, Copy)]
struct PreparedExclusion {
    rule_id: FixedBytes<32>,
    path_prefix: FixedBytes<96>,
}

#[derive(Clone, Copy)]
pub struct PreparedConfig {
    mode: WafMode,
    custom: [Option<PreparedRule>; MAX_CUSTOM_RULES],
    exclusions: [Option<PreparedExclusion>; MAX_EXCLUSIONS],
}

impl PreparedConfig {
    pub const fn managed_only(mode: WafMode) -> Self {
        Self {
            mode,
            custom: [None; MAX_CUSTOM_RULES],
            exclusions: [None; MAX_EXCLUSIONS],
        }
    }
}

pub fn prepare_config(config: WafConfig<'_>) -> Result<PreparedConfig, ConfigError> {
    if config.custom_rules.len() > MAX_CUSTOM_RULES {
        return Err(ConfigError::TooManyRules);
    }
    if config.exclusions.len() > MAX_EXCLUSIONS {
        return Err(ConfigError::TooManyExclusions);
    }
    let mut prepared = PreparedConfig::managed_only(config.mode);
    for (index, rule) in config.custom_rules.iter().enumerate() {
        if !valid_id(rule.id.as_bytes()) {
            return Err(ConfigError::InvalidRuleId);
        }
        if rule.needle.len() < 2 || !rule.needle.is_ascii() {
            return Err(ConfigError::InvalidNeedle);
        }
        for prior in config.custom_rules.iter().take(index) {
            if prior.id == rule.id {
                return Err(ConfigError::DuplicateRuleId);
            }
        }
        prepared.custom[index] = Some(PreparedRule {
            id: FixedBytes::new(rule.id.as_bytes()).ok_or(ConfigError::InvalidRuleId)?,
            target: rule.target,
            needle: FixedBytes::new(rule.needle).ok_or(ConfigError::InvalidNeedle)?,
        });
    }
    for (index, exclusion) in config.exclusions.iter().enumerate() {
        if !valid_id(exclusion.rule_id.as_bytes()) {
            return Err(ConfigError::InvalidRuleId);
        }
        if exclusion.path_prefix.first() != Some(&b'/') || !exclusion.path_prefix.is_ascii() {
            return Err(ConfigError::InvalidPathPrefix);
        }
        if !known_rule(config.custom_rules, exclusion.rule_id) {
            return Err(ConfigError::UnknownExcludedRule);
        }
        prepared.exclusions[index] = Some(PreparedExclusion {
            rule_id: FixedBytes::new(exclusion.rule_id.as_bytes())
                .ok_or(ConfigError::InvalidRuleId)?,
            path_prefix: FixedBytes::new(exclusion.path_prefix)
                .ok_or(ConfigError::InvalidPathPrefix)?,
        });
    }
    Ok(prepared)
}

fn known_rule(custom: &[CustomRule<'_>], id: &str) -> bool {
    MANAGED_RULES.iter().any(|rule| rule.id == id) || custom.iter().any(|rule| rule.id == id)
}

fn valid_id(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value[0].is_ascii_lowercase()
        && value
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[derive(Clone, Copy, Debug)]
pub struct TrustedSource<'a> {
    pub authenticated: bool,
    pub address: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub enum BodyWindow<'a> {
    Complete(&'a [u8]),
    Truncated(&'a [u8]),
    Unavailable,
}

#[derive(Clone, Copy, Debug)]
pub struct NormalizedRequest<'a> {
    pub site: &'a str,
    pub method: &'a [u8],
    pub path: &'a [u8],
    pub query: &'a [u8],
    pub headers: &'a [u8],
    pub trusted_source: TrustedSource<'a>,
    pub body: BodyWindow<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReason {
    Clean,
    RuleMatched,
    BodyWindowSkipped,
    TrustedSourceUnavailable,
}

impl DecisionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::RuleMatched => "rule_matched",
            Self::BodyWindowSkipped => "body_window_skipped",
            Self::TrustedSourceUnavailable => "trusted_source_unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Evaluation {
    pub action: PolicyAction,
    pub status_code: u16,
    pub reason: DecisionReason,
    rule_id: FixedBytes<32>,
    pub source_digest: u64,
}

impl Evaluation {
    pub fn rule_id(&self) -> &[u8] {
        self.rule_id.as_slice()
    }

    pub fn write_event(&self, site: &str, output: &mut [u8]) -> Option<usize> {
        let disposition = match self.action {
            PolicyAction::Deny => b"deny".as_slice(),
            PolicyAction::Observe => b"observe".as_slice(),
            _ => b"allow".as_slice(),
        };
        let digest = hex_u64(self.source_digest);
        join_event(
            output,
            &[
                site.as_bytes(),
                self.rule_id(),
                &digest,
                disposition,
                self.reason.as_str().as_bytes(),
            ],
        )
    }
}

pub struct WafEngine<'a> {
    config: &'a PreparedConfig,
}

impl<'a> WafEngine<'a> {
    pub const fn new(config: &'a PreparedConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(&self, request: NormalizedRequest<'_>) -> Evaluation {
        if !request.trusted_source.authenticated {
            return self.visible_skip(
                request.trusted_source.address,
                DecisionReason::TrustedSourceUnavailable,
            );
        }
        for rule in MANAGED_RULES {
            if self.excluded(rule.id.as_bytes(), request.path) {
                continue;
            }
            if contains_ascii_fold(target_bytes(rule.target, &request), rule.needle) {
                return self.matched(rule.id.as_bytes(), request.trusted_source.address);
            }
        }
        for rule in self.config.custom.iter().flatten() {
            if self.excluded(rule.id.as_slice(), request.path) {
                continue;
            }
            if contains_ascii_fold(target_bytes(rule.target, &request), rule.needle.as_slice()) {
                return self.matched(rule.id.as_slice(), request.trusted_source.address);
            }
        }
        if !matches!(request.body, BodyWindow::Complete(_)) {
            return self.visible_skip(
                request.trusted_source.address,
                DecisionReason::BodyWindowSkipped,
            );
        }
        Evaluation {
            action: PolicyAction::Allow,
            status_code: 0,
            reason: DecisionReason::Clean,
            rule_id: FixedBytes::EMPTY,
            source_digest: source_digest(request.trusted_source.address),
        }
    }

    fn matched(&self, id: &[u8], source: &[u8]) -> Evaluation {
        let deny = self.config.mode == WafMode::Deny;
        Evaluation {
            action: if deny {
                PolicyAction::Deny
            } else {
                PolicyAction::Observe
            },
            status_code: if deny { 403 } else { 0 },
            reason: DecisionReason::RuleMatched,
            rule_id: FixedBytes::new(id).unwrap_or(FixedBytes::EMPTY),
            source_digest: source_digest(source),
        }
    }

    fn visible_skip(&self, source: &[u8], reason: DecisionReason) -> Evaluation {
        Evaluation {
            action: PolicyAction::Observe,
            status_code: 0,
            reason,
            rule_id: FixedBytes::EMPTY,
            source_digest: source_digest(source),
        }
    }

    fn excluded(&self, rule_id: &[u8], path: &[u8]) -> bool {
        self.config.exclusions.iter().flatten().any(|exclusion| {
            exclusion.rule_id.as_slice() == rule_id
                && path.starts_with(exclusion.path_prefix.as_slice())
        })
    }
}

fn target_bytes<'a>(target: Target, request: &'a NormalizedRequest<'a>) -> &'a [u8] {
    match target {
        Target::Path => request.path,
        Target::Query => request.query,
        Target::Headers => request.headers,
        Target::Body => match request.body {
            BodyWindow::Complete(value) | BodyWindow::Truncated(value) => value,
            BodyWindow::Unavailable => &[],
        },
    }
}

fn contains_ascii_fold(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut offset = 0;
    while offset <= haystack.len() - needle.len() {
        let Some(window) = haystack.get(offset..offset + needle.len()) else {
            return false;
        };
        if window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.to_ascii_lowercase() == right.to_ascii_lowercase())
        {
            return true;
        }
        offset += 1;
    }
    false
}

fn source_digest(source: &[u8]) -> u64 {
    let mut digest = 0xcbf29ce484222325_u64;
    for byte in source {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x100000001b3);
    }
    digest
}

fn hex_u64(value: u64) -> [u8; 16] {
    let mut output = [0_u8; 16];
    for (index, slot) in output.iter_mut().enumerate() {
        let shift = (15 - index) * 4;
        let digit = ((value >> shift) & 0xf) as u8;
        *slot = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
    }
    output
}

fn join_event(output: &mut [u8], fields: &[&[u8]]) -> Option<usize> {
    let needed =
        fields.iter().map(|field| field.len()).sum::<usize>() + fields.len().saturating_sub(1);
    if needed > output.len() {
        return None;
    }
    let mut cursor = 0;
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            *output.get_mut(cursor)? = b'|';
            cursor += 1;
        }
        copy_bounded(output.get_mut(cursor..cursor + field.len())?, field)?;
        cursor += field.len();
    }
    Some(cursor)
}

fn copy_bounded(output: &mut [u8], input: &[u8]) -> Option<()> {
    if output.len() < input.len() {
        return None;
    }
    // SAFETY: the slices are equally sized and non-overlapping at every call site.
    unsafe { core::ptr::copy_nonoverlapping(input.as_ptr(), output.as_mut_ptr(), input.len()) };
    Some(())
}

pub(crate) struct ManagedRule {
    pub id: &'static str,
    pub target: Target,
    pub needle: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/managed_rules.rs"));
