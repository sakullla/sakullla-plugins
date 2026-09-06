use nre_policy_guest::{
    AbiStatus, DatasetClassification as WireClassification, DatasetMatchCoverage,
    DatasetQueryRequest, DatasetQueryStatus, DatasetReference, DatasetResolveRequest, GuestError,
    HostClient, HostLimits, HostTransport, InitRequest, PolicyAction, PolicyDomainSource,
    PolicySecurityEvent, ReasonCode, RuntimeErrorCode, SecurityEventAction, SecurityEventCode,
    SecurityEventReason,
};

use crate::config::{Config, FixedStr, MAX_CLASSIFICATIONS, MAX_DATASETS, Overlay, Rule, Selector};
use crate::{IpAddress, RuleEffect};

const DATASET_CALL_MICROS: u32 = 1200;
const DATASET_RESPONSE_BYTES: u32 = 4096;
const HOST_CALLS: u16 = 8;

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const fn init_lifecycle_status(initialized: bool) -> AbiStatus {
    if initialized {
        AbiStatus::InvalidArgument
    } else {
        AbiStatus::Ok
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const fn reset_lifecycle_status(input_active: bool, output_active: bool) -> AbiStatus {
    if input_active || output_active {
        AbiStatus::InvalidArgument
    } else {
        AbiStatus::Ok
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const fn valid_input_allocation(size: u32, maximum: usize) -> bool {
    size != 0 && size as usize <= maximum
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedReference {
    handle: FixedStr<256>,
    instance_id: FixedStr<512>,
    generation: FixedStr<512>,
    source_id: FixedStr<32>,
    version_digest: FixedStr<71>,
}

pub fn emit_failure<H: HostTransport>(error: EvaluationError, transport: H) {
    if let Ok(mut host) = HostClient::<_, 64, 1>::new(transport, HostLimits::new(1, 1)) {
        let _ = host.emit_policy_event(error.event);
    }
}

impl OwnedReference {
    const EMPTY: Self = Self {
        handle: FixedStr::EMPTY,
        instance_id: FixedStr::EMPTY,
        generation: FixedStr::EMPTY,
        source_id: FixedStr::EMPTY,
        version_digest: FixedStr::EMPTY,
    };

    fn copy_from(reference: DatasetReference<'_>) -> Result<Self, RuntimeErrorCode> {
        let mut result = Self::EMPTY;
        result
            .handle
            .set(reference.handle)
            .map_err(|_| RuntimeErrorCode::InvalidArgument)?;
        result
            .instance_id
            .set(reference.instance_id)
            .map_err(|_| RuntimeErrorCode::InvalidArgument)?;
        result
            .generation
            .set(reference.generation)
            .map_err(|_| RuntimeErrorCode::InvalidArgument)?;
        result
            .source_id
            .set(reference.source_id)
            .map_err(|_| RuntimeErrorCode::InvalidArgument)?;
        result
            .version_digest
            .set(reference.version_digest)
            .map_err(|_| RuntimeErrorCode::InvalidArgument)?;
        Ok(result)
    }

    fn borrowed(&self) -> DatasetReference<'_> {
        DatasetReference {
            handle: self.handle.as_str(),
            instance_id: self.instance_id.as_str(),
            generation: self.generation.as_str(),
            source_id: self.source_id.as_str(),
            version_digest: self.version_digest.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeState {
    pub config: Config,
    generation: FixedStr<512>,
    references: [OwnedReference; MAX_DATASETS],
}

impl RuntimeState {
    pub fn initialize<H: HostTransport>(
        request: InitRequest<'_>,
        transport: H,
    ) -> Result<Self, RuntimeErrorCode> {
        if request.generation.is_empty()
            || !request
                .granted_scopes
                .contains("dataset.resolve")
                .map_err(map_guest)?
            || !request
                .granted_scopes
                .contains("dataset.query")
                .map_err(map_guest)?
            || !request
                .granted_scopes
                .contains("policy.trusted-source")
                .map_err(map_guest)?
        {
            return Err(RuntimeErrorCode::PermissionDenied);
        }
        let config =
            Config::parse(request.config).map_err(|_| RuntimeErrorCode::InvalidArgument)?;
        let mut generation = FixedStr::EMPTY;
        generation
            .set(request.generation)
            .map_err(|_| RuntimeErrorCode::InvalidArgument)?;
        let mut references = [OwnedReference::EMPTY; MAX_DATASETS];
        let mut host = HostClient::<_, 4096, 4096>::new(
            transport,
            HostLimits::new(HOST_CALLS, DATASET_RESPONSE_BYTES as usize),
        )
        .map_err(map_guest)?;
        for index in 0..config.dataset_len as usize {
            let source_id = config
                .datasets
                .get(index)
                .ok_or(RuntimeErrorCode::InvalidArgument)?
                .source_id
                .as_str();
            let response = host
                .dataset_resolve(DatasetResolveRequest {
                    source_id,
                    max_duration_micros: DATASET_CALL_MICROS,
                    max_response_bytes: DATASET_RESPONSE_BYTES,
                })
                .map_err(map_guest)?;
            let reference = response
                .reference
                .ok_or_else(|| map_runtime_failure(response.error.unwrap().code))?;
            if reference.source_id != source_id || reference.generation != request.generation {
                return Err(RuntimeErrorCode::PermissionDenied);
            }
            if index != 0
                && references.first().is_some_and(|first| {
                    reference.instance_id != first.instance_id.as_str()
                        || reference.generation != first.generation.as_str()
                })
            {
                return Err(RuntimeErrorCode::PermissionDenied);
            }
            *references
                .get_mut(index)
                .ok_or(RuntimeErrorCode::InvalidArgument)? = OwnedReference::copy_from(reference)?;
        }
        Ok(Self {
            config,
            generation,
            references,
        })
    }

    pub fn evaluate<H: HostTransport>(
        &self,
        overlay_payload: &[u8],
        transport: H,
    ) -> Result<Evaluation, EvaluationError> {
        let overlay = if overlay_payload.is_empty() {
            Overlay {
                rules: [crate::config::Rule {
                    id: FixedStr::EMPTY,
                    action: RuleEffect::Deny,
                    selector: Selector::Classification(0),
                }; crate::config::MAX_OVERLAY_RULES],
                len: 0,
            }
        } else {
            Overlay::parse(overlay_payload, &self.config)
                .map_err(|_| EvaluationError::data_invalid())?
        };
        let mut host = HostClient::<_, 16384, 4096>::new(
            transport,
            HostLimits::new(HOST_CALLS, DATASET_RESPONSE_BYTES as usize),
        )
        .map_err(EvaluationError::host)?;

        let trusted = host.read_trusted_source().map_err(EvaluationError::host)?;
        let source = match trusted.source {
            Some(source) => source,
            None => {
                return Err(EvaluationError::source_failure(trusted.error.unwrap().code));
            }
        };
        if source.generation != self.generation.as_str()
            || (self.config.dataset_len != 0
                && self
                    .references
                    .first()
                    .is_some_and(|reference| source.instance_id != reference.instance_id.as_str()))
        {
            return Err(EvaluationError::source_unauthenticated());
        }
        let address = IpAddress::from_network_bytes(source.source_address)
            .map_err(|_| EvaluationError::source_unauthenticated())?;
        if let Some((rule_index, rule)) = first_local_match(
            self.config.rules(),
            overlay.rules(),
            address,
            RuleEffect::Deny,
        ) {
            let decision = rule_decision(rule_index, rule.action, None);
            let _ = host.emit_policy_event(decision.event);
            return Ok(decision);
        }

        let mut lookups = [Lookup::EMPTY; MAX_CLASSIFICATIONS];
        self.query_required(&overlay, &mut host, &mut lookups)?;

        if self.config.province_len != 0 {
            let mut selected = None;
            let mut unknown = None;
            for raw in self
                .config
                .province_whitelist
                .get(..self.config.province_len as usize)
                .unwrap_or(&[])
            {
                let index = *raw as usize;
                let lookup = lookups
                    .get(index)
                    .copied()
                    .ok_or_else(EvaluationError::data_invalid)?;
                if lookup.coverage == DatasetMatchCoverage::Covered && lookup.matched {
                    selected = Some(index);
                    break;
                }
                if lookup.coverage != DatasetMatchCoverage::Covered && unknown.is_none() {
                    unknown = Some(index);
                }
            }
            if selected.is_none() {
                let first = self
                    .config
                    .province_whitelist
                    .first()
                    .copied()
                    .ok_or_else(EvaluationError::data_invalid)?;
                let index = unknown.unwrap_or(first as usize);
                let classification = self
                    .config
                    .classifications
                    .get(index)
                    .copied()
                    .ok_or_else(EvaluationError::data_invalid)?;
                let event = PolicySecurityEvent {
                    code: SecurityEventCode::IpRuleMatch,
                    action: SecurityEventAction::Deny,
                    rule_index: 0,
                    dataset_index: classification.dataset as u32 + 1,
                    classification_index: classification.index_in_dataset as u32 + 1,
                    outbound_index: 0,
                    reason: if unknown.is_some() {
                        SecurityEventReason::CoverageUnknown
                    } else {
                        SecurityEventReason::None
                    },
                    domain_source: PolicyDomainSource::Unspecified,
                };
                let _ = host.emit_policy_event(event);
                return Ok(Evaluation {
                    action: PolicyAction::Deny,
                    event,
                });
            }
        }

        for effect in [RuleEffect::Deny, RuleEffect::Allow] {
            for (rule_index, rule) in effective_rules(self.config.rules(), overlay.rules()) {
                if rule.action != effect {
                    continue;
                }
                let matched = match rule.selector {
                    Selector::Ip(expected) => expected == address,
                    Selector::Cidr(cidr) => cidr.contains(address),
                    Selector::Classification(index) => {
                        let classification = self
                            .config
                            .classifications
                            .get(index as usize)
                            .copied()
                            .ok_or_else(EvaluationError::data_invalid)?;
                        let lookup = lookups
                            .get(index as usize)
                            .copied()
                            .ok_or_else(EvaluationError::data_invalid)?;
                        if lookup.coverage != DatasetMatchCoverage::Covered {
                            return Err(EvaluationError::coverage(
                                classification.dataset as u32 + 1,
                                classification.index_in_dataset as u32 + 1,
                            ));
                        }
                        lookup.matched
                    }
                };
                if matched {
                    let classification = match rule.selector {
                        Selector::Classification(index) => {
                            self.config.classifications.get(index as usize).copied()
                        }
                        _ => None,
                    };
                    let decision = rule_decision(rule_index, effect, classification);
                    let _ = host.emit_policy_event(decision.event);
                    return Ok(decision);
                }
            }
        }

        Ok(Evaluation {
            action: match self.config.default_action {
                RuleEffect::Allow => PolicyAction::Allow,
                RuleEffect::Deny => PolicyAction::Deny,
            },
            event: PolicySecurityEvent {
                code: SecurityEventCode::IpRuleMatch,
                action: match self.config.default_action {
                    RuleEffect::Allow => SecurityEventAction::Allow,
                    RuleEffect::Deny => SecurityEventAction::Deny,
                },
                rule_index: 0,
                dataset_index: 0,
                classification_index: 0,
                outbound_index: 0,
                reason: SecurityEventReason::None,
                domain_source: PolicyDomainSource::Unspecified,
            },
        })
    }

    fn query_required<H: HostTransport>(
        &self,
        overlay: &Overlay,
        host: &mut HostClient<H, 16384, 4096>,
        lookups: &mut [Lookup; MAX_CLASSIFICATIONS],
    ) -> Result<(), EvaluationError> {
        let mut required = [false; MAX_CLASSIFICATIONS];
        for index in self
            .config
            .province_whitelist
            .get(..self.config.province_len as usize)
            .unwrap_or(&[])
        {
            *required
                .get_mut(*index as usize)
                .ok_or_else(EvaluationError::data_invalid)? = true;
        }
        for (_, rule) in effective_rules(self.config.rules(), overlay.rules()) {
            if let Selector::Classification(index) = rule.selector {
                *required
                    .get_mut(index as usize)
                    .ok_or_else(EvaluationError::data_invalid)? = true;
            }
        }

        for dataset_index in 0..self.config.dataset_len as usize {
            let dataset = self
                .config
                .datasets
                .get(dataset_index)
                .copied()
                .ok_or_else(EvaluationError::data_invalid)?;
            let start = dataset.classification_start as usize;
            let end = start + dataset.classification_len as usize;
            let mut wire = [WireClassification {
                name: "placeholder",
                kind: nre_policy_guest::DatasetClassificationKind::Cidr,
            }; 64];
            let mut mapping = [0u8; 64];
            let mut length = 0usize;
            for index in start..end {
                if required.get(index).copied().unwrap_or(false) {
                    let classification = self
                        .config
                        .classifications
                        .get(index)
                        .ok_or_else(EvaluationError::data_invalid)?;
                    *wire
                        .get_mut(length)
                        .ok_or_else(EvaluationError::data_invalid)? = WireClassification {
                        name: classification.name.as_str(),
                        kind: classification.kind,
                    };
                    *mapping
                        .get_mut(length)
                        .ok_or_else(EvaluationError::data_invalid)? = index as u8;
                    length += 1;
                }
            }
            if length == 0 {
                continue;
            }
            let request = DatasetQueryRequest {
                reference: self
                    .references
                    .get(dataset_index)
                    .ok_or_else(EvaluationError::data_invalid)?
                    .borrowed(),
                classifications: wire
                    .get(..length)
                    .ok_or_else(EvaluationError::data_invalid)?,
                max_duration_micros: DATASET_CALL_MICROS,
                max_response_bytes: DATASET_RESPONSE_BYTES,
            };
            let response = host.dataset_query(request).map_err(EvaluationError::host)?;
            if response.status != DatasetQueryStatus::Ok {
                return Err(EvaluationError::dataset_status(
                    response.status,
                    dataset_index as u32 + 1,
                ));
            }
            for item in response.matches() {
                let item = item.map_err(EvaluationError::host)?;
                let global = mapping
                    .get(item.index as usize)
                    .copied()
                    .ok_or_else(EvaluationError::data_invalid)?
                    as usize;
                *lookups
                    .get_mut(global)
                    .ok_or_else(EvaluationError::data_invalid)? = Lookup {
                    matched: item.matched,
                    coverage: item.coverage,
                };
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Lookup {
    matched: bool,
    coverage: DatasetMatchCoverage,
}

impl Lookup {
    const EMPTY: Self = Self {
        matched: false,
        coverage: DatasetMatchCoverage::Unspecified,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evaluation {
    pub action: PolicyAction,
    pub event: PolicySecurityEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationError {
    pub code: RuntimeErrorCode,
    pub event: PolicySecurityEvent,
}

impl EvaluationError {
    fn new(code: RuntimeErrorCode, reason: SecurityEventReason, dataset: u32, class: u32) -> Self {
        Self {
            code,
            event: PolicySecurityEvent {
                code: SecurityEventCode::IpCheckFailure,
                action: SecurityEventAction::Deny,
                rule_index: 0,
                dataset_index: dataset,
                classification_index: class,
                outbound_index: 0,
                reason,
                domain_source: PolicyDomainSource::Unspecified,
            },
        }
    }

    fn host(error: GuestError) -> Self {
        let reason = match error.reason {
            ReasonCode::HostResourceExhausted
            | ReasonCode::HostCallBudgetExceeded
            | ReasonCode::HostResponseBudgetExceeded
            | ReasonCode::HostDeadlineExceeded => SecurityEventReason::BudgetExceeded,
            ReasonCode::HostPermissionDenied => SecurityEventReason::SourceUnauthenticated,
            ReasonCode::InvalidWire | ReasonCode::NonCanonicalWire | ReasonCode::InvalidUtf8 => {
                SecurityEventReason::DataInvalid
            }
            _ => SecurityEventReason::DatasetUnavailable,
        };
        Self::new(map_guest(error), reason, 0, 0)
    }

    fn source_failure(code: RuntimeErrorCode) -> Self {
        let reason = match code {
            RuntimeErrorCode::ResourceExhausted | RuntimeErrorCode::DeadlineExceeded => {
                SecurityEventReason::BudgetExceeded
            }
            RuntimeErrorCode::InvalidArgument | RuntimeErrorCode::Internal => {
                SecurityEventReason::DataInvalid
            }
            _ => SecurityEventReason::SourceUnauthenticated,
        };
        Self::new(map_runtime_failure(code), reason, 0, 0)
    }

    fn source_unauthenticated() -> Self {
        Self::new(
            RuntimeErrorCode::PermissionDenied,
            SecurityEventReason::SourceUnauthenticated,
            0,
            0,
        )
    }

    fn data_invalid() -> Self {
        Self::new(
            RuntimeErrorCode::InvalidArgument,
            SecurityEventReason::DataInvalid,
            0,
            0,
        )
    }

    fn coverage(dataset: u32, class: u32) -> Self {
        Self::new(
            RuntimeErrorCode::Unavailable,
            SecurityEventReason::CoverageUnknown,
            dataset,
            class,
        )
    }

    fn dataset_status(status: DatasetQueryStatus, dataset: u32) -> Self {
        match status {
            DatasetQueryStatus::MissingClassification => Self::new(
                RuntimeErrorCode::Unavailable,
                SecurityEventReason::ClassificationMissing,
                dataset,
                0,
            ),
            DatasetQueryStatus::BudgetExceeded => Self::new(
                RuntimeErrorCode::ResourceExhausted,
                SecurityEventReason::BudgetExceeded,
                dataset,
                0,
            ),
            DatasetQueryStatus::InvalidData => Self::new(
                RuntimeErrorCode::Internal,
                SecurityEventReason::DataInvalid,
                dataset,
                0,
            ),
            _ => Self::new(
                RuntimeErrorCode::Unavailable,
                SecurityEventReason::DatasetUnavailable,
                dataset,
                0,
            ),
        }
    }
}

fn effective_rules<'a>(
    global: &'a [Rule],
    overlay: &'a [Rule],
) -> impl Iterator<Item = (u32, Rule)> + 'a {
    global
        .iter()
        .copied()
        .enumerate()
        .map(|(index, rule)| (index as u32 + 1, rule))
        .chain(
            overlay
                .iter()
                .copied()
                .enumerate()
                .map(move |(index, rule)| (global.len() as u32 + index as u32 + 1, rule)),
        )
}

fn first_local_match(
    global: &[Rule],
    overlay: &[Rule],
    address: IpAddress,
    effect: RuleEffect,
) -> Option<(u32, Rule)> {
    effective_rules(global, overlay)
        .find(|(_, rule)| rule.action == effect && rule.matches_local(address))
}

fn rule_decision(
    rule_index: u32,
    effect: RuleEffect,
    classification: Option<crate::config::Classification>,
) -> Evaluation {
    let (dataset_index, classification_index) = classification
        .map(|value| (value.dataset as u32 + 1, value.index_in_dataset as u32 + 1))
        .unwrap_or((0, 0));
    Evaluation {
        action: match effect {
            RuleEffect::Allow => PolicyAction::Allow,
            RuleEffect::Deny => PolicyAction::Deny,
        },
        event: PolicySecurityEvent {
            code: SecurityEventCode::IpRuleMatch,
            action: match effect {
                RuleEffect::Allow => SecurityEventAction::Allow,
                RuleEffect::Deny => SecurityEventAction::Deny,
            },
            rule_index,
            dataset_index,
            classification_index,
            outbound_index: 0,
            reason: SecurityEventReason::None,
            domain_source: PolicyDomainSource::Unspecified,
        },
    }
}

fn map_guest(error: GuestError) -> RuntimeErrorCode {
    match error.status {
        AbiStatus::InvalidArgument => RuntimeErrorCode::InvalidArgument,
        AbiStatus::PermissionDenied => RuntimeErrorCode::PermissionDenied,
        AbiStatus::ResourceExhausted => RuntimeErrorCode::ResourceExhausted,
        AbiStatus::DeadlineExceeded => RuntimeErrorCode::DeadlineExceeded,
        AbiStatus::Unavailable => RuntimeErrorCode::Unavailable,
        AbiStatus::IncompatibleAbi => RuntimeErrorCode::IncompatibleAbi,
        AbiStatus::Internal | AbiStatus::Ok => RuntimeErrorCode::Internal,
    }
}

fn map_runtime_failure(code: RuntimeErrorCode) -> RuntimeErrorCode {
    if code == RuntimeErrorCode::Unspecified {
        RuntimeErrorCode::Internal
    } else {
        code
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn abi_sequence_preserves_initialized_runtime_across_request_resets() {
        let mut initialized = false;
        assert_eq!(init_lifecycle_status(initialized), AbiStatus::Ok);
        initialized = true;

        assert!(initialized);
        assert_eq!(reset_lifecycle_status(false, false), AbiStatus::Ok);
        assert!(initialized);
        assert_eq!(reset_lifecycle_status(false, false), AbiStatus::Ok);
        assert!(initialized);

        assert_eq!(
            init_lifecycle_status(initialized),
            AbiStatus::InvalidArgument
        );
        assert_eq!(
            reset_lifecycle_status(true, false),
            AbiStatus::InvalidArgument
        );
        assert_eq!(
            reset_lifecycle_status(false, true),
            AbiStatus::InvalidArgument
        );
        assert!(!valid_input_allocation(0, 128 << 10));
        assert!(!valid_input_allocation((128 << 10) + 1, 128 << 10));
        assert!(valid_input_allocation(1024, 128 << 10));
    }
}
