use nre_policy_guest::PolicyAction;

use crate::{BucketSpec, GcraState, Preview};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StableId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MonotonicInstant(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionKind {
    Http,
    L4NewConnection,
    L4NewFlow,
    L4ExistingSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BucketScope {
    HttpSource,
    HttpRuleGlobal,
    L4Source,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterKey {
    pub generation: StableId,
    pub policy: StableId,
    pub rule: StableId,
    pub source: StableId,
    scope: BucketScope,
}

impl CounterKey {
    fn http_source(
        generation: StableId,
        policy: StableId,
        rule: StableId,
        source: StableId,
    ) -> Self {
        Self {
            generation,
            policy,
            rule,
            source,
            scope: BucketScope::HttpSource,
        }
    }

    fn http_global(generation: StableId, policy: StableId, rule: StableId) -> Self {
        Self {
            generation,
            policy,
            rule,
            source: StableId(0),
            scope: BucketScope::HttpRuleGlobal,
        }
    }

    fn l4_source(generation: StableId, policy: StableId, rule: StableId, source: StableId) -> Self {
        Self {
            generation,
            policy,
            rule,
            source,
            scope: BucketScope::L4Source,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReason {
    Allowed,
    ExistingSession,
    SourceLimited,
    RuleGlobalLimited,
    ClockRegressed,
    StateCapacityExhausted,
    InvalidConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    pub action: PolicyAction,
    pub http_status: Option<u16>,
    pub reason: DecisionReason,
    pub retry_after_ns: u64,
}

#[derive(Clone, Copy)]
struct Entry {
    key: Option<CounterKey>,
    state: GcraState,
}

impl Entry {
    const EMPTY: Self = Self {
        key: None,
        state: GcraState::new(),
    };
}

/// Fixed-capacity, process-local state. Callers serialize each instance; the
/// canonical Host must provide atomic cross-instance mutation before packaging.
pub struct LocalLimiter<const MAX_KEYS: usize> {
    entries: [Entry; MAX_KEYS],
    last_now: Option<MonotonicInstant>,
}

impl<const MAX_KEYS: usize> LocalLimiter<MAX_KEYS> {
    pub const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; MAX_KEYS],
            last_now: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        kind: AdmissionKind,
        now: MonotonicInstant,
        generation: StableId,
        policy: StableId,
        rule: StableId,
        source: StableId,
        source_spec: BucketSpec,
        global_spec: Option<BucketSpec>,
    ) -> Admission {
        if self.last_now.is_some_and(|last| now < last) {
            return deny(DecisionReason::ClockRegressed, 0, kind);
        }
        if matches!(kind, AdmissionKind::L4ExistingSession) {
            self.last_now = Some(now);
            return allow(DecisionReason::ExistingSession);
        }
        let source_key = match kind {
            AdmissionKind::Http => CounterKey::http_source(generation, policy, rule, source),
            AdmissionKind::L4NewConnection | AdmissionKind::L4NewFlow => {
                CounterKey::l4_source(generation, policy, rule, source)
            }
            AdmissionKind::L4ExistingSession => unreachable!(),
        };
        let global_key = matches!(kind, AdmissionKind::Http)
            .then(|| CounterKey::http_global(generation, policy, rule));
        let Some(source_index) = self.find_or_empty(source_key, None) else {
            return deny(DecisionReason::StateCapacityExhausted, 0, kind);
        };
        let global_index = match (global_key, global_spec) {
            (Some(key), Some(_)) => match self.find_or_empty(key, Some(source_index)) {
                Some(index) => Some(index),
                None => return deny(DecisionReason::StateCapacityExhausted, 0, kind),
            },
            (None, None) | (Some(_), None) => None,
            (None, Some(_)) => return deny(DecisionReason::InvalidConfig, 0, kind),
        };

        let source_preview = match self.entries[source_index].state.preview(now.0, source_spec) {
            Ok(preview) => preview,
            Err(_) => return deny(DecisionReason::InvalidConfig, 0, kind),
        };
        let global_preview = match (global_index, global_spec) {
            (Some(index), Some(spec)) => match self.entries[index].state.preview(now.0, spec) {
                Ok(preview) => Some(preview),
                Err(_) => return deny(DecisionReason::InvalidConfig, 0, kind),
            },
            _ => None,
        };
        if !source_preview.allowed {
            return deny(
                DecisionReason::SourceLimited,
                source_preview.retry_after_ns,
                kind,
            );
        }
        if let Some(preview) = global_preview
            && !preview.allowed
        {
            return deny(
                DecisionReason::RuleGlobalLimited,
                preview.retry_after_ns,
                kind,
            );
        }

        self.install_and_commit(source_index, source_key, source_preview);
        if let (Some(index), Some(key), Some(preview)) = (global_index, global_key, global_preview)
        {
            self.install_and_commit(index, key, preview);
        }
        self.last_now = Some(now);
        allow(DecisionReason::Allowed)
    }

    pub fn reset_generation(&mut self, generation: StableId) -> usize {
        let mut removed = 0;
        for entry in &mut self.entries {
            if entry.key.is_some_and(|key| key.generation == generation) {
                *entry = Entry::EMPTY;
                removed += 1;
            }
        }
        removed
    }

    /// Disabling a binding discards all local counters. Re-enabling starts
    /// from an empty generation-local state rather than resurrecting quota.
    pub fn disable(&mut self) -> usize {
        let removed = self.key_count();
        self.entries.fill(Entry::EMPTY);
        self.last_now = None;
        removed
    }

    pub fn key_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.key.is_some())
            .count()
    }

    fn find_or_empty(&self, key: CounterKey, excluded: Option<usize>) -> Option<usize> {
        if let Some(index) = self.entries.iter().position(|entry| entry.key == Some(key)) {
            return Some(index);
        }
        self.entries
            .iter()
            .enumerate()
            .find(|(index, entry)| Some(*index) != excluded && entry.key.is_none())
            .map(|(index, _)| index)
    }

    fn install_and_commit(&mut self, index: usize, key: CounterKey, preview: Preview) {
        let entry = &mut self.entries[index];
        if entry.key.is_none() {
            entry.key = Some(key);
        }
        entry.state.commit(preview);
    }
}

impl<const MAX_KEYS: usize> Default for LocalLimiter<MAX_KEYS> {
    fn default() -> Self {
        Self::new()
    }
}

const fn allow(reason: DecisionReason) -> Admission {
    Admission {
        action: PolicyAction::Allow,
        http_status: None,
        reason,
        retry_after_ns: 0,
    }
}

const fn deny(reason: DecisionReason, retry_after_ns: u64, kind: AdmissionKind) -> Admission {
    Admission {
        action: PolicyAction::Deny,
        http_status: if matches!(kind, AdmissionKind::Http) {
            Some(429)
        } else {
            None
        },
        reason,
        retry_after_ns,
    }
}
