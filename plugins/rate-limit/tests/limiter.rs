use std::sync::{Arc, Mutex};

use nre_policy_guest::PolicyAction;
use sakullla_rate_limit::{
    AdmissionKind, BucketSpec, DecisionReason, LocalLimiter, MonotonicInstant, StableId,
};

const GENERATION: StableId = StableId(1);
const POLICY: StableId = StableId(2);
const RULE: StableId = StableId(3);
const SOURCE: StableId = StableId(4);

fn spec(interval: u64, burst: u32) -> BucketSpec {
    BucketSpec {
        emission_interval_ns: interval,
        burst,
    }
}

fn admit<const N: usize>(
    limiter: &mut LocalLimiter<N>,
    kind: AdmissionKind,
    now: u64,
    source: StableId,
    source_spec: BucketSpec,
    global: Option<BucketSpec>,
) -> sakullla_rate_limit::Admission {
    limiter.admit(
        kind,
        MonotonicInstant(now),
        GENERATION,
        POLICY,
        RULE,
        source,
        source_spec,
        global,
    )
}

#[test]
fn http_source_and_rule_global_buckets_are_independent_and_return_429() {
    let mut limiter = LocalLimiter::<16>::new();
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::Http,
            0,
            StableId(10),
            spec(10, 10),
            Some(spec(10, 1))
        )
        .action,
        PolicyAction::Allow
    );
    let denied = admit(
        &mut limiter,
        AdmissionKind::Http,
        0,
        StableId(11),
        spec(10, 10),
        Some(spec(10, 1)),
    );
    assert_eq!(denied.reason, DecisionReason::RuleGlobalLimited);
    assert_eq!(denied.http_status, Some(429));
    // The failed dual-bucket admission did not consume source 11.
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::Http,
            10,
            StableId(11),
            spec(10, 1),
            Some(spec(10, 1))
        )
        .action,
        PolicyAction::Allow
    );
}

#[test]
fn l4_consumes_only_new_connection_or_flow() {
    let mut limiter = LocalLimiter::<8>::new();
    for _ in 0..10 {
        assert_eq!(
            admit(
                &mut limiter,
                AdmissionKind::L4ExistingSession,
                0,
                SOURCE,
                spec(100, 1),
                None
            )
            .reason,
            DecisionReason::ExistingSession
        );
    }
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::L4NewConnection,
            0,
            SOURCE,
            spec(100, 1),
            None
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::L4NewFlow,
            0,
            SOURCE,
            spec(100, 1),
            None
        )
        .reason,
        DecisionReason::SourceLimited
    );
}

#[test]
fn generation_reset_and_hot_update_do_not_reuse_old_keys() {
    let mut limiter = LocalLimiter::<8>::new();
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::L4NewConnection,
            0,
            SOURCE,
            spec(100, 1),
            None
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::L4NewConnection,
            0,
            SOURCE,
            spec(100, 1),
            None
        )
        .action,
        PolicyAction::Deny
    );
    let new_generation = limiter.admit(
        AdmissionKind::L4NewConnection,
        MonotonicInstant(0),
        StableId(9),
        POLICY,
        RULE,
        SOURCE,
        spec(50, 1),
        None,
    );
    assert_eq!(new_generation.action, PolicyAction::Allow);
    assert_eq!(limiter.reset_generation(GENERATION), 1);
    assert_eq!(limiter.key_count(), 1);
}

#[test]
fn disable_discards_local_counters_before_reenable() {
    let mut limiter = LocalLimiter::<8>::new();
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::Http,
            50,
            SOURCE,
            spec(100, 1),
            Some(spec(100, 1))
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(limiter.disable(), 2);
    assert_eq!(limiter.key_count(), 0);
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::Http,
            0,
            SOURCE,
            spec(100, 1),
            Some(spec(100, 1))
        )
        .action,
        PolicyAction::Allow
    );
}

#[test]
fn high_cardinality_state_is_bounded_and_fails_closed() {
    let mut limiter = LocalLimiter::<3>::new();
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::Http,
            0,
            StableId(10),
            spec(1, 10),
            Some(spec(1, 10))
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::Http,
            0,
            StableId(11),
            spec(1, 10),
            Some(spec(1, 10))
        )
        .action,
        PolicyAction::Allow
    );
    let denied = admit(
        &mut limiter,
        AdmissionKind::Http,
        0,
        StableId(12),
        spec(1, 10),
        Some(spec(1, 10)),
    );
    assert_eq!(denied.reason, DecisionReason::StateCapacityExhausted);
    assert_eq!(limiter.key_count(), 3);
}

#[test]
fn monotonic_regression_fails_closed() {
    let mut limiter = LocalLimiter::<4>::new();
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::L4NewConnection,
            10,
            SOURCE,
            spec(1, 2),
            None
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut limiter,
            AdmissionKind::L4NewConnection,
            9,
            SOURCE,
            spec(1, 2),
            None
        )
        .reason,
        DecisionReason::ClockRegressed
    );
}

#[test]
fn monotonic_observation_advances_on_denial_before_any_state_change() {
    let mut source_limited = LocalLimiter::<4>::new();
    assert_eq!(
        admit(
            &mut source_limited,
            AdmissionKind::L4NewConnection,
            100,
            SOURCE,
            spec(100, 1),
            None
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut source_limited,
            AdmissionKind::L4NewConnection,
            150,
            SOURCE,
            spec(100, 1),
            None
        )
        .reason,
        DecisionReason::SourceLimited
    );
    assert_eq!(
        admit(
            &mut source_limited,
            AdmissionKind::L4NewConnection,
            140,
            SOURCE,
            spec(100, 1),
            None
        )
        .reason,
        DecisionReason::ClockRegressed
    );

    let mut global_limited = LocalLimiter::<8>::new();
    assert_eq!(
        admit(
            &mut global_limited,
            AdmissionKind::Http,
            100,
            StableId(10),
            spec(1, 10),
            Some(spec(100, 1))
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut global_limited,
            AdmissionKind::Http,
            150,
            StableId(11),
            spec(1, 10),
            Some(spec(100, 1))
        )
        .reason,
        DecisionReason::RuleGlobalLimited
    );
    assert_eq!(
        admit(
            &mut global_limited,
            AdmissionKind::Http,
            140,
            StableId(11),
            spec(1, 10),
            Some(spec(100, 1))
        )
        .reason,
        DecisionReason::ClockRegressed
    );

    let mut capacity_limited = LocalLimiter::<1>::new();
    assert_eq!(
        admit(
            &mut capacity_limited,
            AdmissionKind::L4NewConnection,
            100,
            StableId(10),
            spec(1, 1),
            None
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut capacity_limited,
            AdmissionKind::L4NewConnection,
            150,
            StableId(11),
            spec(1, 1),
            None
        )
        .reason,
        DecisionReason::StateCapacityExhausted
    );
    assert_eq!(capacity_limited.reset_generation(GENERATION), 1);
    assert_eq!(capacity_limited.key_count(), 0);
    assert_eq!(
        admit(
            &mut capacity_limited,
            AdmissionKind::L4NewConnection,
            140,
            StableId(11),
            spec(1, 1),
            None
        )
        .reason,
        DecisionReason::ClockRegressed
    );
    assert_eq!(capacity_limited.key_count(), 0);
}

#[test]
fn concurrent_callers_share_one_atomic_process_boundary() {
    let limiter = Arc::new(Mutex::new(LocalLimiter::<8>::new()));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let limiter = Arc::clone(&limiter);
        threads.push(std::thread::spawn(move || {
            admit(
                &mut limiter.lock().unwrap(),
                AdmissionKind::L4NewConnection,
                0,
                SOURCE,
                spec(100, 4),
                None,
            )
            .action
        }));
    }
    let allowed = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|action| *action == PolicyAction::Allow)
        .count();
    assert_eq!(allowed, 4);
}

#[test]
fn independent_pool_instances_are_explicitly_node_local() {
    let mut first = LocalLimiter::<4>::new();
    let mut second = LocalLimiter::<4>::new();
    assert_eq!(
        admit(
            &mut first,
            AdmissionKind::L4NewConnection,
            0,
            SOURCE,
            spec(100, 1),
            None
        )
        .action,
        PolicyAction::Allow
    );
    assert_eq!(
        admit(
            &mut second,
            AdmissionKind::L4NewConnection,
            0,
            SOURCE,
            spec(100, 1),
            None
        )
        .action,
        PolicyAction::Allow
    );
}
