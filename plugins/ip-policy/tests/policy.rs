use nre_policy_guest::PolicyAction;
use sakullla_ip_policy::{
    Cidr, DecisionReason, GeoFailurePolicy, GeoHandle, GeoLookup, GeoProvider, GeoRecord, GeoRule,
    GeoStatus, IpAddress, IpPolicy, PolicySet, RuleEffect, SourceAuthentication, TrustedSource,
};

struct Geo(GeoLookup);

impl GeoProvider for Geo {
    fn lookup(&self, _: GeoHandle<'_>, _: IpAddress) -> GeoLookup {
        self.0
    }
}

fn source(address: &str, authentication: SourceAuthentication) -> TrustedSource {
    TrustedSource {
        address: IpAddress::parse(address).unwrap(),
        authentication,
    }
}

#[test]
fn cidr_is_normalized_and_ipv4_ipv6_match() {
    let normalized = Cidr::parse("10.1.2.99/24").unwrap();
    assert_eq!(normalized.network().octets()[..4], [10, 1, 2, 0]);

    let mut set = PolicySet::<300>::new();
    set.insert(normalized, RuleEffect::Deny).unwrap();
    set.insert(Cidr::parse("2001:db8::/32").unwrap(), RuleEffect::Allow)
        .unwrap();
    assert!(set.contains(IpAddress::parse("10.1.2.7").unwrap(), RuleEffect::Deny));
    assert!(set.contains(IpAddress::parse("2001:db8::7").unwrap(), RuleEffect::Allow));
    assert!(!set.contains(IpAddress::parse("10.1.3.7").unwrap(), RuleEffect::Deny));
}

#[test]
fn deny_precedes_allow_across_shared_and_overlay() {
    let mut shared = PolicySet::<300>::new();
    shared
        .insert(Cidr::parse("10.0.0.0/8").unwrap(), RuleEffect::Deny)
        .unwrap();
    let mut overlay = PolicySet::<300>::new();
    overlay
        .insert(Cidr::parse("10.1.2.3/32").unwrap(), RuleEffect::Allow)
        .unwrap();
    let policy = IpPolicy {
        shared: &shared,
        overlay: Some(&overlay),
        geo_rules: &[],
        geo_handle: None,
        geo_failure: GeoFailurePolicy::Deny,
        default: RuleEffect::Allow,
    };
    let result = policy.evaluate(
        source("10.1.2.3", SourceAuthentication::Socket),
        &Geo(GeoLookup::Missing),
    );
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(result.reason, DecisionReason::SharedDeny);
    assert!(overlay.contains(IpAddress::parse("10.1.2.3").unwrap(), RuleEffect::Allow));
}

#[test]
fn forged_forwarded_source_fails_closed() {
    let shared = PolicySet::<8>::new();
    let policy = IpPolicy {
        shared: &shared,
        overlay: None,
        geo_rules: &[],
        geo_handle: None,
        geo_failure: GeoFailurePolicy::Deny,
        default: RuleEffect::Allow,
    };
    let result = policy.evaluate(
        source(
            "203.0.113.8",
            SourceAuthentication::UntrustedForwardedHeader,
        ),
        &Geo(GeoLookup::Missing),
    );
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(result.reason, DecisionReason::UnauthenticatedSource);
}

#[test]
fn geo_handle_status_is_visible_and_failure_policy_is_explicit() {
    let shared = PolicySet::<8>::new();
    let rules = [GeoRule {
        country: *b"US",
        region: None,
        effect: RuleEffect::Deny,
    }];
    let policy = IpPolicy {
        shared: &shared,
        overlay: None,
        geo_rules: &rules,
        geo_handle: Some(GeoHandle {
            id: "mmdb-managed",
            generation: 7,
        }),
        geo_failure: GeoFailurePolicy::Deny,
        default: RuleEffect::Allow,
    };
    let trusted = source("203.0.113.8", SourceAuthentication::Relay);
    let denied = policy.evaluate(
        trusted,
        &Geo(GeoLookup::Found(GeoRecord {
            country: *b"US",
            region: None,
        })),
    );
    assert_eq!(denied.reason, DecisionReason::GeoDeny);
    assert_eq!(denied.geo_status, GeoStatus::Fresh);
    let expired = policy.evaluate(trusted, &Geo(GeoLookup::Expired));
    assert_eq!(expired.reason, DecisionReason::GeoExpired);
    assert_eq!(expired.geo_status, GeoStatus::Expired);
}

#[test]
fn deterministic_corpus_covers_source_overlay_and_geo_states() {
    let corpus = include_str!("../../../testing/corpus/ip-policy/cases.txt");
    let cases: Vec<&str> = corpus
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(cases.len(), 5);
    assert!(cases.iter().any(|line| line.ends_with("|deny|shared-deny")));
    assert!(
        cases
            .iter()
            .any(|line| line.ends_with("|deny|overlay-deny"))
    );
    assert!(
        cases
            .iter()
            .any(|line| line.ends_with("|deny|unauthenticated-source"))
    );
    assert!(
        cases
            .iter()
            .any(|line| line.ends_with("|allow|default-allow"))
    );
    assert!(cases.iter().any(|line| line.ends_with("|deny|geo-expired")));
}
