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
    let mut executed = 0;
    for line in corpus
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields.len(), 5, "invalid corpus row: {line}");
        let (id, address, provenance, expected_action, expected_reason) =
            (fields[0], fields[1], fields[2], fields[3], fields[4]);

        let mut shared = PolicySet::<300>::new();
        let mut overlay = PolicySet::<300>::new();
        let exact_cidr = format!("{address}/{}", if address.contains(':') { 128 } else { 32 });
        if id == "shared-ipv4-deny" {
            shared
                .insert(Cidr::parse(&exact_cidr).unwrap(), RuleEffect::Deny)
                .unwrap();
        }
        if id == "overlay-ipv6-deny" {
            overlay
                .insert(Cidr::parse(&exact_cidr).unwrap(), RuleEffect::Deny)
                .unwrap();
        }
        let geo_rules = [GeoRule {
            country: *b"US",
            region: None,
            effect: RuleEffect::Deny,
        }];
        let use_geo = id == "geo-expired";
        let policy = IpPolicy {
            shared: &shared,
            overlay: (id == "overlay-ipv6-deny").then_some(&overlay),
            geo_rules: if use_geo { &geo_rules } else { &[] },
            geo_handle: use_geo.then_some(GeoHandle {
                id: "mmdb-managed",
                generation: 7,
            }),
            geo_failure: GeoFailurePolicy::Deny,
            default: RuleEffect::Allow,
        };
        let authentication = match provenance {
            "socket" => SourceAuthentication::Socket,
            "proxy" => SourceAuthentication::ProxyProtocol,
            "relay" => SourceAuthentication::Relay,
            "xff" => SourceAuthentication::UntrustedForwardedHeader,
            other => panic!("unknown corpus provenance: {other}"),
        };
        let result = policy.evaluate(
            source(address, authentication),
            &Geo(if use_geo {
                GeoLookup::Expired
            } else {
                GeoLookup::Missing
            }),
        );
        let action = match expected_action {
            "allow" => PolicyAction::Allow,
            "deny" => PolicyAction::Deny,
            other => panic!("unknown expected action: {other}"),
        };
        let reason = match expected_reason {
            "shared-deny" => DecisionReason::SharedDeny,
            "overlay-deny" => DecisionReason::OverlayDeny,
            "unauthenticated-source" => DecisionReason::UnauthenticatedSource,
            "default-allow" => DecisionReason::DefaultAllow,
            "geo-expired" => DecisionReason::GeoExpired,
            other => panic!("unknown expected reason: {other}"),
        };
        assert_eq!(
            (result.action, result.reason),
            (action, reason),
            "case {id}"
        );
        executed += 1;
    }
    assert_eq!(executed, 5);
}
