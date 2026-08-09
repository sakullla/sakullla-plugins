use nre_policy_guest::PolicyAction;
use sakullla_waf::{
    BodyWindow, ConfigError, CustomRule, DecisionReason, Exclusion, NormalizedRequest, Target,
    TrustedSource, WafConfig, WafEngine, WafMode, prepare_config,
};

fn request<'a>(path: &'a [u8], query: &'a [u8], body: BodyWindow<'a>) -> NormalizedRequest<'a> {
    NormalizedRequest {
        site: "site-a",
        method: b"POST",
        path,
        query,
        headers: b"content-type: application/json",
        trusted_source: TrustedSource {
            authenticated: true,
            address: b"192.0.2.10",
        },
        body,
    }
}

#[test]
fn managed_rule_denies_with_403() {
    let config = prepare_config(WafConfig {
        mode: WafMode::Deny,
        custom_rules: &[],
        exclusions: &[],
    })
    .unwrap();
    let result = WafEngine::new(&config).evaluate(request(
        b"/../../etc/passwd",
        b"",
        BodyWindow::Complete(b""),
    ));
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(result.status_code, 403);
    assert_eq!(result.reason, DecisionReason::RuleMatched);
    assert_eq!(result.rule_id(), b"managed-path-traversal");
}

#[test]
fn observe_reports_without_blocking() {
    let config = prepare_config(WafConfig {
        mode: WafMode::Observe,
        custom_rules: &[],
        exclusions: &[],
    })
    .unwrap();
    let result = WafEngine::new(&config).evaluate(request(
        b"/",
        b"q=UNION SELECT password",
        BodyWindow::Complete(b""),
    ));
    assert_eq!(result.action, PolicyAction::Observe);
    assert_eq!(result.status_code, 0);
    assert_eq!(result.rule_id(), b"managed-sqli-union");
}

#[test]
fn custom_rule_and_exclusion_are_prepared() {
    let rules = [CustomRule {
        id: "private-probe",
        target: Target::Path,
        needle: b"/internal/probe",
    }];
    let exclusions = [Exclusion {
        rule_id: "private-probe",
        path_prefix: b"/internal/probe/allowed",
    }];
    let config = prepare_config(WafConfig {
        mode: WafMode::Deny,
        custom_rules: &rules,
        exclusions: &exclusions,
    })
    .unwrap();
    let engine = WafEngine::new(&config);
    assert_eq!(
        engine
            .evaluate(request(b"/internal/probe", b"", BodyWindow::Complete(b"")))
            .action,
        PolicyAction::Deny
    );
    assert_eq!(
        engine
            .evaluate(request(
                b"/internal/probe/allowed",
                b"",
                BodyWindow::Complete(b"")
            ))
            .action,
        PolicyAction::Allow
    );
}

#[test]
fn truncated_body_has_stable_visible_skip() {
    let config = prepare_config(WafConfig {
        mode: WafMode::Deny,
        custom_rules: &[],
        exclusions: &[],
    })
    .unwrap();
    let result = WafEngine::new(&config).evaluate(request(
        b"/upload",
        b"",
        BodyWindow::Truncated(b"prefix"),
    ));
    assert_eq!(result.action, PolicyAction::Observe);
    assert_eq!(result.reason, DecisionReason::BodyWindowSkipped);
}

#[test]
fn unauthenticated_source_fails_closed_to_visible_observe() {
    let config = prepare_config(WafConfig {
        mode: WafMode::Deny,
        custom_rules: &[],
        exclusions: &[],
    })
    .unwrap();
    let mut input = request(b"/", b"", BodyWindow::Complete(b""));
    input.trusted_source.authenticated = false;
    let result = WafEngine::new(&config).evaluate(input);
    assert_eq!(result.action, PolicyAction::Observe);
    assert_eq!(result.reason, DecisionReason::TrustedSourceUnavailable);
}

#[test]
fn event_contains_digest_not_sensitive_request_material() {
    let config = prepare_config(WafConfig {
        mode: WafMode::Deny,
        custom_rules: &[],
        exclusions: &[],
    })
    .unwrap();
    let result = WafEngine::new(&config).evaluate(request(
        b"/../../secret",
        b"token=secret",
        BodyWindow::Complete(b"password"),
    ));
    let mut event = [0; 256];
    let length = result.write_event("site-a", &mut event).unwrap();
    let event = &event[..length];
    assert!(event.starts_with(b"site-a|managed-path-traversal|"));
    assert!(
        !event
            .windows(b"secret".len())
            .any(|value| value == b"secret")
    );
    assert!(
        !event
            .windows(b"password".len())
            .any(|value| value == b"password")
    );
    assert!(
        !event
            .windows(b"192.0.2.10".len())
            .any(|value| value == b"192.0.2.10")
    );
}

#[test]
fn invalid_and_unknown_config_is_rejected_at_prepare() {
    let duplicate = [
        CustomRule {
            id: "same",
            target: Target::Path,
            needle: b"aa",
        },
        CustomRule {
            id: "same",
            target: Target::Query,
            needle: b"bb",
        },
    ];
    assert!(matches!(
        prepare_config(WafConfig {
            mode: WafMode::Deny,
            custom_rules: &duplicate,
            exclusions: &[]
        }),
        Err(ConfigError::DuplicateRuleId)
    ));
    let exclusion = [Exclusion {
        rule_id: "not-present",
        path_prefix: b"/",
    }];
    assert!(matches!(
        prepare_config(WafConfig {
            mode: WafMode::Deny,
            custom_rules: &[],
            exclusions: &exclusion
        }),
        Err(ConfigError::UnknownExcludedRule)
    ));
}
