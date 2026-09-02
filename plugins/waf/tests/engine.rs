use nre_policy_guest::PolicyAction;
use sakullla_waf::{
    BodyWindow, ConfigError, CustomRule, DecisionReason, Exclusion, NormalizedRequest, Target,
    TrustedSource, WafConfig, WafEngine, WafMode, decode_config, decode_overlay, prepare_config,
};

fn request<'a>(path: &'a [u8], query: &'a [u8], body: BodyWindow<'a>) -> NormalizedRequest<'a> {
    request_parts(path, query, b"content-type: application/json", body)
}

fn request_parts<'a>(
    path: &'a [u8],
    query: &'a [u8],
    headers: &'a [u8],
    body: BodyWindow<'a>,
) -> NormalizedRequest<'a> {
    NormalizedRequest {
        path,
        query,
        headers,
        trusted_source: TrustedSource {
            authenticated: true,
            address: b"192.0.2.10",
        },
        body,
    }
}

fn observe_engine() -> sakullla_waf::PreparedConfig {
    decode_config(br#"{}"#).unwrap()
}

fn deny_engine() -> sakullla_waf::PreparedConfig {
    decode_config(br#"{"mode":"deny"}"#).unwrap()
}

#[test]
fn artifact_config_decoder_is_exact_and_prepares_rules() {
    let config = decode_config(
        br#"{"mode":"deny","custom_rules":[{"id":"observe-probe","target":"path","needle":"observe"}],"exclusions":[{"rule_id":"observe-probe","path_prefix":"/allowed"}]}"#,
    )
    .unwrap();
    let engine = WafEngine::new(&config);
    assert_eq!(
        engine
            .evaluate(request(b"/observe", b"", BodyWindow::Complete(b"")))
            .action,
        PolicyAction::Deny
    );
    assert_eq!(
        engine
            .evaluate(request(b"/allowed/observe", b"", BodyWindow::Complete(b"")))
            .action,
        PolicyAction::Allow
    );
    for invalid in [
        br#"{"mode":"deny","unknown":true}"#.as_slice(),
        br#"{"mode":"deny","mode":"observe"}"#.as_slice(),
        br#"{"mode":"block"}"#.as_slice(),
        br#"{"mode":"deny","custom_rules":[{"id":"x","target":"path"}]}"#.as_slice(),
    ] {
        assert!(decode_config(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn default_config_observes_without_blocking() {
    let config = observe_engine();
    let result =
        WafEngine::new(&config).evaluate(request(b"/../../secret", b"", BodyWindow::Complete(b"")));
    assert_eq!(result.action, PolicyAction::Observe);
    assert_eq!(result.status_code, 0);
    assert_eq!(result.reason, DecisionReason::RuleMatched);
    assert_eq!(result.rule_id(), b"managed-path-traversal");
}

#[test]
fn managed_rule_denies_with_403() {
    let config = deny_engine();
    let result =
        WafEngine::new(&config).evaluate(request(b"/../../secret", b"", BodyWindow::Complete(b"")));
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
fn overlay_mode_overrides_instance_default() {
    let observe = observe_engine();
    let denied = WafEngine::new(&observe.with_mode(WafMode::Deny)).evaluate(request(
        b"/etc/passwd",
        b"",
        BodyWindow::Complete(b""),
    ));
    assert_eq!(denied.action, PolicyAction::Deny);
    assert_eq!(denied.status_code, 403);
    assert_eq!(denied.rule_id(), b"managed-path-etc-passwd");

    let instance_deny = deny_engine();
    let observed = WafEngine::new(&instance_deny.with_mode(WafMode::Observe)).evaluate(request(
        b"/etc/passwd",
        b"",
        BodyWindow::Complete(b""),
    ));
    assert_eq!(observed.action, PolicyAction::Observe);
    assert_eq!(observed.status_code, 0);
}

#[test]
fn overlay_decoder_accepts_observe_deny_and_absent() {
    assert_eq!(decode_overlay(b"").unwrap(), None);
    assert_eq!(decode_overlay(b"null").unwrap(), None);
    assert_eq!(decode_overlay(b"  ").unwrap(), None);
    assert_eq!(
        decode_overlay(br#"{"mode":"observe"}"#).unwrap(),
        Some(WafMode::Observe)
    );
    assert_eq!(
        decode_overlay(br#"{"mode":"deny"}"#).unwrap(),
        Some(WafMode::Deny)
    );
    for invalid in [
        br#"{}"#.as_slice(),
        br#"{"mode":"block"}"#.as_slice(),
        br#"{"mode":"deny","extra":true}"#.as_slice(),
        br#"[]"#.as_slice(),
        br#"not-json"#.as_slice(),
    ] {
        assert!(decode_overlay(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn managed_rules_cover_traversal_injection_xss_and_dangerous_features() {
    let config = observe_engine();
    let engine = WafEngine::new(&config);
    let cases = [
        (
            request(b"/etc/passwd", b"", BodyWindow::Complete(b"")),
            &b"managed-path-etc-passwd"[..],
        ),
        (
            request(b"/%2e%2e/secret", b"", BodyWindow::Complete(b"")),
            &b"managed-path-encoded-dotdot"[..],
        ),
        (
            request(b"/", b"q=1 OR 1=1", BodyWindow::Complete(b"")),
            &b"managed-sqli-or-1equal"[..],
        ),
        (
            request(b"/", b"q=javascript:alert(1)", BodyWindow::Complete(b"")),
            &b"managed-xss-javascript"[..],
        ),
        (
            request_parts(b"/", b"", b"${jndi:ldap://evil}", BodyWindow::Complete(b"")),
            &b"managed-log4j-jndi"[..],
        ),
        (
            request(b"/", b"", BodyWindow::Complete(b"<iframe src=x>")),
            &b"managed-xss-iframe"[..],
        ),
        (
            request(b"/app/.git/config", b"", BodyWindow::Complete(b"")),
            &b"managed-git-config"[..],
        ),
    ];
    let mut ids = Vec::new();
    for (input, want) in cases {
        let result = engine.evaluate(input);
        assert_eq!(
            result.reason,
            DecisionReason::RuleMatched,
            "rule {}",
            core::str::from_utf8(want).unwrap()
        );
        assert_eq!(result.action, PolicyAction::Observe);
        assert_eq!(result.rule_id(), want);
        ids.push(result.rule_id().to_vec());
    }
    ids.sort();
    ids.dedup();
    assert!(ids.len() > 4, "managed coverage collapsed to {:?}", ids);
}

#[test]
fn corpus_managed_attacks_match_and_benign_is_clean() {
    let config = observe_engine();
    let engine = WafEngine::new(&config);
    let attacks = include_str!("../../../testing/corpus/waf/managed-attacks.txt");
    let mut matched = 0;
    for line in attacks.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (kind, rest) = line.split_once(' ').expect("corpus target");
        let result = match kind {
            "PATH" => engine.evaluate(request(rest.as_bytes(), b"", BodyWindow::Complete(b""))),
            "QUERY" => engine.evaluate(request(b"/", rest.as_bytes(), BodyWindow::Complete(b""))),
            "HEADER" => engine.evaluate(request_parts(
                b"/",
                b"",
                rest.as_bytes(),
                BodyWindow::Complete(b""),
            )),
            "BODY" => engine.evaluate(request(b"/", b"", BodyWindow::Complete(rest.as_bytes()))),
            other => panic!("unknown corpus target {other}"),
        };
        assert_eq!(
            result.reason,
            DecisionReason::RuleMatched,
            "corpus line {line} was {}",
            result.reason.as_str()
        );
        assert_eq!(result.action, PolicyAction::Observe);
        matched += 1;
    }
    assert!(matched > 4, "corpus only exercised {matched} managed hits");

    let benign = include_str!("../../../testing/corpus/waf/benign.txt");
    assert!(benign.contains("/library?q=classic"));
    assert!(benign.contains("Union Station"));
    let clean = engine.evaluate(request(
        b"/library",
        b"q=classic",
        BodyWindow::Complete(br#"{"title":"Union Station"}"#),
    ));
    assert_eq!(clean.action, PolicyAction::Allow);
    assert_eq!(clean.reason, DecisionReason::Clean);
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
fn managed_exclusion_still_applies_to_expanded_rules() {
    let exclusions = [Exclusion {
        rule_id: "managed-path-etc-passwd",
        path_prefix: b"/etc/passwd",
    }];
    let config = prepare_config(WafConfig {
        mode: WafMode::Deny,
        custom_rules: &[],
        exclusions: &exclusions,
    })
    .unwrap();
    let engine = WafEngine::new(&config);
    assert_eq!(
        engine
            .evaluate(request(b"/etc/passwd", b"", BodyWindow::Complete(b"")))
            .action,
        PolicyAction::Allow
    );
    assert_eq!(
        engine
            .evaluate(request(
                b"/../../etc/passwd",
                b"",
                BodyWindow::Complete(b"")
            ))
            .action,
        PolicyAction::Deny
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
    let config = deny_engine().with_mode(WafMode::Deny);
    let mut input = request(b"/", b"", BodyWindow::Complete(b""));
    input.trusted_source.authenticated = false;
    let result = WafEngine::new(&config).evaluate(input);
    assert_eq!(result.action, PolicyAction::Observe);
    assert_eq!(result.reason, DecisionReason::TrustedSourceUnavailable);
}

#[test]
fn event_contains_digest_not_sensitive_request_material() {
    let config = deny_engine();
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
        event
            .windows(b"|deny|".len())
            .any(|value| value == b"|deny|")
    );
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
    assert!(
        !event
            .windows(b"/../../".len())
            .any(|value| value == b"/../../")
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
