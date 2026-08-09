const HTTP_SOURCE: &str = include_str!("../../../testing/corpus/rate-limit/http-source-limit.json");
const HTTP_GLOBAL: &str = include_str!("../../../testing/corpus/rate-limit/http-global-limit.json");
const L4_EXISTING: &str =
    include_str!("../../../testing/corpus/rate-limit/l4-existing-session.json");
const L4_NEW: &str = include_str!("../../../testing/corpus/rate-limit/l4-new-connection.json");
const GENERATION: &str = include_str!("../../../testing/corpus/rate-limit/generation-reset.json");
const CAPABILITIES: &str =
    include_str!("../../../testing/corpus/rate-limit/capabilities-unavailable.json");

#[test]
fn corpus_keeps_stable_boundary_expectations() {
    assert!(HTTP_SOURCE.contains("\"source_limited\""));
    assert!(HTTP_SOURCE.contains("\"denial_status\": 429"));
    assert!(HTTP_GLOBAL.contains("\"rule_global_limited\""));
    assert!(HTTP_GLOBAL.contains("\"denial_status\": 429"));
    assert!(L4_EXISTING.contains("\"expected_key_count\": 0"));
    assert!(L4_NEW.contains("\"l4_new_connection\""));
    assert!(GENERATION.contains("\"generation_ids\": [7, 8]"));
    assert!(CAPABILITIES.contains("\"policy.monotonic-clock\""));
    assert!(CAPABILITIES.contains("\"policy.atomic-state\""));
    assert!(CAPABILITIES.contains("\"expected_package_gate\": \"blocked\""));
}
