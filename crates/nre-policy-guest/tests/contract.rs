use nre_policy_guest::{
    ABI_MAJOR_VERSION, AbiStatus, CANONICAL_DESCRIPTOR_SET_SHA256, DatasetClassification,
    DatasetClassificationKind, DatasetMatchCoverage, DatasetQueryRequest, DatasetQueryStatus,
    DatasetReference, DatasetResolveRequest, EvaluateRequest, FrameWriter, HostClient, HostImport,
    HostLimits, HostTransport, InitRequest, NormalizedHttpResponse, POLICY_ABI_V1, PolicyAction,
    PolicyResourceBudget, ReasonCode, RuntimeErrorCode, SecurityEventAction, SecurityEventCode,
    SecurityEventReason, TrustedSourceAuthority, WireCursor, WireLimits, encode_evaluate_error,
    encode_evaluate_success, pack_host_result, pack_policy_buffer, unpack_policy_buffer,
};

#[test]
fn generated_contract_identity_and_values_match_canonical_sdk() {
    assert_eq!(POLICY_ABI_V1, "nre:policy/v1");
    assert_eq!(ABI_MAJOR_VERSION, 1);
    assert_eq!(
        CANONICAL_DESCRIPTOR_SET_SHA256,
        "2abec011209434be336af2a245d10268c891914aa6f12b60c8eea2d71a8d5170"
    );
    assert_eq!(AbiStatus::ResourceExhausted as u32, 3);
    assert_eq!(RuntimeErrorCode::IncompatibleAbi as u32, 6);
    assert_eq!(PolicyAction::Observe as u32, 3);
    assert_eq!(TrustedSourceAuthority::Relay as u32, 4);
    assert_eq!(DatasetClassificationKind::Region as u32, 2);
    assert_eq!(DatasetMatchCoverage::UnsupportedFamily as u32, 3);
    assert_eq!(DatasetQueryStatus::InvalidData as u32, 7);
    assert_eq!(SecurityEventCode::IpCheckFailure as u32, 3);
    assert_eq!(SecurityEventAction::Allow as u32, 3);
    assert_eq!(SecurityEventReason::CoverageUnknown as u32, 9);
    assert_eq!(
        HostImport::ReadTrustedSource.name(),
        "nre_host_read_trusted_source"
    );
    assert_eq!(HostImport::DatasetQuery.name(), "nre_host_dataset_query");
    assert_eq!(
        HostImport::DatasetResolve.name(),
        "nre_host_dataset_resolve"
    );
    assert_eq!(
        unpack_policy_buffer(pack_policy_buffer(0x1234, 99)),
        (0x1234, 99)
    );
}

#[test]
fn strict_cursor_is_bounded_and_rejects_noncanonical_wire() {
    let mut cursor =
        WireCursor::new(&[0x08, 0x01, 0x12, 0x02, b'o', b'k'], WireLimits::new(6, 2)).unwrap();
    assert_eq!(cursor.next_field().unwrap().unwrap().number, 1);
    assert_eq!(cursor.next_field().unwrap().unwrap().number, 2);
    assert!(cursor.next_field().unwrap().is_none());

    let error = WireCursor::new(&[0x08, 0x81, 0x00], WireLimits::new(3, 1))
        .unwrap()
        .next_field()
        .unwrap_err();
    assert_eq!(error.reason, ReasonCode::NonCanonicalWire);

    let mut cursor = WireCursor::new(&[0x08, 0x01, 0x10, 0x01], WireLimits::new(4, 1)).unwrap();
    cursor.next_field().unwrap();
    assert_eq!(
        cursor.next_field().unwrap_err().reason,
        ReasonCode::FieldBudgetExceeded
    );

    // A tag whose field-number portion exceeds the protobuf u29 limit must not
    // become valid through integer truncation.
    let oversized_tag = [0x80, 0x80, 0x80, 0x80, 0x10, 0x01];
    assert_eq!(
        WireCursor::new(&oversized_tag, WireLimits::new(oversized_tag.len(), 1))
            .unwrap()
            .next_field()
            .unwrap_err()
            .reason,
        ReasonCode::InvalidWire
    );
}

#[test]
fn request_views_borrow_the_frame_without_allocation() {
    let frame = [
        0x0a, 0x02, b'{', b'}', 0x12, 0x04, b'h', b't', b't', b'p', 0x12, 0x05, b's', b't', b'a',
        b't', b'e', 0x1a, 0x02, b'g', b'1',
    ];
    let init = InitRequest::decode(&frame, WireLimits::new(frame.len(), 8)).unwrap();
    assert_eq!(init.config, b"{}");
    assert_eq!(init.generation, "g1");
    assert!(init.granted_scopes.contains("http").unwrap());
    assert!(init.granted_scopes.contains("state").unwrap());

    let frame = [
        0x0a, 0x0c, b'h', b't', b't', b'p', b'.', b'r', b'e', b'q', b'u', b'e', b's', b't', 0x12,
        0x02, b'r', b'1', 0x1a, 0x01, 0xff, 0x22, 0x03, 0x0a, 0x01, b'/',
    ];
    let request = EvaluateRequest::decode(&frame, WireLimits::new(frame.len(), 6)).unwrap();
    assert_eq!(request.extension_point, "http.request");
    assert_eq!(request.request_id, "r1");
    assert_eq!(request.payload, &[0xff]);
    assert_eq!(request.normalized_http, &[0x0a, 0x01, b'/']);
}

#[test]
fn normalized_http_snapshot_decodes_fixed_fields_without_allocation() {
    let frame = [
        0x0a, 0x05, b'/', b's', b'a', b'f', b'e', 0x12, 0x03, b'q', b'=', b'1', 0x1a, 0x02, b'x',
        b':', 0x22, 0x07, b'1', b'.', b'2', b'.', b'3', b'.', b'4', 0x28, 0x01, 0x30, 0x01, 0x38,
        0x11,
    ];
    let snapshot = NormalizedHttpResponse::decode(&frame, WireLimits::new(frame.len(), 8)).unwrap();
    assert_eq!(snapshot.path, b"/safe");
    assert_eq!(snapshot.query, b"q=1");
    assert_eq!(snapshot.headers, b"x:");
    assert_eq!(snapshot.trusted_source, b"1.2.3.4");
    assert!(snapshot.trusted_source_authenticated);
    assert!(snapshot.body_window_complete);
    assert_eq!(snapshot.body_window_length, 17);
}

#[test]
fn evaluate_result_encoding_is_deterministic_and_bounded() {
    let mut output = [0_u8; 32];
    let success = encode_evaluate_success(&mut output, PolicyAction::Allow, b"ok").unwrap();
    assert_eq!(success, &[0x0a, 0x06, 0x08, 0x01, 0x12, 0x02, b'o', b'k']);

    let mut output = [0_u8; 64];
    let error =
        encode_evaluate_error(&mut output, RuntimeErrorCode::Unavailable, "later", true).unwrap();
    assert_eq!(
        error,
        &[
            0x12, 0x0b, 0x08, 0x05, 0x12, 0x05, b'l', b'a', b't', b'e', b'r', 0x18, 0x01
        ]
    );

    let mut too_small = [0_u8; 3];
    assert_eq!(
        encode_evaluate_success(&mut too_small, PolicyAction::Deny, b"")
            .unwrap_err()
            .reason,
        ReasonCode::OutputBudgetExceeded
    );
}

#[derive(Default)]
struct RetryHost {
    calls: usize,
    capacities: [usize; 2],
}

impl HostTransport for RetryHost {
    fn call(&mut self, import: HostImport, request: &[u8], response: &mut [u8]) -> u64 {
        assert_eq!(import, HostImport::ReadField);
        assert_eq!(request, &[0x0a, 0x06, b'm', b'e', b't', b'h', b'o', b'd']);
        self.capacities[self.calls] = response.len();
        self.calls += 1;
        let encoded = [0x0a, 0x03, b'G', b'E', b'T', 0x10, 0x01];
        if response.len() < encoded.len() {
            return pack_host_result(AbiStatus::ResourceExhausted, encoded.len() as u32);
        }
        response[..encoded.len()].copy_from_slice(&encoded);
        pack_host_result(AbiStatus::Ok, encoded.len() as u32)
    }
}

#[test]
fn host_client_retries_once_within_fixed_response_budget() {
    let host = RetryHost::default();
    let mut client = HostClient::<_, 64, 32>::new(host, HostLimits::new(2, 2)).unwrap();
    let response = client.read_field("method").unwrap();
    assert_eq!(response.value, b"GET");
    assert!(response.found);
    assert_eq!(client.calls_used(), 2);
    let host = client.into_transport();
    assert_eq!(host.capacities, [2, 7]);
}

#[derive(Default)]
struct ExecutedThenExhaustedHost {
    calls: usize,
}

impl HostTransport for ExecutedThenExhaustedHost {
    fn call(&mut self, import: HostImport, _: &[u8], response: &mut [u8]) -> u64 {
        assert!(matches!(
            import,
            HostImport::StatePut | HostImport::EmitEvent | HostImport::AddMetric
        ));
        // Model a Host that performed the side effect but could not encode its
        // response in the supplied window. Reissuing this request would apply
        // the state/event/metric mutation twice.
        self.calls += 1;
        pack_host_result(
            AbiStatus::ResourceExhausted,
            response.len().saturating_add(1) as u32,
        )
    }
}

#[test]
fn side_effecting_imports_are_not_retried_after_exhaustion() {
    let limits = HostLimits::new(6, 1);

    let mut state =
        HostClient::<_, 64, 32>::new(ExecutedThenExhaustedHost::default(), limits).unwrap();
    assert_eq!(
        state.state_put("key", b"value").unwrap_err().reason,
        ReasonCode::HostResourceExhausted
    );
    assert_eq!(state.calls_used(), 1);
    assert_eq!(state.into_transport().calls, 1);

    let mut events =
        HostClient::<_, 64, 32>::new(ExecutedThenExhaustedHost::default(), limits).unwrap();
    assert_eq!(
        events
            .emit_event(SecurityEventCode::WafRuleMatch, SecurityEventAction::Deny)
            .unwrap_err()
            .reason,
        ReasonCode::HostResourceExhausted
    );
    assert_eq!(events.calls_used(), 1);
    assert_eq!(events.into_transport().calls, 1);

    let mut metrics =
        HostClient::<_, 64, 32>::new(ExecutedThenExhaustedHost::default(), limits).unwrap();
    assert_eq!(
        metrics.add_metric("matches", 1).unwrap_err().reason,
        ReasonCode::HostResourceExhausted
    );
    assert_eq!(metrics.calls_used(), 1);
    assert_eq!(metrics.into_transport().calls, 1);
}

struct OversizedHost;

impl HostTransport for OversizedHost {
    fn call(&mut self, _: HostImport, _: &[u8], _: &mut [u8]) -> u64 {
        pack_host_result(AbiStatus::ResourceExhausted, 33)
    }
}

#[test]
fn host_response_and_call_budgets_fail_closed() {
    let mut client = HostClient::<_, 16, 32>::new(OversizedHost, HostLimits::new(2, 1)).unwrap();
    assert_eq!(
        client.read_field("x").unwrap_err().reason,
        ReasonCode::HostResponseBudgetExceeded
    );

    let host = RetryHost::default();
    let mut client = HostClient::<_, 64, 32>::new(host, HostLimits::new(1, 2)).unwrap();
    assert_eq!(
        client.read_field("method").unwrap_err().reason,
        ReasonCode::HostCallBudgetExceeded
    );
}

#[test]
fn resource_budget_uses_canonical_ceilings() {
    let valid = PolicyResourceBudget {
        timeout_milliseconds: 2,
        memory_bytes: 16 << 20,
        concurrency: 64,
        input_frame_bytes: 128 << 10,
        output_frame_bytes: 4 << 10,
    };
    assert_eq!(valid.validate().unwrap(), valid);
    assert_eq!(
        PolicyResourceBudget {
            timeout_milliseconds: 3,
            ..valid
        }
        .validate()
        .unwrap_err()
        .reason,
        ReasonCode::InvalidResourceBudget
    );
}

#[test]
fn writer_reports_fixed_buffer_exhaustion() {
    let mut storage = [0_u8; 4];
    let mut writer = FrameWriter::new(&mut storage);
    assert_eq!(
        writer.write_string_field(1, "long").unwrap_err().reason,
        ReasonCode::OutputBudgetExceeded
    );
}

const TEST_HANDLE: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";
const TEST_DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Default)]
struct SecurityHost;

impl HostTransport for SecurityHost {
    fn call(&mut self, import: HostImport, _: &[u8], response: &mut [u8]) -> u64 {
        let mut nested = [0_u8; 1024];
        let mut nested_writer = FrameWriter::new(&mut nested);
        match import {
            HostImport::ReadTrustedSource => {
                nested_writer.write_string_field(1, "instance-1").unwrap();
                nested_writer.write_string_field(2, "generation-1").unwrap();
                nested_writer.write_string_field(3, "entry-1").unwrap();
                nested_writer.write_bytes_field(4, &[192, 0, 2, 1]).unwrap();
                nested_writer
                    .write_bytes_field(5, &[203, 0, 113, 9])
                    .unwrap();
                nested_writer.write_varint_field(6, 3).unwrap();
                let nested_len = nested_writer.len();
                let mut writer = FrameWriter::new(response);
                writer.write_bytes_field(1, &nested[..nested_len]).unwrap();
                pack_host_result(AbiStatus::Ok, writer.len() as u32)
            }
            HostImport::DatasetResolve => {
                write_reference(&mut nested_writer);
                let nested_len = nested_writer.len();
                let mut writer = FrameWriter::new(response);
                writer.write_bytes_field(1, &nested[..nested_len]).unwrap();
                pack_host_result(AbiStatus::Ok, writer.len() as u32)
            }
            HostImport::DatasetQuery => {
                write_reference(&mut nested_writer);
                let reference_len = nested_writer.len();
                let mut match_frame = [0_u8; 16];
                let mut match_writer = FrameWriter::new(&mut match_frame);
                match_writer.write_varint_field(1, 0).unwrap();
                match_writer.write_varint_field(2, 0).unwrap();
                match_writer.write_varint_field(3, 2).unwrap();
                let match_len = match_writer.len();
                let mut writer = FrameWriter::new(response);
                writer
                    .write_bytes_field(1, &nested[..reference_len])
                    .unwrap();
                writer.write_varint_field(2, 1).unwrap();
                writer
                    .write_bytes_field(3, &match_frame[..match_len])
                    .unwrap();
                pack_host_result(AbiStatus::Ok, writer.len() as u32)
            }
            _ => pack_host_result(AbiStatus::Unavailable, 0),
        }
    }
}

fn write_reference(writer: &mut FrameWriter<'_>) {
    writer.write_string_field(1, TEST_HANDLE).unwrap();
    writer.write_string_field(2, "instance-1").unwrap();
    writer.write_string_field(3, "generation-1").unwrap();
    writer.write_string_field(4, "geoip").unwrap();
    writer.write_string_field(5, TEST_DIGEST).unwrap();
}

#[test]
fn security_import_helpers_round_trip_typed_bounded_frames() {
    let mut host =
        HostClient::<_, 4096, 4096>::new(SecurityHost, HostLimits::new(3, 4096)).unwrap();
    let source = host.read_trusted_source().unwrap().source.unwrap();
    assert_eq!(source.generation, "generation-1");
    assert_eq!(source.source_address, &[203, 0, 113, 9]);
    assert_eq!(source.authority, TrustedSourceAuthority::Proxy);

    let resolved = host
        .dataset_resolve(DatasetResolveRequest {
            source_id: "geoip",
            max_duration_micros: 1000,
            max_response_bytes: 4096,
        })
        .unwrap()
        .reference
        .unwrap();
    assert_eq!(resolved.version_digest, TEST_DIGEST);

    let reference = DatasetReference {
        handle: TEST_HANDLE,
        instance_id: "instance-1",
        generation: "generation-1",
        source_id: "geoip",
        version_digest: TEST_DIGEST,
    };
    let classifications = [DatasetClassification {
        name: "cn-44",
        kind: DatasetClassificationKind::Region,
    }];
    let response = host
        .dataset_query(DatasetQueryRequest {
            reference,
            classifications: &classifications,
            max_duration_micros: 1000,
            max_response_bytes: 4096,
        })
        .unwrap();
    let matched = response.matches().next().unwrap().unwrap();
    assert!(!matched.matched);
    assert_eq!(matched.coverage, DatasetMatchCoverage::Unknown);
}
