package hostfixture

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func ipPolicyConfig() []byte {
	return []byte(`{"schema":"sakullla.ip-policy/v1","default_action":"allow","datasets":[{"id":"province-data","source_id":"dbip-cn-province","classifications":[{"id":"guangdong","name":"cn-44","kind":"region"}]}],"province_whitelist":[{"dataset_id":"province-data","classification_id":"guangdong"}],"rules":[{"id":"deny-probe","action":"deny","selector":{"type":"cidr","value":"198.51.100.0/24"}}]}`)
}

func ipPolicyOptions() wafArtifactOptions {
	reference := pluginsdk.DatasetReference{Handle: strings.Repeat("a", 43), InstanceID: "ip-instance", Generation: "generation-1", SourceID: "dbip-cn-province", VersionDigest: "sha256:" + strings.Repeat("1", 64)}
	source := &pluginsdk.PolicyTrustedSource{InstanceID: "ip-instance", Generation: "generation-1", EntryID: "entry-1", PeerAddress: netip.MustParseAddr("192.0.2.10"), SourceAddress: netip.MustParseAddr("192.0.2.10"), Authority: pluginsdk.PolicySourceSocket}
	return wafArtifactOptions{
		config: ipPolicyConfig(), generation: "generation-1", extensionPoint: "http.request",
		grants:        []string{string(pluginsdk.CapabilityDatasetResolve), string(pluginsdk.CapabilityDatasetQuery), string(pluginsdk.CapabilityPolicyTrustedSource), "http.inspect", "l4.inspect", "event.emit"},
		trustedSource: source, datasetReferences: map[string]pluginsdk.DatasetReference{"dbip-cn-province": reference},
		datasetMatches: map[string]pluginsdk.DatasetMatch{"region:cn-44": {Matched: true, Coverage: pluginsdk.DatasetCovered}},
	}
}

func TestIPPolicyArtifactUsesTrustedSourceAndImmutableDataset(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	options := ipPolicyOptions()
	if err := pluginsdk.ValidatePolicyV1WASMForHost(artifact, pluginsdk.PolicyV1MaxMemoryBytes, options.grants, options.grants, policyHostImports()); err != nil {
		t.Fatalf("IP policy artifact violates current Host contract: %v", err)
	}
	if bytes.Contains(artifact, []byte("wasi_snapshot_preview1")) {
		t.Fatal("IP policy artifact unexpectedly imports WASI")
	}
	session, status := startWAFArtifact(t, artifact, options)
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK {
		t.Fatalf("init status = %d", status)
	}
	if action := session.Evaluate(); action != pluginsdk.PolicyActionAllow {
		t.Fatalf("covered Guangdong action = %d", action)
	}
	if len(session.lastPayload) != 0 {
		t.Fatalf("success payload contains diagnostics: %x", session.lastPayload)
	}
	if session.HostCalls(pluginsdk.PolicyHostDatasetResolve) != 1 || session.HostCalls(pluginsdk.PolicyHostReadTrustedSource) != 1 || session.HostCalls(pluginsdk.PolicyHostDatasetQuery) != 1 {
		t.Fatalf("Host calls resolve/source/query = %d/%d/%d", session.HostCalls(pluginsdk.PolicyHostDatasetResolve), session.HostCalls(pluginsdk.PolicyHostReadTrustedSource), session.HostCalls(pluginsdk.PolicyHostDatasetQuery))
	}
}

func TestIPPolicyProvinceUnknownAndExplicitCIDRDeny(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	t.Run("unknown province coverage", func(t *testing.T) {
		unknown := ipPolicyOptions()
		unknown.datasetMatches["region:cn-44"] = pluginsdk.DatasetMatch{Coverage: pluginsdk.DatasetUnknown}
		session, status := startWAFArtifact(t, artifact, unknown)
		defer session.Close()
		if status != pluginsdk.PolicyStatusOK {
			t.Fatalf("unknown init status = %d", status)
		}
		if action := session.Evaluate(); action != pluginsdk.PolicyActionDeny {
			t.Fatalf("unknown province coverage action = %d", action)
		}
		events := session.SecurityEvents()
		if len(events) == 0 || events[len(events)-1].Code != pluginsdk.PolicySecurityEventCodeIPRuleMatch || events[len(events)-1].Reason != pluginsdk.PolicySecurityEventReasonCoverageUnknown || events[len(events)-1].Action != pluginsdk.PolicySecurityEventActionDeny {
			t.Fatalf("unknown coverage events = %+v", events)
		}
	})
	t.Run("explicit CIDR deny", func(t *testing.T) {
		blocked := ipPolicyOptions()
		blocked.trustedSource.SourceAddress = netip.MustParseAddr("198.51.100.7")
		blocked.trustedSource.PeerAddress = blocked.trustedSource.SourceAddress
		blocked.datasetMatches["region:cn-44"] = pluginsdk.DatasetMatch{Matched: true, Coverage: pluginsdk.DatasetCovered}
		session, status := startWAFArtifact(t, artifact, blocked)
		defer session.Close()
		if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionDeny {
			t.Fatalf("CIDR deny status=%d", status)
		}
	})
}

func TestIPPolicyTrustedSourceAcrossHTTPAndL4EntryKinds(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	for _, test := range []struct {
		name, extension, entry string
		authority              pluginsdk.PolicySourceAuthority
	}{
		{name: "http xff", extension: "http.request", entry: "http-7", authority: pluginsdk.PolicySourceXFF},
		{name: "tcp socket", extension: "l4.accept", entry: "tcp-8", authority: pluginsdk.PolicySourceSocket},
		{name: "udp proxy", extension: "l4.accept", entry: "udp-9", authority: pluginsdk.PolicySourcePROXY},
		{name: "managed relay", extension: "l4.accept", entry: "ss-instance", authority: pluginsdk.PolicySourceRelay},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := ipPolicyOptions()
			options.extensionPoint = test.extension
			options.trustedSource.EntryID = test.entry
			options.trustedSource.Authority = test.authority
			session, status := startWAFArtifact(t, artifact, options)
			defer session.Close()
			if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionAllow {
				t.Fatalf("entry=%s authority=%d status=%d", test.entry, test.authority, status)
			}
		})
	}
}

func TestIPPolicyReportsTypedSourceDatasetAndBudgetFailures(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	for _, test := range []struct {
		name       string
		configure  func(*wafArtifactOptions)
		wantReason pluginsdk.PolicySecurityEventReason
	}{
		{name: "forged source", configure: func(options *wafArtifactOptions) {
			options.trustedSourceStatus = pluginsdk.PolicyStatusPermissionDenied
		}, wantReason: pluginsdk.PolicySecurityEventReasonSourceUnauthenticated},
		{name: "dataset unavailable", configure: func(options *wafArtifactOptions) { options.datasetStatus = pluginsdk.DatasetQueryUnavailable }, wantReason: pluginsdk.PolicySecurityEventReasonDatasetUnavailable},
		{name: "classification missing", configure: func(options *wafArtifactOptions) { options.datasetStatus = pluginsdk.DatasetQueryMissingClassification }, wantReason: pluginsdk.PolicySecurityEventReasonClassificationMissing},
		{name: "budget exceeded", configure: func(options *wafArtifactOptions) { options.datasetStatus = pluginsdk.DatasetQueryBudgetExceeded }, wantReason: pluginsdk.PolicySecurityEventReasonBudgetExceeded},
		{name: "invalid data", configure: func(options *wafArtifactOptions) { options.datasetStatus = pluginsdk.DatasetQueryInvalidData }, wantReason: pluginsdk.PolicySecurityEventReasonDataInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := ipPolicyOptions()
			test.configure(&options)
			session, status := startWAFArtifact(t, artifact, options)
			defer session.Close()
			if status != pluginsdk.PolicyStatusOK || !session.EvaluateHasError() {
				t.Fatalf("failure status=%d", status)
			}
			events := session.SecurityEvents()
			if len(events) == 0 || events[len(events)-1].Code != pluginsdk.PolicySecurityEventCodeIPCheckFailure || events[len(events)-1].Reason != test.wantReason || events[len(events)-1].Action != pluginsdk.PolicySecurityEventActionDeny {
				t.Fatalf("failure events=%+v", events)
			}
		})
	}
}

func TestIPPolicyProvinceWhitelistMatrixAndCountryCannotExpandIt(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	config := []byte(`{"schema":"sakullla.ip-policy/v1","default_action":"allow","datasets":[{"id":"province-data","source_id":"dbip-cn-province","classifications":[{"id":"beijing","name":"cn-11","kind":"region"},{"id":"jiangsu","name":"cn-32","kind":"region"},{"id":"guangdong","name":"cn-44","kind":"region"},{"id":"guangxi","name":"cn-45","kind":"region"},{"id":"china","name":"cn","kind":"country"}]}],"province_whitelist":[{"dataset_id":"province-data","classification_id":"jiangsu"},{"dataset_id":"province-data","classification_id":"guangdong"}],"rules":[{"id":"allow-china","action":"allow","selector":{"type":"classification","dataset_id":"province-data","classification_id":"china"}}]}`)
	for _, test := range []struct {
		name, matched string
		unknown       string
		want          pluginsdk.PolicyAction
	}{
		{name: "Guangdong", matched: "region:cn-44", want: pluginsdk.PolicyActionAllow},
		{name: "Jiangsu", matched: "region:cn-32", want: pluginsdk.PolicyActionAllow},
		{name: "Beijing", matched: "region:cn-11", want: pluginsdk.PolicyActionDeny},
		{name: "Guangxi", matched: "region:cn-45", want: pluginsdk.PolicyActionDeny},
		{name: "foreign despite country allow", matched: "country:cn", want: pluginsdk.PolicyActionDeny},
		{name: "unknown", unknown: "region:cn-44", want: pluginsdk.PolicyActionDeny},
		{name: "IPv6 partial", unknown: "region:cn-32", want: pluginsdk.PolicyActionDeny},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := ipPolicyOptions()
			options.config = config
			options.datasetMatches = map[string]pluginsdk.DatasetMatch{}
			for _, classification := range []string{"region:cn-11", "region:cn-32", "region:cn-44", "region:cn-45", "country:cn"} {
				options.datasetMatches[classification] = pluginsdk.DatasetMatch{Coverage: pluginsdk.DatasetCovered, Matched: classification == test.matched}
			}
			if test.unknown != "" {
				options.datasetMatches[test.unknown] = pluginsdk.DatasetMatch{Coverage: pluginsdk.DatasetUnknown}
			}
			session, status := startWAFArtifact(t, artifact, options)
			defer session.Close()
			if status != pluginsdk.PolicyStatusOK || session.Evaluate() != test.want {
				t.Fatalf("status=%d matched=%q unknown=%q", status, test.matched, test.unknown)
			}
		})
	}
}

func TestIPPolicyGenerationIsolationAndGlobalDenyOverEntryAllow(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	first := ipPolicyOptions()
	first.trustedSource.SourceAddress = netip.MustParseAddr("198.51.100.7")
	first.trustedSource.PeerAddress = first.trustedSource.SourceAddress
	first.overlay = []byte(`{"schema":"sakullla.ip-policy-overlay/v1","rules":[{"id":"entry-allow","action":"allow","selector":{"type":"ip","value":"198.51.100.7"}}]}`)
	firstSession, status := startWAFArtifact(t, artifact, first)
	defer firstSession.Close()
	if status != pluginsdk.PolicyStatusOK || firstSession.Evaluate() != pluginsdk.PolicyActionDeny {
		t.Fatalf("global deny was weakened by entry allow: status=%d", status)
	}
	events := firstSession.SecurityEvents()
	if len(events) == 0 || events[len(events)-1].RuleIndex != 1 {
		t.Fatalf("global rule dictionary index=%+v", events)
	}

	second := ipPolicyOptions()
	second.generation = "generation-2"
	reference := second.datasetReferences["dbip-cn-province"]
	reference.Generation = second.generation
	reference.Handle = strings.Repeat("b", 43)
	second.datasetReferences["dbip-cn-province"] = reference
	second.trustedSource.Generation = second.generation
	second.datasetMatches["region:cn-44"] = pluginsdk.DatasetMatch{Coverage: pluginsdk.DatasetCovered}
	secondSession, status := startWAFArtifact(t, artifact, second)
	defer secondSession.Close()
	if status != pluginsdk.PolicyStatusOK || secondSession.Evaluate() != pluginsdk.PolicyActionDeny {
		t.Fatalf("new generation did not use its own dataset result: status=%d", status)
	}
	if first.datasetReferences["dbip-cn-province"].Generation != "generation-1" {
		t.Fatal("new generation mutated old immutable reference")
	}
}

func TestIPPolicyCanonicalIPv6CIDR(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	options := ipPolicyOptions()
	options.config = []byte(`{"schema":"sakullla.ip-policy/v1","default_action":"allow","datasets":[],"province_whitelist":[],"rules":[{"id":"deny-v6","action":"deny","selector":{"type":"cidr","value":"2001:db8::/32"}}]}`)
	options.datasetReferences = nil
	options.datasetMatches = nil
	options.trustedSource.SourceAddress = netip.MustParseAddr("2001:db8::7")
	options.trustedSource.PeerAddress = options.trustedSource.SourceAddress
	session, status := startWAFArtifact(t, artifact, options)
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionDeny {
		t.Fatalf("IPv6 CIDR status=%d", status)
	}
}

func TestIPPolicyPooledInstanceResetPreservesGenerationAcrossRequests(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	options := ipPolicyOptions()
	session, status := startWAFArtifact(t, artifact, options)
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionAllow {
		t.Fatalf("first pooled request status=%d", status)
	}
	firstEventCount := len(session.SecurityEvents())
	session.Reset()

	initWire := marshalPolicyInit(t, options.config, options.grants, options.generation)
	initPointer := wafAllocateAndWrite(t, context.Background(), session.guest, initWire)
	result, err := session.guest.ExportedFunction(pluginsdk.PolicyExportInit).Call(context.Background(), uint64(initPointer), uint64(len(initWire)))
	wafFree(t, context.Background(), session.guest, initPointer, uint32(len(initWire)))
	if err != nil || len(result) != 1 || pluginsdk.PolicyStatus(uint32(result[0])) != pluginsdk.PolicyStatusInvalidArgument {
		t.Fatalf("second init result=%v err=%v", result, err)
	}

	options.trustedSource.SourceAddress = netip.MustParseAddr("203.0.113.7")
	options.trustedSource.PeerAddress = options.trustedSource.SourceAddress
	options.datasetMatches["region:cn-44"] = pluginsdk.DatasetMatch{Coverage: pluginsdk.DatasetCovered}
	if action := session.Evaluate(); action != pluginsdk.PolicyActionDeny {
		t.Fatalf("second pooled request action=%d", action)
	}
	if session.HostCalls(pluginsdk.PolicyHostReadTrustedSource) != 2 || session.HostCalls(pluginsdk.PolicyHostDatasetQuery) != 2 {
		t.Fatalf("pooled Host calls source/query=%d/%d", session.HostCalls(pluginsdk.PolicyHostReadTrustedSource), session.HostCalls(pluginsdk.PolicyHostDatasetQuery))
	}
	events := session.SecurityEvents()
	if len(events) != firstEventCount+1 || events[len(events)-1].Action != pluginsdk.PolicySecurityEventActionDeny || events[len(events)-1].DatasetIndex != 1 || events[len(events)-1].ClassificationIndex != 1 {
		t.Fatalf("pooled events crossed requests: %+v", events)
	}
}

func TestIPPolicyL4ConsumesHostProjectedOverlay(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	options := ipPolicyOptions()
	options.extensionPoint = pluginsdk.ExtensionL4Accept
	options.trustedSource.EntryID = "tcp-8"
	options.trustedSource.SourceAddress = netip.MustParseAddr("203.0.113.7")
	options.trustedSource.PeerAddress = options.trustedSource.SourceAddress
	options.overlay = []byte(`{"schema":"sakullla.ip-policy-overlay/v1","rules":[{"id":"entry-deny","action":"deny","selector":{"type":"ip","value":"203.0.113.7"}}]}`)
	session, status := startWAFArtifact(t, artifact, options)
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionDeny {
		t.Fatalf("L4 overlay status=%d", status)
	}
	if bytes.Contains(options.overlay, []byte("token")) {
		t.Fatal("management token leaked into policy overlay")
	}
}

func policyHostImports() []string {
	imports := make([]string, 0, len(pluginsdk.PolicyV1HostFunctions()))
	for name := range pluginsdk.PolicyV1HostFunctions() {
		imports = append(imports, name)
	}
	return imports
}
