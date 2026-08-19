package cloudflaredns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type hostCallFunc func(context.Context, pluginsdk.HostRuntimeCall, any) error

func (function hostCallFunc) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, result any) error {
	return function(ctx, call, result)
}

type capturedHostHTTPRequest struct {
	SecretRef string            `json:"secret_ref"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      []byte            `json:"body"`
}

func TestHostCloudflareClientPaginatesAndPreservesMutationSemantics(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		var request capturedHostHTTPRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		parsed, err := url.Parse(request.URL)
		if err != nil {
			return err
		}
		var response cloudflareHTTPResult
		switch {
		case parsed.Path == "/client/v4/zones" && parsed.Query().Get("page") == "1":
			response = cloudflareTestResponse(t, http.StatusOK, map[string]any{"success": true, "result": []cloudflareZone{{ID: "zone-a", Name: "example.com"}}, "result_info": map[string]int{"page": 1, "total_pages": 2}}, request.Method)
		case parsed.Path == "/client/v4/zones" && parsed.Query().Get("page") == "2":
			response = cloudflareTestResponse(t, http.StatusOK, map[string]any{"success": true, "result": []cloudflareZone{{ID: "zone-b", Name: "sub.example.com"}}, "result_info": map[string]int{"page": 2, "total_pages": 2}}, request.Method)
		case parsed.Path == "/client/v4/zones/zone-a/dns_records" && request.Method == http.MethodGet && parsed.Query().Get("page") == "1":
			if parsed.Query().Get("per_page") != "100" {
				t.Fatalf("record page size = %q", parsed.Query().Get("per_page"))
			}
			response = cloudflareTestResponse(t, http.StatusOK, map[string]any{"success": true, "result": []cloudflareRecord{{ID: "record-listed-a", ZoneID: "zone-a", Type: "A", Name: "a.example.com", Content: "192.0.2.1", TTL: 60}, {ID: "ignored-ns", ZoneID: "zone-a", Type: "NS", Name: "example.com", Content: "ns.example.com", TTL: 60}}, "result_info": map[string]int{"page": 1, "total_pages": 2}}, request.Method)
		case parsed.Path == "/client/v4/zones/zone-a/dns_records" && request.Method == http.MethodGet && parsed.Query().Get("page") == "2":
			response = cloudflareTestResponse(t, http.StatusOK, map[string]any{"success": true, "result": []cloudflareRecord{{ID: "record-listed-b", ZoneID: "zone-a", Type: "TXT", Name: "txt.example.com", Content: "value", TTL: 120}}, "result_info": map[string]int{"page": 2, "total_pages": 2}}, request.Method)
		case parsed.Path == "/client/v4/zones/zone-a/dns_records" && request.Method == http.MethodPost:
			var payload map[string]any
			if err := json.Unmarshal(request.Body, &payload); err != nil {
				return err
			}
			if payload["proxied"] != false || payload["type"] != "A" || payload["ttl"] != float64(60) {
				t.Fatalf("create payload = %#v", payload)
			}
			response = cloudflareTestResponse(t, http.StatusOK, map[string]any{"success": true, "result": cloudflareRecord{ID: "record-a", ZoneID: "zone-a", Type: "A", Name: "www.example.com", Content: "192.0.2.10", TTL: 60}}, request.Method)
		case parsed.Path == "/client/v4/zones/zone-a/dns_records/record-a" && request.Method == http.MethodPatch:
			var payload map[string]any
			if err := json.Unmarshal(request.Body, &payload); err != nil {
				return err
			}
			if _, found := payload["proxied"]; found {
				t.Fatalf("update unexpectedly overwrote proxied: %#v", payload)
			}
			response = cloudflareTestResponse(t, http.StatusOK, map[string]any{"success": true, "result": cloudflareRecord{ID: "record-a", ZoneID: "zone-a", Type: "A", Name: "www.example.com", Content: "192.0.2.11", TTL: 120}}, request.Method)
		case parsed.Path == "/client/v4/zones/zone-a/dns_records/missing" && request.Method == http.MethodDelete:
			response = cloudflareTestResponse(t, http.StatusNotFound, map[string]any{"success": false, "result": nil}, request.Method)
		default:
			t.Fatalf("unexpected Cloudflare request %s %s", request.Method, request.URL)
		}
		return copyHostResult(response, target)
	})

	zones, err := listCloudflareZones(context.Background(), client, "secret/main")
	if err != nil || len(zones) != 2 || zones[0].Name != "sub.example.com" {
		t.Fatalf("zones = %#v, err = %v", zones, err)
	}
	dns := &hostDNS{client: client}
	records, err := dns.ListRecords(context.Background(), TokenAttestation{SecretRef: "secret/main"}, "zone-a", 10)
	if err != nil || len(records) != 2 || records[0].ID != "record-listed-a" || records[1].ID != "record-listed-b" {
		t.Fatalf("ListRecords() = %#v, %v", records, err)
	}
	created, err := dns.Create(context.Background(), TokenAttestation{SecretRef: "secret/main"}, DNSRecord{ZoneID: "zone-a", Type: "A", Name: "www.example.com", Content: "192.0.2.10", TTL: 60}, "operation-create")
	if err != nil || created.ID != "record-a" {
		t.Fatalf("Create() = %#v, %v", created, err)
	}
	updated, err := dns.Update(context.Background(), TokenAttestation{SecretRef: "secret/main"}, DNSRecord{ID: "record-a", ZoneID: "zone-a", Type: "A", Name: "www.example.com", Content: "192.0.2.11", TTL: 120}, "operation-update")
	if err != nil || updated.Content != "192.0.2.11" {
		t.Fatalf("Update() = %#v, %v", updated, err)
	}
	if err := dns.Delete(context.Background(), TokenAttestation{SecretRef: "secret/main"}, "zone-a", "missing", "operation-delete"); err != nil {
		t.Fatalf("Delete(404) = %v", err)
	}
	if calls[len(calls)-3].OperationID != "operation-create" || calls[len(calls)-2].OperationID != "operation-update" || calls[len(calls)-1].OperationID != "operation-delete" {
		t.Fatalf("mutation operation ids were not forwarded: %#v", calls)
	}
}

func TestHostCloudflareDeleteRejectsMismatchedResultIdentity(t *testing.T) {
	t.Parallel()
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		var request capturedHostHTTPRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		return copyHostResult(cloudflareTestResponse(t, http.StatusOK, map[string]any{"success": true, "result": map[string]string{"id": "different-record"}}, request.Method), target)
	})
	err := (&hostDNS{client: client}).Delete(context.Background(), TokenAttestation{SecretRef: "secret/main"}, "zone-a", "record-a", "operation-delete")
	if !errors.Is(err, ErrDNSOperationFailed) {
		t.Fatalf("Delete(mismatched id) = %v", err)
	}
}

func TestHostVaultVerifyChecksActiveTokenAndEnumeratesZones(t *testing.T) {
	t.Parallel()
	var httpCalls int
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		switch call.Operation {
		case "secret.describe":
			return copyHostResult(hostSecretResult{Found: true, Ref: "secret/main", Version: "version-1"}, target)
		case "http.secret-request":
			httpCalls++
			var request capturedHostHTTPRequest
			if err := json.Unmarshal(call.Payload, &request); err != nil {
				return err
			}
			parsed, err := url.Parse(request.URL)
			if err != nil {
				return err
			}
			if request.SecretRef != "secret/main" || request.Method != http.MethodGet {
				t.Fatalf("verify request = %#v", request)
			}
			var body any
			switch parsed.Path {
			case "/client/v4/user/tokens/verify":
				body = map[string]any{"success": true, "result": map[string]string{"id": "token-id", "status": "active"}}
			case "/client/v4/zones":
				body = map[string]any{"success": true, "result": []cloudflareZone{{ID: "zone-a", Name: "example.com"}}, "result_info": map[string]int{"page": 1, "total_pages": 1}}
			default:
				t.Fatalf("unexpected verify endpoint %q", parsed.Path)
			}
			return copyHostResult(cloudflareTestResponse(t, http.StatusOK, body, request.Method), target)
		default:
			t.Fatalf("unexpected host operation %q", call.Operation)
			return nil
		}
	})
	attestation, err := (&hostVault{client: client}).Verify(context.Background(), "secret/main")
	if err != nil || attestation.SecretRef != "secret/main" || attestation.Version != "version-1" || len(attestation.ZoneIDs) != 1 || attestation.ZoneIDs[0] != "zone-a" || !attestation.hasPermission(PermissionZoneRead) || !attestation.hasPermission(PermissionDNSEdit) || httpCalls != 2 {
		t.Fatalf("Verify() = %#v, calls=%d, err=%v", attestation, httpCalls, err)
	}
}

func TestHostCloudflareClientRejectsMalformedEnvelopeAndParsesRetryAfter(t *testing.T) {
	t.Parallel()
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		var request capturedHostHTTPRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		response := cloudflareTestResponse(t, http.StatusOK, map[string]any{"result": []cloudflareZone{}}, request.Method)
		return copyHostResult(response, target)
	})
	if _, err := listCloudflareZones(context.Background(), client, "secret/main"); !errors.Is(err, ErrDNSOperationFailed) {
		t.Fatalf("malformed envelope err = %v", err)
	}
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if got := parseCloudflareRetryAfter("15", now); got != 15*time.Second {
		t.Fatalf("delta Retry-After = %v", got)
	}
	if got := parseCloudflareRetryAfter(now.Add(time.Minute).Format(http.TimeFormat), now); got != time.Minute {
		t.Fatalf("date Retry-After = %v", got)
	}
}

func TestHostOperationJournalDecodesDurableOutcomes(t *testing.T) {
	t.Parallel()
	secretPayload, _ := json.Marshal(hostSecretResult{Found: true, Ref: "secret/main", Version: "v2"})
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		if call.Operation != "operation.inspect" {
			t.Fatalf("operation = %q", call.Operation)
		}
		return copyHostResult(struct {
			State    string                        `json:"state"`
			Response pluginsdk.HostRuntimeResponse `json:"response"`
		}{State: "committed", Response: pluginsdk.HostRuntimeResponse{Payload: secretPayload}}, target)
	})
	outcome, err := newHostOperationJournal(client).Inspect(context.Background(), "operation-token")
	if err != nil || outcome.State != OperationCommitted || outcome.Token.Version != "v2" {
		t.Fatalf("Inspect() = %#v, %v", outcome, err)
	}
}

func TestCommittedHostOutcomeKeepsUncertainProviderEffectsUnknown(t *testing.T) {
	t.Parallel()
	for name, response := range map[string]cloudflareHTTPResult{
		"server error":      {Status: http.StatusBadGateway, RequestMethod: http.MethodPost},
		"malformed success": {Status: http.StatusOK, RequestMethod: http.MethodPost, Body: []byte(`{"success":true,"result":null}`)},
	} {
		t.Run(name, func(t *testing.T) {
			payload, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := committedHostOutcome(pluginsdk.HostRuntimeResponse{Payload: payload})
			if err != nil || outcome.State != OperationUnknown {
				t.Fatalf("outcome = %#v, %v", outcome, err)
			}
		})
	}
}

func TestRecoveredMutationRequiresTheOriginalRecordIdentity(t *testing.T) {
	t.Parallel()
	want := DNSRecord{ID: "record-a", ZoneID: "zone-a", Type: "A", Name: "www.example.com", Content: "192.0.2.10", TTL: 60}
	if !cloudflareRecoveredRecordMatches("dns-update", want, want) {
		t.Fatal("matching recovered update was rejected")
	}
	wrong := want
	wrong.Content = "192.0.2.11"
	if cloudflareRecoveredRecordMatches("dns-update", wrong, want) {
		t.Fatal("recovered update with different content was accepted")
	}
	created := want
	created.ID = "record-created"
	want.ID = ""
	if !cloudflareRecoveredRecordMatches("dns-create", created, want) {
		t.Fatal("matching recovered create was rejected")
	}
}

func cloudflareTestResponse(t *testing.T, status int, body any, method string) cloudflareHTTPResult {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return cloudflareHTTPResult{Status: status, Body: encoded, Headers: map[string]string{}, ContentType: "application/json", RequestMethod: method}
}

func copyHostResult(value, target any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}
