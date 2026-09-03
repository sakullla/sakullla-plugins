package waf

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestHostListProjectsAttachmentFromPolicyRef(t *testing.T) {
	t.Parallel()
	host := newFakeHostRuntime()
	host.rules["agent-1"] = []hostHTTPRuleListItem{
		{RuleRef: "11", FrontendURL: "http://plain.example.com", Backend: "127.0.0.1:8096", Enabled: true},
		{
			RuleRef: "12", FrontendURL: "http://app.example.com", Backend: "127.0.0.1:8096", Enabled: true,
			PolicyRef: &hostPolicyRef{ID: "waf-instance", Overlay: json.RawMessage(`{"mode":"observe"}`)},
		},
		{
			RuleRef: "13", FrontendURL: "http://deny.example.com", Enabled: true,
			PolicyRef: &hostPolicyRef{ID: "waf-instance", Overlay: json.RawMessage(`{"mode":"deny"}`)},
		},
		{
			RuleRef: "14", FrontendURL: "http://broken.example.com", Enabled: true,
			PolicyRef: &hostPolicyRef{ID: "waf-instance", Overlay: json.RawMessage(`{"mode":"block"}`)},
		},
	}
	runtime := newHostCapabilityRuntime(host)
	entries, err := runtime.List(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries=%#v", entries)
	}
	if entries[0].Attached || entries[0].Mode != "" {
		t.Fatalf("bare rule must not be fabricated as attached observe: %#v", entries[0])
	}
	if !entries[1].Attached || entries[1].Mode != ModeObserve || entries[1].OverlayInvalid {
		t.Fatalf("observe overlay = %#v", entries[1])
	}
	if !entries[2].Attached || entries[2].Mode != ModeDeny {
		t.Fatalf("deny overlay = %#v", entries[2])
	}
	if !entries[3].Attached || !entries[3].OverlayInvalid || entries[3].Notice != invalidOverlayNotice {
		t.Fatalf("invalid overlay = %#v", entries[3])
	}
}

func TestHostRuntimePersistsConfigOverlayAndEvents(t *testing.T) {
	t.Parallel()
	host := newFakeHostRuntime()
	host.rules["agent-1"] = []hostHTTPRuleListItem{{
		RuleRef: "12", FrontendURL: "http://app.example.com", Enabled: true,
		PolicyRef: &hostPolicyRef{ID: "waf-instance", Overlay: json.RawMessage(`{"mode":"observe"}`)},
	}}
	host.events = []hostPolicyEvent{{
		Site: "app.example.com", RuleID: "path-traversal", Digest: "abc",
		Disposition: ModeObserve, Reason: "rule_matched", Code: hostWAFRuleMatchCode,
	}}
	runtime := newHostCapabilityRuntime(host)
	if err := runtime.SetMode(context.Background(), "agent-1", "12", ModeDeny); err != nil {
		t.Fatal(err)
	}
	entries, err := runtime.List(context.Background(), "agent-1")
	if err != nil || len(entries) != 1 || entries[0].Mode != ModeDeny || !entries[0].Attached {
		t.Fatalf("overlay persist entries=%#v err=%v", entries, err)
	}
	config := Configuration{Mode: ModeDeny, CustomRules: []CustomRule{{ID: "block-admin", Target: "path", Needle: "/admin"}}}
	if err := runtime.StoreConfig(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if host.stored.Mode != ModeDeny || len(host.stored.CustomRules) != 1 || host.stored.CustomRules[0].ID != "block-admin" {
		t.Fatalf("instance config = %#v", host.stored)
	}
	events, err := runtime.ListEvents(context.Background(), "agent-1")
	if err != nil || len(events) != 1 || events[0].RuleID != "path-traversal" || events[0].Reason != "rule_matched" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestHostRuntimeFailsVisiblyWhenContractsReject(t *testing.T) {
	t.Parallel()
	host := newFakeHostRuntime()
	host.reject = true
	runtime := newHostCapabilityRuntime(host)
	if err := runtime.SetMode(context.Background(), "agent-1", "12", ModeDeny); err != ErrUnavailable {
		t.Fatalf("SetMode error=%v", err)
	}
	if err := runtime.StoreConfig(context.Background(), Configuration{Mode: ModeObserve}); err != ErrUnavailable {
		t.Fatalf("StoreConfig error=%v", err)
	}
	if _, err := runtime.ListEvents(context.Background(), "agent-1"); err != ErrUnavailable {
		t.Fatalf("ListEvents error=%v", err)
	}
}

type fakeHostRuntime struct {
	mu     sync.Mutex
	rules  map[string][]hostHTTPRuleListItem
	events []hostPolicyEvent
	stored Configuration
	reject bool
}

func newFakeHostRuntime() *fakeHostRuntime {
	return &fakeHostRuntime{rules: map[string][]hostHTTPRuleListItem{}}
}

func (host *fakeHostRuntime) Call(_ context.Context, call pluginsdk.HostRuntimeCall, result any) error {
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.reject {
		return ErrUnavailable
	}
	switch call.Operation {
	case pluginsdk.HostRuntimeHTTPRule:
		var request struct {
			Action  string          `json:"action"`
			AgentID string          `json:"agent_id"`
			RuleRef string          `json:"rule_ref"`
			Overlay json.RawMessage `json:"overlay"`
		}
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		if request.Action == pluginsdk.HTTPRuleActionList {
			return writeFakeHostResult(result, hostHTTPRuleListResponse{Rules: append([]hostHTTPRuleListItem(nil), host.rules[request.AgentID]...)})
		}
		if request.Action != pluginsdk.HTTPRuleActionCutover || len(request.Overlay) == 0 {
			return ErrUnavailable
		}
		rules := host.rules[request.AgentID]
		for index := range rules {
			if rules[index].RuleRef != request.RuleRef {
				continue
			}
			if rules[index].PolicyRef == nil {
				rules[index].PolicyRef = &hostPolicyRef{ID: "waf-instance"}
			}
			rules[index].PolicyRef.Overlay = append(json.RawMessage(nil), request.Overlay...)
			host.rules[request.AgentID] = rules
			return writeFakeHostResult(result, map[string]string{"rule_ref": request.RuleRef})
		}
		return ErrUnknownEntry
	case hostInstanceConfigOp:
		var request struct {
			Config json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		config, err := ParseConfiguration(request.Config)
		if err != nil {
			return err
		}
		host.stored = config
		return writeFakeHostResult(result, map[string]bool{"stored": true})
	case hostEventListOp:
		return writeFakeHostResult(result, hostEventListResponse{Events: append([]hostPolicyEvent(nil), host.events...)})
	default:
		return ErrUnavailable
	}
}

func writeFakeHostResult(result any, payload any) error {
	if result == nil {
		return nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, result)
}

func TestProjectHostPolicyEventIgnoresForeignCodes(t *testing.T) {
	t.Parallel()
	if _, ok := projectHostPolicyEvent(hostPolicyEvent{Code: "other.event", Action: ModeDeny}); ok {
		t.Fatal("foreign event codes must not be listed")
	}
	event, ok := projectHostPolicyEvent(hostPolicyEvent{Code: hostWAFRuleMatchCode, Action: ModeDeny, Site: "app.example.com"})
	if !ok || event.Disposition != ModeDeny || strings.Contains(event.Site, "<") {
		t.Fatalf("event=%#v ok=%v", event, ok)
	}
}
