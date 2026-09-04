package waf

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestCustomRuleValidateRejectsDigitStartID(t *testing.T) {
	t.Parallel()
	rule := CustomRule{ID: "1admin", Target: "path", Needle: "/admin"}
	if err := rule.Validate(); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("digit-start custom id error=%v", err)
	}
	if err := (CustomRule{ID: "block-admin", Target: "path", Needle: "/admin"}).Validate(); err != nil {
		t.Fatalf("valid custom id error=%v", err)
	}
}

func TestExclusionValidateRejectsInvalidRuleID(t *testing.T) {
	t.Parallel()
	for _, ruleID := range []string{"1admin", "BAD", "", "not_present", "-leading"} {
		if err := (Exclusion{RuleID: ruleID, PathPrefix: "/health"}).Validate(); !errors.Is(err, ErrInvalidExclusion) {
			t.Fatalf("rule_id %q error=%v", ruleID, err)
		}
	}
	if err := (Exclusion{RuleID: "managed-path-traversal", PathPrefix: "/health"}).Validate(); err != nil {
		t.Fatalf("valid exclusion id error=%v", err)
	}
}

func TestConfigurationValidateRejectsUnknownExclusion(t *testing.T) {
	t.Parallel()
	unknown := Configuration{
		Mode:       ModeObserve,
		Exclusions: []Exclusion{{RuleID: "not-present", PathPrefix: "/"}},
	}
	if err := unknown.Validate(); !errors.Is(err, ErrInvalidExclusion) {
		t.Fatalf("unknown exclusion error=%v", err)
	}
	if _, err := ParseConfiguration([]byte(`{"mode":"observe","exclusions":[{"rule_id":"not-present","path_prefix":"/"}]}`)); !errors.Is(err, ErrInvalidExclusion) {
		t.Fatalf("parse unknown exclusion error=%v", err)
	}
}

func TestConfigurationValidateAcceptsManagedAndCustomExclusions(t *testing.T) {
	t.Parallel()
	managed := Configuration{
		Mode:       ModeObserve,
		Exclusions: []Exclusion{{RuleID: "managed-path-traversal", PathPrefix: "/health"}},
	}
	if err := managed.Validate(); err != nil {
		t.Fatalf("managed exclusion error=%v", err)
	}
	custom := Configuration{
		Mode:        ModeObserve,
		CustomRules: []CustomRule{{ID: "block-admin", Target: "path", Needle: "/admin"}},
		Exclusions:  []Exclusion{{RuleID: "block-admin", PathPrefix: "/health"}},
	}
	if err := custom.Validate(); err != nil {
		t.Fatalf("custom exclusion error=%v", err)
	}
}

func TestManagedRuleIDsComeFromManagedRulesFile(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("rules/managed.rules")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := managedRuleIDs["managed-path-traversal"]; !ok {
		t.Fatalf("managed ids missing managed-path-traversal: %#v", managedRuleIDs)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, _, ok := strings.Cut(line, "|")
		if !ok {
			t.Fatalf("unparsed managed rule line %q", line)
		}
		if _, known := managedRuleIDs[id]; !known {
			t.Fatalf("managed id %q missing from parse", id)
		}
	}
}

func TestConfigSchemaIDPatternRejectsDigitStart(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `^[a-z0-9][a-z0-9-]{0,31}$`) {
		t.Fatal("schema still allows digit-start ids")
	}
	var schema struct {
		Properties struct {
			CustomRules struct {
				Items struct {
					Properties struct {
						ID struct {
							Pattern string `json:"pattern"`
						} `json:"id"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"custom_rules"`
			Exclusions struct {
				Items struct {
					Properties struct {
						RuleID struct {
							Pattern string `json:"pattern"`
						} `json:"rule_id"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"exclusions"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	want := `^[a-z][a-z0-9-]{0,31}$`
	if schema.Properties.CustomRules.Items.Properties.ID.Pattern != want {
		t.Fatalf("custom id pattern = %q", schema.Properties.CustomRules.Items.Properties.ID.Pattern)
	}
	if schema.Properties.Exclusions.Items.Properties.RuleID.Pattern != want {
		t.Fatalf("exclusion rule_id pattern = %q", schema.Properties.Exclusions.Items.Properties.RuleID.Pattern)
	}
	compiled := regexp.MustCompile(want)
	if compiled.MatchString("1admin") || compiled.MatchString("BAD") || compiled.MatchString("") {
		t.Fatal("schema pattern still matches digit-start or invalid ids")
	}
	if !compiled.MatchString("block-admin") || !compiled.MatchString("managed-path-traversal") {
		t.Fatal("schema pattern rejected valid ids")
	}
}
