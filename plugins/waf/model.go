package waf

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed rules/managed.rules
var managedRulesSource string

const (
	PluginID      = "waf"
	PluginVersion = "0.1.1"
	MaxRules      = 16
	MaxExclusions = 16
	ModeObserve   = "observe"
	ModeDeny      = "deny"
)

var (
	ErrUnauthorized      = errors.New("无权管理 Web 防火墙。")
	ErrUnavailable       = errors.New("暂时无法管理 Web 防火墙。")
	ErrPolicyUnavailable = errors.New("防护执行面暂时不可用。")
	ErrInvalidConfig     = errors.New("Web 防火墙设置无效。")
	ErrBoundExceeded     = errors.New("超出自定义规则或排除项上限。")
	ErrUnknownEntry      = errors.New("HTTP 入口不存在。")
	ErrInvalidMode       = errors.New("只能切换为观察或拦截。")
	ErrInvalidRule       = errors.New("自定义规则无效。")
	ErrInvalidExclusion  = errors.New("排除项无效。")
	ErrDuplicateRule     = errors.New("自定义规则 ID 已存在。")
	ErrAgentRequired     = errors.New("请先选择一台节点。")
	customRuleTargets    = map[string]struct{}{"path": {}, "query": {}, "headers": {}, "body": {}}
	managedRuleIDs       = parseManagedRuleIDs(managedRulesSource)
)

type Configuration struct {
	Mode        string       `json:"mode"`
	CustomRules []CustomRule `json:"custom_rules,omitempty"`
	Exclusions  []Exclusion  `json:"exclusions,omitempty"`
}

type CustomRule struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Needle string `json:"needle"`
}

type Exclusion struct {
	RuleID     string `json:"rule_id"`
	PathPrefix string `json:"path_prefix"`
}

type HTTPEntry struct {
	RuleRef        string `json:"rule_ref"`
	FrontendURL    string `json:"frontend_url"`
	Backend        string `json:"backend,omitempty"`
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	Attached       bool   `json:"attached"`
	OverlayInvalid bool   `json:"overlay_invalid,omitempty"`
	Notice         string `json:"notice,omitempty"`
}

type SecurityEvent struct {
	Site        string `json:"site"`
	RuleID      string `json:"rule_id"`
	Digest      string `json:"digest"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason,omitempty"`
}

func ParseConfiguration(raw []byte) (Configuration, error) {
	config := Configuration{Mode: ModeObserve}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return config, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Configuration{}, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if strings.TrimSpace(config.Mode) == "" {
		config.Mode = ModeObserve
	}
	if err := config.Validate(); err != nil {
		return Configuration{}, err
	}
	return config, nil
}

func (config Configuration) Validate() error {
	if !validMode(config.Mode) {
		return ErrInvalidMode
	}
	if len(config.CustomRules) > MaxRules || len(config.Exclusions) > MaxExclusions {
		return ErrBoundExceeded
	}
	seen := make(map[string]struct{}, len(config.CustomRules))
	for _, rule := range config.CustomRules {
		if err := rule.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return ErrDuplicateRule
		}
		seen[rule.ID] = struct{}{}
	}
	for _, exclusion := range config.Exclusions {
		if err := exclusion.Validate(); err != nil {
			return err
		}
		if !knownRule(seen, exclusion.RuleID) {
			return ErrInvalidExclusion
		}
	}
	return nil
}

func (rule CustomRule) Validate() error {
	if !validID(rule.ID) {
		return ErrInvalidRule
	}
	if _, ok := customRuleTargets[rule.Target]; !ok {
		return ErrInvalidRule
	}
	if !boundedLiteral(rule.Needle, 2, 64) {
		return ErrInvalidRule
	}
	return nil
}

func (exclusion Exclusion) Validate() error {
	if !validID(exclusion.RuleID) {
		return ErrInvalidExclusion
	}
	if !strings.HasPrefix(exclusion.PathPrefix, "/") || !boundedLiteral(exclusion.PathPrefix, 1, 96) {
		return ErrInvalidExclusion
	}
	return nil
}

func validID(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	if value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
			return false
		}
	}
	return true
}

func knownRule(customIDs map[string]struct{}, ruleID string) bool {
	if _, ok := managedRuleIDs[ruleID]; ok {
		return true
	}
	_, ok := customIDs[ruleID]
	return ok
}

func parseManagedRuleIDs(source string) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 3 || fields[0] == "" {
			panic("plugins/waf: invalid managed rule line: " + line)
		}
		ids[fields[0]] = struct{}{}
	}
	if len(ids) == 0 {
		panic("plugins/waf: managed.rules produced no rule ids")
	}
	return ids
}

func validMode(value string) bool {
	return value == ModeObserve || value == ModeDeny
}

func validAgentID(value string) bool {
	return pluginsdk.ValidatePolicyIdentity(value) == nil
}

func boundedLiteral(value string, minimum, maximum int) bool {
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, character := range value {
		if character > unicode.MaxASCII || (!unicode.IsPrint(character) && !unicode.IsSpace(character)) {
			return false
		}
	}
	return true
}

func overlayKey(agentID, ruleRef string) string {
	return strings.TrimSpace(agentID) + "/" + strings.TrimSpace(ruleRef)
}

func parseOverlayMode(overlay json.RawMessage) (string, bool) {
	overlay = json.RawMessage(strings.TrimSpace(string(overlay)))
	if len(overlay) == 0 || string(overlay) == "null" {
		return "", true
	}
	decoder := json.NewDecoder(strings.NewReader(string(overlay)))
	decoder.DisallowUnknownFields()
	var parsed struct {
		Mode string `json:"mode"`
	}
	if err := decoder.Decode(&parsed); err != nil || decoder.More() || !validMode(strings.TrimSpace(parsed.Mode)) {
		return "", false
	}
	return strings.TrimSpace(parsed.Mode), true
}

func cloneConfiguration(config Configuration) Configuration {
	cloned := Configuration{Mode: config.Mode}
	if len(config.CustomRules) > 0 {
		cloned.CustomRules = append([]CustomRule(nil), config.CustomRules...)
	}
	if len(config.Exclusions) > 0 {
		cloned.Exclusions = append([]Exclusion(nil), config.Exclusions...)
	}
	return cloned
}

func cloneOverlays(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneEntries(entries []HTTPEntry) []HTTPEntry {
	if entries == nil {
		return nil
	}
	cloned := make([]HTTPEntry, len(entries))
	copy(cloned, entries)
	return cloned
}

func cloneEvents(events []SecurityEvent) []SecurityEvent {
	if events == nil {
		return nil
	}
	cloned := make([]SecurityEvent, len(events))
	copy(cloned, events)
	return cloned
}
