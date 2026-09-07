package waf

import (
	"context"
	"net/http"
	"strings"
)

func managedRuleCatalog() []CustomRule {
	rules := []CustomRule{}
	for _, line := range strings.Split(managedRulesSource, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) == 3 {
			rules = append(rules, CustomRule{ID: parts[0], Target: strings.ToLower(parts[1]), Needle: parts[2]})
		}
	}
	return rules
}

func (controller *Controller) serveEntryModes(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeWAFJSON(writer, http.StatusMethodNotAllowed, wafAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeWAFJSON(writer, http.StatusForbidden, wafAPIResponse{Error: deniedMessage})
		return
	}
	body, err := decodeWAFWrite(request)
	if err != nil || !validMode(body.Mode) || !validAgentID(body.AgentID) {
		writeWAFJSON(writer, http.StatusBadRequest, wafAPIResponse{Error: ErrInvalidConfig.Error()})
		return
	}
	entries, err := controller.listEntries(request.Context(), body.AgentID)
	if err == nil && controller.overlaysW == nil {
		err = ErrUnavailable
	}
	if err == nil {
		for _, entry := range entries {
			if !entry.Enabled || !entry.Attached || entry.OverlayInvalid || entry.RuleRef == "" {
				continue
			}
			if err = controller.overlaysW.SetMode(request.Context(), body.AgentID, entry.RuleRef, body.Mode); err != nil {
				break
			}
		}
	}
	if err != nil {
		writeWAFJSON(writer, wafStatus(err), wafAPIResponse{Error: publicWAFError(err)})
		return
	}
	writeWAFJSON(writer, http.StatusOK, wafAPIResponse{Ready: true})
}

func (controller *Controller) removeCustomRule(ctx context.Context, id string) error {
	config := controller.currentConfig()
	found := false
	for i, rule := range config.CustomRules {
		if rule.ID == id {
			config.CustomRules = append(config.CustomRules[:i], config.CustomRules[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return ErrInvalidRule
	}
	// Removing a custom rule also removes its now-unused exclusions atomically.
	kept := config.Exclusions[:0]
	for _, rule := range config.Exclusions {
		if rule.RuleID != id {
			kept = append(kept, rule)
		}
	}
	config.Exclusions = kept
	return controller.replaceConfig(ctx, config)
}

func (controller *Controller) removeExclusion(ctx context.Context, id, path string) error {
	config := controller.currentConfig()
	for i, rule := range config.Exclusions {
		if rule.RuleID == id && rule.PathPrefix == path {
			config.Exclusions = append(config.Exclusions[:i], config.Exclusions[i+1:]...)
			return controller.replaceConfig(ctx, config)
		}
	}
	return ErrInvalidExclusion
}
