package dockerapp

import (
	"fmt"
	"regexp"
	"strings"
)

var requiredComposeVariablePattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:\?|\?)([^}]*)\}`)

func validateRequiredComposeVariables(compose, environment string) error {
	values := parseComposeEnvironment(environment)
	compose = composeInterpolationText(compose)
	for _, match := range requiredComposeVariablePattern.FindAllStringSubmatchIndex(compose, -1) {
		if match[0] > 0 && compose[match[0]-1] == '$' {
			continue
		}
		name := compose[match[2]:match[3]]
		operator := compose[match[4]:match[5]]
		value, found := values[name]
		if found && (operator == "?" || value != "") {
			continue
		}
		message := strings.TrimSpace(compose[match[6]:match[7]])
		if message == "" {
			message = name + " is required"
		}
		return fmt.Errorf("%w: %s: %s", ErrMissingComposeVariable, name, message)
	}
	return nil
}

func composeInterpolationText(document string) string {
	lines := strings.Split(strings.ReplaceAll(document, "\r\n", "\n"), "\n")
	for index, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines[index] = ""
		}
	}
	return strings.Join(lines, "\n")
}

func parseComposeEnvironment(document string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(document, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || !validComposeVariableName(name) {
			continue
		}
		values[name] = strings.TrimSpace(value)
	}
	return values
}

func validComposeVariableName(value string) bool {
	if value == "" {
		return false
	}
	for index, current := range value {
		if current == '_' || current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' || index > 0 && current >= '0' && current <= '9' {
			continue
		}
		return false
	}
	return true
}
