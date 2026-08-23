package dockerapp

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRequiredComposeVariables(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		compose     string
		environment string
		wantError   bool
	}{
		{name: "colon question rejects missing", compose: `${DATABASE_PASSWORD:?password is required}`, wantError: true},
		{name: "colon question rejects empty", compose: `${DATABASE_PASSWORD:?password is required}`, environment: "DATABASE_PASSWORD=\n", wantError: true},
		{name: "question accepts empty", compose: `${DATABASE_PASSWORD?password must be declared}`, environment: "DATABASE_PASSWORD=\n"},
		{name: "default does not require input", compose: `${DATABASE_PASSWORD:-generated-default}`},
		{name: "escaped expansion is ignored", compose: `$${DATABASE_PASSWORD:?expanded in container}`},
		{name: "commented example is ignored", compose: "# ${DATABASE_PASSWORD:?example only}\nservices: {}\n"},
		{name: "dotenv value satisfies requirement", compose: `${DATABASE_PASSWORD:?password is required}`, environment: "# deployment values\nexport DATABASE_PASSWORD=fixture-value\n"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateRequiredComposeVariables(test.compose, test.environment)
			if test.wantError && !errors.Is(err, ErrMissingComposeVariable) {
				t.Fatalf("error=%v, want ErrMissingComposeVariable", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateRequiredComposeVariablesReturnsActionableSafeError(t *testing.T) {
	t.Parallel()
	err := validateRequiredComposeVariables(
		`${DATABASE_PASSWORD:?set DATABASE_PASSWORD in .env}`,
		"UNRELATED_VALUE=fixture-value\n",
	)
	if !errors.Is(err, ErrMissingComposeVariable) {
		t.Fatalf("error=%v, want ErrMissingComposeVariable", err)
	}
	message := err.Error()
	if !strings.Contains(message, "DATABASE_PASSWORD") || !strings.Contains(message, "set DATABASE_PASSWORD in .env") {
		t.Fatalf("error is not actionable: %q", message)
	}
	if strings.Contains(message, "fixture-value") {
		t.Fatalf("error leaked an environment value: %q", message)
	}
}
