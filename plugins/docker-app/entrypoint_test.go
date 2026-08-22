package dockerapp

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRunEntrypointNormalStartupUsesCanonicalSDKServers(t *testing.T) {
	t.Setenv("NRE_PLUGIN_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	t.Setenv("NRE_PLUGIN_HTTP_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_HTTP_COOKIE_FILE", "")

	err := RunEntrypoint(context.Background(), nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("RunEntrypoint() unexpectedly succeeded without host endpoints")
	}
	if errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("RunEntrypoint() returned the old startup sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "NRE_PLUGIN_") {
		t.Fatalf("RunEntrypoint() error = %v, want canonical SDK endpoint validation", err)
	}
}

func TestRunEntrypointProductionWiresReportedEngineSource(t *testing.T) {
	config := productionControllerConfig()
	if config.UIEngineSource == nil {
		t.Fatal("production entrypoint still pins a zero UIEngine as the only observation path")
	}
}
