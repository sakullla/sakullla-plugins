package buildkit

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestBuildCommandUsesIsolatedGoCache(t *testing.T) {
	t.Parallel()
	command := "go"
	args := []string{"env", "GOCACHE"}
	if runtime.GOOS == "js" {
		t.Skip("subprocesses unavailable")
	}
	output, err := RunIsolated(context.Background(), CommandSpec{Name: command, Args: args, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cache := strings.TrimSpace(string(output))
	if cache == "" || cache == os.Getenv("GOCACHE") {
		t.Fatalf("isolated build cache was not applied: %q", cache)
	}
}

func TestBuildToolchainVersionRequiresExactToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tool     string
		output   string
		expected string
	}{
		{"go", "go version go1.27.00 windows/amd64", "1.27.0"},
		{"rustc", "rustc 1.97.10 (abcdef 2026-01-01)", "1.97.1"},
		{"protoc", "libprotoc 32.0.1", "32.0"},
	}
	for _, test := range tests {
		if err := verifyToolVersionOutput(test.tool, test.output, test.expected); err == nil {
			t.Errorf("%s accepted prefix-matching version %q", test.tool, test.output)
		}
	}
	for _, test := range []struct{ tool, output, expected string }{
		{"go", "go version go1.27.0 windows/amd64", "1.27.0"},
		{"rustc", "rustc 1.97.1 (abcdef 2026-01-01)", "1.97.1"},
		{"protoc", "libprotoc 32.0", "32.0"},
	} {
		if err := verifyToolVersionOutput(test.tool, test.output, test.expected); err != nil {
			t.Errorf("%s rejected exact version: %v", test.tool, err)
		}
	}
}
