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
