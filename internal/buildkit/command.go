package buildkit

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Toolchain struct {
	GoVersion     string
	RustVersion   string
	ProtocVersion string
}

type CommandSpec struct {
	Name string
	Args []string
	Dir  string
}

func (toolchain Toolchain) Verify(ctx context.Context) error {
	checks := []struct {
		name    string
		args    []string
		expects string
	}{
		{"go", []string{"version"}, "go" + toolchain.GoVersion},
		{"rustc", []string{"--version"}, "rustc " + toolchain.RustVersion},
		{"protoc", []string{"--version"}, "libprotoc " + toolchain.ProtocVersion},
	}
	for _, check := range checks {
		if check.expects == "go" || check.expects == "rustc " || check.expects == "libprotoc " {
			return fmt.Errorf("all toolchain versions must be pinned")
		}
		output, err := exec.CommandContext(ctx, check.name, check.args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("run %s version check: %w", check.name, err)
		}
		if !strings.Contains(string(output), check.expects) {
			return fmt.Errorf("%s version mismatch: expected %q, got %q", check.name, check.expects, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func RunIsolated(ctx context.Context, spec CommandSpec) ([]byte, error) {
	if spec.Name == "" || spec.Dir == "" {
		return nil, fmt.Errorf("command name and working directory are required")
	}
	cacheRoot, err := os.MkdirTemp("", "sakullla-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cacheRoot)
	command := exec.CommandContext(ctx, spec.Name, spec.Args...)
	command.Dir = spec.Dir
	command.Env = append(os.Environ(),
		"GOTOOLCHAIN=local",
		"GOCACHE="+filepath.Join(cacheRoot, "go-build"),
		"GOMODCACHE="+filepath.Join(cacheRoot, "go-mod"),
		"CARGO_TARGET_DIR="+filepath.Join(cacheRoot, "cargo-target"),
		"TMPDIR="+filepath.Join(cacheRoot, "tmp"),
		"TEMP="+filepath.Join(cacheRoot, "tmp"),
		"TMP="+filepath.Join(cacheRoot, "tmp"),
	)
	if runtime.GOOS != "windows" {
		command.Env = append(command.Env, "SOURCE_DATE_EPOCH=0", "TZ=UTC", "LC_ALL=C")
	}
	if err := os.MkdirAll(filepath.Join(cacheRoot, "tmp"), 0o755); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return output.Bytes(), fmt.Errorf("isolated command failed: %w", err)
	}
	return output.Bytes(), nil
}
