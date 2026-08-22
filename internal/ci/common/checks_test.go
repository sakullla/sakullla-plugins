package common

import (
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSecretCheckRejectsPrivateKey(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	key := "-----BEGIN " + "PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(root, "fixture.pem"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecrets(root); err == nil {
		t.Fatal("private key fixture was not rejected")
	}
}

func TestSecretCheckAcceptsOrdinarySource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecrets(root); err != nil {
		t.Fatal(err)
	}
}

func TestSecretCheckRejectsNULPEMAndBinaryKeyExtension(t *testing.T) {
	t.Parallel()
	for name, contents := range map[string][]byte{
		"hidden.bin": append([]byte{0}, []byte("-----BEGIN "+"PRIVATE KEY-----\nfixture")...),
		"bundle.pfx": {0, 1, 2, 3, 0, 255},
	} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckSecrets(root); err == nil {
			t.Errorf("secret fixture %s was not rejected", name)
		}
	}
}

func TestSecretCheckRejectsForcedTrackedIgnoredPaths(t *testing.T) {
	t.Parallel()
	for _, rel := range []string{".env", ".env.production", "runtime-data/session.db", "nested/runtime-data/state.bin"} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			runGit(t, root, "init", "--quiet")
			if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".env\n.env.*\nruntime-data/\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("PASSWORD=hunter2\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runGit(t, root, "add", ".gitignore")
			runGit(t, root, "add", "-f", filepath.ToSlash(rel))
			if err := CheckSecrets(root); err == nil {
				t.Fatal("forced tracked secret/runtime path was accepted")
			}
		})
	}
}

func TestLicenseCheckRequiresReviewedDependencies(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.27.0\n\nrequire example.com/dependency v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCargoLock(t, root, "")
	if err := CheckLicenses(root, LicensePolicy{}); err == nil {
		t.Fatal("unreviewed dependency license was accepted")
	}
	if err := CheckLicenses(root, LicensePolicy{Modules: map[string]string{"example.com/dependency": "Apache-2.0"}}); err != nil {
		t.Fatal(err)
	}
}

func TestLicenseCheckRejectsHostImplementationModule(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE"), 0o644); err != nil {
		t.Fatal(err)
	}
	module := "github.com/sakullla/nginx-reverse-emby/panel/backend-go"
	contents := "module fixture\n\ngo 1.27.0\n\nrequire " + module + " v0.0.0\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCargoLock(t, root, "")
	if err := CheckLicenses(root, LicensePolicy{Modules: map[string]string{module: "GPL-3.0-only"}}); err == nil {
		t.Fatal("host implementation module was accepted")
	}
}

func TestLicenseCheckRequiresReviewedLockedRustCrates(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.27.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCargoLock(t, root, `
[[package]]
name = "serde"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fixture"
`)
	if err := CheckLicenses(root, LicensePolicy{}); err == nil {
		t.Fatal("unreviewed locked Rust crate was accepted")
	}
	if err := CheckLicenses(root, LicensePolicy{Crates: map[string]string{"serde@1.2.3": "MIT OR Apache-2.0"}}); err != nil {
		t.Fatal(err)
	}
}

func TestReproducibleCommandOnCleanCopies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("stable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAKULLA_REPRO_HELPER", "stable")
	if err := CheckReproducible(context.Background(), root, "out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err != nil {
		t.Fatal(err)
	}
}

func TestReproducibleCommandOnCleanCopiesUsesIsolatedResources(t *testing.T) {
	root := t.TempDir()
	trace := filepath.Join(t.TempDir(), "trace.txt")
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("stable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAKULLA_REPRO_HELPER", "stable")
	t.Setenv("SAKULLA_REPRO_TRACE", trace)
	if err := CheckReproducible(context.Background(), root, "out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err != nil {
		t.Fatal(err)
	}
	records := readReproducibleTrace(t, trace)
	if len(records) != 2 {
		t.Fatalf("isolated execution count = %d, want 2: %q", len(records), records)
	}
	first := strings.Split(records[0], "\x00")
	second := strings.Split(records[1], "\x00")
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("malformed isolated execution trace: %q", records)
	}
	for index, label := range []string{"worktree", "Go cache", "Cargo target"} {
		if first[index] == second[index] {
			t.Errorf("isolated %s was shared: %q", label, first[index])
		}
	}
}

func TestReproducibleInPlaceRunsTwiceAndKeepsOutput(t *testing.T) {
	root := newReproducibleFixture(t)
	trace := filepath.Join(t.TempDir(), "trace.txt")
	t.Setenv("SAKULLA_REPRO_HELPER", "stable")
	t.Setenv("SAKULLA_REPRO_TRACE", trace)
	if err := CheckReproducibleInPlace(context.Background(), root, "target/out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err != nil {
		t.Fatal(err)
	}
	records := readReproducibleTrace(t, trace)
	if len(records) != 2 {
		t.Fatalf("in-place execution count = %d, want 2: %q", len(records), records)
	}
	first := strings.Split(records[0], "\x00")
	second := strings.Split(records[1], "\x00")
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("malformed in-place execution trace: %q", records)
	}
	wantRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	for index, record := range [][]string{first, second} {
		if record[0] != wantRoot {
			t.Errorf("execution %d worktree = %q, want %q", index+1, record[0], wantRoot)
		}
	}
	if first[1] != second[1] || first[2] != second[2] {
		t.Fatalf("in-place executions did not share caches: first %q, second %q", first, second)
	}
	artifact, err := os.ReadFile(filepath.Join(root, "target", "out", "artifact.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact) != "stable" {
		t.Fatalf("retained artifact = %q, want stable", artifact)
	}
}

func TestReproducibleInPlaceRejectsBuildFailures(t *testing.T) {
	for _, mode := range []string{"fail-first", "fail-second"} {
		t.Run(mode, func(t *testing.T) {
			root := newReproducibleFixture(t)
			trace := filepath.Join(t.TempDir(), "trace.txt")
			t.Setenv("SAKULLA_REPRO_HELPER", mode)
			t.Setenv("SAKULLA_REPRO_TRACE", trace)
			if err := CheckReproducibleInPlace(context.Background(), root, "target/out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err == nil {
				t.Fatalf("%s build failure was accepted", mode)
			}
			wantExecutions := 1
			if mode == "fail-second" {
				wantExecutions = 2
			}
			if records := readReproducibleTrace(t, trace); len(records) != wantExecutions {
				t.Fatalf("%s execution count = %d, want %d", mode, len(records), wantExecutions)
			}
		})
	}
}

func TestReproducibleInPlaceRejectsMissingFreshOutput(t *testing.T) {
	for _, mode := range []string{"missing-first", "missing-second"} {
		t.Run(mode, func(t *testing.T) {
			root := newReproducibleFixture(t)
			output := filepath.Join(root, "target", "out")
			if err := os.MkdirAll(output, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(output, "artifact.bin"), []byte("historical"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SAKULLA_REPRO_HELPER", mode)
			if err := CheckReproducibleInPlace(context.Background(), root, "target/out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err == nil {
				t.Fatalf("%s reused a historical declared output", mode)
			}
		})
	}
}

func TestReproducibleInPlaceRejectsNondeterministicOutput(t *testing.T) {
	root := newReproducibleFixture(t)
	t.Setenv("SAKULLA_REPRO_HELPER", "different")
	if err := CheckReproducibleInPlace(context.Background(), root, "target/out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err == nil {
		t.Fatal("different declared outputs were accepted")
	}
}

func TestReproducibleInPlaceAcceptsDirtyWorktree(t *testing.T) {
	root := newReproducibleFixture(t)
	runGit(t, root, "init", "--quiet")
	runGit(t, root, "add", "input.txt")
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("uncommitted change\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("also an input\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAKULLA_REPRO_HELPER", "stable")
	if err := CheckReproducibleInPlace(context.Background(), root, "target/out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err != nil {
		t.Fatal(err)
	}
}

func TestReproducibleInPlaceRejectsInputChangesDuringBuilds(t *testing.T) {
	root := newReproducibleFixture(t)
	t.Setenv("SAKULLA_REPRO_HELPER", "mutate-input")
	if err := CheckReproducibleInPlace(context.Background(), root, "target/out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err == nil {
		t.Fatal("input changed during the two builds was accepted")
	}
}

func TestReproducibleRejectsNondeterministicOutput(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("stable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAKULLA_REPRO_HELPER", "random")
	if err := CheckReproducible(context.Background(), root, "out", os.Args[0], []string{"-test.run=TestReproducibleHelperProcess"}); err == nil {
		t.Fatal("nondeterministic declared output was accepted")
	}
}

func TestReproducibleHelperProcess(t *testing.T) {
	mode := os.Getenv("SAKULLA_REPRO_HELPER")
	if mode == "" {
		return
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		os.Exit(2)
	}
	if trace := os.Getenv("SAKULLA_REPRO_TRACE"); trace != "" {
		record := strings.Join([]string{workingDirectory, os.Getenv("GOCACHE"), os.Getenv("CARGO_TARGET_DIR")}, "\x00") + "\n"
		file, err := os.OpenFile(trace, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			os.Exit(2)
		}
		if _, err := file.WriteString(record); err != nil || file.Close() != nil {
			os.Exit(2)
		}
	}
	outputDirectory := os.Getenv("SAKULLA_REPRO_OUTPUT")
	if outputDirectory == "" {
		outputDirectory = "out"
	}
	countPath := filepath.Join("target", "reproducible-helper-count")
	if err := os.MkdirAll(filepath.Dir(countPath), 0o755); err != nil {
		os.Exit(2)
	}
	execution := 1
	if encoded, err := os.ReadFile(countPath); err == nil {
		execution, err = strconv.Atoi(strings.TrimSpace(string(encoded)))
		if err != nil {
			os.Exit(2)
		}
		execution++
	} else if !os.IsNotExist(err) {
		os.Exit(2)
	}
	if err := os.WriteFile(countPath, []byte(strconv.Itoa(execution)), 0o644); err != nil {
		os.Exit(2)
	}
	if (mode == "fail-first" && execution == 1) || (mode == "fail-second" && execution == 2) {
		os.Exit(3)
	}
	if (mode == "missing-first" && execution == 1) || (mode == "missing-second" && execution == 2) {
		if err := os.RemoveAll(outputDirectory); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		os.Exit(2)
	}
	contents := []byte("stable")
	if mode == "random" {
		contents = make([]byte, 32)
		if _, err := rand.Read(contents); err != nil {
			os.Exit(2)
		}
	} else if mode == "different" {
		contents = []byte(strconv.Itoa(execution))
	}
	if err := os.WriteFile(filepath.Join(outputDirectory, "artifact.bin"), contents, 0o644); err != nil {
		os.Exit(2)
	}
	if mode == "mutate-input" && execution == 1 {
		if err := os.WriteFile("input.txt", []byte("changed during build\n"), 0o644); err != nil {
			os.Exit(2)
		}
	}
	os.Exit(0)
}

func newReproducibleFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SAKULLA_REPRO_OUTPUT", filepath.Join("target", "out"))
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("stable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func readReproducibleTrace(t *testing.T, path string) []string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(contents)), "\n")
}

func writeCargoLock(t *testing.T, root, packages string) {
	t.Helper()
	contents := "# generated fixture\nversion = 4\n" + packages
	if err := os.WriteFile(filepath.Join(root, "Cargo.lock"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	if output, err := exec.Command("git", commandArgs...).CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}
