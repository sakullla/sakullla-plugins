package common

import (
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
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
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.26\n\nrequire example.com/dependency v1.0.0\n"), 0o644); err != nil {
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
	contents := "module fixture\n\ngo 1.26\n\nrequire " + module + " v0.0.0\n"
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
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.26\n"), 0o644); err != nil {
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
	if err := os.MkdirAll("out", 0o755); err != nil {
		os.Exit(2)
	}
	contents := []byte("stable")
	if mode == "random" {
		contents = make([]byte, 32)
		if _, err := rand.Read(contents); err != nil {
			os.Exit(2)
		}
	}
	if err := os.WriteFile(filepath.Join("out", "artifact.bin"), contents, 0o644); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
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
