package common

import (
	"context"
	"os"
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

func TestLicenseCheckRequiresReviewedDependencies(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.26\n\nrequire example.com/dependency v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	if err := CheckLicenses(root, LicensePolicy{Modules: map[string]string{module: "GPL-3.0-only"}}); err == nil {
		t.Fatal("host implementation module was accepted")
	}
}

func TestReproducibleCommandOnCleanCopies(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("stable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckReproducible(context.Background(), root, "go", []string{"version"}); err != nil {
		t.Fatal(err)
	}
}
