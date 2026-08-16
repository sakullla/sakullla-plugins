package buildkit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPackageBlobIsByteReproducible(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "artifact"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plugin.yaml"), []byte("id: example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "artifact", "plugin"), []byte("payload\r\nbytes\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(t.TempDir(), "first.nrepkg")
	secondPath := filepath.Join(t.TempDir(), "second.nrepkg")
	first, err := BuildPackageBlob(root, firstPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPackageBlob(root, secondPath)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(firstPath)
	secondBytes, _ := os.ReadFile(secondPath)
	if first.SHA256 != second.SHA256 || first.Size != second.Size || !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("deterministic package blob changed between builds")
	}
}

func TestPackageBlobRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "payload"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := BuildPackageBlob(root, filepath.Join(t.TempDir(), "package.nrepkg")); err == nil {
		t.Fatal("symlink package entry was accepted")
	}
}
