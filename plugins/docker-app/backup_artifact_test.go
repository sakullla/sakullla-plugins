package dockerapp

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

const backupTestCompose = "services:\n  web:\n    image: nginx:1.27\n"

func backupTestTar(files map[string]string) []byte {
	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := files[name]
		if strings.HasSuffix(name, "/") {
			if err := tarWriter.WriteHeader(&tar.Header{
				Name:     strings.TrimSuffix(name, "/"),
				Mode:     0o755,
				Typeflag: tar.TypeDir,
			}); err != nil {
				panic(err)
			}
			continue
		}
		header := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			panic(err)
		}
		if _, err := tarWriter.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type backupTestWorkspace struct {
	dir      string
	files    map[string]string
	compose  string
	volumes  map[string]map[string]string
	created  time.Time
	appID    string
	destDir  string
	artifact BackupArtifactInfo
}

func prepareBackupTestWorkspace(t *testing.T) *backupTestWorkspace {
	t.Helper()
	fixture := &backupTestWorkspace{
		appID: "wiki",
		files: map[string]string{
			"data/app.conf": "listen = 127.0.0.1\n",
			"notes.txt":     "hello\n",
		},
		compose: backupTestCompose,
		volumes: map[string]map[string]string{
			"pgdata": {"PG_VERSION": "15\n", "base/db": "rows\n"},
			"cache":  {"kv": "v"},
		},
		created: time.Date(2026, 10, 22, 8, 30, 0, 0, time.UTC),
	}
	root := t.TempDir()
	fixture.dir = filepath.Join(root, fixture.appID)
	fixture.destDir = filepath.Join(root, "backups")
	for _, dir := range []string{fixture.dir, fixture.destDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for rel, content := range fixture.files {
		path := filepath.Join(fixture.dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The workspace compose copy must be excluded from workspace members.
	if err := os.WriteFile(filepath.Join(fixture.dir, ComposeFileName), []byte(fixture.compose), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := CreateBackupArtifact(fixture.destDir, fixture.backupSource())
	if err != nil {
		t.Fatal(err)
	}
	fixture.artifact = info
	return fixture
}

func (fixture *backupTestWorkspace) backupSource() BackupSource {
	names := make([]string, 0, len(fixture.volumes))
	for name := range fixture.volumes {
		names = append(names, name)
	}
	sort.Strings(names)
	volumes := make([]BackupVolumeSource, 0, len(names))
	for _, name := range names {
		volumes = append(volumes, BackupVolumeSource{
			Name: name,
			Tar:  bytes.NewReader(backupTestTar(fixture.volumes[name])),
		})
	}
	return BackupSource{
		AppID:     fixture.appID,
		Compose:   fixture.compose,
		Workdir:   fixture.dir,
		Volumes:   volumes,
		CreatedAt: fixture.created,
	}
}

func TestCreateBackupArtifactRoundTrip(t *testing.T) {
	t.Parallel()
	fixture := prepareBackupTestWorkspace(t)

	if filepath.Base(fixture.artifact.Path) != "wiki-20261022T083000Z.tar.zst" {
		t.Fatalf("artifact name=%q", fixture.artifact.Path)
	}
	entries, err := os.ReadDir(fixture.destDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(fixture.artifact.Path) {
		t.Fatalf("destination entries=%v", entries)
	}
	filePayload, err := os.ReadFile(fixture.artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	fileDigest := sha256.Sum256(filePayload)
	if fixture.artifact.SHA256 != hex.EncodeToString(fileDigest[:]) {
		t.Fatalf("artifact sha256=%q want %q", fixture.artifact.SHA256, hex.EncodeToString(fileDigest[:]))
	}
	if fixture.artifact.Size != int64(len(filePayload)) {
		t.Fatalf("artifact size=%d want %d", fixture.artifact.Size, len(filePayload))
	}

	reader, err := OpenBackupArtifact(fixture.artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	manifest := reader.Manifest()
	if manifest.Version != 1 || manifest.AppID != fixture.appID || manifest.Compression != "zstd" {
		t.Fatalf("manifest header=%+v", manifest)
	}
	if manifest.CreatedAt != fixture.created.Format(time.RFC3339) {
		t.Fatalf("manifest created_at=%q", manifest.CreatedAt)
	}
	wantMembers := []string{
		ComposeFileName,
		"workspace/data/app.conf",
		"workspace/notes.txt",
		"volumes/cache.tar",
		"volumes/pgdata.tar",
	}
	gotMembers := make([]string, 0, len(manifest.Members))
	var wantPayloadSize int64
	for _, member := range manifest.Members {
		gotMembers = append(gotMembers, member.Name)
		wantPayloadSize += member.Size
	}
	if strings.Join(gotMembers, ",") != strings.Join(wantMembers, ",") {
		t.Fatalf("members=%v want %v", gotMembers, wantMembers)
	}
	if manifest.PayloadSize != wantPayloadSize {
		t.Fatalf("payload size=%d want %d", manifest.PayloadSize, wantPayloadSize)
	}

	compose, err := reader.ReadCompose()
	if err != nil {
		t.Fatal(err)
	}
	if compose != fixture.compose {
		t.Fatalf("compose=%q", compose)
	}

	volumes := reader.VolumeNames()
	if strings.Join(volumes, ",") != "cache,pgdata" {
		t.Fatalf("volume names=%v", volumes)
	}
	for _, volume := range []string{"cache", "pgdata"} {
		dest := filepath.Join(t.TempDir(), volume)
		if err := os.MkdirAll(dest, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := reader.ExtractVolume(volume, dest); err != nil {
			t.Fatalf("volume %s: %v", volume, err)
		}
		backupTestAssertTree(t, dest, fixture.volumes[volume])
	}
	if err := reader.ExtractVolume("ghost", t.TempDir()); err == nil {
		t.Fatal("missing volume extraction succeeded")
	}
	if err := reader.ExtractVolume("../escape", t.TempDir()); err == nil {
		t.Fatal("invalid volume name extraction succeeded")
	}

	workspaceDest := t.TempDir()
	if err := reader.ExtractWorkspace(workspaceDest); err != nil {
		t.Fatal(err)
	}
	backupTestAssertTree(t, workspaceDest, fixture.files)
	if _, err := os.Stat(filepath.Join(workspaceDest, ComposeFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace compose copy extracted: %v", err)
	}
}

func backupTestAssertTree(t *testing.T, root string, want map[string]string) {
	t.Helper()
	got := make(map[string]string)
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || !entry.Type().IsRegular() {
			return walkErr
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		payload, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = string(payload)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("tree=%v want %v", got, want)
	}
	for name, content := range want {
		if got[name] != content {
			t.Fatalf("file %s=%q want %q", name, got[name], content)
		}
	}
}

// backupTestRewrite decodes an artifact, applies mutate to the non-manifest
// member payloads, and repacks it with zstd so corruption cases keep the
// original manifest.
func backupTestRewrite(t *testing.T, path string, mutate func(members map[string][]byte)) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder, err := zstd.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	tarReader := tar.NewReader(decoder)
	var order []string
	members := make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, header.Name)
		members[header.Name] = payload
	}
	mutate(members)
	known := make(map[string]struct{}, len(order))
	for _, name := range order {
		known[name] = struct{}{}
	}
	var added []string
	for name := range members {
		if _, seen := known[name]; !seen {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	order = append(order, added...)
	var out bytes.Buffer
	encoder, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	tarWriter := tar.NewWriter(encoder)
	for _, name := range order {
		payload := members[name]
		if err := tarWriter.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(payload)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestOpenBackupArtifactRejectsCorruption(t *testing.T) {
	t.Parallel()
	fixture := prepareBackupTestWorkspace(t)
	valid, err := os.ReadFile(fixture.artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	flipped := append([]byte(nil), valid...)
	flipped[len(flipped)*2/3] ^= 0xff

	tests := []struct {
		name    string
		payload []byte
	}{
		{"not zstd", bytes.Repeat([]byte{0x01, 0x02, 0x03}, 512)},
		{"truncated", valid[:len(valid)-37]},
		{"flipped byte", flipped},
		{"member digest mismatch", backupTestRewrite(t, fixture.artifact.Path, func(members map[string][]byte) {
			members["volumes/pgdata.tar"] = backupTestTar(map[string]string{"PG_VERSION": "16\n"})
		})},
		{"missing member", backupTestRewrite(t, fixture.artifact.Path, func(members map[string][]byte) {
			delete(members, "volumes/pgdata.tar")
		})},
		{"extra member", backupTestRewrite(t, fixture.artifact.Path, func(members map[string][]byte) {
			members["workspace/extra.txt"] = []byte("extra\n")
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate.tar.zst")
			if err := os.WriteFile(path, test.payload, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenBackupArtifact(path); !errors.Is(err, ErrBackupArtifactCorrupt) {
				t.Fatalf("err=%v want ErrBackupArtifactCorrupt", err)
			}
		})
	}
}

func TestOpenBackupArtifactRejectsMissingFile(t *testing.T) {
	t.Parallel()
	if _, err := OpenBackupArtifact(filepath.Join(t.TempDir(), "absent.tar.zst")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v want os.ErrNotExist", err)
	}
}

type backupTestFailReader struct {
	pending []byte
}

func (reader *backupTestFailReader) Read(buffer []byte) (int, error) {
	if len(reader.pending) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(buffer, reader.pending)
	reader.pending = reader.pending[n:]
	return n, nil
}

func TestCreateBackupArtifactFailuresLeaveNoArtifacts(t *testing.T) {
	t.Parallel()
	newSource := func(volumes ...BackupVolumeSource) BackupSource {
		return BackupSource{
			AppID:     "wiki",
			Compose:   backupTestCompose,
			CreatedAt: time.Date(2026, 10, 22, 8, 30, 0, 0, time.UTC),
			Volumes:   volumes,
		}
	}
	symlinkCase := func(t *testing.T) BackupSource {
		workdir := t.TempDir()
		link := filepath.Join(workdir, "link")
		if err := os.Symlink(filepath.Join(workdir, "target"), link); err != nil {
			t.Skipf("symlink creation failed: %v", err)
		}
		source := newSource()
		source.Workdir = workdir
		return source
	}
	failing := &backupTestFailReader{pending: backupTestTar(map[string]string{"k": "v"})}
	tests := []struct {
		name   string
		source func(t *testing.T) BackupSource
	}{
		{"invalid app id", func(t *testing.T) BackupSource {
			source := newSource()
			source.AppID = "Bad ID"
			return source
		}},
		{"empty compose", func(t *testing.T) BackupSource {
			source := newSource()
			source.Compose = ""
			return source
		}},
		{"duplicate volume", func(t *testing.T) BackupSource {
			tarBytes := backupTestTar(map[string]string{"k": "v"})
			return newSource(
				BackupVolumeSource{Name: "data", Tar: bytes.NewReader(tarBytes)},
				BackupVolumeSource{Name: "data", Tar: bytes.NewReader(tarBytes)},
			)
		}},
		{"invalid volume name", func(t *testing.T) BackupSource {
			return newSource(BackupVolumeSource{Name: "../escape", Tar: bytes.NewReader(nil)})
		}},
		{"volume stream fails", func(t *testing.T) BackupSource {
			return newSource(BackupVolumeSource{Name: "data", Tar: failing})
		}},
		{"workspace symlink", symlinkCase},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dest := t.TempDir()
			_, err := CreateBackupArtifact(dest, test.source(t))
			if err == nil {
				t.Fatal("creation succeeded")
			}
			entries, readErr := os.ReadDir(dest)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failure left %d entries: %v", len(entries), entries)
			}
		})
	}
}

func TestCreateBackupArtifactDoesNotOverwriteExisting(t *testing.T) {
	t.Parallel()
	fixture := prepareBackupTestWorkspace(t)
	_, err := CreateBackupArtifact(fixture.destDir, fixture.backupSource())
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err=%v want already-exists failure", err)
	}
	entries, readErr := os.ReadDir(fixture.destDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 {
		t.Fatalf("destination entries=%v", entries)
	}
	if _, err := OpenBackupArtifact(fixture.artifact.Path); err != nil {
		t.Fatalf("original artifact damaged: %v", err)
	}
}

func TestCreateBackupArtifactDeterministic(t *testing.T) {
	t.Parallel()
	fixture := prepareBackupTestWorkspace(t)
	other := t.TempDir()
	info, err := CreateBackupArtifact(other, fixture.backupSource())
	if err != nil {
		t.Fatal(err)
	}
	if info.SHA256 != fixture.artifact.SHA256 {
		t.Fatalf("sha256=%s want %s", info.SHA256, fixture.artifact.SHA256)
	}
}

func TestExtractVolumeRejectsUnsafeTarEntries(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dest := filepath.Join(root, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	source := BackupSource{
		AppID:     "wiki",
		Compose:   backupTestCompose,
		CreatedAt: time.Date(2026, 10, 22, 8, 30, 0, 0, time.UTC),
		Volumes: []BackupVolumeSource{
			{Name: "evil", Tar: bytes.NewReader(backupTestUnsafeTar(t))},
		},
	}
	info, err := CreateBackupArtifact(root, source)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenBackupArtifact(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	err = reader.ExtractVolume("evil", dest)
	if !errors.Is(err, ErrBackupArtifactCorrupt) {
		t.Fatalf("err=%v want ErrBackupArtifactCorrupt", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "escaped.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("escaped entry written: %v", statErr)
	}
}

func backupTestUnsafeTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)
	escape := &tar.Header{
		Name:     "../../escaped.txt",
		Mode:     0o644,
		Size:     4,
		Typeflag: tar.TypeReg,
	}
	if err := tarWriter.WriteHeader(escape); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte("boom")); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBackupVolumeNameValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		valid bool
	}{
		{"pgdata", true},
		{"db.data-2", true},
		{"", false},
		{".hidden", false},
		{"-lead", false},
		{"has/slash", false},
		{"has\\slash", false},
		{"has space", false},
		{strings.Repeat("a", 129), false},
		{strings.Repeat("a", 128), true},
	}
	for _, test := range tests {
		if got := validBackupVolumeName(test.name); got != test.valid {
			t.Errorf("validBackupVolumeName(%q)=%v want %v", test.name, got, test.valid)
		}
	}
	if !validBackupVolumeName(fmt.Sprintf("v%d", 1)) {
		t.Fatal("digit-prefixed volume name rejected")
	}
}
