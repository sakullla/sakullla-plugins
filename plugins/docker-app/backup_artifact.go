package dockerapp

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Backup artifacts are single files named <appID>-<timestamp>.tar.zst. The
// outer tar is zstd-compressed and always starts with manifest.json; every
// other member is stored uncompressed so checksums cover plain bytes:
//
//	manifest.json        whole-payload SHA-256, per-member checksums, algorithm
//	compose.yaml         the compose document
//	workspace/<rel>      one member per workspace file (compose excluded)
//	volumes/<name>.tar   one uncompressed tar per application volume
//
// The plugin-owned workspace trees backups/ (finished artifacts) and
// backup-staging/ (staged volume archives) are never packed as workspace
// members. Creation stages every member beside the destination and renames
// the finished artifact into place, so a failed run never leaves a usable
// product behind.

const (
	// BackupManifestName is the first tar member of every backup artifact.
	BackupManifestName = "manifest.json"

	backupManifestVersion  = 1
	backupCompressionZstd  = "zstd"
	backupTimestampLayout  = "20060102T150405Z"
	backupArtifactSuffix   = ".tar.zst"
	backupManifestMaxBytes = 1 << 20
	backupVolumeNameMax    = 128
	backupVolumeMax        = 256
	backupWorkspacePrefix  = "workspace/"
	backupVolumePrefix     = "volumes/"
	backupComposeMember    = ComposeFileName
)

// ErrBackupArtifactCorrupt reports an artifact that fails structural or
// checksum verification; wrapper text names the failing stage or member.
var ErrBackupArtifactCorrupt = errors.New("backup artifact is corrupt")

// BackupVolumeSource is one application volume packed as an uncompressed tar
// stream read once during creation.
type BackupVolumeSource struct {
	Name string
	Tar  io.Reader
}

// BackupSource describes one app backup: the compose document, the app
// workspace directory, and per-volume tar streams.
type BackupSource struct {
	AppID     string
	Compose   string
	Workdir   string
	Volumes   []BackupVolumeSource
	CreatedAt time.Time
}

// BackupMemberDigest is one artifact member with the SHA-256 of its
// uncompressed bytes.
type BackupMemberDigest struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// BackupManifest is the manifest.json member. PayloadSHA256 covers the
// concatenated uncompressed bytes of every member in Members order.
type BackupManifest struct {
	Version       int                  `json:"version"`
	AppID         string               `json:"app_id"`
	CreatedAt     string               `json:"created_at"`
	Compression   string               `json:"compression"`
	PayloadSHA256 string               `json:"payload_sha256"`
	PayloadSize   int64                `json:"payload_size"`
	Members       []BackupMemberDigest `json:"members"`
}

// BackupArtifactInfo describes a committed artifact; SHA256 and Size cover
// the final .tar.zst file for external records.
type BackupArtifactInfo struct {
	Path     string
	SHA256   string
	Size     int64
	Manifest BackupManifest
}

// BackupArtifactName returns the artifact file name for an app and instant.
func BackupArtifactName(appID string, createdAt time.Time) string {
	return appID + "-" + createdAt.UTC().Format(backupTimestampLayout) + backupArtifactSuffix
}

type stagedBackupMember struct {
	name string
	path string
}

// CreateBackupArtifact packs source into destDir as <appID>-<timestamp>.tar.zst.
// All members are staged in a sibling temporary directory first; the finished
// artifact is renamed into place, and any failure removes the whole staging
// directory so no partial product remains.
func CreateBackupArtifact(destDir string, source BackupSource) (BackupArtifactInfo, error) {
	if strings.TrimSpace(destDir) == "" {
		return BackupArtifactInfo{}, errors.New("backup destination is invalid")
	}
	if !validID(source.AppID) {
		return BackupArtifactInfo{}, errors.New("backup app id is invalid")
	}
	if !boundedCompose(source.Compose, MaxConfigBytes) {
		return BackupArtifactInfo{}, errors.New("backup compose is invalid")
	}
	if len(source.Volumes) > backupVolumeMax {
		return BackupArtifactInfo{}, errors.New("backup volume count exceeds limit")
	}
	seenVolumes := make(map[string]struct{}, len(source.Volumes))
	for _, volume := range source.Volumes {
		if !validBackupVolumeName(volume.Name) {
			return BackupArtifactInfo{}, fmt.Errorf("backup volume name %q is invalid", volume.Name)
		}
		if _, exists := seenVolumes[volume.Name]; exists {
			return BackupArtifactInfo{}, fmt.Errorf("backup volume %q is duplicated", volume.Name)
		}
		seenVolumes[volume.Name] = struct{}{}
	}
	created := source.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	} else {
		created = created.UTC()
	}
	staging, err := os.MkdirTemp(destDir, "."+source.AppID+"-backup-")
	if err != nil {
		return BackupArtifactInfo{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	staged, err := stageBackupMembers(staging, source)
	if err != nil {
		return BackupArtifactInfo{}, err
	}
	manifest, err := hashStagedBackupMembers(staged, source.AppID, created)
	if err != nil {
		return BackupArtifactInfo{}, err
	}
	partPath := filepath.Join(staging, "artifact.tar.zst.part")
	if err := writeBackupArtifact(partPath, manifest, staged, created); err != nil {
		return BackupArtifactInfo{}, err
	}
	artifactSHA, artifactSize, err := hashFileContents(partPath)
	if err != nil {
		return BackupArtifactInfo{}, err
	}
	finalPath := filepath.Join(destDir, BackupArtifactName(source.AppID, created))
	if _, err := os.Lstat(finalPath); err == nil {
		return BackupArtifactInfo{}, fmt.Errorf("backup artifact %s already exists", filepath.Base(finalPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupArtifactInfo{}, err
	}
	if err := os.Rename(partPath, finalPath); err != nil {
		return BackupArtifactInfo{}, err
	}
	_ = os.RemoveAll(staging)
	committed = true
	return BackupArtifactInfo{
		Path:     finalPath,
		SHA256:   artifactSHA,
		Size:     artifactSize,
		Manifest: manifest,
	}, nil
}

// stageBackupMembers snapshots every member into staging so hashing and
// packing read one consistent copy.
func stageBackupMembers(staging string, source BackupSource) ([]stagedBackupMember, error) {
	var staged []stagedBackupMember
	stage := func(name string, content io.Reader) error {
		target := filepath.Join(staging, fmt.Sprintf("member-%04d.bin", len(staged)))
		file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(file, content); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		staged = append(staged, stagedBackupMember{name: name, path: target})
		return nil
	}
	if err := stage(backupComposeMember, strings.NewReader(source.Compose)); err != nil {
		return nil, err
	}
	if source.Workdir != "" {
		err := filepath.WalkDir(source.Workdir, func(current string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(source.Workdir, current)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("backup workspace contains a symlink")
			}
			if entry.IsDir() {
				if isBackupOwnedWorkspaceTree(filepath.ToSlash(rel)) {
					// Plugin-owned backup trees (finished artifacts and staged
					// volume archives) never become workspace members.
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return errors.New("backup workspace contains an irregular file")
			}
			slash := filepath.ToSlash(rel)
			if slash == backupComposeMember {
				// The workspace compose copy is packed as the compose member.
				return nil
			}
			file, err := os.Open(current)
			if err != nil {
				return err
			}
			defer file.Close()
			return stage(backupWorkspacePrefix+slash, file)
		})
		if err != nil {
			return nil, err
		}
	}
	for _, volume := range source.Volumes {
		if err := stage(backupVolumeMember(volume.Name), volume.Tar); err != nil {
			return nil, err
		}
	}
	return staged, nil
}

// hashStagedBackupMembers builds the manifest from the staged members.
func hashStagedBackupMembers(staged []stagedBackupMember, appID string, created time.Time) (BackupManifest, error) {
	members := make([]BackupMemberDigest, 0, len(staged))
	payload := sha256.New()
	var payloadSize int64
	for _, member := range staged {
		digest, size, err := hashBackupMemberFile(member.path, payload)
		if err != nil {
			return BackupManifest{}, err
		}
		members = append(members, BackupMemberDigest{Name: member.name, SHA256: digest, Size: size})
		payloadSize += size
	}
	return BackupManifest{
		Version:       backupManifestVersion,
		AppID:         appID,
		CreatedAt:     created.Format(time.RFC3339),
		Compression:   backupCompressionZstd,
		PayloadSHA256: hex.EncodeToString(payload.Sum(nil)),
		PayloadSize:   payloadSize,
		Members:       members,
	}, nil
}

func writeBackupArtifact(target string, manifest BackupManifest, staged []stagedBackupMember, created time.Time) error {
	file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	encoder, err := zstd.NewWriter(file)
	if err != nil {
		file.Close()
		return err
	}
	tarWriter := tar.NewWriter(encoder)
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		file.Close()
		return err
	}
	if err := writeBackupTarMember(tarWriter, BackupManifestName, int64(len(manifestJSON)), created, bytes.NewReader(manifestJSON)); err != nil {
		file.Close()
		return err
	}
	for _, member := range staged {
		info, err := os.Lstat(member.path)
		if err != nil {
			file.Close()
			return err
		}
		content, err := os.Open(member.path)
		if err != nil {
			file.Close()
			return err
		}
		err = writeBackupTarMember(tarWriter, member.name, info.Size(), created, content)
		content.Close()
		if err != nil {
			file.Close()
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		file.Close()
		return err
	}
	if err := encoder.Close(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func writeBackupTarMember(tarWriter *tar.Writer, name string, size int64, created time.Time, content io.Reader) error {
	header := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     size,
		Typeflag: tar.TypeReg,
		ModTime:  created,
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return err
	}
	_, err := io.Copy(tarWriter, content)
	return err
}

// BackupArtifactReader reads one verified artifact; every operation reopens
// the file and re-checks the member digest it streams.
type BackupArtifactReader struct {
	path     string
	manifest BackupManifest
}

// OpenBackupArtifact verifies the whole artifact and returns a reader for it.
func OpenBackupArtifact(path string) (*BackupArtifactReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	manifest, err := verifyBackupArtifact(file)
	if err != nil {
		return nil, err
	}
	return &BackupArtifactReader{path: path, manifest: manifest}, nil
}

func verifyBackupArtifact(file io.Reader) (BackupManifest, error) {
	decoder, err := zstd.NewReader(file)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("%w: %v", ErrBackupArtifactCorrupt, err)
	}
	defer decoder.Close()
	tarReader := tar.NewReader(decoder)
	manifest, err := readBackupManifest(tarReader)
	if err != nil {
		return BackupManifest{}, err
	}
	payload := sha256.New()
	var payloadSize int64
	for _, want := range manifest.Members {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return BackupManifest{}, fmt.Errorf("%w: member %s is missing", ErrBackupArtifactCorrupt, want.Name)
		}
		if err != nil {
			return BackupManifest{}, fmt.Errorf("%w: %v", ErrBackupArtifactCorrupt, err)
		}
		if header.Name != want.Name || header.Typeflag != tar.TypeReg {
			return BackupManifest{}, fmt.Errorf("%w: member %s is missing or not a regular file", ErrBackupArtifactCorrupt, want.Name)
		}
		digest := sha256.New()
		size, err := io.Copy(io.MultiWriter(digest, payload), tarReader)
		if err != nil {
			return BackupManifest{}, fmt.Errorf("%w: member %s is truncated: %v", ErrBackupArtifactCorrupt, want.Name, err)
		}
		if size != want.Size || hex.EncodeToString(digest.Sum(nil)) != want.SHA256 {
			return BackupManifest{}, fmt.Errorf("%w: member %s checksum mismatch", ErrBackupArtifactCorrupt, want.Name)
		}
		payloadSize += size
	}
	if _, err := tarReader.Next(); !errors.Is(err, io.EOF) {
		if err != nil {
			return BackupManifest{}, fmt.Errorf("%w: %v", ErrBackupArtifactCorrupt, err)
		}
		return BackupManifest{}, fmt.Errorf("%w: unexpected member after %s", ErrBackupArtifactCorrupt, manifest.Members[len(manifest.Members)-1].Name)
	}
	if payloadSize != manifest.PayloadSize || hex.EncodeToString(payload.Sum(nil)) != manifest.PayloadSHA256 {
		return BackupManifest{}, fmt.Errorf("%w: payload checksum mismatch", ErrBackupArtifactCorrupt)
	}
	return manifest, nil
}

func readBackupManifest(tarReader *tar.Reader) (BackupManifest, error) {
	header, err := tarReader.Next()
	if err != nil {
		return BackupManifest{}, fmt.Errorf("%w: manifest is unreadable: %v", ErrBackupArtifactCorrupt, err)
	}
	if header.Name != BackupManifestName || header.Typeflag != tar.TypeReg || header.Size > backupManifestMaxBytes {
		return BackupManifest{}, fmt.Errorf("%w: manifest is missing or oversized", ErrBackupArtifactCorrupt)
	}
	payload, err := io.ReadAll(tarReader)
	if err != nil {
		return BackupManifest{}, fmt.Errorf("%w: manifest is truncated: %v", ErrBackupArtifactCorrupt, err)
	}
	var manifest BackupManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return BackupManifest{}, fmt.Errorf("%w: manifest is not valid JSON: %v", ErrBackupArtifactCorrupt, err)
	}
	if err := validateBackupManifest(&manifest); err != nil {
		return BackupManifest{}, fmt.Errorf("%w: %v", ErrBackupArtifactCorrupt, err)
	}
	return manifest, nil
}

func validateBackupManifest(manifest *BackupManifest) error {
	if manifest.Version != backupManifestVersion {
		return fmt.Errorf("manifest version %d is unsupported", manifest.Version)
	}
	if !validID(manifest.AppID) {
		return errors.New("manifest app id is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.CreatedAt); err != nil {
		return errors.New("manifest timestamp is invalid")
	}
	if manifest.Compression != backupCompressionZstd {
		return fmt.Errorf("manifest compression %q is unsupported", manifest.Compression)
	}
	if !sha256Hex(manifest.PayloadSHA256) {
		return errors.New("manifest payload checksum is invalid")
	}
	if manifest.PayloadSize < 0 {
		return errors.New("manifest payload size is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Members))
	hasCompose := false
	for _, member := range manifest.Members {
		if !validBackupMemberName(member.Name) {
			return fmt.Errorf("manifest member %q is invalid", member.Name)
		}
		if !sha256Hex(member.SHA256) {
			return fmt.Errorf("manifest member %q checksum is invalid", member.Name)
		}
		if member.Size < 0 {
			return fmt.Errorf("manifest member %q size is invalid", member.Name)
		}
		if _, exists := seen[member.Name]; exists {
			return fmt.Errorf("manifest member %q is duplicated", member.Name)
		}
		seen[member.Name] = struct{}{}
		if member.Name == backupComposeMember {
			hasCompose = true
		}
	}
	if !hasCompose {
		return fmt.Errorf("manifest member %s is missing", backupComposeMember)
	}
	return nil
}

// Manifest returns the verified manifest of the opened artifact.
func (reader *BackupArtifactReader) Manifest() BackupManifest {
	return reader.manifest
}

// VolumeNames returns the volume names packed into the artifact.
func (reader *BackupArtifactReader) VolumeNames() []string {
	var names []string
	for _, member := range reader.manifest.Members {
		if !strings.HasPrefix(member.Name, backupVolumePrefix) {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(member.Name, backupVolumePrefix), ".tar")
		if validBackupVolumeName(name) {
			names = append(names, name)
		}
	}
	return names
}

// ReadCompose returns the compose document stored in the artifact.
func (reader *BackupArtifactReader) ReadCompose() (string, error) {
	var compose string
	err := reader.withMember(backupComposeMember, func(content io.Reader) error {
		payload, err := io.ReadAll(io.LimitReader(content, MaxConfigBytes+1))
		if err != nil {
			return err
		}
		if len(payload) > MaxConfigBytes {
			return errors.New("backup compose exceeds size limit")
		}
		compose = string(payload)
		return nil
	})
	if err != nil {
		return "", err
	}
	return compose, nil
}

// ExtractVolume streams one volume's uncompressed tar out of the artifact
// into destDir, re-verifying that member's checksum while copying.
func (reader *BackupArtifactReader) ExtractVolume(volume, destDir string) error {
	if !validBackupVolumeName(volume) {
		return errors.New("backup volume name is invalid")
	}
	if err := requireBackupDestDir(destDir); err != nil {
		return err
	}
	return reader.withMember(backupVolumeMember(volume), func(content io.Reader) error {
		return extractTarToDir(tar.NewReader(content), destDir)
	})
}

// ExtractWorkspace streams every workspace member into destDir, re-verifying
// each member's checksum while copying.
func (reader *BackupArtifactReader) ExtractWorkspace(destDir string) error {
	if err := requireBackupDestDir(destDir); err != nil {
		return err
	}
	file, decoder, tarReader, err := reader.openTar()
	if err != nil {
		return err
	}
	defer decoder.Close()
	defer file.Close()
	if err := skipBackupManifest(tarReader); err != nil {
		return err
	}
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBackupArtifactCorrupt, err)
		}
		if header.Typeflag != tar.TypeReg || !strings.HasPrefix(header.Name, backupWorkspacePrefix) {
			continue
		}
		rel, ok := safeBackupEntryName(strings.TrimPrefix(header.Name, backupWorkspacePrefix))
		if !ok {
			return fmt.Errorf("%w: workspace member %s escapes destination", ErrBackupArtifactCorrupt, header.Name)
		}
		want, err := reader.memberDigest(header.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(io.MultiWriter(out, digest), tarReader)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(digest.Sum(nil)) != want {
			return fmt.Errorf("%w: member %s checksum mismatch", ErrBackupArtifactCorrupt, header.Name)
		}
	}
}

// withMember streams one member to consume, hashing its bytes and comparing
// the digest against the verified manifest.
func (reader *BackupArtifactReader) withMember(name string, consume func(io.Reader) error) error {
	file, decoder, tarReader, err := reader.openTar()
	if err != nil {
		return err
	}
	defer decoder.Close()
	defer file.Close()
	if err := skipBackupManifest(tarReader); err != nil {
		return err
	}
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: member %s is missing", ErrBackupArtifactCorrupt, name)
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBackupArtifactCorrupt, err)
		}
		if header.Name != name {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: member %s is not a regular file", ErrBackupArtifactCorrupt, name)
		}
		want, err := reader.memberDigest(name)
		if err != nil {
			return err
		}
		digest := sha256.New()
		if err := consume(io.TeeReader(tarReader, digest)); err != nil {
			return err
		}
		if _, err := io.Copy(digest, tarReader); err != nil {
			return fmt.Errorf("%w: member %s is truncated: %v", ErrBackupArtifactCorrupt, name, err)
		}
		if hex.EncodeToString(digest.Sum(nil)) != want {
			return fmt.Errorf("%w: member %s checksum mismatch", ErrBackupArtifactCorrupt, name)
		}
		return nil
	}
}

func (reader *BackupArtifactReader) memberDigest(name string) (string, error) {
	for _, member := range reader.manifest.Members {
		if member.Name == name {
			return member.SHA256, nil
		}
	}
	return "", fmt.Errorf("%w: member %s is not in manifest", ErrBackupArtifactCorrupt, name)
}

func (reader *BackupArtifactReader) openTar() (*os.File, *zstd.Decoder, *tar.Reader, error) {
	file, err := os.Open(reader.path)
	if err != nil {
		return nil, nil, nil, err
	}
	decoder, err := zstd.NewReader(file)
	if err != nil {
		file.Close()
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrBackupArtifactCorrupt, err)
	}
	return file, decoder, tar.NewReader(decoder), nil
}

func skipBackupManifest(tarReader *tar.Reader) error {
	header, err := tarReader.Next()
	if err != nil {
		return fmt.Errorf("%w: manifest is unreadable: %v", ErrBackupArtifactCorrupt, err)
	}
	if header.Name != BackupManifestName {
		return fmt.Errorf("%w: manifest is missing", ErrBackupArtifactCorrupt)
	}
	return nil
}

func requireBackupDestDir(destDir string) error {
	info, err := os.Stat(destDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("backup destination is not a directory")
	}
	return nil
}

// extractTarToDir streams an uncompressed volume tar into root, rejecting
// entries that would escape it or carry unsupported types.
func extractTarToDir(tarReader *tar.Reader, root string) error {
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: volume tar is invalid: %v", ErrBackupArtifactCorrupt, err)
		}
		rel, ok := safeBackupEntryName(header.Name)
		if !ok {
			return fmt.Errorf("%w: volume tar entry %q escapes destination", ErrBackupArtifactCorrupt, header.Name)
		}
		target := filepath.Join(root, filepath.FromSlash(rel))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(header.Mode).Perm()
			if mode == 0 {
				mode = 0o644
			}
			if err := writeTarFile(tarReader, target, mode); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: volume tar entry %q has unsupported type", ErrBackupArtifactCorrupt, header.Name)
		}
	}
}

func writeTarFile(content io.Reader, target string, mode os.FileMode) error {
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, content)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// safeBackupEntryName reports whether name is a clean relative slash path
// that stays inside an extraction root, and returns its cleaned form.
func safeBackupEntryName(name string) (string, bool) {
	if name == "" || len(name) > 512 || strings.ContainsAny(name, "\x00\\") {
		return "", false
	}
	if path.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", false
	}
	if _, _, ok := windowsDrive(name); ok {
		return "", false
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", false
	}
	return clean, true
}

func validBackupMemberName(name string) bool {
	if _, ok := safeBackupEntryName(name); !ok || strings.Contains(name, "/../") {
		return false
	}
	if name == backupComposeMember {
		return true
	}
	if strings.HasPrefix(name, backupWorkspacePrefix) && len(name) > len(backupWorkspacePrefix) {
		return true
	}
	if strings.HasPrefix(name, backupVolumePrefix) && strings.HasSuffix(name, ".tar") &&
		len(name) > len(backupVolumePrefix)+len(".tar") {
		return true
	}
	return false
}

func validBackupVolumeName(name string) bool {
	if name == "" || len(name) > backupVolumeNameMax {
		return false
	}
	first := name[0]
	isAlnum := (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')
	if !isAlnum {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func backupVolumeMember(volume string) string {
	return backupVolumePrefix + volume + ".tar"
}

func sha256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func hashBackupMemberFile(path string, payload hash.Hash) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(io.MultiWriter(digest, payload), file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func hashFileContents(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}
