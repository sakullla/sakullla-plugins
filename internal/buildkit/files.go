package buildkit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type FileRecord struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func writeCanonicalJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func copyRegularFile(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source %q is not a regular file", source)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	return errors.Join(copyErr, closeErr)
}

func recordsForTree(root string, excluded map[string]bool) ([]FileRecord, error) {
	return recordsForTreeWithModes(root, excluded, nil)
}

func recordsForTreeWithModes(root string, excluded map[string]bool, modeOverrides map[string]string) ([]FileRecord, error) {
	var records []FileRecord
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("package tree contains non-regular entry %q", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if excluded[rel] {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(contents)
		mode := "0644"
		if info.Mode()&0o111 != 0 {
			mode = "0755"
		}
		if declared, ok := modeOverrides[rel]; ok {
			if declared != "0644" && declared != "0755" {
				return fmt.Errorf("package mode override for %q is invalid", rel)
			}
			if runtime.GOOS != "windows" && mode != declared {
				return fmt.Errorf("package file %q mode is %s, want %s", rel, mode, declared)
			}
			mode = declared
		}
		records = append(records, FileRecord{
			Path: rel, Mode: mode, SHA256: hex.EncodeToString(digest[:]), Size: info.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func digestRecords(records []FileRecord) string {
	hash := sha256.New()
	for _, record := range records {
		fmt.Fprintf(hash, "%s\x00%s\x00%d\x00%s\n", record.Path, record.Mode, record.Size, record.SHA256)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func safeBaseName(path string) (string, error) {
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "." || base == string(filepath.Separator) || strings.Contains(base, "\x00") {
		return "", fmt.Errorf("invalid file path %q", path)
	}
	return base, nil
}

func safePackagePath(value string) bool {
	if value == "" || strings.Contains(value, `\`) || filepath.IsAbs(filepath.FromSlash(value)) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}
