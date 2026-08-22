package webdav

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const OwnedShareName = "share"

var errPathEscape = errors.New("path is outside the share root")

func resolveShareRoot(ownedRoot, configuredRoot string) (string, error) {
	configuredRoot = strings.TrimSpace(configuredRoot)
	if configuredRoot != "" {
		if !filepath.IsAbs(configuredRoot) {
			return "", errors.New("root_path must be an absolute path")
		}
		return validateShareRoot(configuredRoot, false)
	}
	if strings.TrimSpace(ownedRoot) != "" {
		return validateShareRoot(ownedRoot, true)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return validateShareRoot(filepath.Join(cwd, OwnedShareName), true)
}

func validateShareRoot(root string, create bool) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", errors.New("share root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if isVolumeRoot(abs) {
		return "", errors.New("share root must not be the filesystem root")
	}
	if create {
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return "", err
		}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("share root is not accessible: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("share root is not a directory")
	}
	return abs, nil
}

func isVolumeRoot(path string) bool {
	cleaned := filepath.Clean(path)
	separator := string(os.PathSeparator)
	if cleaned == separator {
		return true
	}
	volume := filepath.VolumeName(cleaned)
	return volume != "" && (cleaned == volume+separator || cleaned == volume+`\` || cleaned == volume+`/`)
}

func resolveInsideRoot(root, name string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("share root is required")
	}
	if strings.Contains(name, "\x00") {
		return "", errPathEscape
	}
	if filepath.VolumeName(name) != "" {
		return "", errPathEscape
	}
	virtual := strings.ReplaceAll(name, `\`, "/")
	if filepath.VolumeName(virtual) != "" {
		return "", errPathEscape
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(virtual, "/"))
	if cleaned != "/" && !strings.HasPrefix(cleaned, "/") {
		return "", errPathEscape
	}
	rel := strings.TrimPrefix(cleaned, "/")
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", errPathEscape
	}
	if rel != "" {
		for _, part := range strings.Split(rel, "/") {
			if part == "" || part == "." || part == ".." || filepath.VolumeName(part) != "" {
				return "", errPathEscape
			}
		}
	}
	target := root
	if rel != "" {
		target = filepath.Join(root, filepath.FromSlash(rel))
	}
	target = filepath.Clean(target)
	relative, err := filepath.Rel(root, target)
	if err != nil || !relativePathInside(relative) {
		return "", errPathEscape
	}
	return target, nil
}

func relativePathInside(rel string) bool {
	if rel == "." {
		return true
	}
	if rel == "" || filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || strings.HasPrefix(rel, "../") {
		return false
	}
	return true
}

func virtualPath(root, target string) string {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}
