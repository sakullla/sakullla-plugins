package webdav

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const OwnedShareName = "share"

type Handler struct {
	root string
}

func NewHandler(root string) (*Handler, error) {
	cleaned, err := validateShareRoot(root, false)
	if err != nil {
		return nil, err
	}
	return &Handler{root: cleaned}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (handler *Handler) Close() error { return nil }

func (handler *Handler) Root() string { return handler.root }

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
