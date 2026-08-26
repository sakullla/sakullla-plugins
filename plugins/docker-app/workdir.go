package dockerapp

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const ComposeFileName = "compose.yaml"

type bindClass int

const (
	bindNamed bindClass = iota
	bindRelative
	bindHost
)

// VolumeBind is a compose bind after classification. Relative binds resolve
// against the app workdir; host mounts stay absolute and still require preview.
type VolumeBind struct {
	Source        string
	HostPath      string
	ContainerPath string
	Relative      bool
}

// Workspace is the Agent-local directory for one app, including the compose
// file written there and binds resolved against that directory.
type Workspace struct {
	Dir         string
	ComposeFile string
	Binds       []VolumeBind
}

// AppWorkDir returns the independent working directory for an app under root.
func AppWorkDir(root, appID string) (string, error) {
	if strings.TrimSpace(root) == "" || !validID(appID) {
		return "", errors.New("app workdir is invalid")
	}
	if !filepath.IsAbs(root) {
		abs, err := filepath.Abs(root)
		if err != nil {
			return "", err
		}
		root = abs
	}
	dir := filepath.Join(root, appID)
	rel, err := filepath.Rel(root, dir)
	if err != nil || !relativePathInside(rel) {
		return "", errors.New("app workdir is invalid")
	}
	return dir, nil
}

// PrepareAppWorkspace creates the app workdir, materializes relative bind
// directories, and writes compose YAML without rewriting volume sources.
func PrepareAppWorkspace(root, appID, compose string) (Workspace, error) {
	dir, err := AppWorkDir(root, appID)
	if err != nil {
		return Workspace{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Workspace{}, err
	}
	binds, err := ResolveComposeBinds(dir, compose)
	if err != nil {
		return Workspace{}, err
	}
	for _, bind := range binds {
		if !bind.Relative {
			continue
		}
		if err := ensureBindHostPath(bind.HostPath, bind.ContainerPath); err != nil {
			return Workspace{}, err
		}
	}
	composeFile := filepath.Join(dir, ComposeFileName)
	if err := writeComposeDocument(composeFile, compose); err != nil {
		return Workspace{}, err
	}
	return Workspace{Dir: dir, ComposeFile: composeFile, Binds: binds}, nil
}

func writeComposeDocument(path, compose string) error {
	err := os.WriteFile(path, []byte(compose), 0o644)
	if err == nil {
		return nil
	}
	info, statErr := os.Lstat(path)
	if statErr == nil && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 && strings.TrimSpace(compose) != "" {
		// Host-owned compose.yaml from the Docker proxy is still usable;
		// the proxy rewrites it on the next allowed command.
		return nil
	}
	return err
}

// ResolveComposeBinds classifies compose volumes and resolves relative sources
// to host paths under workdir. Absolute host mounts are not rewritten.
func ResolveComposeBinds(workdir, document string) ([]VolumeBind, error) {
	if workdir == "" {
		return nil, errors.New("app workdir is invalid")
	}
	binds, err := parseComposeVolumeBinds(document)
	if err != nil {
		return nil, err
	}
	resolved := make([]VolumeBind, 0, len(binds))
	for _, bind := range binds {
		if !bind.Relative {
			bind.HostPath = bind.Source
			resolved = append(resolved, bind)
			continue
		}
		hostPath, err := resolveRelativePath(workdir, bind.Source)
		if err != nil {
			return nil, err
		}
		bind.HostPath = hostPath
		resolved = append(resolved, bind)
	}
	return resolved, nil
}

// ResolveAppBinds resolves an applied app's compose binds against its workdir.
func ResolveAppBinds(app App) ([]VolumeBind, error) {
	if app.WorkDir == "" {
		return nil, errors.New("app workdir is invalid")
	}
	return ResolveComposeBinds(app.WorkDir, app.Compose)
}

type composeBindDocument struct {
	Services map[string]composeBindService `yaml:"services"`
}

type composeBindService struct {
	Volumes []composeBindVolume `yaml:"volumes"`
}

type composeBindVolume struct {
	Short  string
	Source string
	Target string
}

func (volume *composeBindVolume) UnmarshalYAML(value *yaml.Node) error {
	if volume == nil || value == nil {
		return ErrInvalidCompose
	}
	switch value.Kind {
	case yaml.ScalarNode:
		volume.Short = value.Value
		volume.Source = volumeSource(value.Value)
		volume.Target = volumeTarget(value.Value)
		return nil
	case yaml.MappingNode:
		var long struct {
			Source string `yaml:"source"`
			Src    string `yaml:"src"`
			Target string `yaml:"target"`
		}
		if err := value.Decode(&long); err != nil {
			return ErrInvalidCompose
		}
		volume.Source = strings.TrimSpace(long.Source)
		if volume.Source == "" {
			volume.Source = strings.TrimSpace(long.Src)
		}
		volume.Target = strings.TrimSpace(long.Target)
		return nil
	default:
		return ErrInvalidCompose
	}
}

func parseComposeVolumeBinds(document string) ([]VolumeBind, error) {
	if document == "" {
		return nil, nil
	}
	var file composeBindDocument
	if err := yaml.Unmarshal([]byte(document), &file); err != nil {
		return nil, ErrInvalidCompose
	}
	binds := make([]VolumeBind, 0)
	for _, service := range file.Services {
		for _, spec := range service.Volumes {
			source := spec.Source
			class := classifyBindSource(source)
			if class == bindNamed {
				continue
			}
			binds = append(binds, VolumeBind{
				Source:        source,
				ContainerPath: spec.Target,
				Relative:      class == bindRelative,
			})
		}
	}
	return binds, nil
}

func unmarshalComposeDocument(document string, file *composeDocument) error {
	if err := yaml.Unmarshal([]byte(document), file); err != nil {
		return ErrInvalidCompose
	}
	return nil
}

func classifyVolumes(specs []string) (hosts, named, relatives []string) {
	for _, spec := range specs {
		host, volume, relative := classifyVolume(spec)
		if host != "" {
			hosts = append(hosts, host)
		}
		if volume != "" {
			named = append(named, volume)
		}
		if relative != "" {
			relatives = append(relatives, relative)
		}
	}
	return hosts, named, relatives
}

func classifyVolume(spec string) (hostMount, namedVolume, relativeBind string) {
	source := volumeSource(spec)
	switch classifyBindSource(source) {
	case bindRelative:
		return "", "", spec
	case bindHost:
		return spec, "", ""
	default:
		if source == "" {
			return "", "", ""
		}
		return "", source, ""
	}
}

func classifyBindSource(source string) bindClass {
	if source == "" {
		return bindNamed
	}
	if strings.HasPrefix(source, "~") || strings.HasPrefix(source, "/") || strings.HasPrefix(source, "\\") {
		return bindHost
	}
	if _, _, ok := windowsDrive(source); ok {
		return bindHost
	}
	normalized := strings.ReplaceAll(source, "\\", "/")
	if normalized == ".." || strings.HasPrefix(normalized, "../") {
		return bindHost
	}
	if normalized == "." || strings.HasPrefix(normalized, "./") {
		if relativeEscapes(normalized) {
			return bindHost
		}
		return bindRelative
	}
	if strings.Contains(normalized, "/") {
		if relativeEscapes(normalized) {
			return bindHost
		}
		return bindRelative
	}
	return bindNamed
}

func relativeEscapes(source string) bool {
	normalized := strings.ReplaceAll(source, "\\", "/")
	const dummy = "/work"
	joined := path.Join(dummy, normalized)
	if joined == dummy {
		return false
	}
	return !strings.HasPrefix(joined, dummy+"/")
}

func volumeSource(spec string) string {
	if drive, rest, ok := windowsDrive(spec); ok {
		if index := strings.IndexByte(rest, ':'); index >= 0 {
			return drive + rest[:index]
		}
		return spec
	}
	if index := strings.IndexByte(spec, ':'); index >= 0 {
		return spec[:index]
	}
	return spec
}

func volumeTarget(spec string) string {
	source := volumeSource(spec)
	if len(spec) <= len(source) {
		return ""
	}
	rest := spec[len(source):]
	rest = strings.TrimPrefix(rest, ":")
	target, _, _ := strings.Cut(rest, ":")
	return target
}

func windowsDrive(spec string) (string, string, bool) {
	if len(spec) < 2 || spec[1] != ':' {
		return "", "", false
	}
	letter := spec[0]
	if (letter < 'A' || letter > 'Z') && (letter < 'a' || letter > 'z') {
		return "", "", false
	}
	return spec[:2], spec[2:], true
}

func resolveRelativePath(workdir, source string) (string, error) {
	joined := filepath.Join(workdir, filepath.FromSlash(strings.ReplaceAll(source, "\\", "/")))
	cleaned := filepath.Clean(joined)
	rel, err := filepath.Rel(workdir, cleaned)
	if err != nil || !relativePathInside(rel) {
		return "", errors.New("relative bind escapes app workdir")
	}
	return cleaned, nil
}

func relativePathInside(rel string) bool {
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || strings.HasPrefix(rel, "../") {
		return false
	}
	return true
}

func ensureBindHostPath(hostPath, containerPath string) error {
	if looksLikeFileBind(hostPath, containerPath) {
		return ensureBindFilePath(hostPath)
	}
	return os.MkdirAll(hostPath, 0o755)
}

func ensureBindFilePath(hostPath string) error {
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(hostPath)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(hostPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
		if createErr != nil {
			if errors.Is(createErr, os.ErrExist) {
				return ensureBindFilePath(hostPath)
			}
			return createErr
		}
		return file.Close()
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("relative bind path is a symlink")
	}
	if !info.IsDir() {
		return nil
	}
	entries, readErr := os.ReadDir(hostPath)
	if readErr != nil {
		return readErr
	}
	if len(entries) > 0 {
		return errors.New("relative file bind is a non-empty directory")
	}
	if err := os.Remove(hostPath); err != nil {
		return err
	}
	return ensureBindFilePath(hostPath)
}

func looksLikeFileBind(hostPath, containerPath string) bool {
	for _, candidate := range []string{hostPath, containerPath} {
		base := filepath.Base(candidate)
		ext := filepath.Ext(base)
		if ext != "" && ext != base {
			return true
		}
	}
	return false
}

func resolveWorkspaceFilePath(root, appID, filePath string) (workdir, resolved string, err error) {
	workdir, err = AppWorkDir(root, appID)
	if err != nil {
		return "", "", err
	}
	relative, err := normalizeWorkspaceRelativePath(filePath)
	if err != nil {
		return "", "", err
	}
	resolved, err = resolveRelativePath(workdir, relative)
	if err != nil {
		return "", "", errors.New("file path is not relative to app workdir")
	}
	rel, err := filepath.Rel(workdir, resolved)
	if err != nil || !relativePathInside(rel) {
		return "", "", errors.New("file path is not relative to app workdir")
	}
	if err := rejectSymlinkTraversal(workdir, rel); err != nil {
		return "", "", err
	}
	return workdir, resolved, nil
}

func rejectSymlinkTraversal(root, relative string) error {
	if relative == "." {
		return nil
	}
	current := root
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("file path is not relative to app workdir")
		}
	}
	return nil
}

func normalizeWorkspaceRelativePath(filePath string) (string, error) {
	trimmed := strings.TrimSpace(filePath)
	if trimmed == "" {
		return "", errors.New("file path is not relative to app workdir")
	}
	if strings.ContainsRune(trimmed, '\x00') {
		return "", errors.New("file path is not relative to app workdir")
	}
	normalized := strings.ReplaceAll(trimmed, "\\", "/")
	if filepath.IsAbs(trimmed) || path.IsAbs(normalized) {
		return "", errors.New("file path is not relative to app workdir")
	}
	if classifyBindSource(trimmed) == bindHost {
		return "", errors.New("file path is not relative to app workdir")
	}
	for _, segment := range strings.Split(normalized, "/") {
		if segment == ".." {
			return "", errors.New("file path is not relative to app workdir")
		}
	}
	return trimmed, nil
}

func workspaceDisplayPath(workdir, resolved string) (string, error) {
	rel, err := filepath.Rel(workdir, resolved)
	if err != nil || !relativePathInside(rel) {
		return "", errors.New("file path is not relative to app workdir")
	}
	if rel == "." {
		return ".", nil
	}
	return filepath.ToSlash(rel), nil
}

type workspaceFileEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size,omitempty"`
}
