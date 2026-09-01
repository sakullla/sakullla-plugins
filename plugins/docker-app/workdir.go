package dockerapp

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	lchownPath = os.Lchown
	chmodPath  = os.Chmod
)

const (
	ComposeFileName   = "compose.yaml"
	usedImagesDirName = ".nre-used-images"
)

type bindClass int

const (
	bindNamed bindClass = iota
	bindRelative
	bindHost
)

// VolumeBind is a compose bind after classification. Relative binds resolve
// against the app workdir; host mounts stay absolute and still require preview.
// Numeric compose user: is applied only to relative binds. Agent plugin
// sandboxes often map only uid 0, so chown to 1000:1000 can fail; those
// binds are then made world-writable so the container user can write.
type VolumeBind struct {
	Source        string
	HostPath      string
	ContainerPath string
	Relative      bool
	uid           int
	gid           int
	applyOwner    bool
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
		if err := applyRelativeBindOwner(bind); err != nil {
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
	User    any                 `yaml:"user"`
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
		uid, gid, applyOwner := parseComposeUser(service.User)
		for _, spec := range service.Volumes {
			source := spec.Source
			class := classifyBindSource(source)
			if class == bindNamed {
				continue
			}
			relative := class == bindRelative
			binds = append(binds, VolumeBind{
				Source:        source,
				ContainerPath: spec.Target,
				Relative:      relative,
				uid:           uid,
				gid:           gid,
				applyOwner:    applyOwner && relative,
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

func parseComposeUser(raw any) (uid, gid int, ok bool) {
	switch value := raw.(type) {
	case nil:
		return 0, 0, false
	case string:
		return parseNumericUser(strings.TrimSpace(value))
	case int:
		return parseNumericUser(strconv.Itoa(value))
	case int64:
		return parseNumericUser(strconv.FormatInt(value, 10))
	case uint64:
		return parseNumericUser(strconv.FormatUint(value, 10))
	default:
		return 0, 0, false
	}
}

func parseNumericUser(spec string) (uid, gid int, ok bool) {
	if spec == "" {
		return 0, 0, false
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	uid, ok = parseHostID(userPart)
	if !ok {
		return 0, 0, false
	}
	if !hasGroup {
		return uid, -1, true
	}
	if groupPart == "" || strings.Contains(groupPart, ":") {
		return 0, 0, false
	}
	gid, ok = parseHostID(groupPart)
	if !ok {
		return 0, 0, false
	}
	return uid, gid, true
}

func parseHostID(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 0 {
		return 0, false
	}
	return int(parsed), true
}

func applyRelativeBindOwner(bind VolumeBind) error {
	if !bind.applyOwner {
		return nil
	}
	hostPath := bind.HostPath
	if hostPath == "" {
		return nil
	}
	info, err := os.Lstat(hostPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("relative bind path is a symlink")
	}
	_ = walkRelativeBind(hostPath, info, func(path string, _ bool) error {
		return lchownPath(path, bind.uid, bind.gid)
	})
	if bind.uid == 0 {
		return nil
	}
	return walkRelativeBind(hostPath, info, func(path string, dir bool) error {
		mode := os.FileMode(0o666)
		if dir {
			mode = 0o777
		}
		return chmodPath(path, mode)
	})
}

func walkRelativeBind(hostPath string, info os.FileInfo, visit func(path string, dir bool) error) error {
	if !info.IsDir() {
		return visit(hostPath, false)
	}
	return filepath.WalkDir(hostPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return visit(path, entry.IsDir())
	})
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

func pinComposeImages(document string, serviceDigests map[string]string) string {
	if strings.TrimSpace(document) == "" || len(serviceDigests) == 0 {
		return document
	}
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(document), &raw); err != nil || raw == nil {
		return document
	}
	services, _ := raw["services"].(map[string]any)
	if len(services) == 0 {
		return document
	}
	changed := false
	for name, digest := range serviceDigests {
		name = strings.TrimSpace(name)
		digest = strings.TrimSpace(digest)
		if name == "" || digest == "" {
			continue
		}
		body, ok := services[name].(map[string]any)
		if !ok {
			continue
		}
		image, _ := body["image"].(string)
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		pinned := pinImageDigest(image, digest)
		if pinned == image {
			continue
		}
		body["image"] = pinned
		changed = true
	}
	if !changed {
		return document
	}
	encoded, err := yaml.Marshal(raw)
	if err != nil {
		return document
	}
	return string(encoded)
}

func pinComposeImagesForRef(document, image, digest string) string {
	want := imageRefName(image)
	if want == "" || strings.TrimSpace(digest) == "" {
		return document
	}
	pins := make(map[string]string)
	for _, service := range composeServiceImages(document) {
		if imageRefName(service.Image) == want {
			pins[service.Name] = digest
		}
	}
	return pinComposeImages(document, pins)
}

func imageRefName(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	if at := strings.LastIndex(image, "@"); at >= 0 {
		return strings.TrimSpace(image[:at])
	}
	return image
}

func imageDigestSuffix(image string) string {
	image = strings.TrimSpace(image)
	at := strings.LastIndex(image, "@")
	if at < 0 {
		return ""
	}
	return strings.TrimSpace(image[at+1:])
}

func composeImageRefs(document string) []string {
	if strings.TrimSpace(document) == "" {
		return nil
	}
	var file struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(document), &file); err != nil {
		return nil
	}
	images := make([]string, 0, len(file.Services))
	for _, service := range file.Services {
		image := strings.TrimSpace(service.Image)
		if image == "" {
			continue
		}
		images = append(images, image)
	}
	return uniqueImageRefs(images)
}

func uniqueImageRefs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func appImageRefs(app App) []string {
	images := composeImageRefs(app.Compose)
	if strings.TrimSpace(app.Image) != "" {
		images = append(images, app.Image)
	}
	return uniqueImageRefs(images)
}

func siblingComposeImages(root, excludeAppID string) []string {
	if strings.TrimSpace(root) == "" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var images []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == excludeAppID || !validID(name) {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(root, name, ComposeFileName))
		if err != nil {
			continue
		}
		images = append(images, composeImageRefs(string(payload))...)
	}
	return uniqueImageRefs(images)
}

func usedImagesFile(root, appID string) string {
	return filepath.Join(root, usedImagesDirName, appID)
}

func loadUsedImages(root, appID string) []string {
	payload, err := os.ReadFile(usedImagesFile(root, appID))
	if err != nil {
		return nil
	}
	var images []string
	for _, line := range strings.Split(string(payload), "\n") {
		if image := strings.TrimSpace(line); image != "" {
			images = append(images, image)
		}
	}
	return uniqueImageRefs(images)
}

func existingWorkspaceImages(root, appID string) []string {
	var images []string
	if dir, err := AppWorkDir(root, appID); err == nil {
		if payload, err := os.ReadFile(filepath.Join(dir, ComposeFileName)); err == nil {
			images = append(images, composeImageRefs(string(payload))...)
		}
	}
	images = append(images, loadUsedImages(root, appID)...)
	return uniqueImageRefs(images)
}

func recordUsedImages(root, appID string, images []string) {
	merged := uniqueImageRefs(append(loadUsedImages(root, appID), images...))
	if len(merged) == 0 || !validID(appID) {
		return
	}
	dir := filepath.Join(root, usedImagesDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(usedImagesFile(root, appID), []byte(strings.Join(merged, "\n")+"\n"), 0o644)
}

func rewriteUsedImages(root, appID string, images []string) {
	images = uniqueImageRefs(images)
	path := usedImagesFile(root, appID)
	if len(images) == 0 || !validID(appID) {
		_ = os.Remove(path)
		return
	}
	dir := filepath.Join(root, usedImagesDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(strings.Join(images, "\n")+"\n"), 0o644)
}

func removeUsedImagesFile(root, appID string) {
	_ = os.Remove(usedImagesFile(root, appID))
}

func staleImageRefs(previous, current []string) []string {
	keep := make(map[string]struct{}, len(current))
	for _, image := range current {
		keep[image] = struct{}{}
	}
	var stale []string
	for _, image := range previous {
		if _, kept := keep[image]; kept {
			continue
		}
		stale = append(stale, image)
	}
	return uniqueImageRefs(stale)
}
