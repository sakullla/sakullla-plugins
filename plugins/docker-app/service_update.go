package dockerapp

import (
	"errors"
	"strings"
)

const (
	LockShortcutPatch = "patch"
	LockShortcutMinor = "minor"
	LockShortcutMajor = "major"
	LockShortcutPin   = "pin"
)

type appServiceUpdate struct {
	Name string `json:"name"`
	Tag  string `json:"tag"`
}

type appIgnoredUpdate struct {
	Service string `json:"service"`
	Tag     string `json:"tag"`
	Clear   bool   `json:"clear"`
}

type appServiceView struct {
	Name        string          `json:"name"`
	Image       string          `json:"image,omitempty"`
	Tag         string          `json:"tag,omitempty"`
	Lock        string          `json:"lock,omitempty"`
	Ignored     []string        `json:"ignored,omitempty"`
	Update      bool            `json:"update,omitempty"`
	DefaultTag  string          `json:"default_tag,omitempty"`
	Candidates  []appCandidate  `json:"candidates,omitempty"`
	LockOptions []appLockOption `json:"lock_options,omitempty"`
	Unknown     bool            `json:"unknown,omitempty"`
}

type appCandidate struct {
	Tag    string `json:"tag"`
	Major  bool   `json:"major,omitempty"`
	Digest bool   `json:"digest,omitempty"`
}

type appLockOption struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Constraint string `json:"constraint,omitempty"`
}

func projectServiceViews(app App, tagsByService map[string][]string, digestAvailable bool) ([]appServiceView, bool) {
	images := app.ServiceImages
	if len(images) == 0 {
		images = composeServiceImages(app.Compose)
	}
	if len(images) == 0 {
		return nil, false
	}
	views := make([]appServiceView, 0, len(images))
	hasUpdate := false
	for _, service := range images {
		view := projectServiceView(app, service, tagsByService[service.Name], digestAvailable)
		if view.Update {
			hasUpdate = true
		}
		views = append(views, view)
	}
	return views, hasUpdate
}

func projectServiceView(app App, service ServiceImage, tags []string, digestAvailable bool) appServiceView {
	tag := extractDockerTag(service.Image)
	ignored := append([]string(nil), app.IgnoredUpdates[service.Name]...)
	lock := strings.TrimSpace(app.ImageLocks[service.Name])
	view := appServiceView{
		Name:        service.Name,
		Image:       service.Image,
		Tag:         tag,
		Lock:        lock,
		Ignored:     ignored,
		LockOptions: serviceLockOptions(service.Image),
	}
	_, _, semver := ParseSemverTag(service.Image)
	if !semver {
		if digestAvailable && tag != "" && !ignoredUpdateTag(tag, ignored) {
			view.Update = true
			view.DefaultTag = tag
			view.Candidates = []appCandidate{{Tag: tag, Digest: true}}
		}
		return view
	}
	if tags == nil {
		view.Unknown = true
		return view
	}
	allowed := allowedServiceCandidates(service.Image, tags, lock, ignored)
	if len(allowed) == 0 {
		return view
	}
	view.Update = true
	view.DefaultTag = allowed[0]
	view.Candidates = make([]appCandidate, 0, len(allowed))
	for _, candidate := range allowed {
		view.Candidates = append(view.Candidates, appCandidate{
			Tag:   candidate,
			Major: isMajorBump(service.Image, candidate),
		})
	}
	return view
}

func floatingDigestUpdateRequested(app App, serviceTags map[string]string) bool {
	if len(serviceTags) == 0 {
		return false
	}
	images := app.ServiceImages
	if len(images) == 0 {
		images = composeServiceImages(app.Compose)
	}
	for name, want := range serviceTags {
		wantTag := extractDockerTag(want)
		if strings.TrimSpace(name) == "" || wantTag == "" {
			continue
		}
		for _, service := range images {
			if service.Name != name {
				continue
			}
			if _, _, ok := ParseSemverTag(service.Image); ok {
				continue
			}
			if extractDockerTag(service.Image) == wantTag {
				return true
			}
		}
	}
	return false
}

func allowedServiceCandidates(current string, tags []string, lock string, ignored []string) []string {
	selected := SelectSemverCandidates(current, tags, lock)
	if len(selected) == 0 {
		return nil
	}
	kept := make([]string, 0, len(selected))
	for _, tag := range selected {
		if ignoredUpdateTag(tag, ignored) {
			continue
		}
		kept = append(kept, tag)
	}
	return kept
}

func ignoredUpdateTag(tag string, ignored []string) bool {
	for _, item := range ignored {
		if tag == item || SemverEqual(tag, item) {
			return true
		}
	}
	return false
}

func isMajorBump(current, candidate string) bool {
	left, ok := parseSemverTag(current)
	if !ok {
		return false
	}
	right, ok := parseSemverTag(candidate)
	if !ok || left.variant != right.variant {
		return false
	}
	return right.version.Major() > left.version.Major()
}

func serviceLockOptions(current string) []appLockOption {
	version, _, ok := ParseSemverTag(current)
	if !ok {
		return nil
	}
	return []appLockOption{
		{ID: LockShortcutPatch, Label: "仅补丁", Constraint: "~" + version},
		{ID: LockShortcutMinor, Label: "次版本", Constraint: "^" + version},
		{ID: LockShortcutMajor, Label: "允许主版本", Constraint: ">=" + version},
		{ID: LockShortcutPin, Label: "钉死当前", Constraint: version},
	}
}

func mergeIgnoredUpdates(existing map[string][]string, changes []appIgnoredUpdate) (map[string][]string, error) {
	next := cloneStringSlicesMap(existing)
	if len(changes) == 0 {
		return next, nil
	}
	if next == nil {
		next = map[string][]string{}
	}
	for _, change := range changes {
		service := strings.TrimSpace(change.Service)
		tag := strings.TrimSpace(change.Tag)
		if !validID(service) {
			return nil, ErrUnknownService
		}
		if !boundedText(tag, 128) {
			return nil, errors.New("ignored update tag is invalid")
		}
		current := append([]string(nil), next[service]...)
		if change.Clear {
			filtered := current[:0]
			for _, item := range current {
				if item == tag || SemverEqual(item, tag) {
					continue
				}
				filtered = append(filtered, item)
			}
			if len(filtered) == 0 {
				delete(next, service)
			} else {
				next[service] = append([]string(nil), filtered...)
			}
			continue
		}
		if ignoredUpdateTag(tag, current) {
			continue
		}
		current = append(current, tag)
		next[service] = current
	}
	if err := validateIgnoredUpdates(next); err != nil {
		return nil, err
	}
	if len(next) == 0 {
		return nil, nil
	}
	return next, nil
}

func mergeImageLocks(existing map[string]string, changes map[string]string) (map[string]string, error) {
	if len(changes) == 0 {
		return cloneStringMap(existing), nil
	}
	next := cloneStringMap(existing)
	if next == nil {
		next = map[string]string{}
	}
	for service, constraint := range changes {
		service = strings.TrimSpace(service)
		if !validID(service) {
			return nil, ErrUnknownService
		}
		constraint = strings.TrimSpace(constraint)
		if constraint == "" {
			delete(next, service)
			continue
		}
		next[service] = constraint
	}
	if err := validateImageLocks(next); err != nil {
		return nil, err
	}
	if len(next) == 0 {
		return nil, nil
	}
	return next, nil
}

func knownComposeService(app App, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, service := range app.ServiceImages {
		if service.Name == name {
			return true
		}
	}
	for _, service := range composeServiceNames(app.Compose) {
		if service == name {
			return true
		}
	}
	return false
}
