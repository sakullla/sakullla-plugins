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

const (
	serviceListingPending = "pending"
	serviceListingFailed  = "failed"

	serviceListingPendingMessage = "正在列出仓库版本"
	serviceListingFailedMessage  = "暂时无法列出仓库版本"
	serviceDigestCurrentMessage  = "已是该 tag 当前镜像"
)

// serviceVersionCurrentMessage reports that the running tag already carries
// the newest release of its repository.
func serviceVersionCurrentMessage(version string) string {
	if version == "" {
		return "已是最新版本"
	}
	return "已是最新版本 " + version
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
	Listing     string          `json:"listing,omitempty"`
	Message     string          `json:"message,omitempty"`
	// Version is the release tag the service currently runs.
	Version string `json:"version,omitempty"`
	// Latest is the newest release the repository publishes.
	Latest string `json:"latest,omitempty"`
	// VersionState is current, outdated, floating or unknown.
	VersionState string `json:"version_state,omitempty"`
	// Floating marks a service that follows a moving tag such as latest.
	Floating bool `json:"floating,omitempty"`
}

type serviceTagListing struct {
	Tags []string
	// Entries keeps the registry metadata of every tag when the registry
	// publishes it, so a moving tag can be matched to its release.
	Entries []ImageTagEntry
	Failed  bool
	Known   bool
}

type serviceDigestState struct {
	Available bool
	Current   bool
	Failed    bool
	// Latest is the digest the registry currently publishes for the tag.
	Latest string
}

type appCandidate struct {
	Tag    string `json:"tag"`
	Major  bool   `json:"major,omitempty"`
	Digest bool   `json:"digest,omitempty"`
	// Release marks a candidate that pins a moving tag to a release.
	Release bool `json:"release,omitempty"`
}

type appLockOption struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Constraint string `json:"constraint,omitempty"`
}

func projectServiceViews(app App, tagsByService map[string]serviceTagListing, digestByService map[string]serviceDigestState) ([]appServiceView, bool) {
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
		view := projectServiceView(app, service, tagsByService[service.Name], digestByService[service.Name])
		if view.Update {
			hasUpdate = true
		}
		views = append(views, view)
	}
	return views, hasUpdate
}

func projectServiceView(app App, service ServiceImage, listing serviceTagListing, digest serviceDigestState) appServiceView {
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
	release := projectServiceRelease(service.Image, listing, digest.Latest)
	view.Version = release.Version
	view.Latest = release.Latest
	view.VersionState = release.State
	view.Floating = release.Floating

	_, _, semver := ParseSemverTag(service.Image)
	if !semver {
		// Digest inspection can fail after the release line is already known,
		// as it does for a secondary latest service. An empty catalog still
		// has nothing to show, so that case stays a temporary listing failure.
		if digest.Failed && release.Latest == "" {
			view.Listing = serviceListingFailed
			view.Message = serviceListingFailedMessage
			return view
		}
		if digest.Available && tag != "" && !ignoredUpdateTag(tag, ignored) {
			view.Update = true
			view.DefaultTag = tag
			view.Candidates = append(view.Candidates, appCandidate{Tag: tag, Digest: true})
			view.Candidates = append(view.Candidates, releaseUpgradeCandidates(release, tag, ignored)...)
			return view
		}
		if digest.Current {
			view.Message = serviceDigestCurrentMessage
		}
		// A moving tag can still be pinned to the newest release of the
		// repository. Only a proven gap between the running release and the
		// newest one counts as an update; an unresolved version stays an offer.
		upgrades := releaseUpgradeCandidates(release, tag, ignored)
		if len(upgrades) > 0 {
			view.Candidates = upgrades
			if release.State == VersionStateOutdated {
				view.Update = true
				view.DefaultTag = upgrades[0].Tag
			}
		}
		return view
	}
	if !listing.Known {
		if listing.Failed {
			view.Listing = serviceListingFailed
			view.Message = serviceListingFailedMessage
			return view
		}
		view.Listing = serviceListingPending
		view.Message = serviceListingPendingMessage
		return view
	}
	allowed := allowedServiceCandidates(service.Image, listing.Tags, lock, ignored)
	if len(allowed) == 0 {
		if release.State == VersionStateCurrent {
			view.Message = serviceVersionCurrentMessage(release.Version)
		}
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
