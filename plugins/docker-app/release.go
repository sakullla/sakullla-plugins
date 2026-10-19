package dockerapp

import (
	"strings"
)

// ImageTagEntry is one repository tag plus the metadata the version detector
// needs. Digest is the manifest digest the registry publishes for the tag and
// stays empty when the registry only exposes tag names. UpdatedAt is the
// registry's publish timestamp in RFC 3339 form.
type ImageTagEntry struct {
	Tag       string `json:"tag"`
	Digest    string `json:"digest,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Version states reported for one service image.
const (
	// VersionStateCurrent means the running tag already carries the newest
	// release of its repository.
	VersionStateCurrent = "current"
	// VersionStateOutdated means the repository publishes a newer release.
	VersionStateOutdated = "outdated"
	// VersionStateFloating means the service follows a moving tag such as
	// latest and the exact release behind it could not be resolved.
	VersionStateFloating = "floating"
	// VersionStateUnknown means the repository published no readable release.
	VersionStateUnknown = "unknown"
)

// imageRelease is a repository tag that carries a semantic version.
type imageRelease struct {
	Tag     string
	Version string
	Variant string
	Digest  string
}

// serviceRelease is the version story of one service image.
type serviceRelease struct {
	// Version is the release tag the service currently runs.
	Version string
	// Latest is the newest release tag the repository publishes.
	Latest string
	// State is one of the VersionState values.
	State string
	// Floating marks a service that follows a moving tag.
	Floating bool
	// LatestRelease is the newest release the service could move to.
	LatestRelease string
}

// imageReleases keeps the tags that carry a semantic version. A tag such as
// "2.42.6" and "2.42.6-http-meta" are different release lines, so the suffix
// is kept as the variant and never merged into the version.
func imageReleases(entries []ImageTagEntry) []imageRelease {
	releases := make([]imageRelease, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		tag := strings.TrimSpace(entry.Tag)
		if tag == "" {
			continue
		}
		parsed, ok := parseSemverTag(tag)
		if !ok {
			continue
		}
		if _, dup := seen[tag]; dup {
			continue
		}
		seen[tag] = struct{}{}
		releases = append(releases, imageRelease{
			Tag:     tag,
			Version: parsed.version.String(),
			Variant: parsed.variant,
			Digest:  strings.TrimSpace(entry.Digest),
		})
	}
	return releases
}

// listingEntries returns the tag metadata of a listing. A registry that only
// publishes tag names still yields the release line, just without digests.
func listingEntries(listing serviceTagListing) []ImageTagEntry {
	if len(listing.Entries) > 0 {
		return listing.Entries
	}
	entries := make([]ImageTagEntry, 0, len(listing.Tags))
	for _, tag := range listing.Tags {
		name := strings.TrimSpace(tag)
		if name == "" {
			continue
		}
		entries = append(entries, ImageTagEntry{Tag: name})
	}
	return entries
}

// releaseFamily groups releases that share a variant suffix.
func releaseFamily(releases []imageRelease, variant string) []imageRelease {
	family := make([]imageRelease, 0, len(releases))
	for _, release := range releases {
		if release.Variant == variant {
			family = append(family, release)
		}
	}
	return family
}

// newestRelease returns the highest release of a family.
func newestRelease(releases []imageRelease) (imageRelease, bool) {
	best := imageRelease{}
	found := false
	for _, release := range releases {
		if !found || releaseGreater(release, best) {
			best = release
			found = true
		}
	}
	return best, found
}

// releaseGreater reports whether candidate outranks current. The version
// decides; the tag breaks ties so "v2.0.0" and "2.0.0" do not fight.
func releaseGreater(candidate, current imageRelease) bool {
	left, leftOK := parseSemverTag(candidate.Tag)
	right, rightOK := parseSemverTag(current.Tag)
	if !leftOK || !rightOK {
		return candidate.Version > current.Version
	}
	if !left.version.Equal(right.version) {
		return left.version.GreaterThan(right.version)
	}
	return candidate.Tag > current.Tag
}

// primaryReleaseLine picks the release line a floating tag should follow. The
// plain line wins when the repository publishes one; otherwise the line with
// the highest version is used.
func primaryReleaseLine(releases []imageRelease) []imageRelease {
	if plain := releaseFamily(releases, ""); len(plain) > 0 {
		return plain
	}
	best := imageRelease{}
	found := false
	for _, release := range releases {
		if !found || releaseGreater(release, best) {
			best = release
			found = true
		}
	}
	if !found {
		return nil
	}
	return releaseFamily(releases, best.Variant)
}

// releaseByDigest finds the release a moving tag currently points at.
func releaseByDigest(releases []imageRelease, digest string) (imageRelease, bool) {
	core := digestCore(digest)
	if core == "" {
		return imageRelease{}, false
	}
	for _, release := range releases {
		if digestCore(release.Digest) == core {
			return release, true
		}
	}
	return imageRelease{}, false
}

// projectServiceRelease derives the version story of one service image from the
// repository tags and the digest the node observed for the current tag.
//
// A pinned version (fatedier/frpc:v0.71.1) reports whether the repository
// already publishes something newer. A moving tag (xream/sub-store:latest)
// reports the release it currently points at and the release it could move to.
func projectServiceRelease(image string, listing serviceTagListing, observedDigest string) serviceRelease {
	tag := extractDockerTag(image)
	if tag == "" {
		return serviceRelease{State: VersionStateUnknown}
	}
	releases := imageReleases(listingEntries(listing))
	parsed, pinned := parseSemverTag(image)
	if pinned {
		family := releaseFamily(releases, parsed.variant)
		latest, hasLatest := newestRelease(family)
		release := serviceRelease{Version: tag, State: VersionStateCurrent}
		if hasLatest {
			release.Latest = latest.Tag
			release.LatestRelease = latest.Tag
			if latest.Version != parsed.version.String() {
				release.State = VersionStateOutdated
			}
		} else if !listing.Known {
			release.State = VersionStateUnknown
		}
		return release
	}

	// A moving tag: resolve the release behind it and the release to move to.
	line := primaryReleaseLine(releases)
	latest, hasLatest := newestRelease(line)
	release := serviceRelease{Floating: true, State: VersionStateFloating}
	if hasLatest {
		release.Latest = latest.Tag
		release.LatestRelease = latest.Tag
	}
	if resolved, ok := releaseByDigest(releases, observedDigest); ok {
		release.Version = resolved.Tag
		release.State = VersionStateFloating
		if hasLatest && resolved.Version == latest.Version {
			release.State = VersionStateCurrent
		} else if hasLatest {
			release.State = VersionStateOutdated
		}
		return release
	}
	if !listing.Known {
		release.State = VersionStateUnknown
	}
	return release
}

// releaseUpgradeCandidates returns the release tags a service may move to.
// A pinned version only moves forward inside its own release line; a moving
// tag may be pinned to the newest release of the repository.
func releaseUpgradeCandidates(release serviceRelease, current string, ignored []string) []appCandidate {
	if release.LatestRelease == "" || release.LatestRelease == current {
		return nil
	}
	if release.State == VersionStateCurrent {
		// The service already runs the newest release; pinning it would only
		// freeze the tag without changing anything.
		return nil
	}
	if ignoredUpdateTag(release.LatestRelease, ignored) {
		return nil
	}
	return []appCandidate{{Tag: release.LatestRelease, Release: true}}
}

// imageRepository returns the repository part of an image reference.
func imageRepository(image string) string {
	ref := strings.TrimSpace(image)
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		ref = ref[:colon]
	}
	return strings.TrimSpace(ref)
}

// hasReleaseDigest reports whether the listing already carries a digest for
// one of its releases.
func hasReleaseDigest(entries []ImageTagEntry) bool {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Digest) != "" {
			return true
		}
	}
	return false
}

// appendTagDigest records the digest of one tag in a listing.
func appendTagDigest(entries []ImageTagEntry, tag, digest string) []ImageTagEntry {
	updated := make([]ImageTagEntry, 0, len(entries)+1)
	for _, entry := range entries {
		if strings.TrimSpace(entry.Tag) == tag {
			entry.Digest = digest
		}
		updated = append(updated, entry)
	}
	return updated
}
