package dockerapp

import (
	"sort"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
)

// parsedSemverTag is a docker tag split into an npm-style version and an
// image variant such as alpine. Floating tags like latest are not semver.
type parsedSemverTag struct {
	version *semver.Version
	variant string
}

var prereleaseChannels = []string{
	"experimental", "snapshot", "preview", "nightly", "canary",
	"alpha", "beta", "next", "dev", "pre", "rc",
}

// ParseSemverTag reports whether tag (or the tag of an image ref) is semver.
func ParseSemverTag(tag string) (version string, variant string, ok bool) {
	parsed, ok := parseSemverTag(tag)
	if !ok {
		return "", "", false
	}
	return parsed.version.String(), parsed.variant, true
}

// SemverEqual reports whether a and b are the same semver version and variant.
// An optional v prefix is ignored.
func SemverEqual(a, b string) bool {
	left, ok := parseSemverTag(a)
	if !ok {
		return false
	}
	right, ok := parseSemverTag(b)
	if !ok {
		return false
	}
	return left.variant == right.variant && left.version.Equal(right.version)
}

// SemverCompare compares two semver tags. ok is false when either tag is not
// semver or the variants differ.
func SemverCompare(a, b string) (int, bool) {
	left, ok := parseSemverTag(a)
	if !ok {
		return 0, false
	}
	right, ok := parseSemverTag(b)
	if !ok {
		return 0, false
	}
	if left.variant != right.variant {
		return 0, false
	}
	return left.version.Compare(right.version), true
}

// SemverGreater reports whether a is a higher semver than b on the same variant.
func SemverGreater(a, b string) bool {
	cmp, ok := SemverCompare(a, b)
	return ok && cmp > 0
}

// MatchSemverConstraint reports whether tag satisfies an npm-style constraint.
// Prereleases match only when the constraint includes a prerelease.
func MatchSemverConstraint(tag, constraint string) bool {
	parsed, ok := parseSemverTag(tag)
	if !ok {
		return false
	}
	checker, err := semver.NewConstraint(strings.TrimSpace(constraint))
	if err != nil {
		return false
	}
	return checker.Check(parsed.version)
}

// SelectSemverCandidates returns tags higher than current that share its
// variant and match constraint, sorted highest-first. An empty constraint
// accepts any higher version. Prereleases are omitted unless current is a
// prerelease or constraint includes one.
func SelectSemverCandidates(current string, tags []string, constraint string) []string {
	cur, ok := parseSemverTag(current)
	if !ok {
		return nil
	}
	constraint = strings.TrimSpace(constraint)
	var checker *semver.Constraints
	if constraint != "" {
		parsed, err := semver.NewConstraint(constraint)
		if err != nil {
			return nil
		}
		if cur.version.Prerelease() != "" {
			parsed.IncludePrerelease = true
		}
		checker = parsed
	}

	type ranked struct {
		tag     string
		version *semver.Version
	}
	seen := make(map[string]struct{})
	selected := make([]ranked, 0, len(tags))
	for _, tag := range tags {
		candidate, ok := parseSemverTag(tag)
		if !ok || candidate.variant != cur.variant {
			continue
		}
		if !candidate.version.GreaterThan(cur.version) {
			continue
		}
		if checker != nil {
			if !checker.Check(candidate.version) {
				continue
			}
		} else if candidate.version.Prerelease() != "" && cur.version.Prerelease() == "" {
			continue
		}
		key := candidate.version.String() + "\x00" + candidate.variant
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, ranked{tag: tag, version: candidate.version})
	}
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].version.GreaterThan(selected[j].version)
	})
	out := make([]string, len(selected))
	for i, item := range selected {
		out[i] = item.tag
	}
	return out
}

func parseSemverTag(raw string) (parsedSemverTag, bool) {
	tag := extractDockerTag(strings.TrimSpace(raw))
	if tag == "" {
		return parsedSemverTag{}, false
	}
	version, err := semver.NewVersion(normalizeVPrefix(tag))
	if err != nil {
		return parsedSemverTag{}, false
	}
	prerelease, variant := splitSemverVariant(version.Prerelease())
	if variant != "" || prerelease != version.Prerelease() {
		stripped, err := version.SetPrerelease(prerelease)
		if err != nil {
			return parsedSemverTag{}, false
		}
		version = &stripped
	}
	return parsedSemverTag{version: version, variant: variant}, true
}

func extractDockerTag(ref string) string {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if ref == "" {
		return ""
	}
	name := ref
	if slash := strings.LastIndex(ref, "/"); slash >= 0 {
		name = ref[slash+1:]
	}
	_, tag, found := strings.Cut(name, ":")
	if found {
		return tag
	}
	if strings.Contains(ref, "/") {
		return ""
	}
	return ref
}

func normalizeVPrefix(tag string) string {
	if len(tag) >= 2 && tag[0] == 'V' && tag[1] >= '0' && tag[1] <= '9' {
		return "v" + tag[1:]
	}
	return tag
}

func splitSemverVariant(pre string) (prerelease, variant string) {
	if pre == "" {
		return "", ""
	}
	channel, rest, found := strings.Cut(pre, "-")
	if isPrereleaseChannel(channel) {
		if found {
			return channel, rest
		}
		return pre, ""
	}
	return "", pre
}

func isPrereleaseChannel(token string) bool {
	if token == "" {
		return false
	}
	ident, extra, _ := strings.Cut(strings.ToLower(token), ".")
	if isDigits(ident) {
		return extra == "" || isPrereleaseRemainder(extra)
	}
	for _, name := range prereleaseChannels {
		if ident == name {
			return extra == "" || isPrereleaseRemainder(extra)
		}
		if len(ident) > len(name) && strings.HasPrefix(ident, name) && isDigits(ident[len(name):]) {
			return extra == "" || isPrereleaseRemainder(extra)
		}
	}
	return false
}

func isPrereleaseRemainder(value string) bool {
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
		}
	}
	return true
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
