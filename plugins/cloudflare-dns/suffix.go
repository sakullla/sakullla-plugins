package cloudflaredns

import (
	"strings"
	"unicode"
)

// NormalizeDomain lowercases a name and strips a trailing dot. Query names
// and configured suffixes share this form before suffix matching.
func NormalizeDomain(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrInvalidInput
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for _, current := range value {
		if unicode.IsUpper(current) {
			current = unicode.ToLower(current)
		}
		if current > unicode.MaxASCII {
			return "", ErrInvalidInput
		}
		builder.WriteRune(current)
	}
	value = strings.TrimSuffix(builder.String(), ".")
	if value == "" || len(value) > 253 || strings.Contains(value, "..") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return "", ErrInvalidInput
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidInput
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidInput
			}
		}
	}
	return value, nil
}

// DomainMatchesSuffix reports whether normalized domain equals suffix or is a
// descendant of it. Both arguments must already be normalized.
func DomainMatchesSuffix(domain, suffix string) bool {
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}

// LongestSuffixMatch returns the longest normalized configured suffix that is
// a suffix of domain. Non-suffix names never match.
func LongestSuffixMatch(domain string, suffixes []string) (string, bool) {
	normalized, err := NormalizeDomain(domain)
	if err != nil {
		return "", false
	}
	best := ""
	found := false
	for _, suffix := range suffixes {
		current, err := NormalizeDomain(suffix)
		if err != nil {
			continue
		}
		if !DomainMatchesSuffix(normalized, current) {
			continue
		}
		if !found || len(current) > len(best) {
			best = current
			found = true
		}
	}
	return best, found
}
