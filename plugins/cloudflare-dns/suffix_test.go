package cloudflaredns

import (
	"errors"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "lowercase-and-trailing-dot", input: "Example.COM.", want: "example.com"},
		{name: "already-normalized", input: "www.example.com", want: "www.example.com"},
		{name: "empty", input: "   ", wantErr: ErrInvalidInput},
		{name: "dot-only", input: ".", wantErr: ErrInvalidInput},
		{name: "consecutive-dots", input: "example..com", wantErr: ErrInvalidInput},
		{name: "leading-hyphen", input: "-example.com", wantErr: ErrInvalidInput},
		{name: "wildcard", input: "*.example.com", wantErr: ErrInvalidInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeDomain(test.input)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("NormalizeDomain(%q) err=%v want %v", test.input, err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("NormalizeDomain(%q)=(%q,%v) want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestLongestSuffixMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		domain   string
		suffixes []string
		want     string
		found    bool
	}{
		{name: "exact-and-subdomain", domain: "www.example.com", suffixes: []string{"example.com"}, want: "example.com", found: true},
		{name: "exact-apex", domain: "example.com", suffixes: []string{"example.com"}, want: "example.com", found: true},
		{name: "longest-wins", domain: "api.example.com", suffixes: []string{"example.com", "api.example.com"}, want: "api.example.com", found: true},
		{name: "sibling-keeps-shorter", domain: "www.example.com", suffixes: []string{"example.com", "api.example.com"}, want: "example.com", found: true},
		{name: "non-suffix-prefix", domain: "notexample.com", suffixes: []string{"example.com"}, found: false},
		{name: "non-suffix-other-tld", domain: "other.test", suffixes: []string{"example.com"}, found: false},
		{name: "embedded-label", domain: "example.com.evil.test", suffixes: []string{"example.com"}, found: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, found := LongestSuffixMatch(test.domain, test.suffixes)
			if found != test.found || got != test.want {
				t.Fatalf("LongestSuffixMatch(%q)=(%q,%v) want (%q,%v)", test.domain, got, found, test.want, test.found)
			}
		})
	}
}
