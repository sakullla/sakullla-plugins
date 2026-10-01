package webdav

import (
	"net/http"
	"testing"
)

func TestClassifyIfMatch(t *testing.T) {
	const current = `"abc"`
	tests := []struct {
		name   string
		values []string
		want   ifMatchClass
	}{
		{name: "absent", want: ifMatchAbsent},
		{name: "wildcard", values: []string{"*"}, want: ifMatchWildcard},
		{name: "spaced wildcard", values: []string{" * "}, want: ifMatchWildcard},
		{name: "matching tag", values: []string{current}, want: ifMatchMatched},
		{name: "matching tag among others", values: []string{`"nope", "abc"`}, want: ifMatchMatched},
		{name: "second header matches", values: []string{`"nope"`, `"abc"`}, want: ifMatchMatched},
		{name: "other tag", values: []string{`"other"`}, want: ifMatchUnmatched},
		{name: "weak tag", values: []string{`W/"abc"`}, want: ifMatchUnmatched},
		{name: "unquoted", values: []string{"abc"}, want: ifMatchInvalid},
		{name: "empty", values: []string{" "}, want: ifMatchInvalid},
		{name: "wildcard mixed with tag", values: []string{`*, "abc"`}, want: ifMatchInvalid},
		{name: "repeated wildcard", values: []string{"*", "*"}, want: ifMatchInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			for _, value := range test.values {
				header.Add("If-Match", value)
			}
			if got := classifyIfMatch(header, current); got != test.want {
				t.Fatalf("classify = %v, want %v", got, test.want)
			}
		})
	}
}
