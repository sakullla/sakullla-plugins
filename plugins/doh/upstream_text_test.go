package doh

import "testing"

func TestParseUpstreamTextFormatsAndComments(t *testing.T) {
	upstreams, err := parseUpstreamText(`
# comment
94.140.14.140
2a10:50c0::1:ff
94.140.14.140:53
[2a10:50c0::1:ff]:53
udp://unfiltered.adguard-dns.com
tcp://94.140.14.140
tcp://[2a10:50c0::1:ff]
tcp://94.140.14.140:53
tcp://[2a10:50c0::1:ff]:53
tcp://unfiltered.adguard-dns.com
tls://unfiltered.adguard-dns.com
https://unfiltered.adguard-dns.com/dns-query
h3://unfiltered.adguard-dns.com/dns-query
quic://unfiltered.adguard-dns.com
[/example.local/]94.140.14.140 2a10:50c0::1:ff
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 16 {
		t.Fatalf("count=%d", len(upstreams))
	}
	if upstreams[0].Endpoint != "94.140.14.140" || upstreams[0].Domain != "" {
		t.Fatalf("first=%#v", upstreams[0])
	}
	last := upstreams[len(upstreams)-1]
	if last.Domain != "example.local" || last.Endpoint != "2a10:50c0::1:ff" {
		t.Fatalf("domain row=%#v", last)
	}
}

func TestParseUpstreamTextGeneralSeparators(t *testing.T) {
	upstreams, err := parseUpstreamText("8.8.8.8,1.1.1.1，tls://dns.google；https://dns.google/dns-query\n[/example.local/]94.140.14.140,\t2a10:50c0::1:ff")
	if err != nil {
		t.Fatal(err)
	}
	want := []Upstream{
		{Endpoint: "8.8.8.8"},
		{Endpoint: "1.1.1.1"},
		{Endpoint: "tls://dns.google"},
		{Endpoint: "https://dns.google/dns-query"},
		{Endpoint: "94.140.14.140", Domain: "example.local"},
		{Endpoint: "2a10:50c0::1:ff", Domain: "example.local"},
	}
	if len(upstreams) != len(want) {
		t.Fatalf("count=%d want=%d %#v", len(upstreams), len(want), upstreams)
	}
	for index, expected := range want {
		if upstreams[index].Endpoint != expected.Endpoint || upstreams[index].Domain != expected.Domain {
			t.Fatalf("index=%d got=%#v want=%#v", index, upstreams[index], expected)
		}
	}
}

func TestParseUpstreamTextRejectsIllegalLines(t *testing.T) {
	for _, text := range []string{
		"ftp://example.com",
		"[/example.local/]",
		"not a host",
		string(make([]byte, MaxUpstreamLineBytes+1)),
	} {
		if _, err := parseUpstreamText(text); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
}

func TestDomainMatchLongestWins(t *testing.T) {
	configuration := Configuration{Upstreams: []Upstream{
		{ID: "default", Endpoint: "https://default.example/dns-query", Enabled: true},
		{ID: "local", Endpoint: "https://local.example/dns-query", Domain: "local", Enabled: true},
		{ID: "example", Endpoint: "https://example.local/dns-query", Domain: "example.local", Enabled: true},
	}}
	matched := configuration.upstreamsForName("www.example.local")
	if len(matched) != 1 || matched[0].ID != "example" {
		t.Fatalf("matched=%#v", matched)
	}
	defaults := configuration.upstreamsForName("other.example")
	if len(defaults) != 1 || defaults[0].ID != "default" {
		t.Fatalf("defaults=%#v", defaults)
	}
}
