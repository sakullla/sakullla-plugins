package shadowsocksserver

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestIdentityPSKsAreCanonicalStandardBase64AndDistinct(t *testing.T) {
	for method, keyLen := range map[string]int{
		"2022-blake3-aes-128-gcm": 16,
		"2022-blake3-aes-256-gcm": 32,
	} {
		t.Run(method, func(t *testing.T) {
			server, identity, err := GenerateSS2022Identity(method)
			if err != nil {
				t.Fatal(err)
			}
			assertCanonicalPSK(t, method, keyLen, server)
			assertCanonicalPSK(t, method, keyLen, identity)
			if server == identity {
				t.Fatal("server PSK and identity PSK must differ")
			}
			password, err := SS2022ClientPassword(method, []byte(server), []byte(identity))
			if err != nil || password != server+":"+identity || strings.ContainsAny(password, " \t\r\n") {
				t.Fatalf("password=%q err=%v", password, err)
			}
			if _, err = NewProtocolEngine(method, []byte(password)); err != nil {
				t.Fatalf("identity password=%v", err)
			}
		})
	}
}

func TestSIP002SS2022URIUsesIdentityPasswordAndMatchingQR(t *testing.T) {
	for _, test := range []struct {
		method string
		keyLen int
		host   string
		port   int
	}{
		{method: "2022-blake3-aes-128-gcm", keyLen: 16, host: "example.com", port: 8388},
		{method: "2022-blake3-aes-256-gcm", keyLen: 32, host: "2001:db8::1", port: 443},
	} {
		t.Run(test.method+"/"+test.host, func(t *testing.T) {
			server, identity, err := GenerateSS2022Identity(test.method)
			if err != nil {
				t.Fatal(err)
			}
			assertCanonicalPSK(t, test.method, test.keyLen, server)
			assertCanonicalPSK(t, test.method, test.keyLen, identity)
			password, err := SS2022ClientPassword(test.method, []byte(server), []byte(identity))
			if err != nil {
				t.Fatal(err)
			}
			share, err := BuildSIP002(SIP002Account{
				Method: test.method, ServerPSK: server, IdentityPSK: identity,
				Host: test.host, Port: test.port,
			})
			if err != nil {
				t.Fatal(err)
			}
			if share.QR.Content != share.URI || share.Password != password {
				t.Fatalf("share=%+v password=%q", share, password)
			}
			method, gotPassword, host, port := parseSIP002(t, share.URI)
			if method != test.method || gotPassword != password || host != test.host || port != test.port {
				t.Fatalf("parsed method=%q password=%q host=%q port=%d", method, gotPassword, host, port)
			}
			userinfo := sip002Userinfo(t, share.URI)
			decoded := decodeStandardUserinfo(t, userinfo)
			if string(decoded) != test.method+":"+server+":"+identity {
				t.Fatalf("decoded userinfo=%q", decoded)
			}
			if strings.Contains(userinfo, "%") || strings.Contains(userinfo, ":") {
				t.Fatalf("userinfo=%q", userinfo)
			}
		})
	}
}

func TestSIP002URIUsesStandardBase64UserinfoForAllMethods(t *testing.T) {
	server, identity, err := GenerateSS2022Identity("2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method   string
		password string
		name     string
	}{
		{method: "aes-128-gcm", password: "correct-horse-battery", name: "legacy"},
		{method: "aes-256-gcm", password: "correct-horse-battery", name: ""},
		{method: "2022-blake3-aes-128-gcm", password: server + ":" + identity, name: "alice"},
	} {
		t.Run(test.method, func(t *testing.T) {
			uri, err := EncodeSIP002(test.method, test.password, "ss.example.com", 8388, test.name)
			if err != nil {
				t.Fatal(err)
			}
			if SIP002QRContent(uri) != uri {
				t.Fatalf("qr=%q uri=%q", SIP002QRContent(uri), uri)
			}
			userinfo := sip002Userinfo(t, uri)
			decoded := decodeStandardUserinfo(t, userinfo)
			want := test.method + ":" + test.password
			if string(decoded) != want {
				t.Fatalf("decoded=%q want=%q", decoded, want)
			}
			if strings.Contains(userinfo, "%") || strings.Contains(userinfo, ":") {
				t.Fatalf("percent-encoded userinfo: %q", uri)
			}
			if test.name != "" && !strings.HasSuffix(uri, "#"+test.name) {
				t.Fatalf("name fragment missing: %q", uri)
			}
		})
	}
}

func TestIdentityPSKMapsNonCanonicalInputAndKeepsCanonical(t *testing.T) {
	for method, keyLen := range map[string]int{
		"2022-blake3-aes-128-gcm": 16,
		"2022-blake3-aes-256-gcm": 32,
	} {
		t.Run(method, func(t *testing.T) {
			mapped, err := MapSS2022PSK(method, "hello")
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte("hello"))
			want := base64.StdEncoding.EncodeToString(sum[:keyLen])
			if mapped != want {
				t.Fatalf("mapped=%q want=%q", mapped, want)
			}
			assertCanonicalPSK(t, method, keyLen, mapped)
			again, err := MapSS2022PSK(method, mapped)
			if err != nil || again != mapped {
				t.Fatalf("canonical remapped: got=%q err=%v", again, err)
			}
			raw := base64.RawStdEncoding.EncodeToString(sum[:keyLen])
			if raw == mapped {
				t.Fatal("non-canonical fixture equals canonical PSK")
			}
			fromRaw, err := MapSS2022PSK(method, raw)
			if err != nil {
				t.Fatal(err)
			}
			if fromRaw == raw {
				t.Fatalf("non-canonical PSK was kept rather than mapped: %q", raw)
			}
			assertCanonicalPSK(t, method, keyLen, fromRaw)
			password, err := SS2022ClientPassword(method, []byte("server-secret"), []byte("user-secret"))
			if err != nil {
				t.Fatal(err)
			}
			server, user, ok := splitSS2022ClientPassword([]byte(password))
			if !ok {
				t.Fatalf("password=%q", password)
			}
			assertCanonicalPSK(t, method, keyLen, string(server))
			assertCanonicalPSK(t, method, keyLen, string(user))
			if _, engineErr := NewProtocolEngine(method, []byte(password)); engineErr != nil {
				t.Fatalf("mapped password rejected by engine: %v", engineErr)
			}
		})
	}
}

func TestSIP002TagPercentEncodesUTF8Names(t *testing.T) {
	for _, test := range []struct {
		name string
		tag  string
	}{
		{name: "手机", tag: "%E6%89%8B%E6%9C%BA"},
		{name: "家里 NAS", tag: "%E5%AE%B6%E9%87%8C%20NAS"},
		{name: "端口#1", tag: "%E7%AB%AF%E5%8F%A3%231"},
		{name: "alice", tag: "alice"},
	} {
		t.Run(test.name, func(t *testing.T) {
			share, err := BuildSIP002(SIP002Account{
				Method: "aes-128-gcm", Password: "correct-horse-battery",
				Host: "ss.example.com", Port: 8388, Name: test.name,
			})
			if err != nil {
				t.Fatal(err)
			}
			if share.QR.Content != share.URI {
				t.Fatalf("qr=%q uri=%q", share.QR.Content, share.URI)
			}
			if !strings.HasSuffix(share.URI, "#"+test.tag) {
				t.Fatalf("uri=%q want encoded tag %q", share.URI, test.tag)
			}
			if strings.Contains(share.URI, test.name) && test.name != test.tag {
				t.Fatalf("uri still contains raw name %q: %q", test.name, share.URI)
			}
			got, err := url.QueryUnescape(test.tag)
			if err != nil || got != test.name {
				t.Fatalf("round-trip name=%q got=%q err=%v", test.name, got, err)
			}
		})
	}
}

func TestSIP002LegacyURIIsImportableWithSinglePassword(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			const password = "correct-horse-battery"
			share, err := BuildSIP002(SIP002Account{Method: method, Password: password, Host: "ss.example.com", Port: 8488})
			if err != nil {
				t.Fatal(err)
			}
			if share.QR.Content != share.URI {
				t.Fatalf("qr=%q uri=%q", share.QR.Content, share.URI)
			}
			gotMethod, gotPassword, host, port := parseSIP002(t, share.URI)
			if gotMethod != method || gotPassword != password || host != "ss.example.com" || port != 8488 {
				t.Fatalf("parsed method=%q password=%q host=%q port=%d", gotMethod, gotPassword, host, port)
			}
			if strings.Contains(gotPassword, ":") {
				t.Fatalf("legacy password must be a single secret: %q", gotPassword)
			}
			userinfo := sip002Userinfo(t, share.URI)
			if string(decodeStandardUserinfo(t, userinfo)) != method+":"+password {
				t.Fatalf("decoded userinfo=%q", userinfo)
			}
		})
	}
}

func TestParseSIP002AcceptsBothSIP002Encodings(t *testing.T) {
	std := base64.StdEncoding.EncodeToString
	raw := base64.RawURLEncoding.EncodeToString
	for _, test := range []struct {
		name     string
		uri      string
		method   string
		password string
		host     string
		port     int
	}{
		{
			name:     "userinfo standard base64",
			uri:      "ss://" + std([]byte("aes-128-gcm:correct-horse-battery")) + "@ss.example.com:8388",
			method:   "aes-128-gcm",
			password: "correct-horse-battery",
			host:     "ss.example.com",
			port:     8388,
		},
		{
			name:     "userinfo url-safe unpadded base64",
			uri:      "ss://" + raw([]byte("aes-256-gcm:p?ss+word/odd=")) + "@198.51.100.7:443",
			method:   "aes-256-gcm",
			password: "p?ss+word/odd=",
			host:     "198.51.100.7",
			port:     443,
		},
		{
			name:     "legacy fully encoded",
			uri:      "ss://" + std([]byte("aes-256-gcm:legacy-pass@203.0.113.9:10443")),
			method:   "aes-256-gcm",
			password: "legacy-pass",
			host:     "203.0.113.9",
			port:     10443,
		},
		{
			name:     "tag fragment dropped",
			uri:      "ss://" + std([]byte("aes-128-gcm:pw")) + "@ss.example.com:8388#" + url.QueryEscape("节点 one"),
			method:   "aes-128-gcm",
			password: "pw",
			host:     "ss.example.com",
			port:     8388,
		},
		{
			name:     "legacy with tag",
			uri:      "ss://" + raw([]byte("aes-128-gcm:pw@ss.example.com:8388")) + "#tokyo",
			method:   "aes-128-gcm",
			password: "pw",
			host:     "ss.example.com",
			port:     8388,
		},
		{
			name:     "password keeps extra colons verbatim",
			uri:      "ss://" + std([]byte("aes-128-gcm:pa:ss:extra")) + "@ss.example.com:8388",
			method:   "aes-128-gcm",
			password: "pa:ss:extra",
			host:     "ss.example.com",
			port:     8388,
		},
		{
			name:     "bracketed IPv6",
			uri:      "ss://" + std([]byte("aes-128-gcm:pw")) + "@[2001:db8::10]:8388",
			method:   "aes-128-gcm",
			password: "pw",
			host:     "2001:db8::10",
			port:     8388,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			method, password, host, port, err := ParseSIP002(test.uri)
			if err != nil {
				t.Fatalf("ParseSIP002(%q) err=%v", test.uri, err)
			}
			if method != test.method || password != test.password || host != test.host || port != test.port {
				t.Fatalf("parsed method=%q password=%q host=%q port=%d", method, password, host, port)
			}
		})
	}
}

func TestParseSIP002KeepsSS2022IdentityPasswordVerbatim(t *testing.T) {
	server, identity, err := GenerateSS2022Identity("2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	want := server + ":" + identity
	uri, err := EncodeSIP002("2022-blake3-aes-128-gcm", want, "ss.example.com", 8388, "导入")
	if err != nil {
		t.Fatal(err)
	}
	method, password, host, port, err := ParseSIP002(uri)
	if err != nil {
		t.Fatal(err)
	}
	if method != "2022-blake3-aes-128-gcm" || password != want || host != "ss.example.com" || port != 8388 {
		t.Fatalf("parsed method=%q password=%q host=%q port=%d", method, password, host, port)
	}
	if _, err = NewProtocolEngine(method, []byte(password)); err != nil {
		t.Fatalf("parsed SS2022 password rejected: %v", err)
	}
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-256-gcm:"+want+"@ss.example.com:443"))
	method, password, _, _, err = ParseSIP002(legacy)
	if err != nil || method != "2022-blake3-aes-256-gcm" || password != want {
		t.Fatalf("legacy parsed method=%q password=%q err=%v", method, password, err)
	}
}

func TestParseSIP002RoundTripsEncodeSIP002(t *testing.T) {
	uri, err := EncodeSIP002("aes-128-gcm", "correct-horse-battery", "ss.example.com", 8388, "tokyo")
	if err != nil {
		t.Fatal(err)
	}
	method, password, host, port, err := ParseSIP002(uri)
	if err != nil {
		t.Fatal(err)
	}
	if method != "aes-128-gcm" || password != "correct-horse-battery" || host != "ss.example.com" || port != 8388 {
		t.Fatalf("parsed method=%q password=%q host=%q port=%d", method, password, host, port)
	}
}

func TestParseSIP002RejectsPluginAndUnknownQuery(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	for _, test := range []struct {
		name   string
		uri    string
		plugin bool
	}{
		{name: "plugin userinfo form", uri: "ss://" + userinfo + "@ss.example.com:8388?plugin=simple-obfs", plugin: true},
		{name: "plugin empty value", uri: "ss://" + userinfo + "@ss.example.com:8388?plugin=", plugin: true},
		{name: "plugin legacy form", uri: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw@ss.example.com:8388")) + "?plugin=v2ray", plugin: true},
		{name: "plugin with tag", uri: "ss://" + userinfo + "@ss.example.com:8388?plugin=obfs#tag", plugin: true},
		{name: "unknown query", uri: "ss://" + userinfo + "@ss.example.com:8388?outline=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, _, err := ParseSIP002(test.uri)
			if err == nil {
				t.Fatalf("ParseSIP002(%q) unexpectedly succeeded", test.uri)
			}
			if test.plugin && !errors.Is(err, ErrSIP002Plugin) {
				t.Fatalf("err=%v must wrap ErrSIP002Plugin", err)
			}
		})
	}
}

func TestParseSIP002RejectsMalformedAndUnsupported(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	for _, test := range []struct {
		name        string
		uri         string
		unsupported bool
	}{
		{name: "not ss scheme", uri: "http://example.com"},
		{name: "empty payload", uri: "ss://"},
		{name: "only tag", uri: "ss://#tag"},
		{name: "truncated base64", uri: "ss://" + userinfo[:len(userinfo)-3] + "@ss.example.com:8388"},
		{name: "non base64 payload", uri: "ss://!!!invalid!!!@ss.example.com:8388"},
		{name: "non-base64 userinfo", uri: "ss://aes-128-gcm:pw@ss.example.com:8388"},
		{name: "userinfo without password", uri: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm")) + "@ss.example.com:8388"},
		{name: "empty password", uri: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:")) + "@ss.example.com:8388"},
		{name: "legacy without host", uri: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw"))},
		{name: "legacy truncated", uri: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw@"))},
		{name: "missing port", uri: "ss://" + userinfo + "@ss.example.com"},
		{name: "non numeric port", uri: "ss://" + userinfo + "@ss.example.com:http"},
		{name: "port out of range", uri: "ss://" + userinfo + "@ss.example.com:99999"},
		{name: "missing host", uri: "ss://" + userinfo + "@:8388"},
		{name: "unsupported method", uri: "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@ss.example.com:8388", unsupported: true},
		{name: "unsupported method legacy", uri: "ss://" + base64.StdEncoding.EncodeToString([]byte("rc4-md5:pw@ss.example.com:8388")), unsupported: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			method, password, host, port, err := ParseSIP002(test.uri)
			if err == nil {
				t.Fatalf("ParseSIP002(%q) succeeded with %q %q %q %d", test.uri, method, password, host, port)
			}
			if test.unsupported && !errors.Is(err, ErrUnsupportedMethod) {
				t.Fatalf("err=%v must wrap ErrUnsupportedMethod", err)
			}
		})
	}
}

func assertCanonicalPSK(t *testing.T, method string, keyLen int, encoded string) {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != keyLen || base64.StdEncoding.EncodeToString(decoded) != encoded {
		t.Fatalf("psk=%q len=%d err=%v", encoded, len(decoded), err)
	}
	if _, err = NewProtocolEngine(method, []byte(encoded)); err != nil {
		t.Fatalf("engine=%v", err)
	}
}

func parseSIP002(t *testing.T, uri string) (method, password, host string, port int) {
	t.Helper()
	if !strings.HasPrefix(uri, "ss://") || strings.Contains(uri, "?") {
		t.Fatalf("uri=%q", uri)
	}
	userinfo := sip002Userinfo(t, uri)
	decoded := decodeStandardUserinfo(t, userinfo)
	method, password, ok := strings.Cut(string(decoded), ":")
	if !ok || method == "" || password == "" {
		t.Fatalf("decoded userinfo=%q", decoded)
	}
	host, port, err := sip002URIHostPort(uri)
	if err != nil {
		t.Fatalf("uri=%q err=%v", uri, err)
	}
	return method, password, host, port
}

func sip002Userinfo(t *testing.T, uri string) string {
	t.Helper()
	rest, ok := strings.CutPrefix(uri, "ss://")
	if !ok {
		t.Fatalf("uri=%q", uri)
	}
	userinfo, _, ok := strings.Cut(rest, "@")
	if !ok || userinfo == "" {
		t.Fatalf("uri=%q", uri)
	}
	return userinfo
}

func decodeStandardUserinfo(t *testing.T, userinfo string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(userinfo)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != userinfo {
		t.Fatalf("userinfo is not canonical standard Base64: %q err=%v", userinfo, err)
	}
	return decoded
}
