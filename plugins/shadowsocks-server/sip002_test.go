package shadowsocksserver

import (
	"encoding/base64"
	"net/url"
	"strconv"
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
			userinfo, _, ok := strings.Cut(strings.TrimPrefix(share.URI, "ss://"), "@")
			if !ok {
				t.Fatalf("uri=%q", share.URI)
			}
			if _, hasPassword := sip002URLPassword(t, share.URI); !hasPassword {
				t.Fatal("client password missing from SIP002 password position")
			}
			if strings.Count(userinfo, ":") != 1 || !strings.Contains(userinfo, "%") {
				t.Fatalf("userinfo=%q", userinfo)
			}
			if userinfoLooksLikeBase64URL(userinfo, test.method, password) {
				t.Fatalf("userinfo is Base64URL: %q", userinfo)
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
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "ss" {
		t.Fatalf("uri=%q err=%v", uri, err)
	}
	if parsed.RawQuery != "" {
		t.Fatalf("query=%q", parsed.RawQuery)
	}
	host = parsed.Hostname()
	port, err = strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 {
		t.Fatalf("port=%q", parsed.Port())
	}
	if password, ok := parsed.User.Password(); ok {
		return parsed.User.Username(), password, host, port
	}
	decoded, err := decodeBase64Userinfo(parsed.User.Username())
	if err != nil {
		t.Fatalf("userinfo=%q err=%v", parsed.User.Username(), err)
	}
	method, password, ok := strings.Cut(string(decoded), ":")
	if !ok || method == "" || password == "" {
		t.Fatalf("decoded userinfo=%q", decoded)
	}
	return method, password, host, port
}

func sip002URLPassword(t *testing.T, uri string) (string, bool) {
	t.Helper()
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.User.Password()
}

func userinfoLooksLikeBase64URL(userinfo, method, password string) bool {
	want := method + ":" + password
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err := enc.DecodeString(userinfo)
		if err == nil && string(decoded) == want {
			return true
		}
	}
	return false
}

func decodeBase64Userinfo(userinfo string) ([]byte, error) {
	var last error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := enc.DecodeString(userinfo)
		if err == nil {
			return decoded, nil
		}
		last = err
	}
	return nil, last
}
