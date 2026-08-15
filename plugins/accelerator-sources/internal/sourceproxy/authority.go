package sourceproxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var ErrUntrustedAuthority = errors.New("trusted external authority is unavailable")

// ExternalAuthority accepts only the redundant forwarding values supplied by
// the provider transport contract. Ordinary Host and request URL values may
// identify the private plugin endpoint and are deliberately ignored.
func ExternalAuthority(request *http.Request) (*url.URL, error) {
	if request == nil {
		return nil, ErrUntrustedAuthority
	}
	proto := singleHeader(request.Header.Values("X-Forwarded-Proto"))
	host := singleHeader(request.Header.Values("X-Forwarded-Host"))
	forwardedProto, forwardedHost, err := parseForwarded(request.Header.Values("Forwarded"))
	if err != nil || proto == "" || host == "" || !strings.EqualFold(proto, forwardedProto) || !strings.EqualFold(host, forwardedHost) {
		return nil, ErrUntrustedAuthority
	}
	proto = strings.ToLower(proto)
	if proto != "http" && proto != "https" {
		return nil, ErrUntrustedAuthority
	}
	parsed, err := url.Parse(proto + "://" + host)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrUntrustedAuthority
	}
	if strings.ContainsAny(host, "\\/@?#\r\n\t ") || net.ParseIP(parsed.Hostname()) != nil {
		return nil, ErrUntrustedAuthority
	}
	if !validHostname(parsed.Hostname()) {
		return nil, ErrUntrustedAuthority
	}
	port := parsed.Port()
	if port != "" && !((proto == "https" && port == "443") || (proto == "http" && port == "80")) {
		return nil, ErrUntrustedAuthority
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed, nil
}

func singleHeader(values []string) string {
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func parseForwarded(values []string) (string, string, error) {
	value := singleHeader(values)
	if value == "" {
		return "", "", ErrUntrustedAuthority
	}
	var proto, host string
	for _, item := range strings.Split(value, ";") {
		key, raw, found := strings.Cut(strings.TrimSpace(item), "=")
		if !found {
			return "", "", ErrUntrustedAuthority
		}
		raw = strings.Trim(raw, `"`)
		switch strings.ToLower(key) {
		case "proto":
			if proto != "" {
				return "", "", ErrUntrustedAuthority
			}
			proto = raw
		case "host":
			if host != "" {
				return "", "", ErrUntrustedAuthority
			}
			host = raw
		}
	}
	if proto == "" || host == "" {
		return "", "", fmt.Errorf("%w: Forwarded lacks proto or host", ErrUntrustedAuthority)
	}
	return proto, host, nil
}

func validHostname(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
