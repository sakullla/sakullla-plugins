package doh

import (
	"encoding/base64"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func parseUpstreamText(text string) ([]Upstream, error) {
	text = strings.TrimPrefix(text, "\ufeff")
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > MaxUpstreamLines {
		return nil, ErrInvalidRequest
	}
	var upstreams []Upstream
	for _, line := range lines {
		if strings.HasSuffix(line, "\r") {
			line = strings.TrimSuffix(line, "\r")
		}
		if len(line) > MaxUpstreamLineBytes {
			return nil, ErrInvalidRequest
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		tokens := splitUpstreamFields(trimmed)
		if len(tokens) == 0 {
			return nil, ErrInvalidRequest
		}
		domain := ""
		added := 0
		for _, token := range tokens {
			nextDomain, remainder, err := splitDomainPrefix(token)
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(token, "[/") {
				domain = nextDomain
			}
			remainder = strings.TrimSpace(remainder)
			if remainder == "" {
				continue
			}
			if err := validateUpstreamToken(remainder); err != nil {
				return nil, err
			}
			upstreams = append(upstreams, Upstream{
				ID:       "u" + strconv.Itoa(len(upstreams)+1),
				Endpoint: remainder,
				Domain:   domain,
				Enabled:  true,
			})
			added++
			if len(upstreams) > MaxUpstreams {
				return nil, ErrInvalidRequest
			}
		}
		if added == 0 {
			return nil, ErrInvalidRequest
		}
	}
	return upstreams, nil
}

func splitUpstreamFields(line string) []string {
	return strings.FieldsFunc(line, isUpstreamSeparator)
}

func isUpstreamSeparator(char rune) bool {
	switch char {
	case ',', '，', ';', '；':
		return true
	default:
		return unicode.IsSpace(char)
	}
}

func splitDomainPrefix(line string) (string, string, error) {
	if !strings.HasPrefix(line, "[/") {
		return "", line, nil
	}
	end := strings.Index(line, "/]")
	if end < 2 {
		return "", "", ErrInvalidRequest
	}
	domain := normalizeDomain(line[2:end])
	if domain == "" || len(domain) > MaxUpstreamDomainBytes {
		return "", "", ErrInvalidRequest
	}
	return domain, strings.TrimSpace(line[end+2:]), nil
}

func validateUpstreamToken(token string) error {
	if token == "" || len(token) > MaxUpstreamLineBytes {
		return ErrInvalidRequest
	}
	if strings.HasPrefix(token, "sdns://") {
		return validateDNSStamp(token)
	}
	if strings.Contains(token, "://") {
		parsed, err := url.Parse(token)
		if err != nil || parsed.Host == "" || parsed.Opaque != "" {
			return ErrInvalidRequest
		}
		switch parsed.Scheme {
		case "udp", "tcp", "tls", "quic", "https", "http", "h3":
			return nil
		default:
			return ErrInvalidRequest
		}
	}
	if net.ParseIP(token) != nil {
		return nil
	}
	host, port, err := net.SplitHostPort(token)
	if err != nil || host == "" || net.ParseIP(host) == nil && !isHostname(host) {
		return ErrInvalidRequest
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return ErrInvalidRequest
	}
	return nil
}

func validateDNSStamp(token string) error {
	raw := strings.TrimPrefix(token, "sdns://")
	if raw == "" {
		return ErrInvalidRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(raw)
	}
	if err != nil || len(payload) < 1 {
		return ErrInvalidRequest
	}
	switch payload[0] {
	case 0x00, 0x01, 0x02, 0x03, 0x04:
		return nil
	default:
		return ErrInvalidRequest
	}
}

func isHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.Contains(host, " ") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			char := label[i]
			if char >= 'A' && char <= 'Z' {
				char += 'a' - 'A'
			}
			if char != '-' && (char < '0' || char > '9') && (char < 'a' || char > 'z') {
				return false
			}
		}
	}
	return true
}

func normalizeDomain(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".")
	return strings.ToLower(value)
}

func domainMatches(qname, domain string) bool {
	if qname == "" || domain == "" {
		return false
	}
	return qname == domain || strings.HasSuffix(qname, "."+domain)
}

func questionName(question []byte) string {
	if len(question) < 5 {
		return ""
	}
	name := question[:len(question)-4]
	var labels []string
	for index := 0; index < len(name); {
		length := int(name[index])
		index++
		if length == 0 {
			break
		}
		if index+length > len(name) {
			return ""
		}
		labels = append(labels, string(name[index:index+length]))
		index += length
	}
	return strings.Join(labels, ".")
}
