package cloudflaredns

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
)

const (
	ProviderCloudflare = "cloudflare"
	ProviderAliyun     = "aliyun"
	ProviderDNSPodCN   = "dnspod-cn"
	ProviderDNSPodCOM  = "dnspod-com"
	ProviderTencentDNS = "tencent-dns"
)

const (
	domesticOutcomeCreated   = "created"
	domesticOutcomeUpdated   = "updated"
	domesticOutcomeUnchanged = "unchanged"
	domesticOutcomeDeleted   = "deleted"
	domesticOutcomeAbsent    = "absent"
)

type providerCredential struct {
	Provider        string `json:"provider"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	TokenID         string `json:"token_id,omitempty"`
	Token           string `json:"token,omitempty"`
	SecretID        string `json:"secret_id,omitempty"`
	SecretKey       string `json:"secret_key,omitempty"`
}

func (credential *providerCredential) clear() {
	if credential == nil {
		return
	}
	credential.AccessKeyID = ""
	credential.AccessKeySecret = ""
	credential.TokenID = ""
	credential.Token = ""
	credential.SecretID = ""
	credential.SecretKey = ""
}

func (credential providerCredential) secretValues() []string {
	return []string{credential.AccessKeyID, credential.AccessKeySecret, credential.TokenID, credential.Token, credential.SecretID, credential.SecretKey}
}

func canonicalProvider(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ProviderCloudflare:
		return ProviderCloudflare, nil
	case ProviderAliyun, ProviderDNSPodCN, ProviderDNSPodCOM, ProviderTencentDNS:
		return strings.ToLower(strings.TrimSpace(value)), nil
	default:
		return "", ErrInvalidInput
	}
}

func displayProvider(value string) string {
	if strings.TrimSpace(value) == "" {
		return ProviderCloudflare
	}
	return value
}

func isDomesticProvider(value string) bool {
	switch value {
	case ProviderAliyun, ProviderDNSPodCN, ProviderDNSPodCOM, ProviderTencentDNS:
		return true
	default:
		return false
	}
}

func validateCredentialForProvider(provider string, material []byte) error {
	if provider == ProviderCloudflare {
		if !validCloudflareToken(material) {
			return ErrInvalidInput
		}
		return nil
	}
	if !isDomesticProvider(provider) {
		return ErrInvalidInput
	}
	credential, err := decodeProviderCredential(material)
	if err != nil || credential.Provider != provider {
		return ErrInvalidInput
	}
	credential.clear()
	return nil
}

func encodeProviderCredential(credential providerCredential) ([]byte, error) {
	if !isDomesticProvider(credential.Provider) || !credential.complete() {
		return nil, ErrInvalidInput
	}
	encoded, err := json.Marshal(credential)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxTokenBytes {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func decodeProviderCredential(material []byte) (providerCredential, error) {
	decoder := json.NewDecoder(bytes.NewReader(material))
	decoder.DisallowUnknownFields()
	var credential providerCredential
	if err := decoder.Decode(&credential); err != nil {
		return providerCredential{}, ErrInvalidInput
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return providerCredential{}, ErrInvalidInput
	}
	canonical, err := canonicalProvider(credential.Provider)
	if err != nil || !isDomesticProvider(canonical) || !credential.complete() {
		return providerCredential{}, ErrInvalidInput
	}
	credential.Provider = canonical
	return credential, nil
}

func (credential providerCredential) complete() bool {
	switch credential.Provider {
	case ProviderAliyun:
		return validSecretText(credential.AccessKeyID, 128) && validSecretText(credential.AccessKeySecret, 256)
	case ProviderDNSPodCN, ProviderDNSPodCOM:
		return validSecretText(credential.TokenID, 64) && validSecretText(credential.Token, 256) && !strings.Contains(credential.TokenID, ",") && !strings.Contains(credential.Token, ",")
	case ProviderTencentDNS:
		return validSecretText(credential.SecretID, 128) && validSecretText(credential.SecretKey, 256)
	default:
		return false
	}
}

func validSecretText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsAny(value, "\r\n\x00")
}

func redactText(text string, secrets []string) string {
	for _, secret := range secrets {
		if len(secret) < 3 {
			continue
		}
		text = strings.ReplaceAll(text, secret, "[redacted]")
	}
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 240 {
		text = text[:240]
	}
	return text
}

func validateRecordContent(recordType, content string) error {
	if content == "" || len(content) > 4096 || strings.ContainsAny(content, "\r\n\x00") {
		return ErrInvalidInput
	}
	switch recordType {
	case "A":
		parsed := net.ParseIP(content)
		if parsed == nil || parsed.To4() == nil {
			return ErrInvalidInput
		}
	case "AAAA":
		parsed := net.ParseIP(content)
		if parsed == nil || parsed.To4() != nil {
			return ErrInvalidInput
		}
	case "TXT":
	default:
		return ErrInvalidInput
	}
	return nil
}

func sameRecordContent(recordType, left, right string) bool {
	switch recordType {
	case "TXT":
		return canonicalTXT(left) == canonicalTXT(right)
	case "A", "AAAA":
		leftIP, rightIP := net.ParseIP(left), net.ParseIP(right)
		return leftIP != nil && rightIP != nil && leftIP.Equal(rightIP)
	default:
		return left == right
	}
}

func canonicalTXT(content string) string {
	if len(content) >= 2 && content[0] == '"' && content[len(content)-1] == '"' {
		return content[1 : len(content)-1]
	}
	return content
}

func relativeRecordName(zone, name string) (string, error) {
	normalizedZone, err := NormalizeDomain(zone)
	if err != nil {
		return "", err
	}
	raw := strings.TrimSpace(name)
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || raw == "@" {
		return "@", nil
	}
	lowered := strings.ToLower(raw)
	var relative string
	switch {
	case lowered == normalizedZone:
		return "@", nil
	case strings.HasSuffix(lowered, "."+normalizedZone):
		relative = lowered[:len(lowered)-len(normalizedZone)-1]
	case !strings.Contains(lowered, "."):
		relative = lowered
	default:
		return "", ErrInvalidInput
	}
	if !validRelativeName(relative) {
		return "", ErrInvalidInput
	}
	return relative, nil
}

func validRelativeName(value string) bool {
	if value == "@" {
		return true
	}
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}
