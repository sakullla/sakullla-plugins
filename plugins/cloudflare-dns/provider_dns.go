package cloudflaredns

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const domesticUserAgent = "nre-cloudflare-dns/" + PluginVersion

const (
	aliyunEndpointVersion = "2015-01-09"
	tencentDNSVersion     = "2021-03-23"
	providerPageLimit     = 20
)

type domesticRecord struct {
	Type, Name, Content string
	TTL                 uint32
}

type domesticRecordAPI interface {
	Ensure(context.Context, providerCredential, string, domesticRecord) (string, error)
	DeleteTXT(context.Context, providerCredential, string, domesticRecord) (string, error)
}

type providerRecord struct {
	ID, Type, Name, Content, Line string
}

type providerDNSClient struct {
	httpClient *http.Client
	bases      map[string]string
	now        func() time.Time
	nonce      func() string
}

func newProviderDNSClient(bases map[string]string) *providerDNSClient {
	return &providerDNSClient{
		httpClient: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		bases:      bases,
	}
}

func providerAPIHost(provider string) (string, error) {
	switch provider {
	case ProviderAliyun:
		return "alidns.aliyuncs.com", nil
	case ProviderDNSPodCN:
		return "dnsapi.cn", nil
	case ProviderDNSPodCOM:
		return "api.dnspod.com", nil
	case ProviderTencentDNS:
		return "dnspod.tencentcloudapi.com", nil
	default:
		return "", ErrInvalidInput
	}
}

func (client *providerDNSClient) Ensure(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	switch credential.Provider {
	case ProviderAliyun:
		return client.aliyunEnsure(ctx, credential, zone, record)
	case ProviderDNSPodCN, ProviderDNSPodCOM:
		return client.dnspodEnsure(ctx, credential, zone, record)
	case ProviderTencentDNS:
		return client.tencentEnsure(ctx, credential, zone, record)
	default:
		return "", ErrInvalidInput
	}
}

func (client *providerDNSClient) DeleteTXT(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	if record.Type != "TXT" {
		return "", ErrInvalidInput
	}
	switch credential.Provider {
	case ProviderAliyun:
		return client.aliyunDelete(ctx, credential, zone, record)
	case ProviderDNSPodCN, ProviderDNSPodCOM:
		return client.dnspodDelete(ctx, credential, zone, record)
	case ProviderTencentDNS:
		return client.tencentDelete(ctx, credential, zone, record)
	default:
		return "", ErrInvalidInput
	}
}

func (client *providerDNSClient) current() time.Time {
	if client.now != nil {
		return client.now()
	}
	return time.Now()
}

func (client *providerDNSClient) nextNonce() string {
	if client.nonce != nil {
		return client.nonce()
	}
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return strconv.FormatInt(client.current().UnixNano(), 10)
	}
	return hex.EncodeToString(buf[:])
}

func (client *providerDNSClient) resolve(provider string) (string, string, error) {
	official, err := providerAPIHost(provider)
	if err != nil {
		return "", "", err
	}
	if client != nil && client.bases != nil {
		if base := strings.TrimSpace(client.bases[provider]); base != "" {
			parsed, parseErr := url.Parse(base)
			if parseErr != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
				return "", "", ErrInvalidInput
			}
			if strings.EqualFold(parsed.Hostname(), "api.cloudflare.com") {
				return "", "", ErrInvalidInput
			}
			return parsed.Scheme + "://" + parsed.Host, strings.ToLower(parsed.Host), nil
		}
	}
	return "https://" + official, official, nil
}

func (client *providerDNSClient) roundTrip(request *http.Request, credential providerCredential) ([]byte, int, error) {
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, 0, providerFailure(credential, "", "upstream unreachable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		return nil, response.StatusCode, providerFailure(credential, "", "upstream response is invalid")
	}
	return body, response.StatusCode, nil
}

func providerFailure(credential providerCredential, code, detail string) error {
	detail = redactText(detail, credential.secretValues())
	if code == "" && detail == "" {
		return ErrDomesticDNSFailed
	}
	if code == "" {
		return &providerAPIError{provider: credential.Provider, detail: detail}
	}
	return &providerAPIError{provider: credential.Provider, code: code, detail: detail}
}

type providerAPIError struct {
	provider, code, detail string
}

func (err *providerAPIError) Error() string {
	if err.code != "" && err.detail != "" {
		return err.provider + " DNS " + err.code + ": " + err.detail
	}
	if err.detail != "" {
		return err.provider + " DNS: " + err.detail
	}
	return ErrDomesticDNSFailed.Error()
}

type flexibleString string

func (value *flexibleString) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || len(bytes.TrimSpace(raw)) == 0 {
		*value = ""
		return nil
	}
	if raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
		*value = flexibleString(text)
		return nil
	}
	*value = flexibleString(strings.TrimSpace(string(raw)))
	return nil
}

func (client *providerDNSClient) aliyunEnsure(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	found, err := client.aliyunList(ctx, credential, zone, record)
	if err != nil {
		return "", err
	}
	if matchingContent(found, record) {
		return domesticOutcomeUnchanged, nil
	}
	params := map[string]string{"DomainName": zone, "RR": record.Name, "Type": record.Type, "Value": record.Content, "TTL": strconv.FormatUint(uint64(record.TTL), 10)}
	action := "AddDomainRecord"
	outcome := domesticOutcomeCreated
	if record.Type != "TXT" && len(found) > 0 {
		action = "UpdateDomainRecord"
		outcome = domesticOutcomeUpdated
		params["RecordId"] = found[0].ID
	}
	if _, err := client.aliyunCall(ctx, credential, action, params); err != nil {
		return "", err
	}
	return outcome, nil
}

func (client *providerDNSClient) aliyunDelete(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	found, err := client.aliyunList(ctx, credential, zone, record)
	if err != nil {
		return "", err
	}
	matches := matchingContentRecords(found, record)
	if len(matches) == 0 {
		return domesticOutcomeAbsent, nil
	}
	for _, current := range matches {
		if _, err := client.aliyunCall(ctx, credential, "DeleteDomainRecord", map[string]string{"RecordId": current.ID}); err != nil {
			return "", err
		}
	}
	return domesticOutcomeDeleted, nil
}

func (client *providerDNSClient) aliyunList(ctx context.Context, credential providerCredential, zone string, record domesticRecord) ([]providerRecord, error) {
	var records []providerRecord
	for page := 1; page <= providerPageLimit; page++ {
		body, err := client.aliyunCall(ctx, credential, "DescribeDomainRecords", map[string]string{
			"DomainName":  zone,
			"PageNumber":  strconv.Itoa(page),
			"PageSize":    "100",
			"RRKeyWord":   record.Name,
			"TypeKeyWord": record.Type,
			"SearchMode":  "EXACT",
		})
		if err != nil {
			return nil, err
		}
		var envelope struct {
			TotalCount    int    `json:"TotalCount"`
			Code          string `json:"Code"`
			Message       string `json:"Message"`
			DomainRecords struct {
				Record json.RawMessage `json:"Record"`
			} `json:"DomainRecords"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return nil, providerFailure(credential, "", "record list is invalid")
		}
		if envelope.Code != "" {
			return nil, providerFailure(credential, envelope.Code, envelope.Message)
		}
		parsed, err := parseAliyunRecords(envelope.DomainRecords.Record)
		if err != nil {
			return nil, providerFailure(credential, "", "record list is invalid")
		}
		for _, current := range parsed {
			if !sameIdentity(current.Type, current.RR, record) {
				continue
			}
			records = append(records, providerRecord{ID: string(current.RecordID), Type: current.Type, Name: current.RR, Content: current.Value})
		}
		if len(parsed) == 0 || page*100 >= envelope.TotalCount {
			break
		}
	}
	return records, nil
}

type aliyunRecord struct {
	RecordID flexibleString `json:"RecordId"`
	RR       string         `json:"RR"`
	Type     string         `json:"Type"`
	Value    string         `json:"Value"`
}

func parseAliyunRecords(raw json.RawMessage) ([]aliyunRecord, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var many []aliyunRecord
	if json.Unmarshal(raw, &many) == nil {
		return many, nil
	}
	var one aliyunRecord
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []aliyunRecord{one}, nil
}

func (client *providerDNSClient) aliyunCall(ctx context.Context, credential providerCredential, action string, params map[string]string) ([]byte, error) {
	endpoint, _, err := client.resolve(ProviderAliyun)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("Action", action)
	values.Set("Format", "JSON")
	values.Set("Version", aliyunEndpointVersion)
	values.Set("AccessKeyId", credential.AccessKeyID)
	values.Set("SignatureMethod", "HMAC-SHA1")
	values.Set("SignatureVersion", "1.0")
	values.Set("SignatureNonce", client.nextNonce())
	values.Set("Timestamp", client.current().UTC().Format("2006-01-02T15:04:05Z"))
	for key, value := range params {
		values.Set(key, value)
	}
	values.Set("Signature", aliyunSignature(http.MethodPost, credential.AccessKeySecret, values))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(values.Encode()))
	if err != nil {
		return nil, ErrInvalidInput
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", domesticUserAgent)
	body, status, err := client.roundTrip(request, credential)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		var failure struct {
			Code, Message string
		}
		_ = json.Unmarshal(body, &failure)
		if failure.Message == "" {
			failure.Message = "HTTP " + strconv.Itoa(status)
		}
		return nil, providerFailure(credential, failure.Code, failure.Message)
	}
	return body, nil
}

func aliyunSignature(method, secret string, values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "Signature" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, aliyunEscape(key)+"="+aliyunEscape(values.Get(key)))
	}
	canonical := strings.Join(parts, "&")
	stringToSign := method + "&" + aliyunEscape("/") + "&" + aliyunEscape(canonical)
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func aliyunEscape(value string) string {
	escaped := url.QueryEscape(value)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func (client *providerDNSClient) dnspodEnsure(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	found, err := client.dnspodList(ctx, credential, zone, record)
	if err != nil {
		return "", err
	}
	if matchingContent(found, record) {
		return domesticOutcomeUnchanged, nil
	}
	values := url.Values{}
	values.Set("domain", zone)
	values.Set("sub_domain", record.Name)
	values.Set("record_type", record.Type)
	values.Set("record_line", dnspodLine(credential.Provider, found))
	values.Set("value", record.Content)
	values.Set("ttl", strconv.FormatUint(uint64(record.TTL), 10))
	action := "Record.Create"
	outcome := domesticOutcomeCreated
	if record.Type != "TXT" && len(found) > 0 {
		action = "Record.Modify"
		outcome = domesticOutcomeUpdated
		values.Set("record_id", found[0].ID)
	}
	if _, err := client.dnspodCall(ctx, credential, action, values); err != nil {
		return "", err
	}
	return outcome, nil
}

func (client *providerDNSClient) dnspodDelete(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	found, err := client.dnspodList(ctx, credential, zone, record)
	if err != nil {
		return "", err
	}
	matches := matchingContentRecords(found, record)
	if len(matches) == 0 {
		return domesticOutcomeAbsent, nil
	}
	for _, current := range matches {
		values := url.Values{}
		values.Set("domain", zone)
		values.Set("record_id", current.ID)
		if _, err := client.dnspodCall(ctx, credential, "Record.Remove", values); err != nil {
			return "", err
		}
	}
	return domesticOutcomeDeleted, nil
}

func dnspodLine(provider string, found []providerRecord) string {
	if len(found) > 0 && found[0].Line != "" {
		return found[0].Line
	}
	if provider == ProviderDNSPodCOM {
		return "default"
	}
	return "默认"
}

func (client *providerDNSClient) dnspodList(ctx context.Context, credential providerCredential, zone string, record domesticRecord) ([]providerRecord, error) {
	var records []providerRecord
	for page := 0; page < providerPageLimit; page++ {
		values := url.Values{}
		values.Set("domain", zone)
		values.Set("sub_domain", record.Name)
		values.Set("record_type", record.Type)
		values.Set("offset", strconv.Itoa(page*100))
		values.Set("length", "100")
		values.Set("error_on_empty", "no")
		body, err := client.dnspodCall(ctx, credential, "Record.List", values)
		if err != nil {
			return nil, err
		}
		var envelope struct {
			Status struct {
				Code    json.RawMessage `json:"code"`
				Message string          `json:"message"`
			} `json:"status"`
			Records []struct {
				ID    flexibleString `json:"id"`
				Name  string         `json:"name"`
				Type  string         `json:"type"`
				Value string         `json:"value"`
				Line  string         `json:"line"`
			} `json:"records"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return nil, providerFailure(credential, "", "record list is invalid")
		}
		code := strings.Trim(string(envelope.Status.Code), `"`)
		if code == "10" {
			break
		}
		if code != "1" {
			return nil, providerFailure(credential, code, envelope.Status.Message)
		}
		for _, current := range envelope.Records {
			if !sameIdentity(current.Type, current.Name, record) {
				continue
			}
			records = append(records, providerRecord{ID: string(current.ID), Type: current.Type, Name: current.Name, Content: current.Value, Line: current.Line})
		}
		if len(envelope.Records) < 100 {
			break
		}
	}
	return records, nil
}

func (client *providerDNSClient) dnspodCall(ctx context.Context, credential providerCredential, action string, values url.Values) ([]byte, error) {
	endpoint, _, err := client.resolve(credential.Provider)
	if err != nil {
		return nil, err
	}
	values.Set("login_token", credential.TokenID+","+credential.Token)
	values.Set("format", "json")
	if credential.Provider == ProviderDNSPodCOM {
		values.Set("lang", "en")
	} else {
		values.Set("lang", "cn")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/"+action, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, ErrInvalidInput
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", domesticUserAgent)
	body, status, err := client.roundTrip(request, credential)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, providerFailure(credential, strconv.Itoa(status), dnspodMessage(body))
	}
	var statusOnly struct {
		Status struct {
			Code    json.RawMessage `json:"code"`
			Message string          `json:"message"`
		} `json:"status"`
	}
	if json.Unmarshal(body, &statusOnly) != nil {
		return nil, providerFailure(credential, "", "provider response is invalid")
	}
	code := strings.Trim(string(statusOnly.Status.Code), `"`)
	if action != "Record.List" && code != "1" {
		return nil, providerFailure(credential, code, statusOnly.Status.Message)
	}
	return body, nil
}

func dnspodMessage(body []byte) string {
	var envelope struct {
		Status struct {
			Message string `json:"message"`
		} `json:"status"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Status.Message == "" {
		return "provider request failed"
	}
	return envelope.Status.Message
}

func (client *providerDNSClient) tencentEnsure(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	found, err := client.tencentList(ctx, credential, zone, record)
	if err != nil {
		return "", err
	}
	if matchingContent(found, record) {
		return domesticOutcomeUnchanged, nil
	}
	line := "默认"
	if len(found) > 0 && found[0].Line != "" {
		line = found[0].Line
	}
	payload := map[string]any{
		"Domain": zone, "SubDomain": record.Name, "RecordType": record.Type,
		"RecordLine": line, "Value": record.Content, "TTL": record.TTL,
	}
	action := "CreateRecord"
	outcome := domesticOutcomeCreated
	if record.Type != "TXT" && len(found) > 0 {
		action = "ModifyRecord"
		outcome = domesticOutcomeUpdated
		payload["RecordId"] = numericID(found[0].ID)
	}
	if _, err := client.tencentCall(ctx, credential, action, payload); err != nil {
		return "", err
	}
	return outcome, nil
}

func (client *providerDNSClient) tencentDelete(ctx context.Context, credential providerCredential, zone string, record domesticRecord) (string, error) {
	found, err := client.tencentList(ctx, credential, zone, record)
	if err != nil {
		return "", err
	}
	matches := matchingContentRecords(found, record)
	if len(matches) == 0 {
		return domesticOutcomeAbsent, nil
	}
	for _, current := range matches {
		if _, err := client.tencentCall(ctx, credential, "DeleteRecord", map[string]any{"Domain": zone, "RecordId": numericID(current.ID)}); err != nil {
			return "", err
		}
	}
	return domesticOutcomeDeleted, nil
}

func numericID(value string) any {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return value
	}
	return number
}

func (client *providerDNSClient) tencentList(ctx context.Context, credential providerCredential, zone string, record domesticRecord) ([]providerRecord, error) {
	var records []providerRecord
	for page := 0; page < providerPageLimit; page++ {
		body, err := client.tencentCall(ctx, credential, "DescribeRecordList", map[string]any{
			"Domain": zone, "Subdomain": record.Name, "RecordType": record.Type, "Offset": page * 100, "Limit": 100,
		})
		if err != nil {
			return nil, err
		}
		var envelope struct {
			Response struct {
				Error struct {
					Code, Message string
				} `json:"Error"`
				RecordList []struct {
					RecordID flexibleString `json:"RecordId"`
					Name     string         `json:"Name"`
					Type     string         `json:"Type"`
					Value    string         `json:"Value"`
					Line     string         `json:"Line"`
				} `json:"RecordList"`
				RecordCountInfo struct {
					TotalCount int `json:"TotalCount"`
				} `json:"RecordCountInfo"`
			} `json:"Response"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return nil, providerFailure(credential, "", "record list is invalid")
		}
		if envelope.Response.Error.Code != "" {
			if envelope.Response.Error.Code == "ResourceNotFound.NoDataOfRecord" {
				break
			}
			return nil, providerFailure(credential, envelope.Response.Error.Code, envelope.Response.Error.Message)
		}
		for _, current := range envelope.Response.RecordList {
			if !sameIdentity(current.Type, current.Name, record) {
				continue
			}
			records = append(records, providerRecord{ID: string(current.RecordID), Type: current.Type, Name: current.Name, Content: current.Value, Line: current.Line})
		}
		if len(envelope.Response.RecordList) < 100 || len(records) >= envelope.Response.RecordCountInfo.TotalCount {
			break
		}
	}
	return records, nil
}

func (client *providerDNSClient) tencentCall(ctx context.Context, credential providerCredential, action string, payload any) ([]byte, error) {
	endpoint, host, err := client.resolve(ProviderTencentDNS)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalidInput
	}
	timestamp := strconv.FormatInt(client.current().UTC().Unix(), 10)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalidInput
	}
	request.Host = host
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Host", host)
	request.Header.Set("Authorization", tencentAuthorization(credential.SecretID, credential.SecretKey, host, timestamp, body))
	request.Header.Set("X-TC-Action", action)
	request.Header.Set("X-TC-Timestamp", timestamp)
	request.Header.Set("X-TC-Version", tencentDNSVersion)
	request.Header.Set("User-Agent", domesticUserAgent)
	responseBody, status, err := client.roundTrip(request, credential)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Response struct {
			Error struct {
				Code, Message string
			} `json:"Error"`
		} `json:"Response"`
	}
	_ = json.Unmarshal(responseBody, &envelope)
	if status < 200 || status >= 300 || envelope.Response.Error.Code != "" {
		code := envelope.Response.Error.Code
		detail := envelope.Response.Error.Message
		if detail == "" {
			detail = "HTTP " + strconv.Itoa(status)
		}
		if action == "DescribeRecordList" && code == "ResourceNotFound.NoDataOfRecord" {
			return responseBody, nil
		}
		return nil, providerFailure(credential, code, detail)
	}
	return responseBody, nil
}

func tencentAuthorization(secretID, secretKey, host, timestamp string, body []byte) string {
	unix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		unix = 0
	}
	date := time.Unix(unix, 0).UTC().Format("2006-01-02")
	canonicalHeaders := "content-type:application/json\nhost:" + host + "\n"
	signedHeaders := "content-type;host"
	hashedPayload := sha256Hex(body)
	canonical := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedPayload
	scope := date + "/dnspod/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, "dnspod")
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))
	return "TC3-HMAC-SHA256 Credential=" + secretID + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sameIdentity(recordType, name string, record domesticRecord) bool {
	return strings.EqualFold(recordType, record.Type) && strings.EqualFold(name, record.Name)
}

func matchingContent(records []providerRecord, record domesticRecord) bool {
	return len(matchingContentRecords(records, record)) > 0
}

func matchingContentRecords(records []providerRecord, record domesticRecord) []providerRecord {
	var matched []providerRecord
	for _, current := range records {
		if sameIdentity(current.Type, current.Name, record) && sameRecordContent(record.Type, current.Content, record.Content) {
			matched = append(matched, current)
		}
	}
	return matched
}
