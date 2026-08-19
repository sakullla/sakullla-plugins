package cloudflaredns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	cloudflarePageSize = 100
	cloudflareMaxPages = 1000
)

var errCloudflareRecordNotFound = errors.New("Cloudflare DNS record was not found")

type hostDNS struct {
	client hostRuntimeCaller
}

type cloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cloudflareRecord struct {
	ID       string `json:"id"`
	ZoneID   string `json:"zone_id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      uint32 `json:"ttl"`
	Priority uint16 `json:"priority,omitempty"`
}

type cloudflareResultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

type cloudflareEnvelope struct {
	Success    bool                 `json:"success"`
	Result     json.RawMessage      `json:"result"`
	ResultInfo cloudflareResultInfo `json:"result_info"`
}

type cloudflareHTTPResult struct {
	Status        int               `json:"status"`
	Body          []byte            `json:"body"`
	Headers       map[string]string `json:"headers"`
	ContentType   string            `json:"content_type"`
	RequestMethod string            `json:"request_method"`
}

type cloudflareAPIError struct {
	status     int
	retryAfter time.Duration
}

func (err *cloudflareAPIError) Error() string {
	return "Cloudflare API rejected the request"
}

func (dns *hostDNS) Inspect(ctx context.Context, operation string) (OperationOutcome, error) {
	return newHostOperationJournal(dns.client).Inspect(ctx, operation)
}

func (dns *hostDNS) ListZones(ctx context.Context, attestation TokenAttestation, _ string) ([]Zone, error) {
	zones, err := listCloudflareZones(ctx, dns.client, attestation.SecretRef)
	if err != nil {
		return nil, err
	}
	result := make([]Zone, len(zones))
	for index, zone := range zones {
		result[index] = Zone{ID: zone.ID, Name: zone.Name}
	}
	return result, nil
}

func listCloudflareZones(ctx context.Context, client hostRuntimeCaller, secretRef string) ([]cloudflareZone, error) {
	var zones []cloudflareZone
	for page := 1; ; page++ {
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {"50"}}
		var batch []cloudflareZone
		info, err := cloudflareRequest(ctx, client, secretRef, http.MethodGet, cloudflareAPIBase+"/zones?"+query.Encode(), "", nil, &batch)
		if err != nil {
			return nil, err
		}
		if !validCloudflarePage(page, info, len(batch)) {
			return nil, ErrDNSOperationFailed
		}
		for _, zone := range batch {
			name, normalizeErr := NormalizeDomain(zone.Name)
			if normalizeErr != nil || !validCloudflareID(zone.ID) {
				return nil, ErrDNSOperationFailed
			}
			zone.Name = name
			zones = append(zones, zone)
			if len(zones) > MaxZones {
				return nil, ErrBoundExceeded
			}
		}
		if info.TotalPages <= page {
			break
		}
		if page >= cloudflareMaxPages {
			return nil, ErrBoundExceeded
		}
	}
	sort.SliceStable(zones, func(left, right int) bool { return len(zones[left].Name) > len(zones[right].Name) })
	return zones, nil
}

func (dns *hostDNS) ListRecords(ctx context.Context, attestation TokenAttestation, zoneID string, maximum int) ([]DNSRecord, error) {
	if !validCloudflareID(zoneID) || maximum <= 0 || maximum > MaxRecords {
		return nil, ErrInvalidInput
	}
	var result []DNSRecord
	for page := 1; ; page++ {
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(cloudflarePageSize)}}
		var batch []cloudflareRecord
		info, err := cloudflareRequest(ctx, dns.client, attestation.SecretRef, http.MethodGet, cloudflareAPIBase+"/zones/"+url.PathEscape(zoneID)+"/dns_records?"+query.Encode(), "", nil, &batch)
		if err != nil {
			return nil, err
		}
		if !validCloudflarePage(page, info, len(batch)) {
			return nil, ErrDNSOperationFailed
		}
		for _, record := range batch {
			if !supportedCloudflareRecordType(record.Type) {
				continue
			}
			converted := fromCloudflareRecord(record)
			if converted.ZoneID != zoneID || !validCloudflareID(converted.ID) || converted.Validate(true) != nil {
				return nil, ErrDNSOperationFailed
			}
			result = append(result, converted)
			if len(result) > maximum {
				return nil, ErrBoundExceeded
			}
		}
		if info.TotalPages <= page {
			break
		}
		if page >= cloudflareMaxPages {
			return nil, ErrBoundExceeded
		}
	}
	return result, nil
}

func (dns *hostDNS) Create(ctx context.Context, attestation TokenAttestation, record DNSRecord, operation string) (DNSRecord, error) {
	if !validCloudflareID(record.ZoneID) {
		return DNSRecord{}, ErrInvalidInput
	}
	var providerRecord cloudflareRecord
	endpoint := cloudflareAPIBase + "/zones/" + url.PathEscape(record.ZoneID) + "/dns_records"
	if _, err := cloudflareRequest(ctx, dns.client, attestation.SecretRef, http.MethodPost, endpoint, operation, cloudflareCreatePayload(record), &providerRecord); err != nil {
		return DNSRecord{}, err
	}
	result := fromCloudflareRecord(providerRecord)
	if !cloudflareRecordMatches(result, record, false) {
		return DNSRecord{}, ErrDNSOperationFailed
	}
	return result, nil
}

func (dns *hostDNS) Update(ctx context.Context, attestation TokenAttestation, record DNSRecord, operation string) (DNSRecord, error) {
	if !validCloudflareID(record.ZoneID) || !validCloudflareID(record.ID) {
		return DNSRecord{}, ErrInvalidInput
	}
	var providerRecord cloudflareRecord
	endpoint := cloudflareAPIBase + "/zones/" + url.PathEscape(record.ZoneID) + "/dns_records/" + url.PathEscape(record.ID)
	if _, err := cloudflareRequest(ctx, dns.client, attestation.SecretRef, http.MethodPatch, endpoint, operation, cloudflareUpdatePayload(record), &providerRecord); err != nil {
		return DNSRecord{}, err
	}
	result := fromCloudflareRecord(providerRecord)
	if !cloudflareRecordMatches(result, record, true) {
		return DNSRecord{}, ErrDNSOperationFailed
	}
	return result, nil
}

func (dns *hostDNS) Delete(ctx context.Context, attestation TokenAttestation, zoneID, recordID, operation string) error {
	if !validCloudflareID(zoneID) || !validCloudflareID(recordID) {
		return ErrInvalidInput
	}
	var result struct {
		ID string `json:"id"`
	}
	endpoint := cloudflareAPIBase + "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
	_, err := cloudflareRequest(ctx, dns.client, attestation.SecretRef, http.MethodDelete, endpoint, operation, nil, &result)
	if errors.Is(err, errCloudflareRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if result.ID != "" && result.ID != recordID {
		return ErrDNSOperationFailed
	}
	return nil
}

func cloudflareCreatePayload(record DNSRecord) map[string]any {
	payload := recordPayload(record)
	switch record.Type {
	case "A", "AAAA", "CNAME":
		payload["proxied"] = false
	}
	return payload
}

func cloudflareUpdatePayload(record DNSRecord) map[string]any {
	return recordPayload(record)
}

func recordPayload(record DNSRecord) map[string]any {
	payload := map[string]any{"type": record.Type, "name": record.Name, "content": record.Content, "ttl": record.TTL}
	if record.Type == "MX" {
		payload["priority"] = record.Priority
	}
	return payload
}

func fromCloudflareRecord(record cloudflareRecord) DNSRecord {
	return DNSRecord{ID: record.ID, ZoneID: record.ZoneID, Type: record.Type, Name: record.Name, Content: record.Content, TTL: record.TTL, Priority: record.Priority}
}

func cloudflareRecordMatches(got, want DNSRecord, requireID bool) bool {
	if !validCloudflareID(got.ID) || got.ZoneID != want.ZoneID || got.Type != want.Type || !strings.EqualFold(strings.TrimSuffix(got.Name, "."), strings.TrimSuffix(want.Name, ".")) || got.TTL != want.TTL || got.Validate(true) != nil {
		return false
	}
	if requireID && got.ID != want.ID {
		return false
	}
	if got.Type == "MX" && got.Priority != want.Priority {
		return false
	}
	return equalCloudflareContent(got.Type, got.Content, want.Content)
}

func equalCloudflareContent(recordType, left, right string) bool {
	if recordType != "TXT" {
		return left == right
	}
	return canonicalCloudflareTXTContent(left) == canonicalCloudflareTXTContent(right)
}

func canonicalCloudflareTXTContent(content string) string {
	if len(content) >= 2 && content[0] == '"' && content[len(content)-1] == '"' {
		return content[1 : len(content)-1]
	}
	return content
}

func cloudflareRequest(ctx context.Context, client hostRuntimeCaller, secretRef, method, endpoint, operation string, body, target any) (cloudflareResultInfo, error) {
	var info cloudflareResultInfo
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return info, ErrInvalidInput
		}
	}
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	input := map[string]any{"secret_ref": secretRef, "method": method, "url": endpoint, "headers": headers, "body": encoded}
	var response cloudflareHTTPResult
	if err := callHostOperation(ctx, client, "http.secret-request", operation, input, &response); err != nil {
		return info, err
	}
	if response.Status == http.StatusNotFound && method == http.MethodDelete {
		return info, errCloudflareRecordNotFound
	}
	if response.Status < 200 || response.Status >= 300 {
		return info, &cloudflareAPIError{status: response.Status, retryAfter: parseCloudflareRetryAfter(response.Headers["Retry-After"], time.Now())}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body, &fields); err != nil {
		return info, ErrDNSOperationFailed
	}
	var envelope cloudflareEnvelope
	if err := json.Unmarshal(response.Body, &envelope); err != nil || len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return info, ErrDNSOperationFailed
	}
	if success, found := fields["success"]; found {
		if json.Unmarshal(success, &envelope.Success) != nil || !envelope.Success {
			return info, ErrDNSOperationFailed
		}
	} else if method != http.MethodDelete {
		return info, ErrDNSOperationFailed
	}
	if target != nil && json.Unmarshal(envelope.Result, target) != nil {
		return info, ErrDNSOperationFailed
	}
	return envelope.ResultInfo, nil
}

func validCloudflarePage(page int, info cloudflareResultInfo, count int) bool {
	if page <= 0 || info.Page != page || info.TotalPages < 0 || info.TotalPages > cloudflareMaxPages || count < 0 {
		return false
	}
	if info.TotalPages == 0 {
		return page == 1 && count == 0
	}
	return info.TotalPages >= page
}

func validCloudflareID(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func supportedCloudflareRecordType(value string) bool {
	switch value {
	case "A", "AAAA", "CNAME", "TXT", "MX":
		return true
	default:
		return false
	}
}

func parseCloudflareRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		if seconds <= 0 || seconds > int64(time.Duration(1<<63-1)/time.Second) {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func committedHostOutcome(response pluginsdk.HostRuntimeResponse) (OperationOutcome, error) {
	if response.Error != nil {
		return OperationOutcome{State: OperationFailed}, nil
	}
	var secret hostSecretResult
	if json.Unmarshal(response.Payload, &secret) == nil && secret.Found && secret.Ref != "" && secret.Version != "" {
		return OperationOutcome{State: OperationCommitted, Token: TokenMetadata{SecretRef: secret.Ref, Version: secret.Version}}, nil
	}
	var provider cloudflareHTTPResult
	if json.Unmarshal(response.Payload, &provider) != nil || provider.Status == 0 {
		return OperationOutcome{State: OperationFailed}, nil
	}
	if provider.Status == http.StatusNotFound && provider.RequestMethod == http.MethodDelete {
		return OperationOutcome{State: OperationCommitted}, nil
	}
	if provider.Status == http.StatusRequestTimeout || provider.Status >= 500 {
		return OperationOutcome{State: OperationUnknown}, nil
	}
	if provider.Status < 200 || provider.Status >= 300 {
		return OperationOutcome{State: OperationFailed}, nil
	}
	var record cloudflareRecord
	if _, err := decodeCloudflareCommittedResponse(provider.Body, provider.RequestMethod, &record); err != nil {
		return OperationOutcome{State: OperationUnknown}, nil
	}
	return OperationOutcome{State: OperationCommitted, Record: fromCloudflareRecord(record)}, nil
}

func decodeCloudflareCommittedResponse(body []byte, method string, target any) (cloudflareResultInfo, error) {
	caller := staticHostCaller{response: cloudflareHTTPResult{Status: http.StatusOK, Body: body, RequestMethod: method}}
	return cloudflareRequest(context.Background(), caller, "secret", method, cloudflareAPIBase, "", nil, target)
}

type staticHostCaller struct {
	response cloudflareHTTPResult
}

func (caller staticHostCaller) Call(_ context.Context, _ pluginsdk.HostRuntimeCall, target any) error {
	encoded, err := json.Marshal(caller.response)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}
