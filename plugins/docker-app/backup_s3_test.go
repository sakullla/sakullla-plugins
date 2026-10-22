package dockerapp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	testBackupS3AccessKey = "AKIAEXAMPLEACCESSKEY"
	testBackupS3SecretKey = "plaintext-secret-material-5f3a1c"
	testBackupS3Endpoint  = "https://s3.example.test"
	testBackupS3Bucket    = "backups"
	testBackupS3Prefix    = "docker-app"
)

var testBackupS3CredentialsReferenceJSON = fmt.Sprintf(
	`{"instance_id":"instance-a","id":"backup-credentials","version":"version-00000000000000001","scope":%q}`,
	backupSecretScope,
)

var testBackupS3Material = fmt.Sprintf(
	`{"access_key_id":%q,"secret_access_key":%q}`, testBackupS3AccessKey, testBackupS3SecretKey,
)

// fakeScopedSecretSource stands in for the Host scoped-secret transport.
type fakeScopedSecretSource struct {
	mu       sync.Mutex
	material []byte
	err      error
	requests []pluginsdk.ScopedSecretRequest
}

func (fake *fakeScopedSecretSource) ScopedSecret(_ context.Context, request pluginsdk.ScopedSecretRequest) (pluginsdk.ScopedSecretResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.requests = append(fake.requests, request)
	if fake.err != nil {
		return pluginsdk.ScopedSecretResponse{}, fake.err
	}
	material, err := pluginsdk.NewManagedSecretMaterial(fake.material)
	if err != nil {
		return pluginsdk.ScopedSecretResponse{}, err
	}
	return pluginsdk.ScopedSecretResponse{Reference: request.Reference, Material: material}, nil
}

func (fake *fakeScopedSecretSource) requestCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return len(fake.requests)
}

// stubS3Transport answers the path-style S3 wire protocol without any
// network. Error bodies deliberately echo the credential material so every
// assertion proves the plugin never forwards endpoint free text.
type stubS3Transport struct {
	mu                sync.Mutex
	calls             []stubS3Call
	stored            map[string][]byte
	uploadParts       map[int][]byte
	failParts         map[int]bool
	rejectCredentials bool
	accessDenied      bool
	unreachable       bool
	initiates         int
	completes         int
	aborts            int
}

type stubS3Call struct {
	Method        string
	Path          string
	Query         url.Values
	Body          []byte
	Authorization string
}

func (stub *stubS3Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	var body []byte
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
	}
	stub.calls = append(stub.calls, stubS3Call{
		Method: request.Method, Path: request.URL.Path, Query: request.URL.Query(),
		Body: body, Authorization: request.Header.Get("Authorization"),
	})
	if stub.unreachable {
		// An x509 failure is a non-retryable transport error for minio, so
		// the unreachable stage is exercised without retry backoff.
		return nil, x509.UnknownAuthorityError{}
	}
	trimmed := strings.TrimPrefix(request.URL.Path, "/")
	bucket, object, _ := strings.Cut(trimmed, "/")
	if bucket == "" {
		return stub.textResponse(http.StatusBadRequest, "bad request"), nil
	}
	query := request.URL.Query()
	if object == "" {
		return stub.bucketResponse(query), nil
	}
	return stub.objectResponse(request, bucket, object, query, body), nil
}

func (stub *stubS3Transport) bucketResponse(query url.Values) *http.Response {
	if stub.refuse() {
		return stub.errorResponse(stub.refuseStatus(), stub.refuseCode())
	}
	if query.Get("list-type") == "2" {
		return stub.xmlResponse(http.StatusOK, stub.listResultXML(query.Get("prefix")))
	}
	location := `<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`
	return stub.xmlResponse(http.StatusOK, location)
}

func (stub *stubS3Transport) objectResponse(request *http.Request, _, object string, query url.Values, body []byte) *http.Response {
	uploadID := query.Get("uploadId")
	partNumber := query.Get("partNumber")
	switch request.Method {
	case http.MethodPost:
		if stub.refuse() {
			return stub.errorResponse(stub.refuseStatus(), stub.refuseCode())
		}
		if uploadID == "" {
			stub.initiates++
			stub.uploadParts = map[int][]byte{}
			result := `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`
			return stub.xmlResponse(http.StatusOK, result)
		}
		stub.completes++
		var assembled []byte
		for number := 1; ; number++ {
			part, ok := stub.uploadParts[number]
			if !ok {
				break
			}
			assembled = append(assembled, part...)
		}
		stub.stored[object] = assembled
		result := `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult><Location>https://s3.example.test/b/k</Location><Bucket>b</Bucket><Key>k</Key><ETag>"complete-etag"</ETag></CompleteMultipartUploadResult>`
		return stub.xmlResponse(http.StatusOK, result)
	case http.MethodPut:
		if stub.refuse() {
			return stub.errorResponse(stub.refuseStatus(), stub.refuseCode())
		}
		if uploadID != "" && partNumber != "" {
			number, err := strconv.Atoi(partNumber)
			if err != nil {
				return stub.errorResponse(http.StatusBadRequest, "InvalidPart")
			}
			if stub.failParts[number] {
				return stub.errorResponse(http.StatusBadRequest, "InvalidPart")
			}
			stub.uploadParts[number] = append([]byte(nil), body...)
			response := stub.textResponse(http.StatusOK, "")
			response.Header.Set("ETag", fmt.Sprintf(`"part-%d"`, number))
			return response
		}
		stub.stored[object] = append([]byte(nil), body...)
		response := stub.textResponse(http.StatusOK, "")
		response.Header.Set("ETag", `"put-etag"`)
		return response
	case http.MethodGet:
		if content, ok := stub.stored[object]; ok {
			return stub.binaryResponse(http.StatusOK, content)
		}
		return stub.errorResponse(http.StatusNotFound, "NoSuchKey")
	case http.MethodHead:
		if _, ok := stub.stored[object]; ok {
			return stub.textResponse(http.StatusOK, "")
		}
		return stub.textResponse(http.StatusNotFound, "")
	case http.MethodDelete:
		if query.Has("uploadId") {
			stub.aborts++
			return stub.textResponse(http.StatusNoContent, "")
		}
		if stub.refuse() {
			return stub.errorResponse(stub.refuseStatus(), stub.refuseCode())
		}
		delete(stub.stored, object)
		return stub.textResponse(http.StatusNoContent, "")
	default:
		return stub.textResponse(http.StatusMethodNotAllowed, "")
	}
}

func (stub *stubS3Transport) refuse() bool {
	return stub.rejectCredentials || stub.accessDenied
}

func (stub *stubS3Transport) refuseStatus() int {
	return http.StatusForbidden
}

func (stub *stubS3Transport) refuseCode() string {
	if stub.accessDenied {
		return "AccessDenied"
	}
	return "InvalidAccessKeyId"
}

// errorResponse embeds the credential material in the server message: any
// plugin path that forwards endpoint free text fails the leak assertions.
func (stub *stubS3Transport) errorResponse(status int, code string) *http.Response {
	body := fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>echo %s %s</Message><Resource>/b/k</Resource><RequestId>req-1</RequestId></Error>`,
		code, testBackupS3AccessKey, testBackupS3SecretKey,
	)
	return stub.xmlResponse(status, body)
}

func (stub *stubS3Transport) listResultXML(prefix string) string {
	keys := make([]string, 0, len(stub.stored))
	for key := range stub.stored {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>b</Name><Prefix>`)
	builder.WriteString(prefix)
	builder.WriteString(`</Prefix><KeyCount>`)
	builder.WriteString(strconv.Itoa(len(keys)))
	builder.WriteString(`</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`)
	for _, key := range keys {
		builder.WriteString(`<Contents><Key>`)
		builder.WriteString(key)
		builder.WriteString(`</Key><LastModified>2026-01-02T03:04:05.000Z</LastModified><ETag>"etag"</ETag><Size>`)
		builder.WriteString(strconv.Itoa(len(stub.stored[key])))
		builder.WriteString(`</Size><StorageClass>STANDARD</StorageClass></Contents>`)
	}
	builder.WriteString(`</ListBucketResult>`)
	return builder.String()
}

func (stub *stubS3Transport) xmlResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d status", status),
		Header: http.Header{"Content-Type": []string{"application/xml"}},
		Body:   io.NopCloser(strings.NewReader(body)),
	}
}

func (stub *stubS3Transport) textResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d status", status),
		Header: http.Header{"Content-Type": []string{"text/plain"}},
		Body:   io.NopCloser(strings.NewReader(body)),
	}
}

func (stub *stubS3Transport) binaryResponse(status int, body []byte) *http.Response {
	response := &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d status", status),
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
	}
	response.Header.Set("ETag", `"object-etag"`)
	response.Header.Set("Last-Modified", "Fri, 02 Jan 2026 03:04:05 GMT")
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return response
}

func (stub *stubS3Transport) storedContent(key string) ([]byte, bool) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	content, ok := stub.stored[key]
	return append([]byte(nil), content...), ok
}

func (stub *stubS3Transport) counters() (initiates, completes, aborts int) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.initiates, stub.completes, stub.aborts
}

func (stub *stubS3Transport) callsOf(method string) []stubS3Call {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	var matched []stubS3Call
	for _, call := range stub.calls {
		if call.Method == method {
			matched = append(matched, call)
		}
	}
	return matched
}

func withBackupS3Stub(t *testing.T, configure func(*stubS3Transport)) *stubS3Transport {
	t.Helper()
	previous := backupS3HTTPTransport
	stub := &stubS3Transport{stored: map[string][]byte{}, uploadParts: map[int][]byte{}}
	if configure != nil {
		configure(stub)
	}
	backupS3HTTPTransport = stub
	t.Cleanup(func() { backupS3HTTPTransport = previous })
	return stub
}

func withBackupS3PartSize(t *testing.T, size int64) {
	t.Helper()
	previous := backupS3PartSize
	backupS3PartSize = size
	t.Cleanup(func() { backupS3PartSize = previous })
}

func newBackupS3Controller(t *testing.T, source ScopedSecretSource, root string) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		BackupSecrets: source, UIWorkDirRoot: root,
		CommandRunner: unusedDockerRunner(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: requiredGrants(), Generation: "generation-1",
	}); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{
		Generation: "generation-1", Config: []byte(`{"apps":[]}`),
	}); response.Error != nil {
		t.Fatal(response.Error)
	}
	return controller
}

func callBackupS3Action(t *testing.T, controller *Controller, action string, extra map[string]any) ([]byte, error) {
	t.Helper()
	payload := map[string]any{
		"action": action, "agent_id": "agent-1", "app_id": "media",
		"endpoint": testBackupS3Endpoint, "bucket": testBackupS3Bucket, "prefix": testBackupS3Prefix,
		"credentials_secret": testBackupS3CredentialsReferenceJSON,
	}
	for key, value := range extra {
		payload[key] = value
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return controller.Call(context.Background(), "generation-1", pluginCallBackupS3Name, raw)
}

func writeBackupS3Fixture(t *testing.T, root, name string, size int) (string, []byte) {
	t.Helper()
	content := make([]byte, size)
	for index := range content {
		content[index] = byte('a' + index%26)
	}
	workdir := filepath.Join(root, "media")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workdir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, content
}

func TestCallBackupS3GatesUnconfiguredAndMissingCredentials(t *testing.T) {
	root := t.TempDir()
	source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
	controller := newBackupS3Controller(t, source, root)
	withBackupS3Stub(t, nil)
	tests := []struct {
		name   string
		fields map[string]any
		want   string
		gate   error
	}{
		{
			name:   "empty endpoint",
			fields: map[string]any{"endpoint": ""},
			want:   "backup-s3 upload failed: destination is not configured",
			gate:   ErrBackupS3Unconfigured,
		},
		{
			name:   "empty bucket",
			fields: map[string]any{"bucket": ""},
			want:   "backup-s3 upload failed: destination is not configured",
			gate:   ErrBackupS3Unconfigured,
		},
		{
			name:   "missing credentials",
			fields: map[string]any{"credentials_secret": ""},
			want:   "backup-s3 upload failed: credentials secret is missing",
			gate:   ErrBackupS3CredentialsMissing,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := callBackupS3Action(t, controller, backupS3ActionUpload, test.fields)
			if err == nil || err.Error() != test.want {
				t.Fatalf("err = %v want %q", err, test.want)
			}
			if !errors.Is(err, test.gate) {
				t.Fatalf("err %v is not %v", err, test.gate)
			}
		})
	}
	if source.requestCount() != 0 {
		t.Fatalf("gated dispatch read the secret %d times", source.requestCount())
	}
}

func TestParseBackupS3DestinationValidation(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		bucket      string
		prefix      string
		credentials string
		want        string
	}{
		{name: "http endpoint", endpoint: "http://s3.example.test", bucket: "backups", prefix: "p", credentials: testBackupS3CredentialsReferenceJSON, want: s3StageInvalidEndpoint},
		{name: "endpoint with path", endpoint: "https://s3.example.test/base", bucket: "backups", prefix: "p", credentials: testBackupS3CredentialsReferenceJSON, want: s3StageInvalidEndpoint},
		{name: "endpoint host missing", endpoint: "https://", bucket: "backups", prefix: "p", credentials: testBackupS3CredentialsReferenceJSON, want: s3StageInvalidEndpoint},
		{name: "uppercase bucket", endpoint: testBackupS3Endpoint, bucket: "Backups", prefix: "p", credentials: testBackupS3CredentialsReferenceJSON, want: s3StageInvalidConfig},
		{name: "short bucket", endpoint: testBackupS3Endpoint, bucket: "ab", prefix: "p", credentials: testBackupS3CredentialsReferenceJSON, want: s3StageInvalidConfig},
		{name: "prefix with space", endpoint: testBackupS3Endpoint, bucket: "backups", prefix: "a b", credentials: testBackupS3CredentialsReferenceJSON, want: s3StageInvalidConfig},
		{name: "credentials not json", endpoint: testBackupS3Endpoint, bucket: "backups", prefix: "p", credentials: "opaque", want: s3StageInvalidCredential},
		{name: "credentials wrong scope", endpoint: testBackupS3Endpoint, bucket: "backups", prefix: "p", credentials: `{"instance_id":"instance-a","id":"backup-credentials","version":"version-00000000000000001","scope":"other-scope"}`, want: s3StageInvalidCredential},
		{name: "credentials without version", endpoint: testBackupS3Endpoint, bucket: "backups", prefix: "p", credentials: `{"instance_id":"instance-a","id":"backup-credentials","scope":"docker-app-backup"}`, want: s3StageInvalidCredential},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, stage := parseBackupS3Destination(test.endpoint, test.bucket, test.prefix, test.credentials)
			if stage != test.want {
				t.Fatalf("stage = %q want %q", stage, test.want)
			}
		})
	}
	destination, stage := parseBackupS3Destination(testBackupS3Endpoint, testBackupS3Bucket, "", testBackupS3CredentialsReferenceJSON)
	if stage != "" || destination.bucket != testBackupS3Bucket || destination.host != "s3.example.test" {
		t.Fatalf("valid destination rejected: %#v stage=%q", destination, stage)
	}
}

func TestCallBackupS3UploadSinglePut(t *testing.T) {
	root := t.TempDir()
	_, content := writeBackupS3Fixture(t, root, "media-20260101T000000Z.tar.zst", 256)
	source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
	controller := newBackupS3Controller(t, source, root)
	stub := withBackupS3Stub(t, nil)
	raw, err := callBackupS3Action(t, controller, backupS3ActionUpload, map[string]any{
		"object": "media-20260101T000000Z.tar.zst", "path": "media-20260101T000000Z.tar.zst",
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Accepted bool   `json:"accepted"`
		Object   string `json:"object"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Object != "docker-app/media-20260101T000000Z.tar.zst" || result.Size != int64(len(content)) {
		t.Fatalf("result = %s", raw)
	}
	digest := sha256.Sum256(content)
	if result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("sha256 = %s", result.SHA256)
	}
	stored, ok := stub.storedContent("docker-app/media-20260101T000000Z.tar.zst")
	if !ok || string(stored) != string(content) {
		t.Fatalf("stored object content mismatch: %d bytes ok=%v", len(stored), ok)
	}
	initiates, completes, aborts := stub.counters()
	if initiates != 0 || completes != 0 || aborts != 0 {
		t.Fatalf("single upload used multipart: initiates=%d completes=%d aborts=%d", initiates, completes, aborts)
	}
	puts := stub.callsOf(http.MethodPut)
	if len(puts) != 1 || puts[0].Path != "/backups/docker-app/media-20260101T000000Z.tar.zst" {
		t.Fatalf("put calls = %#v", puts)
	}
	if puts[0].Authorization == "" {
		t.Fatal("upload was not signed with resolved credentials")
	}
	if source.requestCount() != 1 {
		t.Fatalf("secret reads = %d", source.requestCount())
	}
}

func TestCallBackupS3UploadMultipart(t *testing.T) {
	root := t.TempDir()
	_, content := writeBackupS3Fixture(t, root, "media-20260101T000000Z.tar.zst", 40)
	source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
	controller := newBackupS3Controller(t, source, root)
	withBackupS3PartSize(t, 16)
	stub := withBackupS3Stub(t, nil)
	if _, err := callBackupS3Action(t, controller, backupS3ActionUpload, map[string]any{
		"object": "media-20260101T000000Z.tar.zst", "path": "media-20260101T000000Z.tar.zst",
	}); err != nil {
		t.Fatal(err)
	}
	initiates, completes, aborts := stub.counters()
	if initiates != 1 || completes != 1 || aborts != 0 {
		t.Fatalf("multipart counters: initiates=%d completes=%d aborts=%d", initiates, completes, aborts)
	}
	stored, ok := stub.storedContent("docker-app/media-20260101T000000Z.tar.zst")
	if !ok || string(stored) != string(content) {
		t.Fatalf("stored multipart content mismatch: %d bytes ok=%v", len(stored), ok)
	}
	var parts []string
	for _, call := range stub.callsOf(http.MethodPut) {
		if call.Query.Get("uploadId") != "upload-1" {
			continue
		}
		parts = append(parts, call.Query.Get("partNumber"))
		if call.Path != "/backups/docker-app/media-20260101T000000Z.tar.zst" {
			t.Fatalf("part path = %s", call.Path)
		}
	}
	if strings.Join(parts, ",") != "1,2,3" {
		t.Fatalf("part numbers = %v", parts)
	}
}

func TestCallBackupS3UploadFailuresLeaveNoRecord(t *testing.T) {
	tests := []struct {
		name      string
		partSize  int64
		configure func(*stubS3Transport)
		want      string
	}{
		{
			name:      "credentials rejected",
			partSize:  64 << 20,
			configure: func(stub *stubS3Transport) { stub.rejectCredentials = true },
			want:      "backup-s3 upload failed: credentials were rejected",
		},
		{
			name:     "endpoint unreachable",
			partSize: 64 << 20,
			configure: func(stub *stubS3Transport) {
				stub.unreachable = true
			},
			want: "backup-s3 upload failed: endpoint is unreachable",
		},
		{
			name:     "part failure aborts",
			partSize: 16,
			configure: func(stub *stubS3Transport) {
				stub.failParts = map[int]bool{2: true}
			},
			want: "backup-s3 upload failed: multipart upload failed partway",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeBackupS3Fixture(t, root, "media-20260101T000000Z.tar.zst", 40)
			source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
			controller := newBackupS3Controller(t, source, root)
			withBackupS3PartSize(t, test.partSize)
			stub := withBackupS3Stub(t, test.configure)
			_, err := callBackupS3Action(t, controller, backupS3ActionUpload, map[string]any{
				"object": "media-20260101T000000Z.tar.zst", "path": "media-20260101T000000Z.tar.zst",
			})
			if err == nil || err.Error() != test.want {
				t.Fatalf("err = %v want %q", err, test.want)
			}
			initiates, completes, aborts := stub.counters()
			if completes != 0 {
				t.Fatalf("failed upload completed %d records", completes)
			}
			if _, residue := stub.storedContent("docker-app/media-20260101T000000Z.tar.zst"); residue {
				t.Fatal("failed upload left a stored object")
			}
			if test.name == "part failure aborts" && (initiates != 1 || aborts != 1) {
				t.Fatalf("abort flow: initiates=%d aborts=%d", initiates, aborts)
			}
		})
	}
}

func TestCallBackupS3DownloadVerifiesChecksum(t *testing.T) {
	root := t.TempDir()
	content := []byte("artifact-payload-0123456789")
	digest := sha256.Sum256(content)
	source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
	controller := newBackupS3Controller(t, source, root)
	stub := withBackupS3Stub(t, nil)
	stub.mu.Lock()
	stub.stored["docker-app/media-20260101T000000Z.tar.zst"] = append([]byte(nil), content...)
	stub.mu.Unlock()

	raw, err := callBackupS3Action(t, controller, backupS3ActionDownload, map[string]any{
		"object": "media-20260101T000000Z.tar.zst", "path": "restored/media-20260101T000000Z.tar.zst",
		"sha256": hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Accepted bool   `json:"accepted"`
		Path     string `json:"path"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Path != "restored/media-20260101T000000Z.tar.zst" || result.Size != int64(len(content)) {
		t.Fatalf("result = %s", raw)
	}
	downloaded, err := os.ReadFile(filepath.Join(root, "media", "restored", "media-20260101T000000Z.tar.zst"))
	if err != nil || string(downloaded) != string(content) {
		t.Fatalf("downloaded file = %q err=%v", downloaded, err)
	}

	_, err = callBackupS3Action(t, controller, backupS3ActionDownload, map[string]any{
		"object": "media-20260101T000000Z.tar.zst", "path": "restored/bad.tar.zst",
		"sha256": strings.Repeat("0", 64),
	})
	if err == nil || err.Error() != "backup-s3 download failed: object checksum mismatch" {
		t.Fatalf("checksum err = %v", err)
	}
	assertNoDownloadResidue(t, filepath.Join(root, "media", "restored"))

	_, err = callBackupS3Action(t, controller, backupS3ActionDownload, map[string]any{
		"object": "missing.tar.zst", "path": "restored/missing.tar.zst",
	})
	if err == nil || err.Error() != "backup-s3 download failed: object was not found" {
		t.Fatalf("missing err = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "media", "restored", "missing.tar.zst")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing object still created a file: %v", err)
	}
}

func assertNoDownloadResidue(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".s3-download-") {
			t.Fatalf("download residue: %s", entry.Name())
		}
		if entry.Name() == "bad.tar.zst" {
			t.Fatal("failed download left its destination file")
		}
	}
}

func TestCallBackupS3DeleteAndList(t *testing.T) {
	root := t.TempDir()
	source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
	controller := newBackupS3Controller(t, source, root)
	stub := withBackupS3Stub(t, nil)
	stub.mu.Lock()
	stub.stored["docker-app/media-a.tar.zst"] = []byte("aaaa")
	stub.stored["docker-app/media-b.tar.zst"] = []byte("bb")
	stub.stored["other/media-c.tar.zst"] = []byte("ccc")
	stub.mu.Unlock()

	raw, err := callBackupS3Action(t, controller, backupS3ActionList, nil)
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Objects []backupS3ObjectEntry `json:"objects"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Objects) != 2 || listing.Objects[0].Key != "docker-app/media-a.tar.zst" ||
		listing.Objects[0].Size != 4 || listing.Objects[1].Key != "docker-app/media-b.tar.zst" {
		t.Fatalf("listing = %s", raw)
	}
	for _, call := range stub.callsOf(http.MethodGet) {
		if call.Query.Get("list-type") == "2" && call.Query.Get("prefix") != "docker-app/" {
			t.Fatalf("list prefix = %q", call.Query.Get("prefix"))
		}
	}

	if _, err := callBackupS3Action(t, controller, backupS3ActionDelete, map[string]any{
		"object": "media-a.tar.zst",
	}); err != nil {
		t.Fatal(err)
	}
	if _, residue := stub.storedContent("docker-app/media-a.tar.zst"); residue {
		t.Fatal("deleted object still stored")
	}
	if _, keep := stub.storedContent("docker-app/media-b.tar.zst"); !keep {
		t.Fatal("delete removed a sibling object")
	}
	deletes := stub.callsOf(http.MethodDelete)
	if len(deletes) != 1 || deletes[0].Path != "/backups/docker-app/media-a.tar.zst" {
		t.Fatalf("delete calls = %#v", deletes)
	}

	stub.mu.Lock()
	stub.accessDenied = true
	stub.mu.Unlock()
	_, err = callBackupS3Action(t, controller, backupS3ActionDelete, map[string]any{"object": "media-b.tar.zst"})
	if err == nil || err.Error() != "backup-s3 delete failed: access was denied" {
		t.Fatalf("denied err = %v", err)
	}
}

func TestCallBackupS3RequestValidation(t *testing.T) {
	root := t.TempDir()
	source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
	controller := newBackupS3Controller(t, source, root)
	withBackupS3Stub(t, nil)
	if _, err := callBackupS3Action(t, controller, "prune", nil); err == nil || err.Error() != `backup-s3 action "prune" is unknown` {
		t.Fatalf("action err = %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"action": backupS3ActionList, "agent_id": "agent-1", "app_id": "media",
		"endpoint": testBackupS3Endpoint, "bucket": testBackupS3Bucket,
		"credentials_secret": testBackupS3CredentialsReferenceJSON,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallBackupS3Name, []byte("{not-json")); err == nil || err.Error() != "backup-s3 payload is invalid" {
		t.Fatalf("payload err = %v", err)
	}
	invalidApp := append([]byte(nil), payload...)
	invalidApp = []byte(strings.Replace(string(invalidApp), `"app_id":"media"`, `"app_id":"bad id"`, 1))
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallBackupS3Name, invalidApp); err == nil || err.Error() != "backup-s3 app id is invalid" {
		t.Fatalf("app id err = %v", err)
	}
	// An object name that escapes the destination prefix is rejected before
	// any credentials are read.
	if _, err := callBackupS3Action(t, controller, backupS3ActionUpload, map[string]any{
		"object": "../escape.tar.zst", "path": "artifact.tar.zst",
	}); err == nil || err.Error() != "backup-s3 upload failed: destination configuration is invalid" {
		t.Fatalf("escape err = %v", err)
	}
	if source.requestCount() != 0 {
		t.Fatalf("invalid requests read the secret %d times", source.requestCount())
	}
}

func TestCallBackupS3SecretReadFailures(t *testing.T) {
	root := t.TempDir()
	writeBackupS3Fixture(t, root, "media-20260101T000000Z.tar.zst", 16)
	// Without a live generation the read is refused before any transport use.
	controller := newBackupS3Controller(t, &fakeScopedSecretSource{material: []byte(testBackupS3Material)}, root)
	stub := withBackupS3Stub(t, nil)
	if _, err := callBackupS3Action(t, controller, backupS3ActionUpload, map[string]any{
		"object": "media-20260101T000000Z.tar.zst", "path": "media-20260101T000000Z.tar.zst",
	}); err != nil {
		t.Fatal(err)
	}

	unprepared, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		BackupSecrets: &fakeScopedSecretSource{material: []byte(testBackupS3Material)},
		CommandRunner: unusedDockerRunner(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callBackupS3Action(t, unprepared, backupS3ActionList, nil); err == nil ||
		err.Error() != "backup-s3 list failed: credentials secret could not be read" {
		t.Fatalf("unprepared err = %v", err)
	}

	// A revoked or unreadable reference fails closed.
	revoked := newBackupS3Controller(t, &fakeScopedSecretSource{err: errors.New("scoped secret operation failed")}, root)
	if _, err := callBackupS3Action(t, revoked, backupS3ActionList, nil); err == nil ||
		err.Error() != "backup-s3 list failed: credentials secret could not be read" {
		t.Fatalf("revoked err = %v", err)
	}

	// Material in an unexpected shape is rejected without any upload.
	badMaterial := newBackupS3Controller(t, &fakeScopedSecretSource{material: []byte("not-json")}, root)
	if _, err := callBackupS3Action(t, badMaterial, backupS3ActionUpload, map[string]any{
		"object": "media-20260101T000000Z.tar.zst", "path": "media-20260101T000000Z.tar.zst",
	}); err == nil || err.Error() != "backup-s3 upload failed: credentials secret is invalid" {
		t.Fatalf("bad material err = %v", err)
	}
	if initiates, completes, _ := stub.counters(); initiates != 0 || completes != 0 {
		t.Fatalf("unexpected multipart counters initiates=%d completes=%d", initiates, completes)
	}
	if stored, ok := stub.storedContent("docker-app/media-20260101T000000Z.tar.zst"); !ok || len(stored) != 16 {
		t.Fatalf("valid upload not stored: ok=%v len=%d", ok, len(stored))
	}
}

type recordingLogHandler struct {
	mu      sync.Mutex
	records []string
}

func (handler *recordingLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (handler *recordingLogHandler) Handle(_ context.Context, record slog.Record) error {
	var builder strings.Builder
	builder.WriteString(record.Message)
	record.Attrs(func(attribute slog.Attr) bool {
		builder.WriteString(" ")
		builder.WriteString(attribute.Key)
		builder.WriteString("=")
		builder.WriteString(attribute.Value.String())
		return true
	})
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.records = append(handler.records, builder.String())
	return nil
}

func (handler *recordingLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return handler }
func (handler *recordingLogHandler) WithGroup(name string) slog.Handler       { return handler }

func (handler *recordingLogHandler) output() string {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return strings.Join(handler.records, "\n")
}

// TestCallBackupS3NeverLeaksCredentialMaterial runs success and failure paths
// while the stub endpoint echoes the credential material in every error body,
// then asserts the material appears nowhere the plugin emits: destination
// config serialization, error strings, responses, and log records.
func TestCallBackupS3NeverLeaksCredentialMaterial(t *testing.T) {
	root := t.TempDir()
	_, content := writeBackupS3Fixture(t, root, "media-20260101T000000Z.tar.zst", 40)
	source := &fakeScopedSecretSource{material: []byte(testBackupS3Material)}
	controller := newBackupS3Controller(t, source, root)
	withBackupS3PartSize(t, 16)
	stub := withBackupS3Stub(t, nil)
	stub.mu.Lock()
	stub.stored["docker-app/restored.tar.zst"] = append([]byte(nil), content...)
	stub.mu.Unlock()

	handler := &recordingLogHandler{}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(previousLogger)

	var emitted []string
	emit := func(value string) { emitted = append(emitted, value) }

	if raw, err := callBackupS3Action(t, controller, backupS3ActionUpload, map[string]any{
		"object": "media-20260101T000000Z.tar.zst", "path": "media-20260101T000000Z.tar.zst",
	}); err != nil {
		t.Fatal(err)
	} else {
		emit(string(raw))
	}
	if raw, err := callBackupS3Action(t, controller, backupS3ActionDownload, map[string]any{
		"object": "restored.tar.zst", "path": "restored.tar.zst",
	}); err != nil {
		t.Fatal(err)
	} else {
		emit(string(raw))
	}
	if raw, err := callBackupS3Action(t, controller, backupS3ActionList, nil); err != nil {
		emit(err.Error())
	} else {
		emit(string(raw))
	}

	stub.mu.Lock()
	stub.rejectCredentials = true
	stub.mu.Unlock()
	for _, action := range []string{backupS3ActionUpload, backupS3ActionDownload, backupS3ActionDelete, backupS3ActionList} {
		if _, err := callBackupS3Action(t, controller, action, map[string]any{
			"object": "media-20260101T000000Z.tar.zst", "path": "media-20260101T000000Z.tar.zst",
		}); err != nil {
			emit(err.Error())
		} else {
			t.Fatalf("%s unexpectedly succeeded with rejected credentials", action)
		}
	}

	// The persisted destination wire carries only reference strings.
	destinationWire, err := json.Marshal(map[string]any{
		"endpoint": testBackupS3Endpoint, "bucket": testBackupS3Bucket, "prefix": testBackupS3Prefix,
		"credentials_secret": testBackupS3CredentialsReferenceJSON,
	})
	if err != nil {
		t.Fatal(err)
	}
	emit(string(destinationWire))
	emit(handler.output())

	signed := false
	stub.mu.Lock()
	for _, call := range stub.calls {
		if strings.Contains(call.Authorization, "AWS4-HMAC-SHA256") {
			signed = true
		}
	}
	stub.mu.Unlock()
	if !signed {
		t.Fatal("credentials never reached the S3 wire; the leak assertion is vacuous")
	}

	for _, value := range emitted {
		if strings.Contains(value, testBackupS3SecretKey) {
			t.Fatalf("secret material leaked: %s", value)
		}
		if strings.Contains(value, testBackupS3AccessKey) {
			t.Fatalf("access key leaked outside the signed wire: %s", value)
		}
	}
}

func TestClassifyBackupS3Error(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "invalid access key", err: minio.ErrorResponse{Code: "InvalidAccessKeyId", StatusCode: 403}, want: s3StageCredentialRejected},
		{name: "signature mismatch", err: minio.ErrorResponse{Code: "SignatureDoesNotMatch", StatusCode: 403}, want: s3StageCredentialRejected},
		{name: "unauthorized status", err: minio.ErrorResponse{Code: "Whatever", StatusCode: 401}, want: s3StageCredentialRejected},
		{name: "access denied code", err: minio.ErrorResponse{Code: "AccessDenied", StatusCode: 403}, want: s3StageAccessDenied},
		{name: "forbidden status", err: minio.ErrorResponse{Code: "Whatever", StatusCode: 403}, want: s3StageAccessDenied},
		{name: "missing key", err: minio.ErrorResponse{Code: "NoSuchKey", StatusCode: 404}, want: s3StageObjectMissing},
		{name: "not found status", err: minio.ErrorResponse{Code: "Whatever", StatusCode: 404}, want: s3StageObjectMissing},
		{name: "missing bucket", err: minio.ErrorResponse{Code: "NoSuchBucket", StatusCode: 404}, want: s3StageBucketMissing},
		{name: "server error", err: minio.ErrorResponse{Code: "InternalError", StatusCode: 500}, want: s3StageFailed},
		{name: "canceled", err: context.Canceled, want: s3StageTimeout},
		{name: "deadline", err: context.DeadlineExceeded, want: s3StageTimeout},
		{name: "url error", err: &url.Error{Op: "Post", URL: testBackupS3Endpoint, Err: errors.New("dial tcp: connection refused")}, want: s3StageEndpointUnreachable},
		{name: "generic", err: errors.New("boom"), want: s3StageFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyBackupS3Error(test.err); got != test.want {
				t.Fatalf("stage = %q want %q", got, test.want)
			}
		})
	}
	if classifyBackupS3Error(nil) != "" {
		t.Fatal("nil error classified")
	}
}

func TestParseBackupS3Credentials(t *testing.T) {
	if _, _, err := parseBackupS3Credentials([]byte(testBackupS3Material)); err != nil {
		t.Fatalf("valid material rejected: %v", err)
	}
	for name, value := range map[string]string{
		"not json":     "opaque",
		"empty fields": `{"access_key_id":"","secret_access_key":""}`,
		"missing key":  `{"access_key_id":"id"}`,
	} {
		if _, _, err := parseBackupS3Credentials([]byte(value)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
