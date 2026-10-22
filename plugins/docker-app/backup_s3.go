package dockerapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// Agent execution-face S3 backup destination I/O. The control plane persists
// only a ScopedSecretReference string (backup.s3.credentials_secret); the
// execution face resolves it through the scoped-secret Host transport and
// materializes credentials only inside ManagedSecretMaterial.WithBytes. The
// transient copy is wiped when the callback returns, and no path forwards
// endpoint free text, so credentials never reach config, state, logs, or call
// responses - not even failure messages.

const pluginCallBackupS3Name = "backup-s3"

// backupSecretScope mirrors plugin.yaml's secret-scope:docker-app-backup grant.
const backupSecretScope = "docker-app-backup"

const (
	backupS3ActionUpload   = "upload"
	backupS3ActionDownload = "download"
	backupS3ActionDelete   = "delete"
	backupS3ActionList     = "list"
)

// Failure stages. They are plugin-owned closed strings: server message bodies
// are never forwarded because a faulty endpoint could echo submitted
// credentials in them.
const (
	s3StageUnconfigured        = "destination is not configured"
	s3StageMissingCredential   = "credentials secret is missing"
	s3StageInvalidCredential   = "credentials secret is invalid"
	s3StageCredentialUnread    = "credentials secret could not be read"
	s3StageCredentialRejected  = "credentials were rejected"
	s3StageInvalidEndpoint     = "destination endpoint is invalid"
	s3StageInvalidConfig       = "destination configuration is invalid"
	s3StageAccessDenied        = "access was denied"
	s3StageEndpointUnreachable = "endpoint is unreachable"
	s3StagePartFailed          = "multipart upload failed partway"
	s3StageObjectMissing       = "object was not found"
	s3StageBucketMissing       = "destination bucket was not found"
	s3StageChecksum            = "object checksum mismatch"
	s3StageLocalFile           = "workspace file is unavailable"
	s3StageUnavailable         = "scoped secret transport is unavailable"
	s3StageTimeout             = "operation timed out"
	s3StageFailed              = "operation failed"
)

var (
	// ErrBackupS3Unconfigured lets callers gate dispatch on a missing S3
	// destination (empty endpoint or bucket).
	ErrBackupS3Unconfigured = errors.New(s3StageUnconfigured)
	// ErrBackupS3CredentialsMissing lets callers gate dispatch on a missing
	// credentials reference.
	ErrBackupS3CredentialsMissing = errors.New(s3StageMissingCredential)
)

const (
	backupS3TransferTimeout = 15 * time.Minute
	backupS3ControlTimeout  = 30 * time.Second
	backupS3AbortTimeout    = 10 * time.Second
	backupS3MaxListEntries  = 1024
)

var (
	// backupS3PartSize bounds one multipart chunk. Tests shrink it to force
	// the multipart path with small fixtures.
	backupS3PartSize int64 = 64 << 20
	// backupS3HTTPTransport is injectable for tests, following the
	// imageTagHTTPClient precedent; nil keeps the minio default transport.
	backupS3HTTPTransport http.RoundTripper
)

var (
	backupS3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	backupS3PrefixPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,512}$`)
)

// ScopedSecretSource delivers scoped secret material through the
// authenticated Host transport (secret.scoped).
type ScopedSecretSource interface {
	ScopedSecret(context.Context, pluginsdk.ScopedSecretRequest) (pluginsdk.ScopedSecretResponse, error)
}

type backupS3CallRequest struct {
	Action            string `json:"action"`
	AgentID           string `json:"agent_id"`
	AppID             string `json:"app_id"`
	WorkDir           string `json:"workdir"`
	Endpoint          string `json:"endpoint"`
	Bucket            string `json:"bucket"`
	Prefix            string `json:"prefix"`
	CredentialsSecret string `json:"credentials_secret"`
	Object            string `json:"object"`
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
}

type backupS3ObjectEntry struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	LastModified string `json:"last_modified,omitempty"`
}

type backupS3Destination struct {
	host      string
	bucket    string
	prefix    string
	reference pluginsdk.ScopedSecretReference
}

// callBackupS3 is the Agent execution-face entry for S3 destination I/O. The
// request carries the destination parameters (only reference strings, never
// material) and one operation; local file paths are workspace-relative.
func (controller *Controller) callBackupS3(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var request backupS3CallRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, errors.New("backup-s3 payload is invalid")
	}
	if !validID(request.AppID) {
		return nil, errors.New("backup-s3 app id is invalid")
	}
	action := strings.TrimSpace(request.Action)
	switch action {
	case backupS3ActionUpload, backupS3ActionDownload, backupS3ActionDelete, backupS3ActionList:
	default:
		return nil, fmt.Errorf("backup-s3 action %q is unknown", action)
	}
	destination, stage := parseBackupS3Destination(request.Endpoint, request.Bucket, request.Prefix, request.CredentialsSecret)
	if stage != "" {
		switch stage {
		case s3StageUnconfigured:
			return nil, fmt.Errorf("backup-s3 %s failed: %w", action, ErrBackupS3Unconfigured)
		case s3StageMissingCredential:
			return nil, fmt.Errorf("backup-s3 %s failed: %w", action, ErrBackupS3CredentialsMissing)
		default:
			return nil, backupS3Failure(action, stage)
		}
	}
	switch action {
	case backupS3ActionUpload:
		return controller.backupS3Upload(ctx, destination, request)
	case backupS3ActionDownload:
		return controller.backupS3Download(ctx, destination, request)
	case backupS3ActionDelete:
		return controller.backupS3Delete(ctx, destination, request)
	default:
		return controller.backupS3List(ctx, destination, request)
	}
}

// parseBackupS3Destination validates the destination wire fields. An empty
// endpoint or bucket is the explicit "not configured" gate; an empty
// credentials reference is the explicit "credentials missing" gate.
func parseBackupS3Destination(endpoint, bucket, prefix, credentials string) (backupS3Destination, string) {
	endpoint = strings.TrimSpace(endpoint)
	bucket = strings.TrimSpace(bucket)
	if endpoint == "" || bucket == "" {
		return backupS3Destination{}, s3StageUnconfigured
	}
	if strings.TrimSpace(credentials) == "" {
		return backupS3Destination{}, s3StageMissingCredential
	}
	host, ok := backupS3EndpointHost(endpoint)
	if !ok {
		return backupS3Destination{}, s3StageInvalidEndpoint
	}
	prefix = strings.TrimSpace(prefix)
	if !backupS3BucketPattern.MatchString(bucket) || (prefix != "" && !backupS3PrefixPattern.MatchString(prefix)) {
		return backupS3Destination{}, s3StageInvalidConfig
	}
	reference, ok := decodeBackupS3Reference(credentials)
	if !ok {
		return backupS3Destination{}, s3StageInvalidCredential
	}
	return backupS3Destination{host: host, bucket: bucket, prefix: prefix, reference: reference}, ""
}

// backupS3EndpointHost accepts https endpoints without user, query, fragment,
// or base path; the returned host is the minio endpoint (host[:port]).
func backupS3EndpointHost(endpoint string) (string, bool) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", false
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", false
	}
	if path := strings.TrimSuffix(parsed.Path, "/"); path != "" {
		return "", false
	}
	return parsed.Host, true
}

// decodeBackupS3Reference accepts a JSON-encoded ScopedSecretReference bound
// to this plugin's backup scope.
func decodeBackupS3Reference(credentials string) (pluginsdk.ScopedSecretReference, bool) {
	var reference pluginsdk.ScopedSecretReference
	if json.Unmarshal([]byte(credentials), &reference) != nil {
		return pluginsdk.ScopedSecretReference{}, false
	}
	if reference.Validate() != nil || reference.Scope != backupSecretScope {
		return pluginsdk.ScopedSecretReference{}, false
	}
	return reference, true
}

func (controller *Controller) backupS3Upload(ctx context.Context, destination backupS3Destination, request backupS3CallRequest) ([]byte, error) {
	key, ok := backupS3ObjectKey(destination.prefix, request.Object)
	if !ok {
		return nil, backupS3Failure(backupS3ActionUpload, s3StageInvalidConfig)
	}
	_, resolved, err := resolveWorkspaceFilePath(controller.callWorkDirRoot(request.WorkDir), request.AppID, request.Path)
	if err != nil {
		return nil, backupS3Failure(backupS3ActionUpload, s3StageLocalFile)
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, backupS3Failure(backupS3ActionUpload, s3StageLocalFile)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, backupS3Failure(backupS3ActionUpload, s3StageLocalFile)
	}
	defer file.Close()
	stage := controller.withBackupS3Client(ctx, destination, backupS3TransferTimeout, func(client *minio.Client) string {
		return backupS3PutObject(ctx, minio.Core{Client: client}, file, info.Size(), destination.bucket, key)
	})
	if stage != "" {
		return nil, backupS3Failure(backupS3ActionUpload, stage)
	}
	digest, size, err := hashFileContents(resolved)
	if err != nil {
		return nil, backupS3Failure(backupS3ActionUpload, s3StageFailed)
	}
	return json.Marshal(map[string]any{"accepted": true, "object": key, "size": size, "sha256": digest})
}

// backupS3PutObject stores one artifact. Files above the part size upload as
// an explicit multipart upload; any part failure aborts the whole upload so no
// completed object record remains at the destination.
func backupS3PutObject(ctx context.Context, core minio.Core, file *os.File, size int64, bucket, key string) string {
	if size < backupS3PartSize {
		if _, err := core.PutObject(ctx, bucket, key, file, size, "", "", minio.PutObjectOptions{}); err != nil {
			return classifyBackupS3Error(err)
		}
		return ""
	}
	uploadID, err := core.NewMultipartUpload(ctx, bucket, key, minio.PutObjectOptions{})
	if err != nil {
		return classifyBackupS3Error(err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), backupS3AbortTimeout)
		defer cancel()
		_ = core.AbortMultipartUpload(abortCtx, bucket, key, uploadID)
	}()
	parts := make([]minio.CompletePart, 0, (size+backupS3PartSize-1)/backupS3PartSize)
	for offset := int64(0); offset < size; offset += backupS3PartSize {
		chunkSize := min(backupS3PartSize, size-offset)
		part, err := core.PutObjectPart(ctx, bucket, key, uploadID, len(parts)+1, io.NewSectionReader(file, offset, chunkSize), chunkSize, minio.PutObjectPartOptions{})
		if err != nil {
			return s3StagePartFailed
		}
		parts = append(parts, minio.CompletePart{PartNumber: len(parts) + 1, ETag: part.ETag})
	}
	if _, err := core.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts, minio.PutObjectOptions{}); err != nil {
		return classifyBackupS3Error(err)
	}
	committed = true
	return ""
}

func (controller *Controller) backupS3Download(ctx context.Context, destination backupS3Destination, request backupS3CallRequest) ([]byte, error) {
	key, ok := backupS3ObjectKey(destination.prefix, request.Object)
	if !ok {
		return nil, backupS3Failure(backupS3ActionDownload, s3StageInvalidConfig)
	}
	expected := strings.TrimSpace(request.SHA256)
	if expected != "" && !sha256Hex(expected) {
		return nil, backupS3Failure(backupS3ActionDownload, s3StageChecksum)
	}
	workdir, resolved, err := resolveWorkspaceFilePath(controller.callWorkDirRoot(request.WorkDir), request.AppID, request.Path)
	if err != nil {
		return nil, backupS3Failure(backupS3ActionDownload, s3StageLocalFile)
	}
	var digest string
	var size int64
	stage := controller.withBackupS3Client(ctx, destination, backupS3TransferTimeout, func(client *minio.Client) string {
		return backupS3FetchObject(ctx, minio.Core{Client: client}, destination.bucket, key, resolved, expected, &digest, &size)
	})
	if stage != "" {
		return nil, backupS3Failure(backupS3ActionDownload, stage)
	}
	display, err := workspaceDisplayPath(workdir, resolved)
	if err != nil {
		return nil, backupS3Failure(backupS3ActionDownload, s3StageLocalFile)
	}
	return json.Marshal(map[string]any{"accepted": true, "path": display, "size": size, "sha256": digest})
}

// backupS3FetchObject streams one object into a staging file next to the
// destination, verifies the optional digest, and only then renames it into
// place so a failed download leaves no partial file behind.
func backupS3FetchObject(ctx context.Context, core minio.Core, bucket, key, resolved, expected string, digest *string, size *int64) string {
	reader, _, _, err := core.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return classifyBackupS3Error(err)
	}
	defer reader.Close()
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return s3StageLocalFile
	}
	temporary, err := os.CreateTemp(filepath.Dir(resolved), ".s3-download-*")
	if err != nil {
		return s3StageLocalFile
	}
	tempName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tempName)
		}
	}()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hasher), reader)
	closeErr := temporary.Close()
	if err != nil {
		return classifyBackupS3Error(err)
	}
	if closeErr != nil {
		return s3StageLocalFile
	}
	*digest = hex.EncodeToString(hasher.Sum(nil))
	*size = written
	if expected != "" && *digest != expected {
		return s3StageChecksum
	}
	if err := os.Rename(tempName, resolved); err != nil {
		return s3StageLocalFile
	}
	committed = true
	return ""
}

func (controller *Controller) backupS3Delete(ctx context.Context, destination backupS3Destination, request backupS3CallRequest) ([]byte, error) {
	key, ok := backupS3ObjectKey(destination.prefix, request.Object)
	if !ok {
		return nil, backupS3Failure(backupS3ActionDelete, s3StageInvalidConfig)
	}
	stage := controller.withBackupS3Client(ctx, destination, backupS3ControlTimeout, func(client *minio.Client) string {
		if err := client.RemoveObject(ctx, destination.bucket, key, minio.RemoveObjectOptions{}); err != nil {
			return classifyBackupS3Error(err)
		}
		return ""
	})
	if stage != "" {
		return nil, backupS3Failure(backupS3ActionDelete, stage)
	}
	return json.Marshal(map[string]any{"accepted": true, "object": key})
}

func (controller *Controller) backupS3List(ctx context.Context, destination backupS3Destination, request backupS3CallRequest) ([]byte, error) {
	prefix := destination.prefix
	if prefix != "" {
		prefix += "/"
	}
	entries := []backupS3ObjectEntry{}
	stage := controller.withBackupS3Client(ctx, destination, backupS3ControlTimeout, func(client *minio.Client) string {
		for object := range client.ListObjects(ctx, destination.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
			if object.Err != nil {
				return classifyBackupS3Error(object.Err)
			}
			entries = append(entries, backupS3ObjectEntry{
				Key: object.Key, Size: object.Size,
				LastModified: object.LastModified.UTC().Format(time.RFC3339),
			})
			if len(entries) >= backupS3MaxListEntries {
				break
			}
		}
		return ""
	})
	if stage != "" {
		return nil, backupS3Failure(backupS3ActionList, stage)
	}
	return json.Marshal(map[string]any{"objects": entries})
}

// withBackupS3Client resolves the destination credentials through the scoped
// secret transport and runs the operation with a transiently materialized
// client. Credentials exist only inside the WithBytes callback: the transient
// copy is wiped when it returns and nothing derived from it is retained,
// logged, or returned.
func (controller *Controller) withBackupS3Client(ctx context.Context, destination backupS3Destination, timeout time.Duration, run func(*minio.Client) string) string {
	if controller == nil || controller.backupSecrets == nil {
		return s3StageUnavailable
	}
	request, err := backupS3SecretRequest(destination.reference, controller.backupS3Generation())
	if err != nil {
		return s3StageCredentialUnread
	}
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := controller.backupSecrets.ScopedSecret(opCtx, request)
	if err != nil || response.Material == nil {
		return s3StageCredentialUnread
	}
	defer response.Material.Close()
	var stage string
	if err := response.Material.WithBytes(func(value []byte) error {
		accessKey, secretKey, credentialErr := parseBackupS3Credentials(value)
		if credentialErr != nil {
			stage = s3StageInvalidCredential
			return nil
		}
		client, clientErr := minio.New(destination.host, &minio.Options{
			Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: true, Transport: backupS3HTTPTransport,
			// S3-compatible endpoints differ in virtual-host wildcard support;
			// path-style addressing works uniformly across them.
			BucketLookup: minio.BucketLookupPath,
		})
		if clientErr != nil {
			stage = s3StageInvalidEndpoint
			return nil
		}
		stage = run(client)
		return nil
	}); err != nil {
		return s3StageInvalidCredential
	}
	return stage
}

// backupS3SecretRequest binds the read to the live lifecycle generation; the
// Host compares this claim against the authenticated caller.
func backupS3SecretRequest(reference pluginsdk.ScopedSecretReference, generation string) (pluginsdk.ScopedSecretRequest, error) {
	binding := pluginsdk.ManagedBinding{InstanceID: reference.InstanceID, Generation: generation, EntryID: reference.InstanceID}
	if binding.Validate() != nil {
		return pluginsdk.ScopedSecretRequest{}, errors.New("scoped secret binding is invalid")
	}
	return pluginsdk.ScopedSecretRequest{Action: pluginsdk.ScopedSecretRead, Binding: binding, Reference: reference}, nil
}

func (controller *Controller) backupS3Generation() string {
	if controller == nil {
		return ""
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.epoch == nil {
		return ""
	}
	return controller.epoch.generation
}

// parseBackupS3Credentials reads the scoped secret material as a JSON object
// with one access key and one secret key.
func parseBackupS3Credentials(value []byte) (string, string, error) {
	if len(value) == 0 || len(value) > pluginsdk.ManagedSecretMaxBytes {
		return "", "", errors.New("scoped secret material size is invalid")
	}
	var document struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if json.Unmarshal(value, &document) != nil {
		return "", "", errors.New("scoped secret material is not valid JSON")
	}
	accessKey := strings.TrimSpace(document.AccessKeyID)
	secretKey := strings.TrimSpace(document.SecretAccessKey)
	if !boundedText(accessKey, 128) || !boundedText(secretKey, 256) {
		return "", "", errors.New("scoped secret material fields are invalid")
	}
	return accessKey, secretKey, nil
}

// backupS3ObjectKey joins the configured prefix with one validated object
// name from the caller.
func backupS3ObjectKey(prefix, object string) (string, bool) {
	rel, ok := safeBackupEntryName(strings.TrimSpace(object))
	if !ok || rel == "" || rel == "." {
		return "", false
	}
	if prefix == "" {
		return rel, true
	}
	return prefix + "/" + rel, true
}

// classifyBackupS3Error maps transport and endpoint failures onto the closed
// stage set. Server-controlled text never reaches the returned stage.
func classifyBackupS3Error(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return s3StageTimeout
	}
	var response minio.ErrorResponse
	if errors.As(err, &response) {
		switch response.Code {
		case "InvalidAccessKeyId", "InvalidClientTokenId", "InvalidToken", "ExpiredToken", "SignatureDoesNotMatch":
			return s3StageCredentialRejected
		case "AccessDenied", "AllAccessDisabled":
			return s3StageAccessDenied
		case "NoSuchKey", "NotFound":
			return s3StageObjectMissing
		case "NoSuchBucket", "NoSuchUpload":
			return s3StageBucketMissing
		}
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return s3StageCredentialRejected
		case http.StatusForbidden:
			return s3StageAccessDenied
		case http.StatusNotFound:
			return s3StageObjectMissing
		}
		return s3StageFailed
	}
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &urlErr) || errors.As(err, &netErr) {
		return s3StageEndpointUnreachable
	}
	return s3StageFailed
}

func backupS3Failure(action, stage string) error {
	return fmt.Errorf("backup-s3 %s failed: %s", action, stage)
}
