package cloudflaredns

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/*
var mappingUIAssets embed.FS

const (
	mappingActorHeader       = "X-NRE-Actor"
	mappingGroupHeader       = "X-NRE-Resource-Group"
	mappingOperationHeader   = "X-NRE-Operation-Key"
	internalDNSResolvePath   = "/.nre/providers/dns/token"
	internalDNSVersionHeader = "X-NRE-DNS-Provider-Version"
	mappingPageCSP           = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

type MappingView struct {
	Suffix     string `json:"suffix"`
	Configured bool   `json:"configured"`
	UpdatedAt  uint64 `json:"updated_at"`
}

type MappingPageAccess struct {
	CanRead   bool `json:"can_read"`
	CanWrite  bool `json:"can_write"`
	CanRotate bool `json:"can_rotate"`
}

type mappingWriteRequest struct {
	Suffix  string `json:"suffix"`
	Token   string `json:"token"`
	Confirm string `json:"confirm"`
}

type mappingAPIResponse struct {
	Mappings []MappingView     `json:"mappings,omitempty"`
	Mapping  *MappingView      `json:"mapping,omitempty"`
	Access   MappingPageAccess `json:"access,omitempty"`
	Error    string            `json:"error,omitempty"`
	Suffix   string            `json:"suffix,omitempty"`
}

type internalDNSResolveRequest struct {
	Domain string `json:"domain"`
}

type internalDNSResolveResponse struct {
	Token []byte `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

func mappingView(mapping TokenMapping) MappingView {
	return MappingView{Suffix: mapping.Suffix, Configured: mapping.Configured, UpdatedAt: mapping.UpdatedAt}
}

func (service *Service) MappingPageAccess(ctx context.Context, request ActionRequest) (MappingPageAccess, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return MappingPageAccess{}, err
	}
	defer finish()
	action := "mapping-page"
	operation := service.mappingOperationKey(action, request, "", 0)
	if err := service.authorizeBare(ctx, action, "", operation, request); err != nil {
		return MappingPageAccess{}, err
	}
	access := MappingPageAccess{CanRead: true, CanWrite: service.probePermission(ctx, request, PermissionVaultEnroll), CanRotate: service.probePermission(ctx, request, PermissionVaultRotate)}
	if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation, Domain: request.Domain}); err != nil {
		return MappingPageAccess{}, service.fail(ctx, action, operation, request, "ui", ErrUIUnavailable)
	}
	if err := service.success(ctx, action, operation, request); err != nil {
		return MappingPageAccess{}, err
	}
	return access, nil
}

func (service *Service) probePermission(ctx context.Context, request ActionRequest, permission string) bool {
	authorization := ActionContext{Phase: "coarse", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, Permission: permission, SecretRef: service.configuration.SecretRef, OperationKey: request.OperationKey}
	_, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Authorizer.Authorize(callCtx, authorization)
	})
	return err == nil
}

func (service *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Security-Policy", mappingPageCSP)
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	path := request.URL.Path
	if path == internalDNSResolvePath {
		service.serveInternalDNSResolve(writer, request)
		return
	}
	if path == "/style.css" || path == "/app.js" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.ServeFileFS(writer, request, mappingUIAssets, "ui"+path)
		return
	}
	if path == "/" || path == "" {
		service.serveMappingPage(writer, request)
		return
	}
	if path == "/api/mappings" {
		service.serveMappingCollection(writer, request)
		return
	}
	suffix, action, ok := parseMappingAPIPath(path)
	if !ok {
		http.Error(writer, "Cloudflare DNS mapping page was not found", http.StatusNotFound)
		return
	}
	service.serveMappingItem(writer, request, suffix, action)
}

func (service *Service) serveInternalDNSResolve(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set(internalDNSVersionHeader, "1")
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeMappingJSON(writer, http.StatusMethodNotAllowed, internalDNSResolveResponse{Error: "method not allowed"})
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 4096))
	decoder.DisallowUnknownFields()
	var body internalDNSResolveRequest
	if err := decoder.Decode(&body); err != nil {
		writeMappingJSON(writer, http.StatusBadRequest, internalDNSResolveResponse{Error: ErrInvalidInput.Error()})
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeMappingJSON(writer, http.StatusBadRequest, internalDNSResolveResponse{Error: ErrInvalidInput.Error()})
		return
	}
	identity, err := service.mappingActionFromRequest(request, "token-resolve")
	if err != nil {
		writeMappingJSON(writer, http.StatusForbidden, internalDNSResolveResponse{Error: ErrAuthorizationDenied.Error()})
		return
	}
	issued, err := service.ResolveToken(request.Context(), identity, body.Domain, nil)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrMappingNotFound) || errors.Is(err, ErrTokenUnavailable) {
			status = http.StatusNotFound
		}
		writeMappingJSON(writer, status, internalDNSResolveResponse{Error: publicMappingError(err)})
		return
	}
	defer issued.Clear()
	token := issued.Token()
	defer clear(token)
	if len(token) == 0 || len(token) > MaxTokenBytes {
		writeMappingJSON(writer, http.StatusServiceUnavailable, internalDNSResolveResponse{Error: ErrMappedTokenUnavailable.Error()})
		return
	}
	writeMappingJSON(writer, http.StatusOK, internalDNSResolveResponse{Token: token})
}

func serveUnavailableMappingUI(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Security-Policy", mappingPageCSP)
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.Path == "/style.css" || request.URL.Path == "/app.js" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.ServeFileFS(writer, request, mappingUIAssets, "ui"+request.URL.Path)
		return
	}
	if request.URL.Path == "/" || request.URL.Path == "" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.ServeFileFS(writer, request, mappingUIAssets, "ui/index.html")
		return
	}
	writeMappingJSON(writer, http.StatusServiceUnavailable, mappingAPIResponse{Error: ErrTypedHandlesUnavailable.Error()})
}

func parseMappingAPIPath(path string) (suffix, action string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/mappings/")
	if !found || rest == "" {
		return "", "", false
	}
	suffix, action, cut := strings.Cut(rest, "/")
	decoded, err := url.PathUnescape(suffix)
	if err != nil || decoded == "" {
		return "", "", false
	}
	if !cut {
		return decoded, "get", true
	}
	switch action {
	case "rename", "rotate", "delete":
		return decoded, action, true
	default:
		return "", "", false
	}
}

func (service *Service) serveMappingPage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFileFS(writer, request, mappingUIAssets, "ui/index.html")
}

func (service *Service) serveMappingCollection(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		identity, err := service.mappingActionFromRequest(request, "mapping-list")
		if err != nil {
			writeMappingJSON(writer, http.StatusForbidden, mappingAPIResponse{Error: ErrAuthorizationDenied.Error()})
			return
		}
		access, err := service.MappingPageAccess(request.Context(), identity)
		if err != nil {
			writeMappingJSON(writer, mappingStatus(err), mappingAPIResponse{Error: publicMappingError(err)})
			return
		}
		listed, err := service.ListMappings(request.Context(), identity)
		if err != nil {
			writeMappingJSON(writer, mappingStatus(err), mappingAPIResponse{Error: publicMappingError(err)})
			return
		}
		writeMappingJSON(writer, http.StatusOK, mappingAPIResponse{Mappings: mappingViews(listed), Access: access})
	case http.MethodPost:
		service.handleMappingWrite(writer, request, "", "create")
	default:
		writer.Header().Set("Allow", "GET, HEAD, POST")
		writeMappingJSON(writer, http.StatusMethodNotAllowed, mappingAPIResponse{Error: "method not allowed"})
	}
}

func (service *Service) serveMappingItem(writer http.ResponseWriter, request *http.Request, suffix, action string) {
	if action == "get" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeMappingJSON(writer, http.StatusMethodNotAllowed, mappingAPIResponse{Error: "method not allowed"})
			return
		}
		identity, err := service.mappingActionFromRequest(request, "mapping-get")
		if err != nil {
			writeMappingJSON(writer, http.StatusForbidden, mappingAPIResponse{Error: ErrAuthorizationDenied.Error()})
			return
		}
		mapping, err := service.GetMapping(request.Context(), identity, suffix)
		if err != nil {
			writeMappingJSON(writer, mappingStatus(err), mappingAPIResponse{Error: publicMappingError(err), Suffix: suffix})
			return
		}
		view := mappingView(mapping)
		writeMappingJSON(writer, http.StatusOK, mappingAPIResponse{Mapping: &view})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeMappingJSON(writer, http.StatusMethodNotAllowed, mappingAPIResponse{Error: "method not allowed"})
		return
	}
	service.handleMappingWrite(writer, request, suffix, action)
}

func (service *Service) handleMappingWrite(writer http.ResponseWriter, request *http.Request, suffix, action string) {
	body, err := readMappingWrite(request)
	if err != nil {
		writeMappingJSON(writer, http.StatusBadRequest, mappingAPIResponse{Error: publicMappingError(err), Suffix: suffix})
		return
	}
	token := []byte(body.Token)
	body.Token = ""
	defer clear(token)
	if action == "rename" || action == "rotate" || action == "delete" {
		if body.Confirm != suffix {
			writeMappingJSON(writer, http.StatusBadRequest, mappingAPIResponse{Error: "confirmation required", Suffix: suffix})
			return
		}
	}
	identity, err := service.mappingActionFromRequest(request, "mapping-"+action)
	if err != nil {
		writeMappingJSON(writer, http.StatusForbidden, mappingAPIResponse{Error: ErrAuthorizationDenied.Error(), Suffix: suffix})
		return
	}
	var mapping TokenMapping
	switch action {
	case "create":
		mapping, err = service.CreateMapping(request.Context(), identity, body.Suffix, token)
	case "rename":
		mapping, err = service.RenameMapping(request.Context(), identity, suffix, body.Suffix)
	case "rotate":
		mapping, err = service.RotateMappingToken(request.Context(), identity, suffix, token)
	case "delete":
		err = service.DeleteMapping(request.Context(), identity, suffix)
	default:
		err = ErrInvalidInput
	}
	if err != nil {
		writeMappingJSON(writer, mappingStatus(err), mappingAPIResponse{Error: publicMappingError(err), Suffix: suffix})
		return
	}
	if action == "delete" {
		writeMappingJSON(writer, http.StatusOK, mappingAPIResponse{Suffix: suffix})
		return
	}
	view := mappingView(mapping)
	writeMappingJSON(writer, http.StatusOK, mappingAPIResponse{Mapping: &view})
}

func readMappingWrite(request *http.Request) (mappingWriteRequest, error) {
	defer request.Body.Close()
	limited := io.LimitReader(request.Body, MaxTokenBytes+4096)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return mappingWriteRequest{}, ErrInvalidInput
	}
	if len(payload) == 0 {
		return mappingWriteRequest{}, nil
	}
	var body mappingWriteRequest
	if err := json.Unmarshal(payload, &body); err != nil {
		clear(payload)
		return mappingWriteRequest{}, ErrInvalidInput
	}
	clear(payload)
	return body, nil
}

func (service *Service) mappingActionFromRequest(request *http.Request, action string) (ActionRequest, error) {
	actor := strings.TrimSpace(request.Header.Get(mappingActorHeader))
	group := strings.TrimSpace(request.Header.Get(mappingGroupHeader))
	if group == "" {
		group = strings.TrimSpace(service.configuration.ResourceGroupRef)
	}
	key := strings.TrimSpace(request.Header.Get(mappingOperationHeader))
	if key == "" {
		key = newMappingUIOperationKey(action)
	}
	identity := ActionRequest{Actor: actor, ResourceGroupRef: group, OperationKey: key}
	if !refPattern.MatchString(identity.Actor) || !refPattern.MatchString(identity.ResourceGroupRef) || !refPattern.MatchString(identity.OperationKey) {
		return ActionRequest{}, ErrAuthorizationDenied
	}
	return identity, nil
}

func newMappingUIOperationKey(action string) string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		sum := sha256.Sum256([]byte(action + "\x00" + strconv.FormatInt(time.Now().UnixNano(), 10)))
		copy(nonce[:], sum[:])
	}
	sanitized := strings.Map(func(value rune) rune {
		switch {
		case value >= 'a' && value <= 'z', value >= '0' && value <= '9', value == '-':
			return value
		default:
			return -1
		}
	}, strings.ToLower(action))
	if sanitized == "" {
		sanitized = "action"
	}
	return "operation/ui/" + sanitized + "/" + hex.EncodeToString(nonce[:])
}

func mappingViews(mappings []TokenMapping) []MappingView {
	views := make([]MappingView, len(mappings))
	for index, mapping := range mappings {
		views[index] = mappingView(mapping)
	}
	return views
}

func writeMappingJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

func mappingStatus(err error) int {
	switch {
	case errors.Is(err, ErrAuthorizationDenied):
		return http.StatusForbidden
	case errors.Is(err, ErrMappingNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrMappingConflict):
		return http.StatusConflict
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrBoundExceeded):
		return http.StatusBadRequest
	case errors.Is(err, ErrRevoked):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func publicMappingError(err error) string {
	switch {
	case errors.Is(err, ErrAuthorizationDenied):
		return ErrAuthorizationDenied.Error()
	case errors.Is(err, ErrMappingNotFound):
		return ErrMappingNotFound.Error()
	case errors.Is(err, ErrMappingConflict):
		return ErrMappingConflict.Error()
	case errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput.Error()
	case errors.Is(err, ErrBoundExceeded):
		return ErrBoundExceeded.Error()
	case errors.Is(err, ErrRevoked):
		return "Cloudflare DNS mapping page is unavailable"
	default:
		return "Cloudflare mapping request failed"
	}
}
