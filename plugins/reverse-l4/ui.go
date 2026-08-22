package reversel4

import (
	"crypto/rand"
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

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed assets/ui/*
var mappingUIAssets embed.FS

const (
	mappingActorHeader     = pluginsdk.HeaderPluginActor
	mappingGroupHeader     = pluginsdk.HeaderPluginResourceGroup
	mappingOperationHeader = pluginsdk.HeaderPluginOperationKey
)

// mappingView is the management-page projection of one mapping: the
// user-facing specification, the enabled state, and the reverse-channel
// connectivity. Host ownership references (rule, session, bridge endpoint)
// stay internal to the plugin.
type mappingView struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	EntryAgentID string `json:"entry_agent_id"`
	ExitAgentID  string `json:"exit_agent_id"`
	Protocol     string `json:"protocol"`
	ListenPort   int    `json:"listen_port"`
	BackendHost  string `json:"backend_host"`
	BackendPort  int    `json:"backend_port"`
	RelayChain   []int  `json:"relay_chain,omitempty"`
	Enabled      bool   `json:"enabled"`
	ChannelState string `json:"channel_state"`
	LastError    string `json:"last_error,omitempty"`
}

type mappingPageAccess struct {
	CanRead  bool `json:"can_read"`
	CanWrite bool `json:"can_write"`
}

// mappingWriteRequest is the request body of every management-page mutation.
type mappingWriteRequest struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	EntryAgentID string `json:"entry_agent_id"`
	ExitAgentID  string `json:"exit_agent_id"`
	Protocol     string `json:"protocol"`
	ListenPort   int    `json:"listen_port"`
	BackendHost  string `json:"backend_host"`
	BackendPort  int    `json:"backend_port"`
	RelayChain   []int  `json:"relay_chain,omitempty"`
	Confirm      string `json:"confirm,omitempty"`
}

type mappingAPIResponse struct {
	Mappings []mappingView     `json:"mappings"`
	Mapping  *mappingView      `json:"mapping,omitempty"`
	Access   mappingPageAccess `json:"access,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// mappingPageIdentity is the actor / resource-group / operation-key identity
// the panel injects into management-page RPC calls.
type mappingPageIdentity struct {
	Actor         string
	ResourceGroup string
	OperationKey  string
}

// ServeHTTP is the plugin-owned management page mounted by the host ui.route
// proxy: canonical assets below assets/ui plus the mapping management API.
func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	if pluginsdk.ServePluginUIAsset(writer, request, mappingUIAssets, "assets/ui") {
		return
	}
	service := controller.Service()
	if service == nil {
		writeMappingJSON(writer, http.StatusServiceUnavailable, mappingAPIResponse{Error: ErrStateUnavailable.Error()})
		return
	}
	if request.URL.Path == "/api/mappings" {
		controller.serveMappingCollection(writer, request, service)
		return
	}
	if id, action, ok := parseMappingAPIPath(request.URL.Path); ok {
		controller.serveMappingItem(writer, request, service, id, action)
		return
	}
	http.Error(writer, "四层反向穿透管理页未找到", http.StatusNotFound)
}

func (controller *Controller) serveMappingCollection(writer http.ResponseWriter, request *http.Request, service *Service) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		if _, err := controller.uiIdentity(request, "mapping-list"); err != nil {
			writeMappingJSON(writer, http.StatusForbidden, mappingAPIResponse{Error: ErrUnauthorized.Error()})
			return
		}
		statuses, err := service.Statuses(request.Context())
		if err != nil {
			writeMappingJSON(writer, mappingHTTPStatus(err), mappingAPIResponse{Error: publicMappingError(err)})
			return
		}
		writeMappingJSON(writer, http.StatusOK, mappingAPIResponse{Mappings: mappingViews(statuses), Access: mappingPageAccess{CanRead: true, CanWrite: true}})
	case http.MethodPost:
		if _, err := controller.uiIdentity(request, "mapping-create"); err != nil {
			writeMappingJSON(writer, http.StatusForbidden, mappingAPIResponse{Error: ErrUnauthorized.Error()})
			return
		}
		body, err := decodeMappingWrite(request)
		if err != nil {
			writeMappingJSON(writer, http.StatusBadRequest, mappingAPIResponse{Error: ErrInvalidMapping.Error()})
			return
		}
		if _, err := service.Create(request.Context(), body.mapping()); err != nil {
			writeMappingJSON(writer, mappingHTTPStatus(err), mappingAPIResponse{Error: publicMappingError(err)})
			return
		}
		controller.writeMappingList(writer, request, service)
	default:
		writer.Header().Set("Allow", "GET, HEAD, POST")
		writeMappingJSON(writer, http.StatusMethodNotAllowed, mappingAPIResponse{Error: "method not allowed"})
	}
}

func (controller *Controller) serveMappingItem(writer http.ResponseWriter, request *http.Request, service *Service, id, action string) {
	if action == "get" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeMappingJSON(writer, http.StatusMethodNotAllowed, mappingAPIResponse{Error: "method not allowed"})
			return
		}
		if _, err := controller.uiIdentity(request, "mapping-get"); err != nil {
			writeMappingJSON(writer, http.StatusForbidden, mappingAPIResponse{Error: ErrUnauthorized.Error()})
			return
		}
		status, err := service.Status(request.Context(), id)
		if err != nil {
			writeMappingJSON(writer, mappingHTTPStatus(err), mappingAPIResponse{Error: publicMappingError(err)})
			return
		}
		view := newMappingView(status)
		writeMappingJSON(writer, http.StatusOK, mappingAPIResponse{Mapping: &view, Access: mappingPageAccess{CanRead: true, CanWrite: true}})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeMappingJSON(writer, http.StatusMethodNotAllowed, mappingAPIResponse{Error: "method not allowed"})
		return
	}
	operation := "mapping-" + action
	if _, err := controller.uiIdentity(request, operation); err != nil {
		writeMappingJSON(writer, http.StatusForbidden, mappingAPIResponse{Error: ErrUnauthorized.Error()})
		return
	}
	body, err := decodeMappingWrite(request)
	if err != nil {
		writeMappingJSON(writer, http.StatusBadRequest, mappingAPIResponse{Error: ErrInvalidMapping.Error()})
		return
	}
	switch action {
	case "update":
		spec := body.mapping()
		spec.ID = id
		_, err = service.Update(request.Context(), spec)
	case "enable":
		_, err = service.SetEnabled(request.Context(), id, true)
	case "disable":
		_, err = service.SetEnabled(request.Context(), id, false)
	case "delete":
		if body.Confirm != id {
			writeMappingJSON(writer, http.StatusBadRequest, mappingAPIResponse{Error: ErrDeleteUnconfirmed.Error()})
			return
		}
		err = service.Delete(request.Context(), id)
	default:
		http.Error(writer, "四层反向穿透管理页未找到", http.StatusNotFound)
		return
	}
	if err != nil {
		writeMappingJSON(writer, mappingHTTPStatus(err), mappingAPIResponse{Error: publicMappingError(err)})
		return
	}
	controller.writeMappingList(writer, request, service)
}

// writeMappingList answers a mutation with the refreshed catalog projection
// so the page renders current enabled and channel states after every action.
func (controller *Controller) writeMappingList(writer http.ResponseWriter, request *http.Request, service *Service) {
	statuses, err := service.Statuses(request.Context())
	if err != nil {
		writeMappingJSON(writer, mappingHTTPStatus(err), mappingAPIResponse{Error: publicMappingError(err)})
		return
	}
	writeMappingJSON(writer, http.StatusOK, mappingAPIResponse{Mappings: mappingViews(statuses), Access: mappingPageAccess{CanRead: true, CanWrite: true}})
}

// uiIdentity validates the actor / resource-group / operation-key header
// identity the panel injects into management-page RPC calls. The operation key
// is minted locally when the caller did not supply one.
func (controller *Controller) uiIdentity(request *http.Request, action string) (mappingPageIdentity, error) {
	actor, ok := pluginsdk.PluginUIActor(request)
	if !ok {
		return mappingPageIdentity{}, ErrUnauthorized
	}
	group := strings.TrimSpace(request.Header.Get(mappingGroupHeader))
	if group == "" {
		group = DeclaredResourceGroupRef
	}
	key := strings.TrimSpace(request.Header.Get(mappingOperationHeader))
	if key == "" {
		key = newUIOperationKey(action)
	}
	identity := mappingPageIdentity{Actor: actor, ResourceGroup: group, OperationKey: key}
	if err := validAgentID(identity.Actor); err != nil {
		return mappingPageIdentity{}, ErrUnauthorized
	}
	if err := validAgentID(identity.ResourceGroup); err != nil {
		return mappingPageIdentity{}, ErrUnauthorized
	}
	if len(identity.OperationKey) > 512 || strings.ContainsAny(identity.OperationKey, "\r\n\x00\t ") {
		return mappingPageIdentity{}, ErrUnauthorized
	}
	return identity, nil
}

func (body mappingWriteRequest) mapping() Mapping {
	return Mapping{
		ID:           strings.TrimSpace(body.ID),
		Name:         strings.TrimSpace(body.Name),
		EntryAgentID: strings.TrimSpace(body.EntryAgentID),
		ExitAgentID:  strings.TrimSpace(body.ExitAgentID),
		Protocol:     strings.ToLower(strings.TrimSpace(body.Protocol)),
		ListenPort:   body.ListenPort,
		BackendHost:  strings.TrimSpace(body.BackendHost),
		BackendPort:  body.BackendPort,
		RelayChain:   body.RelayChain,
	}
}

func newMappingView(status MappingStatus) mappingView {
	return mappingView{
		ID:           status.ID,
		Name:         status.Name,
		EntryAgentID: status.EntryAgentID,
		ExitAgentID:  status.ExitAgentID,
		Protocol:     status.Protocol,
		ListenPort:   status.ListenPort,
		BackendHost:  status.BackendHost,
		BackendPort:  status.BackendPort,
		RelayChain:   append([]int(nil), status.RelayChain...),
		Enabled:      status.Enabled,
		ChannelState: status.ChannelState,
		LastError:    status.LastError,
	}
}

func mappingViews(statuses []MappingStatus) []mappingView {
	views := make([]mappingView, 0, len(statuses))
	for _, status := range statuses {
		views = append(views, newMappingView(status))
	}
	return views
}

func parseMappingAPIPath(path string) (id, action string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/mappings/")
	if !found || rest == "" {
		return "", "", false
	}
	id, action, cut := strings.Cut(rest, "/")
	decoded, err := url.PathUnescape(id)
	if err != nil || decoded == "" {
		return "", "", false
	}
	if !cut {
		return decoded, "get", true
	}
	switch action {
	case "update", "enable", "disable", "delete":
		return decoded, action, true
	default:
		return "", "", false
	}
}

func decodeMappingWrite(request *http.Request) (mappingWriteRequest, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, MaxConfigBytes))
	decoder.DisallowUnknownFields()
	var body mappingWriteRequest
	if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		return mappingWriteRequest{}, err
	}
	return body, nil
}

func writeMappingJSON(writer http.ResponseWriter, status int, payload mappingAPIResponse) {
	if payload.Mappings == nil {
		payload.Mappings = []mappingView{}
	}
	_ = pluginsdk.WritePluginUIJSON(writer, status, payload)
}

// newUIOperationKey mints one operation key for a management-page action when
// the caller supplied none, keeping the header contract total.
func newUIOperationKey(action string) string {
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
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "operation/ui/" + sanitized + "/" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return "operation/ui/" + sanitized + "/" + hex.EncodeToString(nonce[:])
}

func mappingHTTPStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return http.StatusForbidden
	case errors.Is(err, ErrInvalidMapping), errors.Is(err, ErrBoundExceeded), errors.Is(err, ErrDeleteUnconfirmed):
		return http.StatusBadRequest
	case errors.Is(err, ErrMappingNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrMappingExists):
		return http.StatusConflict
	case errors.Is(err, ErrStateUnavailable), errors.Is(err, ErrHostRuntimeUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func publicMappingError(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrInvalidMapping),
		errors.Is(err, ErrMappingExists),
		errors.Is(err, ErrMappingNotFound),
		errors.Is(err, ErrBoundExceeded),
		errors.Is(err, ErrDeleteUnconfirmed),
		errors.Is(err, ErrStateUnavailable),
		errors.Is(err, ErrHostRuntimeUnavailable),
		errors.Is(err, ErrHostRejectedRequest):
		return err.Error()
	default:
		return ErrOperationFailed.Error()
	}
}
