package reversel4

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

const (
	PluginID      = "reverse-l4"
	PluginVersion = "0.1.0"
)

type ControllerConfig struct {
	PackageDigest  string
	ArtifactDigest string
	Clock          Clock
	Backoff        Backoff
	Admission      TypedHandleAdmission
}

// Controller binds the canonical RPC lifecycle to plugin-owned mappings and
// session state. It never creates a Host resource contract; Activate remains
// fail closed until the public SDK publishes typed L4 service handles.
type Controller struct {
	*rpcplugin.Adapter
	mu        sync.Mutex
	store     *MappingStore
	sessions  map[string]*Session
	clock     Clock
	backoff   Backoff
	admission TypedHandleAdmission
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Clock == nil {
		return nil, errors.New("host-attested monotonic clock is required")
	}
	if err := config.Backoff.Validate(); err != nil {
		return nil, err
	}
	if config.Admission == nil {
		config.Admission = publicSDKHandleAdmission{}
	}
	controller := &Controller{store: NewMappingStore(), sessions: make(map[string]*Session), clock: config.Clock, backoff: config.Backoff, admission: config.Admission}
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:   []string{"reverse-l4.mapping-owner"},
		RequiredGrants: []string{"reverse-session"},
		Timeouts:       rpcplugin.Timeouts{Prepare: time.Second, Activate: time.Second, Stop: time.Second, Drain: time.Second},
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.Adapter = adapter
	return controller, nil
}

func (controller *Controller) prepare(_ context.Context, generation *rpcplugin.Generation, config []byte) error {
	var document struct {
		Mappings *[]Mapping `json:"mappings"`
	}
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode mapping config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	if document.Mappings == nil {
		return errors.New("mapping config requires mappings")
	}
	if len(*document.Mappings) > MaxMappings {
		return fmt.Errorf("mapping config has %d mappings, maximum is %d", len(*document.Mappings), MaxMappings)
	}
	store := NewMappingStore()
	sessions := make(map[string]*Session)
	seen := make(map[string]struct{}, len(*document.Mappings))
	for _, mapping := range *document.Mappings {
		if _, exists := seen[mapping.ID]; exists {
			return fmt.Errorf("mapping %q is duplicated", mapping.ID)
		}
		seen[mapping.ID] = struct{}{}
		if err := store.Put(mapping); err != nil {
			return err
		}
		if mapping.Enabled {
			session, err := NewSession(mapping, generation.ID(), controller.backoff, controller.clock)
			if err != nil {
				return err
			}
			sessions[mapping.ID] = session
		}
	}
	controller.mu.Lock()
	controller.store, controller.sessions = store, sessions
	controller.mu.Unlock()
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("mapping config must contain one JSON document")
	}
	return nil
}

func (controller *Controller) activate(ctx context.Context, _ *rpcplugin.Generation) error {
	request, _ := controller.Request()
	controller.mu.Lock()
	mappings := controller.store.List()
	controller.mu.Unlock()
	if err := controller.admission.Admit(ctx, request, mappings); err != nil {
		controller.revokeSessions()
		return err
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	for _, session := range controller.sessions {
		if err := session.BeginConnect(); err != nil {
			for _, cleanup := range controller.sessions {
				cleanup.Revoke()
			}
			return err
		}
	}
	return nil
}

func (controller *Controller) revokeSessions() {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	for _, session := range controller.sessions {
		session.Revoke()
	}
}

func (controller *Controller) stop(_ context.Context, _ *rpcplugin.Generation) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	for _, session := range controller.sessions {
		session.BeginDisable()
	}
	return nil
}

func (controller *Controller) Disable(mappingID string) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if _, err := controller.store.Disable(mappingID); err != nil {
		return err
	}
	if session := controller.sessions[mappingID]; session != nil {
		session.BeginDisable()
	}
	return nil
}

func (controller *Controller) Mapping(mappingID string) (Mapping, bool) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.store.Get(mappingID)
}

func (controller *Controller) Session(mappingID string) (SessionSnapshot, bool) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	session, exists := controller.sessions[mappingID]
	if !exists {
		return SessionSnapshot{}, false
	}
	return session.Snapshot(), true
}
