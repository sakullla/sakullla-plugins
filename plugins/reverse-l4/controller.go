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

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

// MaxConfigBytes is the canonical plugin configuration bound. The plugin is
// zero-config: no field is ever required or accepted.
const MaxConfigBytes = pluginsdk.PluginHostPayloadMaxBytes

// Controller binds the canonical RPC lifecycle to the mapping orchestration
// service. Activation performs no capability gate: host effects are reported
// per operation, never as a permanent fail-closed startup state.
type Controller struct {
	*rpcplugin.Adapter
	mu      sync.Mutex
	service *Service
	state   mappingState
	bind    func() *hostRuntime
}

type ControllerConfig struct {
	PackageDigest  string
	ArtifactDigest string
	State          mappingState
	Runtime        *hostRuntime
	// BindRuntime resolves the production host runtime. When nil the
	// canonical environment client is used; a missing host endpoint leaves the
	// plugin deployable with orchestration reporting an explicit error.
	BindRuntime     func() *hostRuntime
	PrepareTimeout  time.Duration
	ActivateTimeout time.Duration
	StopTimeout     time.Duration
	DrainTimeout    time.Duration
}

func NewController(config ControllerConfig) (*Controller, error) {
	bind := config.BindRuntime
	if bind == nil {
		bind = func() *hostRuntime { return config.Runtime }
	}
	if config.Runtime == nil && config.BindRuntime == nil {
		bind = newProductionHostRuntime
	}
	controller := &Controller{state: config.State, bind: bind}
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		RequiredGrants: requiredGrants(),
		Timeouts: (rpcplugin.Timeouts{
			Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout,
			Stop: config.StopTimeout, Drain: config.DrainTimeout,
		}).WithDefaults(rpcplugin.UniformTimeouts(time.Second)),
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.Adapter = adapter
	return controller, nil
}

// requiredGrants are the generic host capabilities every mapping mutation
// needs: L4 rule orchestration, reverse channel sessions, and the durable
// state holding the mapping catalog.
func requiredGrants() []string {
	return []string{
		pluginsdk.PermissionL4Rule,
		pluginsdk.PermissionChannelReverse,
		"storage.read",
		"storage.write",
	}
}

// Service exposes the active orchestration service, or nil before a
// successful prepare.
func (controller *Controller) Service() *Service {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.service
}

func (controller *Controller) prepare(_ context.Context, _ *rpcplugin.Generation, config []byte) error {
	if len(config) > MaxConfigBytes {
		return fmt.Errorf("%w: config exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	if err := rejectNonEmptyConfig(config); err != nil {
		return err
	}
	runtime := controller.bind()
	state := controller.state
	if state == nil {
		// With a host runtime the catalog is durable host state; without one
		// (build-time probe, host without the endpoint) the plugin still
		// deploys and reports the explicit unavailable error per operation.
		if runtime != nil {
			state = newDurableMappingState(runtime)
		} else {
			state = newMemoryMappingState()
		}
	}
	service, err := NewService(state, runtime)
	if err != nil {
		return err
	}
	controller.mu.Lock()
	controller.service = service
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) activate(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.service == nil {
		return errors.New("mapping service was not prepared")
	}
	return nil
}

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.service = nil
	controller.mu.Unlock()
	return nil
}

// rejectNonEmptyConfig enforces the zero-config contract: the plugin accepts
// an empty, null, or empty-object configuration document and nothing else.
func rejectNonEmptyConfig(config []byte) error {
	trimmed := bytes.TrimSpace(config)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var document map[string]json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("config JSON is invalid: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("config must contain one JSON document")
	}
	if len(document) != 0 {
		return errors.New("plugin is zero-config: no configuration field is accepted")
	}
	return nil
}
