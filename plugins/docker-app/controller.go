package dockerapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
)

const MaxConfigBytes = 1 << 20

type TypedHandleAdmission interface {
	// Admit may acquire resources only by binding them to generation before
	// use. Any host-visible commit must happen through a bound handle's Use.
	Admit(context.Context, *rpcplugin.Generation, pluginsdk.RPCHandshakeRequest, []App) error
}
type TypedHandleAdmissionFunc func(context.Context, *rpcplugin.Generation, pluginsdk.RPCHandshakeRequest, []App) error

func (function TypedHandleAdmissionFunc) Admit(ctx context.Context, generation *rpcplugin.Generation, request pluginsdk.RPCHandshakeRequest, apps []App) error {
	return function(ctx, generation, request, apps)
}

type unavailableAdmission struct{}

func (unavailableAdmission) Admit(context.Context, *rpcplugin.Generation, pluginsdk.RPCHandshakeRequest, []App) error {
	return ErrTypedHandlesUnavailable
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	Admission                                                  TypedHandleAdmission
	PrepareGate                                                func(context.Context) error
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
}

type Controller struct {
	mu          sync.Mutex
	apps        []App
	request     pluginsdk.RPCHandshakeRequest
	admission   TypedHandleAdmission
	prepareGate func(context.Context) error
	lifecycle   *rpcplugin.Lifecycle
	commit      *rpcplugin.Handle[*commitEpoch]
	epoch       *commitEpoch
}

type commitEpoch struct {
	generation string
	live       atomic.Bool
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Admission == nil {
		config.Admission = unavailableAdmission{}
	}
	if config.PrepareTimeout <= 0 {
		config.PrepareTimeout = time.Second
	}
	if config.ActivateTimeout <= 0 {
		config.ActivateTimeout = time.Second
	}
	if config.StopTimeout <= 0 {
		config.StopTimeout = time.Second
	}
	if config.DrainTimeout <= 0 {
		config.DrainTimeout = time.Second
	}
	controller := &Controller{admission: config.Admission, prepareGate: config.PrepareGate}
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:   []string{"docker-app.business-model"},
		RequiredGrants: []string{"docker-compose", "dynamic-ui", "http-rule"},
		Timeouts:       rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout},
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.lifecycle = lifecycle
	return controller, nil
}

func (controller *Controller) Handshake(ctx context.Context, request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCHandshakeResponse, error) {
	response, err := controller.lifecycle.Handshake(ctx, request)
	if err == nil {
		controller.mu.Lock()
		controller.request = request
		controller.mu.Unlock()
	}
	return response, err
}
func (controller *Controller) Prepare(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return controller.lifecycle.Prepare(ctx, request)
}
func (controller *Controller) Activate(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return controller.lifecycle.Activate(ctx, request)
}
func (controller *Controller) Stop(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return controller.lifecycle.Stop(ctx, request)
}
func (controller *Controller) Apps() []App {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return cloneApps(controller.apps)
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, config []byte) error {
	if len(config) > MaxConfigBytes {
		return fmt.Errorf("%w: config exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.DisallowUnknownFields()
	var document struct {
		Apps *[]App `json:"apps"`
	}
	if err := decoder.Decode(&document); err != nil {
		return errors.New("config JSON is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("config must contain one JSON document")
	}
	if document.Apps == nil {
		return errors.New("config requires apps")
	}
	configuration := Configuration{Apps: *document.Apps}
	if err := configuration.Validate(); err != nil {
		return err
	}
	for _, app := range configuration.Apps {
		if app.Generation != generation.ID() {
			return errors.New("app generation does not match lifecycle generation")
		}
	}
	if controller.prepareGate != nil {
		if err := controller.prepareGate(ctx); err != nil {
			return err
		}
	}
	epoch := &commitEpoch{generation: generation.ID()}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, "docker-compose", epoch, func(epoch *commitEpoch) {
		epoch.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == epoch {
			controller.apps = nil
			controller.commit = nil
			controller.epoch = nil
		}
		controller.mu.Unlock()
	})
	if err != nil {
		return err
	}
	return handle.Use(ctx, func(ctx context.Context, epoch *commitEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		controller.mu.Lock()
		defer controller.mu.Unlock()
		if !epoch.live.Load() {
			return rpcplugin.ErrRevoked
		}
		controller.apps, controller.commit, controller.epoch = cloneApps(configuration.Apps), handle, epoch
		return nil
	})
}

func (controller *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	controller.mu.Lock()
	request, apps, handle, epoch := controller.request, cloneApps(controller.apps), controller.commit, controller.epoch
	controller.mu.Unlock()
	if handle == nil || epoch == nil {
		return rpcplugin.ErrRevoked
	}
	return handle.Use(ctx, func(ctx context.Context, value *commitEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value != epoch || !value.live.Load() {
			return rpcplugin.ErrRevoked
		}
		return controller.admission.Admit(ctx, generation, request, apps)
	})
}
func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.apps = nil
	controller.commit = nil
	controller.epoch = nil
	controller.mu.Unlock()
	return nil
}

func cloneApps(apps []App) []App {
	result := append([]App(nil), apps...)
	for index := range result {
		result[index].SecretRefs = append([]string(nil), result[index].SecretRefs...)
	}
	return result
}
