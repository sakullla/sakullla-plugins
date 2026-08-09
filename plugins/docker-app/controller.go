package dockerapp

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
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
)

const MaxConfigBytes = 1 << 20

type TypedHandleAdmission interface {
	Admit(context.Context, pluginsdk.RPCHandshakeRequest, []App) error
}
type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, []App) error

func (function TypedHandleAdmissionFunc) Admit(ctx context.Context, request pluginsdk.RPCHandshakeRequest, apps []App) error {
	return function(ctx, request, apps)
}

type unavailableAdmission struct{}

func (unavailableAdmission) Admit(context.Context, pluginsdk.RPCHandshakeRequest, []App) error {
	return ErrTypedHandlesUnavailable
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest string
	Admission                     TypedHandleAdmission
}

type Controller struct {
	mu        sync.Mutex
	apps      []App
	request   pluginsdk.RPCHandshakeRequest
	admission TypedHandleAdmission
	lifecycle *rpcplugin.Lifecycle
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Admission == nil {
		config.Admission = unavailableAdmission{}
	}
	controller := &Controller{admission: config.Admission}
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:   []string{"docker-app.business-model"},
		RequiredGrants: []string{"docker-compose", "http-rule"},
		Timeouts:       rpcplugin.Timeouts{Prepare: time.Second, Activate: time.Second, Stop: time.Second, Drain: time.Second},
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

func (controller *Controller) prepare(_ context.Context, generation *rpcplugin.Generation, config []byte) error {
	if len(config) > MaxConfigBytes {
		return fmt.Errorf("%w: config exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.DisallowUnknownFields()
	var document struct {
		Apps *[]App `json:"apps"`
	}
	if err := decoder.Decode(&document); err != nil {
		return err
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
	controller.mu.Lock()
	controller.apps = cloneApps(configuration.Apps)
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) activate(ctx context.Context, _ *rpcplugin.Generation) error {
	controller.mu.Lock()
	request, apps := controller.request, cloneApps(controller.apps)
	controller.mu.Unlock()
	if err := controller.admission.Admit(ctx, request, apps); err != nil {
		controller.mu.Lock()
		controller.apps = nil
		controller.mu.Unlock()
		return err
	}
	return nil
}
func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.apps = nil
	controller.mu.Unlock()
	return nil
}

func cloneApps(apps []App) []App {
	result := append([]App(nil), apps...)
	for index := range result {
		result[index].Secrets = append([]string(nil), result[index].Secrets...)
	}
	return result
}
