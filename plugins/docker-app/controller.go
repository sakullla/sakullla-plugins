package dockerapp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

const MaxConfigBytes = 1 << 20

type TypedHandleAdmission interface {
	// Prepare validates/acquires a transaction without any host-visible effect.
	Prepare(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error)
}
type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error)

func (function TypedHandleAdmissionFunc) Prepare(ctx context.Context, request pluginsdk.RPCHandshakeRequest, apps []App) (PreparedAdmission, error) {
	return function(ctx, request, apps)
}

// PreparedAdmission is controller-owned after Prepare returns. Commit may
// perform effects. Abort must be idempotent and non-blocking; generation revoke
// invokes it synchronously as the final compensation boundary.
type PreparedAdmission interface {
	Commit(context.Context) error
	Abort()
}

type PreparedAdmissionFuncs struct {
	CommitFunc func(context.Context) error
	AbortFunc  func()
}

func (prepared PreparedAdmissionFuncs) Commit(ctx context.Context) error {
	if prepared.CommitFunc == nil {
		return nil
	}
	return prepared.CommitFunc(ctx)
}
func (prepared PreparedAdmissionFuncs) Abort() {
	if prepared.AbortFunc != nil {
		prepared.AbortFunc()
	}
}

type unavailableAdmission struct{}

func (unavailableAdmission) Prepare(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
	return nil, ErrTypedHandlesUnavailable
}

type AppStateStore interface {
	LoadApps(context.Context) ([]App, bool, error)
	StoreApps(context.Context, []App) error
	LoadRuntime(context.Context) (map[string]bool, bool, error)
	StoreRuntime(context.Context, map[string]bool) error
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	Admission                                                  TypedHandleAdmission
	PrepareGate                                                func(context.Context) error
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
	UIEngineSource                                             AgentEngineSource
	UIApply                                                    AppApplyExecutor
	UIStart                                                    StartExecutor
	UIStop                                                     StopExecutor
	UIRestart                                                  RestartExecutor
	UILogs                                                     ServiceLogReader
	UIFiles                                                    AppFilesHandle
	UIRemove                                                   AppRemoveExecutor
	UIDiskCleanup                                              DiskCleanupHandle
	UIHTTPRule                                                 HTTPRuleCreateHandle
	UIHTTPRuleList                                             HTTPRuleListHandle
	UIHTTPRuleDelete                                           HTTPRuleDeleteHandle
	UIHTTPBackendOffer                                         HTTPBackendOfferReplaceHandle
	UIAuditor                                                  Auditor
	UIWorkDirRoot                                              string
	UIRolloutExecutor                                          RolloutExecutor
	UIImageObserver                                            ImageUpdateObserver
	CommandRunner                                              CommandRunner
	CallImages                                                 ImageUpdateObserver
	UIAppState                                                 AppStateStore
	UIDeploymentState                                          DeploymentStateStore
}

type Controller struct {
	*rpcplugin.Adapter
	mu                 sync.Mutex
	apps               []App
	registryMirror     string
	resourceGroupRef   string
	admission          TypedHandleAdmission
	prepareGate        func(context.Context) error
	commit             *rpcplugin.Handle[*commitEpoch]
	epoch              *commitEpoch
	uiEngineSource     AgentEngineSource
	uiApply            AppApplyExecutor
	uiStart            StartExecutor
	uiStop             StopExecutor
	uiRestart          RestartExecutor
	uiLogs             ServiceLogReader
	uiFiles            AppFilesHandle
	uiRemove           AppRemoveExecutor
	uiDiskCleanup      DiskCleanupHandle
	uiHTTPRule         HTTPRuleCreateHandle
	uiHTTPRuleList     HTTPRuleListHandle
	uiHTTPRuleDelete   HTTPRuleDeleteHandle
	uiHTTPBackendOffer HTTPBackendOfferReplaceHandle
	uiAuditor          Auditor
	uiWorkDirRoot      string
	uiRollout          Rollout
	uiImageObserver    ImageUpdateObserver
	commandRunner      CommandRunner
	callImages         ImageUpdateObserver
	uiAppState         AppStateStore
	appRuntime         map[string]bool
	imageCache         map[string]cachedImageObservation
	imageRefresh       map[string]bool
	imageObserveToken  map[string]uint64
	imageSlots         chan struct{}
}

type cachedImageObservation struct {
	Image        string
	LatestDigest string
	ObservedAt   time.Time
}

type commitEpoch struct {
	generation string
	live       atomic.Bool
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Admission == nil {
		config.Admission = unavailableAdmission{}
	}
	timeouts := (rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}).WithDefaults(rpcplugin.UniformTimeouts(time.Second))
	auditor := config.UIAuditor
	if auditor == nil {
		auditor = AuditorFunc(func(AuditRecord) {})
	}
	deployments := config.UIDeploymentState
	if deployments == nil {
		deployments = NewDeploymentStore()
	}
	httpRuleList := config.UIHTTPRuleList
	if httpRuleList == nil {
		if lister, ok := config.UIHTTPRule.(HTTPRuleListHandle); ok {
			httpRuleList = lister
		}
	}
	httpRuleDelete := config.UIHTTPRuleDelete
	if httpRuleDelete == nil {
		if deleter, ok := config.UIHTTPRule.(HTTPRuleDeleteHandle); ok {
			httpRuleDelete = deleter
		}
	}
	controller := &Controller{
		admission: config.Admission, prepareGate: config.PrepareGate,
		uiEngineSource: config.UIEngineSource, uiApply: config.UIApply, uiStart: config.UIStart, uiStop: config.UIStop,
		uiRestart: config.UIRestart, uiLogs: config.UILogs, uiFiles: config.UIFiles, uiRemove: config.UIRemove, uiDiskCleanup: config.UIDiskCleanup, uiHTTPRule: config.UIHTTPRule,
		uiHTTPRuleList: httpRuleList, uiHTTPRuleDelete: httpRuleDelete, uiHTTPBackendOffer: config.UIHTTPBackendOffer,
		uiAuditor: auditor, uiWorkDirRoot: config.UIWorkDirRoot, uiImageObserver: config.UIImageObserver,
		commandRunner: config.CommandRunner, callImages: config.CallImages, uiAppState: config.UIAppState,
		appRuntime: map[string]bool{},
		imageCache: map[string]cachedImageObservation{}, imageRefresh: map[string]bool{}, imageObserveToken: map[string]uint64{},
		imageSlots: make(chan struct{}, 2),
		uiRollout:  Rollout{Store: deployments, Executor: config.UIRolloutExecutor, Auditor: auditor},
	}
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:      requiredGrants(),
		RequiredGrants:    requiredGrants(),
		SupportedFeatures: []string{pluginsdk.RPCFeatureDurableActionsV1},
		Timeouts:          timeouts,
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.Adapter = adapter
	return controller, nil
}
func (controller *Controller) Apps() []App {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return cloneApps(controller.apps)
}

func (controller *Controller) RegistryMirror() string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.registryMirror
}

func (controller *Controller) ResourceGroupRef() string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.resourceGroupRef
}

func (controller *Controller) observeAgent(ctx context.Context, agentID string) (AgentEngineReport, error) {
	if !validAgentID(agentID) {
		return AgentEngineReport{}, errors.New("agent id is invalid")
	}
	if controller.uiEngineSource == nil {
		return AgentEngineReport{AgentID: agentID}, nil
	}
	report, err := controller.uiEngineSource.Report(ctx, agentID)
	if err != nil {
		return AgentEngineReport{}, err
	}
	report.AgentID = agentID
	return normalizeAgentEngineReport(report), nil
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, config []byte) error {
	configuration, err := ParseConfiguration(config)
	if err != nil {
		return err
	}
	var restoredRuntime map[string]bool
	if controller.uiAppState != nil {
		persisted, found, loadErr := controller.uiAppState.LoadApps(ctx)
		if loadErr != nil {
			return loadErr
		}
		if found {
			for index := range persisted {
				persisted[index].Generation = generation.ID()
				if err := persisted[index].bindCompose(); err != nil {
					return err
				}
			}
			configuration.Apps = persisted
			if err := configuration.Validate(); err != nil {
				return err
			}
		}
		persistedRuntime, runtimeFound, runtimeErr := controller.uiAppState.LoadRuntime(ctx)
		if runtimeErr != nil {
			return runtimeErr
		}
		if runtimeFound {
			restoredRuntime = cloneAppRuntime(persistedRuntime)
		}
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
	handle, err := rpcplugin.BindHandle(generation, generationHandleScope, epoch, func(epoch *commitEpoch) {
		epoch.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == epoch {
			controller.apps = nil
			controller.registryMirror = ""
			controller.resourceGroupRef = ""
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
		controller.apps = cloneApps(configuration.Apps)
		if restoredRuntime != nil {
			controller.appRuntime = restoredRuntime
		}
		controller.registryMirror = configuration.RegistryMirror
		controller.resourceGroupRef = configuration.ResourceGroupRef
		controller.commit = handle
		controller.epoch = epoch
		return nil
	})
}

func (controller *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	request, _ := controller.Request()
	controller.mu.Lock()
	apps, handle, epoch := cloneApps(controller.apps), controller.commit, controller.epoch
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
		prepared, err := controller.admission.Prepare(ctx, request, apps)
		if err != nil {
			return err
		}
		if prepared == nil {
			return ErrTypedHandlesUnavailable
		}
		transaction, err := rpcplugin.BindHandle(generation, generationHandleScope, prepared, func(prepared PreparedAdmission) { prepared.Abort() })
		if err != nil {
			prepared.Abort()
			return err
		}
		return transaction.Use(ctx, func(ctx context.Context, prepared PreparedAdmission) error { return prepared.Commit(ctx) })
	})
}
func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.apps = nil
	controller.registryMirror = ""
	controller.resourceGroupRef = ""
	controller.commit = nil
	controller.epoch = nil
	controller.mu.Unlock()
	return nil
}

// generationHandleScope binds process-local overlay state to the panel grant.
const generationHandleScope = "ui.dynamic"

func requiredGrants() []string {
	return []string{"http.rule", "ui.dynamic", "service.revocable-resource-handle", "storage.read", "storage.write"}
}

func cloneApps(apps []App) []App {
	result := append([]App(nil), apps...)
	for index := range result {
		result[index].SecretRefs = append([]string(nil), result[index].SecretRefs...)
		result[index].AutoUpdate = cloneBool(result[index].AutoUpdate)
	}
	return result
}

func cloneAppRuntime(values map[string]bool) map[string]bool {
	result := make(map[string]bool, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
