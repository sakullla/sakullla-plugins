package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

type ListenCatalogStore interface {
	LoadListens(context.Context) ([]ListenRule, bool, error)
	StoreListens(context.Context, []ListenRule) error
	LoadSecrets(context.Context) (map[string]string, bool, error)
	StoreSecrets(context.Context, map[string]string) error
	LoadNodes(context.Context) (map[string]NodeAddresses, bool, error)
	StoreNodes(context.Context, map[string]NodeAddresses) error
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	Admission                                                  TypedHandleAdmission
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
	ListenRuntime                                              *hostCapabilityRuntime
	ListenState                                                ListenCatalogStore
	ListenBinder                                               listenBinder
}

type controllerEpoch struct{ live atomic.Bool }

type Controller struct {
	*rpcplugin.Adapter
	mu             sync.Mutex
	configuration  Configuration
	epoch          *controllerEpoch
	commit         *rpcplugin.Handle[*controllerEpoch]
	service        *rpcplugin.Handle[*Service]
	published      *Service
	transaction    *rpcplugin.Handle[PreparedAdmission]
	admission      TypedHandleAdmission
	listenHost     *hostCapabilityRuntime
	listenState    ListenCatalogStore
	listenExec     *listenExecutor
	controlSecrets *issuedSecrets
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Admission == nil {
		config.Admission = unavailableAdmission{}
	}
	timeouts := (rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}).WithDefaults(rpcplugin.UniformTimeouts(time.Second))
	c := &Controller{
		admission:   config.Admission,
		listenHost:  config.ListenRuntime,
		listenState: config.ListenState,
		listenExec:  newListenExecutor(config.ListenBinder),
	}
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities: []string{"shadowsocks.business-model"}, RequiredGrants: requiredGrants(),
		Timeouts: timeouts,
	}, rpcplugin.HookFuncs{PrepareFunc: c.prepare, ActivateFunc: c.activate, StopFunc: c.stop})
	if err != nil {
		return nil, err
	}
	c.Adapter = adapter
	return c, nil
}
func (c *Controller) Use(ctx context.Context, f func(context.Context, *Service) error) error {
	c.mu.Lock()
	service := c.service
	c.mu.Unlock()
	if service == nil {
		return ErrRevoked
	}
	return service.Use(ctx, f)
}

// CreateAccount mints a traditional SS or SS2022 user on the live generation.
// Quota and expiry are filled by the service; callers may omit both.
func (c *Controller) CreateAccount(ctx context.Context, spec AccountSpec) (User, *SecretOnce, error) {
	var user User
	var secret *SecretOnce
	err := c.Use(ctx, func(ctx context.Context, s *Service) error {
		var createErr error
		user, secret, createErr = s.CreateAccount(ctx, spec)
		if createErr != nil {
			return createErr
		}
		s.rememberIssuedSecret(secret)
		return nil
	})
	return user, secret, err
}

func (c *Controller) ListAccounts(ctx context.Context) ([]AccountRecord, error) {
	var accounts []AccountRecord
	err := c.Use(ctx, func(_ context.Context, s *Service) error {
		accounts = s.ListAccounts()
		return nil
	})
	return accounts, err
}

func (c *Controller) SetAccountEnabled(ctx context.Context, userID string, enabled bool) error {
	return c.Use(ctx, func(ctx context.Context, s *Service) error {
		return s.SetAccountEnabled(ctx, userID, enabled)
	})
}

func (c *Controller) DisableAccount(ctx context.Context, userID string) error {
	return c.SetAccountEnabled(ctx, userID, false)
}

func (c *Controller) EnableAccount(ctx context.Context, userID string) error {
	return c.SetAccountEnabled(ctx, userID, true)
}

func (c *Controller) RotateUserKey(ctx context.Context, userID, expectedVersion string) (*SecretOnce, error) {
	var secret *SecretOnce
	err := c.Use(ctx, func(ctx context.Context, s *Service) error {
		var rotateErr error
		secret, rotateErr = s.Rotate(ctx, userID, expectedVersion)
		if rotateErr != nil {
			return rotateErr
		}
		s.rememberIssuedSecret(secret)
		return nil
	})
	return secret, err
}

func (c *Controller) RotateServerPSK(ctx context.Context, expectedVersion string) (*SecretOnce, error) {
	var secret *SecretOnce
	err := c.Use(ctx, func(ctx context.Context, s *Service) error {
		var rotateErr error
		secret, rotateErr = s.RotateServerPSK(ctx, expectedVersion)
		if rotateErr != nil {
			return rotateErr
		}
		s.rememberIssuedSecret(secret)
		return nil
	})
	return secret, err
}

func (c *Controller) ListenBinding(ctx context.Context) (ListenBinding, error) {
	var binding ListenBinding
	err := c.Use(ctx, func(_ context.Context, s *Service) error {
		binding = s.ListenBinding()
		return nil
	})
	return binding, err
}

func (c *Controller) ShareEndpoint(ctx context.Context) (ShareEndpoint, error) {
	var endpoint ShareEndpoint
	err := c.Use(ctx, func(_ context.Context, s *Service) error {
		endpoint = s.ShareEndpoint()
		return nil
	})
	return endpoint, err
}

func (c *Controller) ShareAccount(ctx context.Context, userID string) (AccountShare, error) {
	var share AccountShare
	err := c.Use(ctx, func(ctx context.Context, s *Service) error {
		var shareErr error
		share, shareErr = s.ShareAccount(ctx, userID)
		return shareErr
	})
	return share, err
}

func (c *Controller) ListShares(ctx context.Context) ([]AccountShare, error) {
	var shares []AccountShare
	err := c.Use(ctx, func(ctx context.Context, s *Service) error {
		var listErr error
		shares, listErr = s.ListShares(ctx)
		return listErr
	})
	return shares, err
}

func (c *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	if len(wire) > MaxConfigBytes {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	if err := configuration.Validate(); err != nil {
		return err
	}
	if configuration.Generation != generation.ID() {
		return rpcplugin.ErrGenerationMismatch
	}
	var restoredListeners []ListenRule
	var restoredSecrets map[string]string
	if c.listenState != nil {
		persisted, found, loadErr := c.listenState.LoadListens(ctx)
		if loadErr != nil {
			return loadErr
		}
		if found {
			restoredListeners = persisted
		}
		secrets, secretsFound, secretErr := c.listenState.LoadSecrets(ctx)
		if secretErr != nil {
			return secretErr
		}
		if secretsFound {
			restoredSecrets = secrets
		}
		nodes, nodesFound, nodeErr := c.listenState.LoadNodes(ctx)
		if nodeErr != nil {
			return nodeErr
		}
		if nodesFound && c.listenHost != nil {
			for agentID, node := range nodes {
				c.listenHost.SetAgentNode(agentID, node)
			}
		}
	}
	epoch := &controllerEpoch{}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, "listener", epoch, func(epoch *controllerEpoch) {
		epoch.live.Store(false)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.epoch == epoch {
			c.configuration = Configuration{}
			c.epoch, c.commit, c.service, c.published, c.transaction = nil, nil, nil, nil, nil
		}
	})
	if err != nil {
		return err
	}
	return handle.Use(ctx, func(ctx context.Context, value *controllerEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !value.live.Load() {
			return rpcplugin.ErrRevoked
		}
		next := clone(configuration)
		if restoredListeners != nil {
			next.Listeners = restoredListeners
			next.Generation = generation.ID()
			if err := next.Validate(); err != nil {
				return err
			}
		}
		c.mu.Lock()
		c.configuration, c.epoch, c.commit = next, epoch, handle
		c.service, c.published, c.transaction = nil, nil, nil
		if restoredSecrets != nil {
			c.controlSecrets = &issuedSecrets{items: cloneSecretMap(restoredSecrets)}
		}
		c.mu.Unlock()
		return nil
	})
}

func (c *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	request, _ := c.Request()
	c.mu.Lock()
	configuration, epoch, commit := clone(c.configuration), c.epoch, c.commit
	c.mu.Unlock()
	if epoch == nil || commit == nil {
		return rpcplugin.ErrRevoked
	}
	return commit.Use(ctx, func(ctx context.Context, value *controllerEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value != epoch || !value.live.Load() {
			return rpcplugin.ErrRevoked
		}
		prepared, err := c.admission.Prepare(ctx, request, configuration)
		if err != nil {
			return safeControllerError(err)
		}
		if prepared == nil {
			return ErrTypedHandlesUnavailable
		}
		transaction, err := rpcplugin.BindHandle(generation, "listener", prepared, func(p PreparedAdmission) { p.Abort() })
		if err != nil {
			prepared.Abort()
			return err
		}
		var runtime RuntimeAdapters
		if err = transaction.Use(ctx, func(ctx context.Context, p PreparedAdmission) error {
			var commitErr error
			runtime, commitErr = p.Commit(ctx)
			return commitErr
		}); err != nil {
			transaction.Revoke()
			return safeControllerError(err)
		}
		if !runtime.valid() {
			transaction.Revoke()
			return nil
		}
		runtime.Secrets = wrapIssuedSecrets(runtime.Secrets)
		service, err := NewService(configuration, runtime)
		if err != nil {
			transaction.Revoke()
			return err
		}
		if err = service.Initialize(ctx); err != nil {
			service.Disable()
			transaction.Revoke()
			return safeControllerError(err)
		}
		serviceHandle, err := rpcplugin.BindHandle(generation, "listener", service, func(service *Service) { service.Disable() })
		if err != nil {
			service.Disable()
			transaction.Revoke()
			return err
		}
		if err = serviceHandle.Use(ctx, func(ctx context.Context, service *Service) error {
			if err := runtime.Listener.Register(ctx, configuration.firstListenerID(), service); err != nil {
				return err
			}
			return service.RefreshListenShare(ctx)
		}); err != nil {
			serviceHandle.Revoke()
			transaction.Revoke()
			return safeControllerError(err)
		}
		if err := ctx.Err(); err != nil || !epoch.live.Load() {
			serviceHandle.Revoke()
			transaction.Revoke()
			if err != nil {
				return err
			}
			return rpcplugin.ErrRevoked
		}
		c.mu.Lock()
		if c.epoch != epoch || !epoch.live.Load() {
			c.mu.Unlock()
			serviceHandle.Revoke()
			transaction.Revoke()
			return rpcplugin.ErrRevoked
		}
		c.service, c.published, c.transaction = serviceHandle, service, transaction
		c.mu.Unlock()
		return nil
	})
}

func (c *Controller) stop(ctx context.Context, _ *rpcplugin.Generation) error {
	if c.listenExec != nil {
		c.listenExec.stopAll()
	}
	c.mu.Lock()
	service := c.published
	c.service, c.published = nil, nil
	c.mu.Unlock()
	var drainErr error
	if service != nil {
		drainErr = service.Drain(ctx)
	}
	c.mu.Lock()
	c.configuration = Configuration{}
	c.epoch, c.commit, c.transaction = nil, nil, nil
	c.mu.Unlock()
	return drainErr
}

func safeControllerError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, rpcplugin.ErrRevoked):
		return rpcplugin.ErrRevoked
	default:
		return ErrTypedHandlesUnavailable
	}
}
func requiredGrants() []string {
	return []string{"audit", "listener", "monotonic-clock", "replay", "secret", "traffic"}
}

type issuedSecrets struct {
	mu    sync.Mutex
	base  SecretVerifier
	items map[string]string
}

func wrapIssuedSecrets(base SecretVerifier) SecretVerifier {
	if base == nil {
		return nil
	}
	if issued, ok := base.(*issuedSecrets); ok {
		return issued
	}
	return &issuedSecrets{base: base, items: map[string]string{}}
}

func issuedSecretKey(ref, version string) string {
	return ref + "\x00" + version
}

func (i *issuedSecrets) put(ref, version, material string) {
	if i == nil || ref == "" || version == "" {
		return
	}
	i.mu.Lock()
	i.items[issuedSecretKey(ref, version)] = material
	i.mu.Unlock()
}

func (i *issuedSecrets) lookup(ref, version string) (string, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	material, ok := i.items[issuedSecretKey(ref, version)]
	return material, ok
}

func (i *issuedSecrets) snapshot() map[string]string {
	if i == nil {
		return map[string]string{}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return cloneSecretMap(i.items)
}

func cloneSecretMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func issuedVaultMaterial(material []byte) []byte {
	if _, userPSK, ok := splitSS2022ClientPassword(material); ok {
		return append([]byte(nil), userPSK...)
	}
	return append([]byte(nil), material...)
}

func issuedMaterialMatches(stored string, material []byte) bool {
	if stored == string(material) {
		return true
	}
	if _, userPSK, ok := splitSS2022ClientPassword([]byte(stored)); ok && string(userPSK) == string(material) {
		return true
	}
	if _, userPSK, ok := splitSS2022ClientPassword(material); ok && stored == string(userPSK) {
		return true
	}
	return false
}

func (i *issuedSecrets) Verify(ctx context.Context, ref, version string, material []byte) error {
	if stored, ok := i.lookup(ref, version); ok {
		if issuedMaterialMatches(stored, material) {
			return nil
		}
		return ErrDenied
	}
	return i.base.Verify(ctx, ref, version, material)
}

func (i *issuedSecrets) Resolve(ctx context.Context, ref, version string) ([]byte, error) {
	if stored, ok := i.lookup(ref, version); ok {
		return issuedVaultMaterial([]byte(stored)), nil
	}
	return i.base.Resolve(ctx, ref, version)
}

func (s *Service) issuedSecrets() *issuedSecrets {
	if issued, ok := s.runtime.Secrets.(*issuedSecrets); ok {
		return issued
	}
	issued := wrapIssuedSecrets(s.runtime.Secrets).(*issuedSecrets)
	s.runtime.Secrets = issued
	return issued
}

func peekSecretMaterial(secret *SecretOnce) []byte {
	if secret == nil {
		return nil
	}
	secret.mu.Lock()
	defer secret.mu.Unlock()
	if secret.consumed || len(secret.material) == 0 {
		return nil
	}
	return append([]byte(nil), secret.material...)
}

func (s *Service) rememberIssuedSecret(secret *SecretOnce) {
	if secret == nil {
		return
	}
	material := peekSecretMaterial(secret)
	if len(material) == 0 {
		return
	}
	s.mu.Lock()
	issued := s.issuedSecrets()
	if serverPSK, userPSK, ok := splitSS2022ClientPassword(material); ok {
		// Host Verify/Resolve see the user identity PSK, not SIP002 serverPSK:userPSK.
		issued.put(secret.SecretRef, secret.SecretVersion, string(userPSK))
		if ref, version := listenServerSecret(s.configuration, secret.SecretRef, secret.SecretVersion); ref != "" && version != "" {
			issued.put(ref, version, string(serverPSK))
		}
	} else {
		issued.put(secret.SecretRef, secret.SecretVersion, string(material))
	}
	s.mu.Unlock()
	clear(material)
}

func listenServerSecret(cfg Configuration, secretRef, secretVersion string) (ref, version string) {
	if secretRef == "" || secretVersion == "" {
		return "", ""
	}
	for _, listener := range cfg.Listeners {
		for _, user := range listener.Users {
			if user.SecretRef == secretRef && user.SecretVersion == secretVersion {
				return listener.ServerSecretRef, listener.ServerSecretVersion
			}
		}
	}
	return "", ""
}
