package reversel4

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// Service orchestrates mapping records against two generic host effects: the
// entry-side host L4 rule and the host-managed reverse channel. Every mutation
// persists the durable catalog only after its host effects succeeded, and
// retries replay the same host operation ids, so partial failures converge
// without orphan rules or channels.
type Service struct {
	mu      sync.Mutex
	state   mappingState
	runtime *hostRuntime
}

func NewService(state mappingState, runtime *hostRuntime) (*Service, error) {
	if state == nil {
		return nil, errors.New("mapping state store is required")
	}
	return &Service{state: state, runtime: runtime}, nil
}

// runtimeAvailable reports whether host orchestration is currently usable.
// Read-only listing still works without it.
func (service *Service) runtimeAvailable() bool {
	return service != nil && service.runtime.available()
}

// List returns the durable catalog sorted by mapping id.
func (service *Service) List(ctx context.Context) ([]Mapping, error) {
	if service == nil {
		return nil, ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	mappings := snapshot.clone().Mappings
	sortMappings(mappings)
	return mappings, nil
}

// Status projects one mapping with its current reverse-channel connectivity.
// A disabled mapping is offline by construction; an enabled mapping without a
// session reference reports unknown until its first ensure succeeds.
func (service *Service) Status(ctx context.Context, id string) (MappingStatus, error) {
	if service == nil {
		return MappingStatus{}, ErrStateUnavailable
	}
	service.mu.Lock()
	snapshot, err := service.state.Load(ctx)
	service.mu.Unlock()
	if err != nil {
		return MappingStatus{}, err
	}
	mapping, ok := snapshot.mapping(id)
	if !ok {
		return MappingStatus{}, ErrMappingNotFound
	}
	return service.channelStatusFor(ctx, mapping)
}

// Statuses projects the whole catalog with per-mapping reverse-channel
// connectivity for the management page. A failing channel poll degrades that
// single mapping to unknown instead of hiding the catalog.
func (service *Service) Statuses(ctx context.Context) ([]MappingStatus, error) {
	if service == nil {
		return nil, ErrStateUnavailable
	}
	service.mu.Lock()
	snapshot, err := service.state.Load(ctx)
	service.mu.Unlock()
	if err != nil {
		return nil, err
	}
	statuses := make([]MappingStatus, 0, len(snapshot.Mappings))
	for _, mapping := range snapshot.Mappings {
		status, err := service.channelStatusFor(ctx, mapping)
		if err != nil {
			status = MappingStatus{Mapping: mapping, ChannelState: ChannelUnknown}
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// channelStatusFor derives the management-page connectivity projection of one
// durable mapping record.
func (service *Service) channelStatusFor(ctx context.Context, mapping Mapping) (MappingStatus, error) {
	status := MappingStatus{Mapping: mapping, ChannelState: ChannelUnknown}
	switch {
	case !mapping.Enabled:
		status.ChannelState = ChannelOffline
	case mapping.SessionRef == "":
		status.ChannelState = ChannelUnknown
	case !service.runtimeAvailable():
		// keep unknown: connectivity is not observable without the host runtime
	default:
		session, err := service.runtime.channelStatus(ctx, pollOperationKey("channel.status", mapping.ID), mapping.SessionRef)
		if err != nil {
			if errors.Is(err, ErrHostRejectedRequest) {
				status.ChannelState = ChannelOffline
				status.LastError = "reverse channel session is gone"
				break
			}
			return MappingStatus{}, err
		}
		status.ChannelState = channelStateNormalize(session.State)
		status.LastError = session.LastError
	}
	return status, nil
}

// Create provisions a new mapping: establish the reverse channel first, then
// point a host L4 rule at the returned entry-side bridge endpoint. A failed
// rule step leaves nothing persisted, and the retry replays the durable
// channel outcome before re-running only the rule step.
func (service *Service) Create(ctx context.Context, mapping Mapping) (Mapping, error) {
	if service == nil {
		return Mapping{}, ErrStateUnavailable
	}
	mapping.RuleRef, mapping.SessionRef, mapping.BridgeHost, mapping.BridgePort = "", "", "", 0
	mapping.Enabled = true
	mapping.Revision = 0
	if err := mapping.Validate(); err != nil {
		return Mapping{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, err
	}
	if _, exists := snapshot.mapping(mapping.ID); exists {
		return Mapping{}, ErrMappingExists
	}
	if len(snapshot.Mappings) >= MaxMappings {
		return Mapping{}, fmt.Errorf("%w: mappings maximum is %d", ErrBoundExceeded, MaxMappings)
	}
	revision := snapshot.Revision + 1
	session, err := service.ensureChannelFor(ctx, mapping, "", revision)
	if err != nil {
		return Mapping{}, err
	}
	rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", mapping.ID, revision), ruleRequest(mapping, session))
	if err != nil {
		// No compensating teardown: the durable ensure outcome is keyed to
		// this revision, so a retry re-attaches the same host session and
		// only the rule step runs again. Host sessions are owner-managed and
		// re-created on demand; orphan host rules are the visible resource
		// this path must never leave behind.
		return Mapping{}, err
	}
	created := mapping
	created.SessionRef = session.SessionRef
	created.BridgeHost, created.BridgePort = session.BridgeHost, session.BridgePort
	created.RuleRef = rule.RuleRef
	created.Revision = revision
	return created, service.commit(ctx, snapshot, created, nil)
}

// Update applies a new specification to an existing mapping. The client
// supplies only the user-facing spec; ownership references come from the
// durable record.
func (service *Service) Update(ctx context.Context, spec Mapping) (Mapping, error) {
	if service == nil {
		return Mapping{}, ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, err
	}
	existing, ok := snapshot.mapping(spec.ID)
	if !ok {
		return Mapping{}, ErrMappingNotFound
	}
	updated := spec
	updated.Enabled = existing.Enabled
	updated.RuleRef, updated.SessionRef = existing.RuleRef, existing.SessionRef
	updated.BridgeHost, updated.BridgePort = existing.BridgeHost, existing.BridgePort
	updated.Revision = existing.Revision
	if err := updated.Validate(); err != nil {
		return Mapping{}, err
	}
	revision := existing.Revision + 1
	updated.Revision = revision

	entryMoved := updated.EntryAgentID != existing.EntryAgentID
	ownersMoved := entryMoved || updated.ExitAgentID != existing.ExitAgentID

	if !existing.Enabled {
		// The channel is torn down and the rule disabled; the new spec is
		// applied by the next enable, which re-ensures and re-points the rule.
		if entryMoved && existing.RuleRef != "" {
			if err := service.runtime.deleteRule(ctx, mutationOperationKey("rule.delete", updated.ID, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID)); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		if entryMoved {
			updated.RuleRef, updated.BridgeHost, updated.BridgePort = "", "", 0
		}
		return updated, service.commit(ctx, snapshot, updated, nil)
	}

	reattach := ""
	if !ownersMoved {
		reattach = existing.SessionRef
	} else if existing.SessionRef != "" {
		if err := service.runtime.teardownChannel(ctx, mutationOperationKey("channel.teardown", updated.ID, revision), existing.SessionRef); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return Mapping{}, err
		}
	}
	session, err := service.ensureChannelFor(ctx, updated, reattach, revision)
	if err != nil {
		return Mapping{}, err
	}
	updated.SessionRef = session.SessionRef
	updated.BridgeHost, updated.BridgePort = session.BridgeHost, session.BridgePort

	switch {
	case entryMoved:
		if existing.RuleRef != "" {
			if err := service.runtime.deleteRule(ctx, mutationOperationKey("rule.delete", updated.ID, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID)); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", updated.ID, revision), ruleRequest(updated, session))
		if err != nil {
			return Mapping{}, err
		}
		updated.RuleRef = rule.RuleRef
	case existing.RuleRef == "":
		rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", updated.ID, revision), ruleRequest(updated, session))
		if err != nil {
			return Mapping{}, err
		}
		updated.RuleRef = rule.RuleRef
	default:
		request := ruleRequest(updated, session)
		request.RuleRef = existing.RuleRef
		enabled := true
		request.Enabled = &enabled
		if _, err := service.runtime.updateRule(ctx, mutationOperationKey("rule.update", updated.ID, revision), request); err != nil {
			if errors.Is(err, ErrHostRejectedRequest) {
				rule, createErr := service.runtime.createRule(ctx, mutationOperationKey("rule.create", updated.ID, revision), ruleRequest(updated, session))
				if createErr != nil {
					return Mapping{}, createErr
				}
				updated.RuleRef = rule.RuleRef
				break
			}
			return Mapping{}, err
		}
	}
	return updated, service.commit(ctx, snapshot, updated, nil)
}

// SetEnabled disables or re-enables one mapping. Disabling keeps the record
// and the (disabled) rule but tears the reverse channel down; enabling
// re-ensures the channel and re-points or recreates the rule.
func (service *Service) SetEnabled(ctx context.Context, id string, enabled bool) (Mapping, error) {
	if service == nil {
		return Mapping{}, ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, err
	}
	existing, ok := snapshot.mapping(id)
	if !ok {
		return Mapping{}, ErrMappingNotFound
	}
	if existing.Enabled == enabled {
		return existing, nil
	}
	revision := existing.Revision + 1
	updated := existing
	updated.Revision = revision

	if !enabled {
		if existing.SessionRef != "" {
			if err := service.runtime.teardownChannel(ctx, mutationOperationKey("channel.teardown", id, revision), existing.SessionRef); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		if existing.RuleRef != "" {
			if _, err := service.runtime.setRuleEnabled(ctx, mutationOperationKey("rule.disable", id, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID), false); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		updated.Enabled = false
		updated.BridgeHost, updated.BridgePort = "", 0
		return updated, service.commit(ctx, snapshot, updated, nil)
	}

	session, err := service.ensureChannelFor(ctx, existing, existing.SessionRef, revision)
	if err != nil {
		return Mapping{}, err
	}
	updated.SessionRef = session.SessionRef
	updated.BridgeHost, updated.BridgePort = session.BridgeHost, session.BridgePort
	if existing.RuleRef == "" {
		rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", id, revision), ruleRequest(updated, session))
		if err != nil {
			return Mapping{}, err
		}
		updated.RuleRef = rule.RuleRef
	} else {
		request := ruleRequest(updated, session)
		request.RuleRef = existing.RuleRef
		enabled := true
		request.Enabled = &enabled
		if _, err := service.runtime.updateRule(ctx, mutationOperationKey("rule.update", id, revision), request); err != nil {
			if !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
			rule, createErr := service.runtime.createRule(ctx, mutationOperationKey("rule.create", id, revision), ruleRequest(updated, session))
			if createErr != nil {
				return Mapping{}, createErr
			}
			updated.RuleRef = rule.RuleRef
		}
	}
	updated.Enabled = true
	return updated, service.commit(ctx, snapshot, updated, nil)
}

// Delete releases both host effects and removes the record. Rejected requests
// that mean the target is already gone clear the reference and continue, so
// the delete path is re-runnable after partial failures and leaves no orphan
// rule or channel behind.
func (service *Service) Delete(ctx context.Context, id string) error {
	if service == nil {
		return ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return err
	}
	existing, ok := snapshot.mapping(id)
	if !ok {
		return nil
	}
	revision := existing.Revision + 1
	if existing.SessionRef != "" {
		if err := service.runtime.teardownChannel(ctx, mutationOperationKey("channel.teardown", id, revision), existing.SessionRef); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return err
		}
	}
	if existing.RuleRef != "" {
		if err := service.runtime.deleteRule(ctx, mutationOperationKey("rule.delete", id, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID)); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return err
		}
	}
	return service.commit(ctx, snapshot, Mapping{}, &existing.ID)
}

func (service *Service) ensureChannelFor(ctx context.Context, mapping Mapping, sessionRef string, revision uint64) (channelSession, error) {
	request := pluginsdk.ChannelReverseRequest{
		Action:       pluginsdk.ChannelReverseActionEnsure,
		EntryAgentID: mapping.EntryAgentID,
		ExitAgentID:  mapping.ExitAgentID,
		Protocol:     mapping.Protocol,
		BackendHost:  mapping.BackendHost,
		BackendPort:  mapping.BackendPort,
		RelayChain:   append([]int(nil), mapping.RelayChain...),
		SessionRef:   sessionRef,
	}
	if err := request.Validate(); err != nil {
		return channelSession{}, fmt.Errorf("%w: %v", ErrInvalidMapping, err)
	}
	operation := mutationOperationKey("channel.ensure", mapping.ID, revision)
	return service.runtime.ensureChannel(ctx, operation, request)
}

// ruleRequest projects a mapping onto the entry-side host L4 rule: the rule
// listens for visitor traffic and forwards to the channel bridge endpoint on
// the entry agent loopback. The mapping tag makes the mapping ownership
// recognizable in the host rule list alongside the injected plugin tag.
func ruleRequest(mapping Mapping, session channelSession) pluginsdk.L4RuleRequest {
	name := mapping.Name
	if name == "" {
		name = mapping.ID
	}
	return pluginsdk.L4RuleRequest{
		AgentID:    mapping.EntryAgentID,
		Name:       "reverse-l4/" + name,
		Protocol:   mapping.Protocol,
		ListenPort: mapping.ListenPort,
		Backends: []pluginsdk.L4RuleBackend{{
			Host: session.BridgeHost,
			Port: session.BridgePort,
		}},
		Tags: []string{"reverse-l4", "mapping/" + mapping.ID},
	}
}

func ruleRefRequest(ruleRef, entryAgentID string) pluginsdk.L4RuleRequest {
	return pluginsdk.L4RuleRequest{RuleRef: ruleRef, AgentID: entryAgentID}
}

// commit persists one mutated mapping (or removes it when removedID is set)
// under a fresh catalog revision.
func (service *Service) commit(ctx context.Context, snapshot mappingStateSnapshot, mapping Mapping, removedID *string) error {
	next := mappingStateSnapshot{Revision: snapshot.Revision + 1, Mappings: make([]Mapping, 0, len(snapshot.Mappings)+1)}
	for _, existing := range snapshot.Mappings {
		if removedID != nil && existing.ID == *removedID {
			continue
		}
		if mapping.ID != "" && existing.ID == mapping.ID {
			next.Mappings = append(next.Mappings, mapping.Clone())
			continue
		}
		next.Mappings = append(next.Mappings, existing.Clone())
	}
	if mapping.ID != "" && removedID == nil {
		replaced := false
		for _, existing := range next.Mappings {
			if existing.ID == mapping.ID {
				replaced = true
				break
			}
		}
		if !replaced {
			next.Mappings = append(next.Mappings, mapping.Clone())
		}
	}
	sortMappings(next.Mappings)
	return service.state.Save(ctx, next)
}

// channelStateNormalizes maps any host session state onto the two-value
// connectivity projection used by management surfaces.
func channelStateNormalize(state string) string {
	state = strings.TrimSpace(state)
	if state == pluginsdk.ChannelReverseStateOnline {
		return ChannelOnline
	}
	return ChannelOffline
}
