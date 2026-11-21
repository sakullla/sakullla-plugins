package shadowsocksserver

import (
	"context"
	"reflect"
	"slices"
)

const listenerSecretJournalKey = "listener-secret-cleanup"

// Only references are stored. The host assigns Version during secret.create.
type listenerSecretIntent struct {
	AgentID string `json:"agent_id"`
	Ref     string `json:"ref"`
	Version string `json:"version,omitempty"`
}

func (c *Controller) loadListenerSecretIntents(ctx context.Context) ([]listenerSecretIntent, error) {
	var response struct {
		Value []listenerSecretIntent `json:"value"`
	}
	err := callHost(ctx, c.managedRuntime.client, "state.get", map[string]string{"key": listenerSecretJournalKey}, &response)
	return response.Value, err
}

func (c *Controller) saveListenerSecretIntents(ctx context.Context, intents []listenerSecretIntent) error {
	var response struct {
		Stored bool `json:"stored"`
	}
	err := callHost(ctx, c.managedRuntime.client, "state.put", map[string]any{"key": listenerSecretJournalKey, "value": intents}, &response)
	if err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

// Caller holds directoryMu across staging, the directory change, Agent apply,
// and rollback. A successor uses the saved directory as the commit decision.
func (c *Controller) stageListenerSecrets(ctx context.Context, intents []listenerSecretIntent) error {
	pending, err := c.loadListenerSecretIntents(ctx)
	if err != nil {
		return err
	}
	for _, intent := range intents {
		index := slices.IndexFunc(pending, func(existing listenerSecretIntent) bool {
			return existing.Ref == intent.Ref && (existing.Version == "" || existing.Version == intent.Version)
		})
		if index >= 0 {
			pending[index] = intent
		} else {
			pending = append(pending, intent)
		}
	}
	return c.saveListenerSecretIntents(ctx, pending)
}

func (c *Controller) stageUserMutation(ctx context.Context, agentID string, user User) error {
	if c.managedRuntime == nil {
		return nil
	}
	return c.stageListenerSecrets(ctx, []listenerSecretIntent{{AgentID: agentID, Ref: user.SecretRef, Version: user.SecretVersion}})
}

func (intent listenerSecretIntent) retainedBy(config Configuration) bool {
	matches := func(ref, version string) bool {
		return intent.Ref == ref && (intent.Version == "" || intent.Version == version)
	}
	for _, listen := range config.Listeners {
		if matches(listen.ServerSecretRef, listen.ServerSecretVersion) {
			return true
		}
		for _, user := range listen.Users {
			if matches(user.SecretRef, user.SecretVersion) {
				return true
			}
		}
	}
	for _, upstream := range config.Routing.Upstreams {
		if matches(upstream.SecretRef, upstream.SecretVersion) {
			return true
		}
	}
	return false
}

func (c *Controller) retireListenerSecret(ctx context.Context, intent listenerSecretIntent) error {
	if intent.Version == "" {
		var result struct {
			Found bool   `json:"found"`
			Value string `json:"value"`
		}
		err := callHost(ctx, c.managedRuntime.client, "state.get", map[string]string{"key": "listener-secret-version/" + intent.Ref}, &result)
		if err != nil || !result.Found {
			// An older host cannot confirm the outcome of an interrupted create.
			return ErrTypedHandlesUnavailable
		}
		if result.Value == "" {
			return nil
		}
		intent.Version = result.Value
	}
	return c.managedRuntime.revokeSecret(ctx, intent.Ref, intent.Version)
}

func (c *Controller) recoverListenerSecrets(ctx context.Context, confirmedAgent string) error {
	if c.managedRuntime == nil {
		return nil
	}
	pending, err := c.loadListenerSecretIntents(ctx)
	if err != nil || len(pending) == 0 {
		return err
	}
	if c.listenState == nil {
		return ErrTypedHandlesUnavailable
	}
	// Do not retire a credential on the basis of a missing state.put reply.
	stored, found, err := c.listenState.LoadListens(ctx)
	if err != nil {
		return err
	}
	config := c.directory()
	if found && !reflect.DeepEqual(cloneListeners(config.Listeners), cloneListeners(stored)) {
		config.Listeners = stored
		if err := config.Validate(); err != nil {
			return err
		}
		if err := c.publishDirectory(config); err != nil {
			return err
		}
		confirmedAgent = ""
	}
	c.directoryUnconfirmed = false
	// A port report cannot confirm user additions, disablement or deletion. Only
	// skip the full apply for the Agent which acknowledged this exact directory.
	applied := map[string]error{}
	if confirmedAgent != "" {
		applied[confirmedAgent] = nil
	}
	var firstErr error
	for i := 0; i < len(pending); {
		intent := pending[i]
		if err := ctx.Err(); err != nil {
			return err
		}
		applyErr, attempted := applied[intent.AgentID]
		if !attempted {
			applyErr = c.applyAgentListens(ctx, intent.AgentID)
			applied[intent.AgentID] = applyErr
		}
		if applyErr != nil {
			if firstErr == nil {
				firstErr = applyErr
			}
			i++
			continue
		}
		if !intent.retainedBy(config) {
			if err := c.retireListenerSecret(ctx, intent); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				i++
				continue
			}
		}
		pending = slices.Delete(pending, i, i+1)
		if err := c.saveListenerSecretIntents(ctx, pending); err != nil {
			return err
		}
	}
	return firstErr
}
