// Package dockerapp contains plugin-owned Docker application orchestration
// state. The control-plane management face forwards engine, compose, and image
// work through plugin.call and keeps HTTP ingress on http.rule. The Agent
// execution face runs local docker compose CLI. Neither face dials the
// control-plane docker.socket.
package dockerapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	PluginID                 = "docker-app"
	PluginVersion            = "0.1.13"
	DeclaredResourceGroupRef = "resource-group/docker-app"
	MaxApps                  = 128
	MaxDiscoveries           = 512
	MaxComposeServices       = 128
	MaxCollectionItems       = 256
	MaxSecretRefs            = MaxCollectionItems
)

var resourceGroupRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

var (
	ErrTypedHandlesUnavailable = errors.New("canonical public SDK has no typed Docker, Compose, HTTP-rule, or dynamic UI handles")
	ErrUnauthorized            = errors.New("operation is not authorized")
	ErrBoundExceeded           = errors.New("bounded collection limit exceeded")
	ErrInvalidCompose          = errors.New("compose YAML is invalid")
	ErrMissingComposeImage     = errors.New("compose YAML is missing a deployable image")
	ErrDeleteUnconfirmed       = errors.New("delete was not confirmed")
	ErrEngineNotReady          = errors.New("Docker engine is not ready")
	ErrAgentOffline            = errors.New("target Agent is offline")
	ErrAppAgentConflict        = errors.New("app is already bound to another Agent")
	ErrUnknownService          = errors.New("compose service is unknown")
	ErrEmptyIngressDomain      = errors.New("ingress domain is empty")
	ErrEmptyHTTPRuleRef        = errors.New("http rule ref is empty")
	ErrUnknownHTTPRule         = errors.New("http rule is unknown")
	ErrNoPublishedPort         = errors.New("app has no published port")
	ErrMissingComposeVariable  = errors.New("compose environment variable is missing")
	ErrHTTPRuleListFailed      = errors.New("http rule list failed")
)

type App struct {
	ID         string   `json:"id"`
	AgentID    string   `json:"agent_id,omitempty"`
	Compose    string   `json:"compose"`
	Generation string   `json:"generation"`
	SecretRefs []string `json:"secret_refs,omitempty"`
	AutoUpdate *bool    `json:"auto_update,omitempty"`
	Image      string   `json:"-"`
	RuleRef    string   `json:"-"`
	WorkDir    string   `json:"-"`
	Env        string   `json:"-"`
}

func (app App) Validate() error {
	if !validID(app.ID) || !boundedText(app.Generation, 128) {
		return errors.New("app id or generation is invalid")
	}
	if app.Compose != "" && !boundedCompose(app.Compose, MaxConfigBytes) {
		return ErrInvalidCompose
	}
	if len(app.Env) > MaxConfigBytes || strings.ContainsRune(app.Env, '\x00') {
		return errors.New("compose environment is invalid")
	}
	if !boundedText(app.Image, 512) {
		return errors.New("app image is invalid")
	}
	if app.AgentID != "" && !validAgentID(app.AgentID) {
		return errors.New("agent_id is invalid")
	}
	if app.RuleRef != "" && !boundedText(app.RuleRef, 128) {
		return errors.New("rule_ref is invalid")
	}
	if len(app.SecretRefs) > MaxSecretRefs {
		return fmt.Errorf("%w: secret refs", ErrBoundExceeded)
	}
	for _, reference := range app.SecretRefs {
		if !boundedText(reference, 128) {
			return errors.New("secret reference is invalid")
		}
	}
	if _, err := sortedUnique(app.SecretRefs, MaxSecretRefs); err != nil {
		return err
	}
	return nil
}

type Configuration struct {
	Apps             []App  `json:"apps"`
	RegistryMirror   string `json:"registry_mirror,omitempty"`
	ResourceGroupRef string `json:"resource_group_ref,omitempty"`
}

func (configuration Configuration) Validate() error {
	if err := validateRegistryMirror(configuration.RegistryMirror); err != nil {
		return err
	}
	if err := validateResourceGroupRef(configuration.ResourceGroupRef); err != nil {
		return err
	}
	if len(configuration.Apps) > MaxApps {
		return fmt.Errorf("%w: apps maximum is %d", ErrBoundExceeded, MaxApps)
	}
	seen := make(map[string]struct{}, len(configuration.Apps))
	for _, app := range configuration.Apps {
		if err := app.Validate(); err != nil {
			return err
		}
		if _, exists := seen[app.ID]; exists {
			return errors.New("app id is duplicated")
		}
		seen[app.ID] = struct{}{}
	}
	return nil
}

// ParseConfiguration loads one overlay document. Any unknown field, missing
// apps, invalid registry_mirror, or invalid resource_group_ref rejects the
// whole document.
func ParseConfiguration(wire []byte) (Configuration, error) {
	if len(wire) > MaxConfigBytes {
		return Configuration{}, fmt.Errorf("%w: config exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document struct {
		Apps             *[]App `json:"apps"`
		RegistryMirror   string `json:"registry_mirror"`
		ResourceGroupRef string `json:"resource_group_ref"`
	}
	if err := decoder.Decode(&document); err != nil {
		return Configuration{}, fmt.Errorf("config JSON is invalid: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Configuration{}, errors.New("config must contain one JSON document")
	}
	if document.Apps == nil {
		return Configuration{}, errors.New("config requires apps")
	}
	configuration := Configuration{Apps: *document.Apps, RegistryMirror: document.RegistryMirror, ResourceGroupRef: document.ResourceGroupRef}
	for index := range configuration.Apps {
		if err := configuration.Apps[index].bindCompose(); err != nil {
			return Configuration{}, err
		}
	}
	if err := configuration.Validate(); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

func (app *App) bindCompose() error {
	if !boundedCompose(app.Compose, MaxConfigBytes) {
		return ErrInvalidCompose
	}
	_, parsed, err := ParseComposeDocument(app.Compose, app.ID, app.Generation, app.RuleRef)
	if err != nil {
		return err
	}
	app.Image = parsed.Image
	app.Compose = parsed.Compose
	if len(parsed.SecretRefs) == 0 {
		return nil
	}
	combined := make([]string, 0, len(app.SecretRefs)+len(parsed.SecretRefs))
	seen := make(map[string]struct{}, len(app.SecretRefs)+len(parsed.SecretRefs))
	for _, reference := range append(append([]string(nil), app.SecretRefs...), parsed.SecretRefs...) {
		if _, exists := seen[reference]; exists {
			continue
		}
		seen[reference] = struct{}{}
		combined = append(combined, reference)
	}
	normalized, err := sortedUnique(combined, MaxSecretRefs)
	if err != nil {
		return err
	}
	app.SecretRefs = normalized
	return nil
}

func validateResourceGroupRef(value string) error {
	if value == "" {
		return nil
	}
	if !resourceGroupRefPattern.MatchString(value) {
		return errors.New("resource_group_ref is invalid")
	}
	return nil
}

func validateRegistryMirror(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("registry_mirror is invalid")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
		return errors.New("registry_mirror must be an https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("registry_mirror contains unsupported components")
	}
	return nil
}

func validID(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, current := range value {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
			return false
		}
	}
	return true
}

func boundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func boundedCompose(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func sortedUnique(values []string, maximum int) ([]string, error) {
	if len(values) > maximum {
		return nil, ErrBoundExceeded
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if !boundedText(value, 512) {
			return nil, errors.New("collection value is invalid")
		}
		if index > 0 && result[index-1] == value {
			return nil, errors.New("collection contains a duplicate value")
		}
	}
	return result, nil
}
