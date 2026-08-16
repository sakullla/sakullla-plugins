// Package dockerapp contains plugin-owned Docker application orchestration
// state. It never opens a Docker socket or executes docker/compose commands.
package dockerapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

const (
	PluginID           = "docker-app"
	PluginVersion      = "0.1.0"
	MaxApps            = 128
	MaxDiscoveries     = 512
	MaxComposeServices = 128
	MaxCollectionItems = 256
)

var (
	ErrTypedHandlesUnavailable = errors.New("canonical public SDK has no typed Docker, Compose, HTTP-rule, or dynamic UI handles")
	ErrUnauthorized            = errors.New("operation is not authorized")
	ErrBoundExceeded           = errors.New("bounded collection limit exceeded")
)

type App struct {
	ID         string   `json:"id"`
	Image      string   `json:"image"`
	RuleRef    string   `json:"rule_ref"`
	Generation string   `json:"generation"`
	SecretRefs []string `json:"secret_refs,omitempty"`
	AutoUpdate *bool    `json:"auto_update,omitempty"`
}

func (app App) Validate() error {
	if !validID(app.ID) || !boundedText(app.Image, 512) || !boundedText(app.RuleRef, 128) || !boundedText(app.Generation, 128) {
		return errors.New("app id, image, rule_ref, or generation is invalid")
	}
	if len(app.SecretRefs) > 32 {
		return fmt.Errorf("%w: secret refs", ErrBoundExceeded)
	}
	for _, reference := range app.SecretRefs {
		if !boundedText(reference, 128) {
			return errors.New("secret reference is invalid")
		}
	}
	if _, err := sortedUnique(app.SecretRefs, 32); err != nil {
		return err
	}
	return nil
}

type Configuration struct {
	Apps           []App  `json:"apps"`
	RegistryMirror string `json:"registry_mirror,omitempty"`
}

func (configuration Configuration) Validate() error {
	if err := validateRegistryMirror(configuration.RegistryMirror); err != nil {
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
// apps, or invalid registry_mirror rejects the whole document.
func ParseConfiguration(wire []byte) (Configuration, error) {
	if len(wire) > MaxConfigBytes {
		return Configuration{}, fmt.Errorf("%w: config exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document struct {
		Apps           *[]App `json:"apps"`
		RegistryMirror string `json:"registry_mirror"`
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
	configuration := Configuration{Apps: *document.Apps, RegistryMirror: document.RegistryMirror}
	if err := configuration.Validate(); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
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
