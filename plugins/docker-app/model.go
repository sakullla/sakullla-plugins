// Package dockerapp contains plugin-owned Docker application orchestration
// state. It never opens a Docker socket or executes docker/compose commands.
package dockerapp

import (
	"errors"
	"fmt"
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
	Secrets    []string `json:"secrets,omitempty"`
}

func (app App) Validate() error {
	if !validID(app.ID) || !boundedText(app.Image, 512) || !boundedText(app.RuleRef, 128) || !boundedText(app.Generation, 128) {
		return errors.New("app id, image, rule_ref, or generation is invalid")
	}
	if len(app.Secrets) > 32 {
		return fmt.Errorf("%w: secrets", ErrBoundExceeded)
	}
	for _, secret := range app.Secrets {
		if secret == "" || len(secret) > 4096 {
			return errors.New("secret is invalid")
		}
	}
	return nil
}

type Configuration struct {
	Apps []App `json:"apps"`
}

func (configuration Configuration) Validate() error {
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
