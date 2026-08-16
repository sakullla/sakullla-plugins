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
	AppLabel              = "nre.app.id"
	OfficialInstallScript = "curl -fsSL https://get.docker.com | sh"
)

var ErrInvalidOverlay = errors.New("configuration overlay is rejected")

type ContainerObservation struct {
	ID           string
	Labels       map[string]string
	ExposedPorts []uint16
}

type Discovery struct {
	ContainerID string
	AppID       string
	Ports       []uint16
	Candidate   bool
}

// EngineObservation is supplied by a future container.compose handle.
// DiscoverEngine never opens a socket or installs the engine.
type EngineObservation struct {
	Installed bool
	Version   string
}

// InstallSuggestion is copy-only panel text. Script is always the official
// get.docker.com command; DaemonJSON is present only when a mirror is set.
type InstallSuggestion struct {
	Script     string
	DaemonJSON string
	Text       string
}

// EngineReadiness is the panel projection of an engine observation.
// HasInstallAction is always false: missing engines only yield Command.
type EngineReadiness struct {
	Ready   bool
	Version string
	Command InstallSuggestion
}

func (EngineReadiness) HasInstallAction() bool { return false }

// Discover consumes observations supplied by a future typed broker handle.
// It performs no Engine call: labeled containers are owned discoveries, while
// unlabeled exposed ports are candidates requiring explicit adoption.
func Discover(observations []ContainerObservation) ([]Discovery, error) {
	if len(observations) > MaxDiscoveries {
		return nil, fmt.Errorf("%w: discoveries maximum is %d", ErrBoundExceeded, MaxDiscoveries)
	}
	result := make([]Discovery, 0, len(observations))
	for _, observation := range observations {
		if !boundedText(observation.ID, 128) || len(observation.ExposedPorts) > 64 {
			return nil, ErrBoundExceeded
		}
		ports := append([]uint16(nil), observation.ExposedPorts...)
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		for _, port := range ports {
			if port == 0 {
				return nil, fmt.Errorf("container %q exposes port zero", observation.ID)
			}
		}
		if appID := observation.Labels[AppLabel]; appID != "" {
			if !validID(appID) {
				return nil, fmt.Errorf("container %q has invalid app label", observation.ID)
			}
			result = append(result, Discovery{ContainerID: observation.ID, AppID: appID, Ports: ports})
		} else if len(ports) != 0 {
			result = append(result, Discovery{ContainerID: observation.ID, Ports: ports, Candidate: true})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ContainerID < result[j].ContainerID })
	return result, nil
}

// RegistryMirror returns the effective registry_mirror from a whole
// configuration document. Unknown fields or a non-https value reject the
// entire overlay so no partial command can be generated.
func RegistryMirror(document []byte) (string, error) {
	if len(document) > MaxConfigBytes {
		return "", fmt.Errorf("%w: config exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	if len(bytes.TrimSpace(document)) == 0 {
		document = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var parsed struct {
		Apps           json.RawMessage `json:"apps"`
		RegistryMirror string          `json:"registry_mirror"`
	}
	if err := decoder.Decode(&parsed); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidOverlay, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w: config must contain one JSON document", ErrInvalidOverlay)
	}
	return normalizeRegistryMirror(parsed.RegistryMirror)
}

// InstallCommand builds the copy-only official install suggestion from the
// agent-effective registry_mirror. An empty mirror yields get.docker.com
// without registry-mirrors; a valid https URL attaches a daemon.json hint.
func InstallCommand(registryMirror string) (InstallSuggestion, error) {
	mirror, err := normalizeRegistryMirror(registryMirror)
	if err != nil {
		return InstallSuggestion{}, err
	}
	suggestion := InstallSuggestion{Script: OfficialInstallScript, Text: OfficialInstallScript}
	if mirror == "" {
		return suggestion, nil
	}
	payload, err := json.MarshalIndent(struct {
		RegistryMirrors []string `json:"registry-mirrors"`
	}{RegistryMirrors: []string{mirror}}, "", "  ")
	if err != nil {
		return InstallSuggestion{}, err
	}
	suggestion.DaemonJSON = string(payload)
	suggestion.Text = OfficialInstallScript + "\n" + suggestion.DaemonJSON
	return suggestion, nil
}

// DiscoverEngine projects a container.compose observation against the
// agent-effective registry_mirror. Installed engines are ready. Missing
// engines only yield a copyable command; this function never installs.
func DiscoverEngine(observation EngineObservation, registryMirror string) (EngineReadiness, error) {
	command, err := InstallCommand(registryMirror)
	if err != nil {
		return EngineReadiness{}, err
	}
	if !observation.Installed {
		return EngineReadiness{Command: command}, nil
	}
	if observation.Version != "" && !boundedText(observation.Version, 128) {
		return EngineReadiness{}, fmt.Errorf("%w: engine version", ErrBoundExceeded)
	}
	return EngineReadiness{Ready: true, Version: observation.Version, Command: command}, nil
}

// DiscoverEngineDocument is DiscoverEngine using the registry_mirror from a
// whole configuration document, including the package default with no mirror.
func DiscoverEngineDocument(observation EngineObservation, document []byte) (EngineReadiness, error) {
	mirror, err := RegistryMirror(document)
	if err != nil {
		return EngineReadiness{}, err
	}
	return DiscoverEngine(observation, mirror)
}

func normalizeRegistryMirror(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if !boundedText(value, 512) {
		return "", fmt.Errorf("%w: registry_mirror exceeds 512 bytes", ErrInvalidOverlay)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return "", fmt.Errorf("%w: registry_mirror must be an https URL", ErrInvalidOverlay)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: registry_mirror contains unsupported components", ErrInvalidOverlay)
	}
	return parsed.String(), nil
}
