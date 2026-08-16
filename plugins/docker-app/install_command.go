package dockerapp

import "encoding/json"

const OfficialInstallScript = "curl -fsSL https://get.docker.com | sh"

// EngineInstaller is the remote-install hook the panel must not invoke.
// ProjectEngineReady accepts it only so callers can prove it stays unused.
type EngineInstaller interface {
	Install() error
}

// InstallSuggestion is copy-only panel text. Script is always the official
// get.docker.com command; DaemonJSON is present only when a mirror is set.
type InstallSuggestion struct {
	Script     string
	DaemonJSON string
	Text       string
}

type EngineStatus struct {
	Ready   bool
	Version string
}

func (EngineStatus) RequestsInstall() bool { return false }

type EngineReadyView struct {
	Status  EngineStatus
	Command InstallSuggestion
}

// ProjectEngine maps a host-supplied observation to readiness. It never
// requests an install action; an absent engine only yields Ready=false.
func ProjectEngine(observation EngineObservation) EngineStatus {
	if !observation.Installed {
		return EngineStatus{}
	}
	return EngineStatus{Ready: true, Version: observation.Version}
}

// ProjectEngineReady maps a compose-handle observation and this agent's
// overlay onto readiness plus a copyable install command. Installed engines
// are ready. Missing engines never call installer.
func ProjectEngineReady(observation EngineObservation, document []byte, installer EngineInstaller) (EngineReadyView, error) {
	command, err := InstallCommandForDocument(document)
	if err != nil {
		return EngineReadyView{}, err
	}
	status := ProjectEngine(observation)
	if status.RequestsInstall() {
		return EngineReadyView{}, ErrUnauthorized
	}
	if status.Ready {
		return EngineReadyView{Status: status}, nil
	}
	return EngineReadyView{Status: status, Command: command}, nil
}

// InstallCommandForDocument builds the official get.docker.com command from
// this agent's overlay. An empty registry_mirror omits registry-mirrors. A
// valid https URL attaches a daemon.json suggestion. Illegal overlays are
// rejected in full.
func InstallCommandForDocument(document []byte) (InstallSuggestion, error) {
	configuration, err := ParseConfiguration(document)
	if err != nil {
		return InstallSuggestion{}, err
	}
	return InstallCommand(configuration.RegistryMirror)
}

// InstallCommand builds the copy-only official install suggestion from the
// agent-effective registry_mirror. An empty mirror yields get.docker.com
// without registry-mirrors; a valid https URL attaches a daemon.json hint.
func InstallCommand(registryMirror string) (InstallSuggestion, error) {
	if err := validateRegistryMirror(registryMirror); err != nil {
		return InstallSuggestion{}, err
	}
	suggestion := InstallSuggestion{Script: OfficialInstallScript, Text: OfficialInstallScript}
	if registryMirror == "" {
		return suggestion, nil
	}
	payload, err := json.MarshalIndent(struct {
		RegistryMirrors []string `json:"registry-mirrors"`
	}{RegistryMirrors: []string{registryMirror}}, "", "  ")
	if err != nil {
		return InstallSuggestion{}, err
	}
	suggestion.DaemonJSON = string(payload)
	suggestion.Text = OfficialInstallScript + "\n" + suggestion.DaemonJSON
	return suggestion, nil
}
