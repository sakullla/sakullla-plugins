package dockerapp

// EngineInstaller is the remote-install hook the panel must not invoke.
// ProjectEngineReady accepts it only so callers can prove it stays unused.
type EngineInstaller interface {
	Install() error
}

type EngineReadyView struct {
	Status  EngineStatus
	Command InstallSuggestion
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
	return InstallCommand(configuration)
}
