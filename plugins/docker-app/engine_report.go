package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
)

// AgentEngineReport is the plugin-side mapping of a generic Agent node-channel
// projection: online presence plus Agent-local engine installed/version.
// Missing or offline reports are never treated as ready.
type AgentEngineReport struct {
	AgentID   string
	Online    bool
	Installed bool
	Version   string
}

// AgentEngineSource looks up a generic Agent report. Production consumes the
// node-channel projection; tests inject catalogs. It does not open Docker.
type AgentEngineSource interface {
	Report(context.Context, string) (AgentEngineReport, error)
}

type AgentEngineSourceFunc func(context.Context, string) (AgentEngineReport, error)

func (function AgentEngineSourceFunc) Report(ctx context.Context, agentID string) (AgentEngineReport, error) {
	return function(ctx, agentID)
}

// ReportedEngineCatalog stores generic Agent engine reports for the
// control-plane plugin. Consume accepts host node-channel JSON; missing
// agents stay offline and not ready.
type ReportedEngineCatalog struct {
	mu      sync.RWMutex
	reports map[string]AgentEngineReport
}

func NewReportedEngineCatalog() *ReportedEngineCatalog {
	return &ReportedEngineCatalog{reports: map[string]AgentEngineReport{}}
}

func (catalog *ReportedEngineCatalog) Consume(payload []byte) error {
	report, err := DecodeAgentEngineReport(payload)
	if err != nil {
		return err
	}
	catalog.Replace(report)
	return nil
}

func (catalog *ReportedEngineCatalog) Replace(report AgentEngineReport) {
	if !validAgentID(report.AgentID) {
		return
	}
	report = normalizeAgentEngineReport(report)
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	if catalog.reports == nil {
		catalog.reports = map[string]AgentEngineReport{}
	}
	catalog.reports[report.AgentID] = report
}

func (catalog *ReportedEngineCatalog) Report(_ context.Context, agentID string) (AgentEngineReport, error) {
	if !validAgentID(agentID) {
		return AgentEngineReport{}, errors.New("agent id is invalid")
	}
	catalog.mu.RLock()
	defer catalog.mu.RUnlock()
	report, ok := catalog.reports[agentID]
	if !ok {
		return AgentEngineReport{AgentID: agentID}, nil
	}
	return report, nil
}

// DecodeAgentEngineReport maps a generic Agent payload onto the plugin-side
// report. Extra host fields are ignored. Offline reports drop installed/version
// so a previous ready cache cannot be reused.
func DecodeAgentEngineReport(payload []byte) (AgentEngineReport, error) {
	if len(payload) > MaxConfigBytes {
		return AgentEngineReport{}, ErrBoundExceeded
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return AgentEngineReport{}, errors.New("agent report JSON is invalid")
	}
	report := AgentEngineReport{AgentID: stringField(raw, "agent_id")}
	if report.AgentID == "" {
		report.AgentID = stringField(raw, "id")
	}
	if online, ok := raw["online"].(bool); ok {
		report.Online = online
	} else if stringField(raw, "status") == "online" {
		report.Online = true
	}
	if engine, ok := raw["engine"].(map[string]any); ok {
		report.Installed, _ = engine["installed"].(bool)
		report.Version = stringField(engine, "version")
	} else {
		report.Installed, _ = raw["installed"].(bool)
		report.Version = stringField(raw, "version")
	}
	if !validAgentID(report.AgentID) {
		return AgentEngineReport{}, errors.New("agent id is invalid")
	}
	return normalizeAgentEngineReport(report), nil
}

func ObservationFromReport(report AgentEngineReport) EngineObservation {
	if !report.Online {
		return EngineObservation{}
	}
	return EngineObservation{Installed: report.Installed, Version: report.Version}
}

func normalizeAgentEngineReport(report AgentEngineReport) AgentEngineReport {
	if !report.Online {
		report.Installed = false
		report.Version = ""
	}
	return report
}

func stringField(raw map[string]any, key string) string {
	value, _ := raw[key].(string)
	return value
}

func validAgentID(value string) bool {
	return boundedText(value, 128)
}
