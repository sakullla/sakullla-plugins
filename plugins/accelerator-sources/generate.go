package acceleratorsources

import (
	"context"
	"encoding/json"
	"strings"
)

type GenerationPolicy struct {
	Sort             SortMode
	RequireAvailable bool
}

type DockerDaemonConfiguration struct {
	RegistryMirrors []string `json:"registry-mirrors"`
}

type GitHubReplacement struct {
	SourceID string `json:"source_id"`
	URL      string `json:"url"`
}

type GitHubGeneration struct {
	Original     string              `json:"original"`
	Replacements []GitHubReplacement `json:"replacements"`
	Text         string              `json:"text"`
}

func (manager *Manager) GenerateDocker(ctx context.Context, policy GenerationPolicy) ([]byte, error) {
	flow, err := manager.startOperation(ctx, "generate-docker", "", &DynamicEvent{Kind: "action", Action: "generate-docker"})
	if err != nil {
		return nil, err
	}
	records := eligibleRecords(manager.Snapshot(), CategoryDocker, policy)
	configuration := DockerDaemonConfiguration{RegistryMirrors: make([]string, 0, len(records))}
	for _, record := range records {
		configuration.RegistryMirrors = append(configuration.RegistryMirrors, record.Source.URL)
	}
	wire, err := json.Marshal(configuration)
	if err != nil {
		return nil, flow.fail(ErrInvalidSource, false)
	}
	return wire, flow.finish(true)
}

func (manager *Manager) GenerateGitHub(ctx context.Context, original string, policy GenerationPolicy) (GitHubGeneration, error) {
	canonical, err := CanonicalHTTPSURL(original)
	if err != nil || canonical != original || (!strings.HasPrefix(original, "https://github.com/") && original != "https://github.com") {
		return GitHubGeneration{}, manager.failedAttempt(ctx, "generate-github", "", ErrInvalidSource)
	}
	flow, err := manager.startOperation(ctx, "generate-github", "", &DynamicEvent{Kind: "action", Action: "generate-github"})
	if err != nil {
		return GitHubGeneration{}, err
	}
	records := eligibleRecords(manager.Snapshot(), CategoryGitHub, policy)
	result := GitHubGeneration{Original: original, Replacements: make([]GitHubReplacement, 0, len(records))}
	lines := make([]string, 0, len(records))
	for _, record := range records {
		replacement := record.Source.URL + "/" + strings.TrimPrefix(original, "https://")
		if _, err := CanonicalHTTPSURL(replacement); err != nil {
			return GitHubGeneration{}, flow.fail(ErrInvalidSource, false)
		}
		result.Replacements = append(result.Replacements, GitHubReplacement{SourceID: record.Source.ID, URL: replacement})
		lines = append(lines, replacement)
	}
	result.Text = strings.Join(lines, "\n")
	return result, flow.finish(true)
}

func eligibleRecords(records []SourceRecord, category Category, policy GenerationPolicy) []SourceRecord {
	filtered := make([]SourceRecord, 0, len(records))
	for _, record := range records {
		if record.Source.Category != category || !record.Source.Enabled || record.Status.Availability == AvailabilityUnavailable || (policy.RequireAvailable && record.Status.Availability != AvailabilityAvailable) {
			continue
		}
		filtered = append(filtered, record)
	}
	return SortRecords(filtered, policy.Sort)
}
