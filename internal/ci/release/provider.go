package release

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/sakullla/sakullla-plugins/internal/buildkit"
)

var environmentName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

type ProviderConfig struct {
	Command          string   `json:"command"`
	Args             []string `json:"args,omitempty"`
	Identity         string   `json:"identity"`
	ValidatorCommand string   `json:"validator_command"`
	ValidatorArgs    []string `json:"validator_args,omitempty"`
}

func LoadProvider(specification string) (buildkit.CommandSigner, buildkit.CommandValidator, error) {
	name, ok := strings.CutPrefix(specification, "env:")
	if !ok || !environmentName.MatchString(name) {
		return buildkit.CommandSigner{}, buildkit.CommandValidator{}, fmt.Errorf("official signer must use env:UPPER_CASE_NAME")
	}
	value := os.Getenv(name)
	if strings.TrimSpace(value) == "" {
		return buildkit.CommandSigner{}, buildkit.CommandValidator{}, fmt.Errorf("official signer environment %s is not configured", name)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.DisallowUnknownFields()
	var config ProviderConfig
	if err := decoder.Decode(&config); err != nil {
		return buildkit.CommandSigner{}, buildkit.CommandValidator{}, fmt.Errorf("decode official signer provider: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return buildkit.CommandSigner{}, buildkit.CommandValidator{}, fmt.Errorf("official signer provider contains trailing JSON")
	}
	identity := strings.ToLower(config.Identity)
	if config.Command == "" || config.ValidatorCommand == "" || config.Identity == "" {
		return buildkit.CommandSigner{}, buildkit.CommandValidator{}, fmt.Errorf("official signer command, identity, and validator command are required")
	}
	if strings.Contains(identity, "test") || strings.Contains(identity, "fixture") || strings.Contains(identity, "development") {
		return buildkit.CommandSigner{}, buildkit.CommandValidator{}, fmt.Errorf("test signer identity is forbidden in the official release path")
	}
	return buildkit.CommandSigner{Command: config.Command, Args: config.Args, Identity: config.Identity},
		buildkit.CommandValidator{Command: config.ValidatorCommand, Args: config.ValidatorArgs}, nil
}
