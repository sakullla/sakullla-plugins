package buildkit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type Signature struct {
	Algorithm string `json:"algorithm"`
	Identity  string `json:"identity"`
	Value     []byte `json:"-"`
}

type Signer interface {
	Sign(context.Context, []byte) (Signature, error)
}

type CommandSigner struct {
	Command  string
	Args     []string
	Identity string
}

func (signer CommandSigner) Sign(ctx context.Context, digest []byte) (Signature, error) {
	if signer.Command == "" || signer.Identity == "" {
		return Signature{}, fmt.Errorf("official signer command and identity are required")
	}
	request, err := json.Marshal(struct {
		Digest   string `json:"digest_sha256"`
		Identity string `json:"identity"`
	}{base64.StdEncoding.EncodeToString(digest), signer.Identity})
	if err != nil {
		return Signature{}, err
	}
	command := exec.CommandContext(ctx, signer.Command, signer.Args...)
	command.Stdin = bytes.NewReader(append(request, '\n'))
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return Signature{}, fmt.Errorf("signer provider failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var response struct {
		Algorithm string `json:"algorithm"`
		Identity  string `json:"identity"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return Signature{}, fmt.Errorf("decode signer response: %w", err)
	}
	if response.Identity != signer.Identity || response.Algorithm == "" {
		return Signature{}, fmt.Errorf("signer response identity or algorithm mismatch")
	}
	value, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil || len(value) == 0 {
		return Signature{}, fmt.Errorf("decode signer signature: %w", err)
	}
	return Signature{Algorithm: response.Algorithm, Identity: response.Identity, Value: value}, nil
}

type Validator interface {
	Validate(context.Context, string) error
}

type CommandValidator struct {
	Command string
	Args    []string
}

func (validator CommandValidator) Validate(ctx context.Context, packageDir string) error {
	if validator.Command == "" {
		return fmt.Errorf("validator command is required")
	}
	args := append(append([]string{}, validator.Args...), packageDir)
	command := exec.CommandContext(ctx, validator.Command, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("validator rejected package: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
