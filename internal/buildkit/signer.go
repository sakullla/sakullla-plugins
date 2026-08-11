package buildkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// VerifyPackageEnvelope validates the deterministic release envelope before a
// package can enter an official candidate. The detached signature covers the
// exact payload digest recorded by package.files.json.
func VerifyPackageEnvelope(packageDir, identity string, publicKey ed25519.PublicKey) error {
	if identity == "" || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("official signer identity and Ed25519 public key are required")
	}
	data, err := os.ReadFile(filepath.Join(packageDir, "signature.json"))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document signatureDocument
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode package signature: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("package signature contains trailing JSON")
	}
	if document.SchemaVersion != 1 || document.Algorithm != "ed25519" || document.Identity != identity {
		return fmt.Errorf("package signature identity or algorithm mismatch")
	}
	digestBytes, err := hex.DecodeString(document.PayloadSHA256)
	if err != nil || len(digestBytes) != 32 || hex.EncodeToString(digestBytes) != document.PayloadSHA256 {
		return fmt.Errorf("package signature payload digest is not lowercase SHA-256")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("package signature is not canonical Ed25519 base64")
	}
	records, err := recordsForTree(packageDir, map[string]bool{"package.files.json": true, "signature.json": true})
	if err != nil {
		return err
	}
	if digestRecords(records) != document.PayloadSHA256 {
		return fmt.Errorf("package payload digest mismatch")
	}
	manifestData, err := os.ReadFile(filepath.Join(packageDir, "package.files.json"))
	if err != nil {
		return err
	}
	var manifest packageFileManifest
	manifestDecoder := json.NewDecoder(bytes.NewReader(manifestData))
	manifestDecoder.DisallowUnknownFields()
	if err := manifestDecoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode package file manifest: %w", err)
	}
	if err := manifestDecoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("package file manifest contains trailing JSON")
	}
	if manifest.SchemaVersion != 1 || manifest.PayloadSHA256 != document.PayloadSHA256 || len(manifest.Files) != len(records) {
		return fmt.Errorf("package file manifest does not match signed payload")
	}
	for index := range records {
		if manifest.Files[index] != records[index] {
			return fmt.Errorf("package file manifest entry %d differs from payload", index)
		}
	}
	if !ed25519.Verify(publicKey, digestBytes, signature) {
		return fmt.Errorf("package Ed25519 signature is invalid")
	}
	return nil
}
