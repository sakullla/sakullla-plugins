package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sakullla/sakullla-plugins/internal/buildkit"
)

const defaultKeyEnvironment = "NRE_OFFICIAL_ED25519_PRIVATE_KEY"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "nre-signing-provider:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected keygen, sign, or verify")
	}
	switch args[0] {
	case "keygen":
		flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
		output := flags.String("output", "", "directory for the private secret and public identity")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *output == "" {
			return errors.New("keygen requires --output DIR")
		}
		return generateKey(*output, stdout)
	case "sign":
		flags := flag.NewFlagSet("sign", flag.ContinueOnError)
		keyEnvironment := flags.String("key-env", defaultKeyEnvironment, "environment variable containing base64 PKCS#8 Ed25519 private key")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("sign accepts no positional arguments")
		}
		return signRequest(stdin, stdout, *keyEnvironment)
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		publicKeyFile := flags.String("public-key-file", "", "file containing the trusted lowercase-hex Ed25519 public key")
		identity := flags.String("identity", "", "required signer identity")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 1 || *identity == "" || *publicKeyFile == "" {
			return errors.New("verify requires --public-key-file FILE --identity ID PACKAGE_DIR")
		}
		return verifyPackageSignature(flags.Arg(0), *identity, *publicKeyFile)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func generateKey(output string, stdout io.Writer) error {
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	privatePath := filepath.Join(output, "private-key.pkcs8.base64")
	publicPath := filepath.Join(output, "public-key.hex")
	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(der)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "private_secret_file=%s\npublic_key_file=%s\npublic_key_hex=%s\n", privatePath, publicPath, hex.EncodeToString(publicKey))
	return err
}

func signRequest(stdin io.Reader, stdout io.Writer, keyEnvironment string) error {
	privateKey, err := privateKeyFromEnvironment(keyEnvironment)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(stdin, 8193))
	decoder.DisallowUnknownFields()
	var request struct {
		Digest   string `json:"digest_sha256"`
		Identity string `json:"identity"`
	}
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode signing request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("signing request contains trailing JSON")
	}
	if request.Identity == "" || request.Identity != strings.TrimSpace(request.Identity) {
		return errors.New("signing identity is not canonical")
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(request.Digest)
	if err != nil || len(digest) == 0 {
		return errors.New("signing digest is not canonical base64")
	}
	response := struct {
		Algorithm string `json:"algorithm"`
		Identity  string `json:"identity"`
		Signature string `json:"signature"`
	}{Algorithm: "ed25519", Identity: request.Identity, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest))}
	return json.NewEncoder(stdout).Encode(response)
}

func verifyPackageSignature(root, identity, publicKeyFile string) error {
	publicKey, err := publicKeyFromFile(publicKeyFile)
	if err != nil {
		return err
	}
	return buildkit.VerifyPackageEnvelope(root, identity, publicKey)
}

func publicKeyFromFile(path string) (ed25519.PublicKey, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(value))
	key, err := hex.DecodeString(text)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != text {
		return nil, errors.New("trusted public key is not canonical lowercase Ed25519 hex")
	}
	return ed25519.PublicKey(key), nil
}

func privateKeyFromEnvironment(name string) (ed25519.PrivateKey, error) {
	if name == "" || name != strings.TrimSpace(name) {
		return nil, errors.New("private key environment name is invalid")
	}
	value := os.Getenv(name)
	if value == "" || value != strings.TrimSpace(value) {
		return nil, fmt.Errorf("private key environment %s is missing or non-canonical", name)
	}
	der, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, errors.New("private key is not canonical base64 PKCS#8")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("private key is not PKCS#8")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("private key is not Ed25519")
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}
