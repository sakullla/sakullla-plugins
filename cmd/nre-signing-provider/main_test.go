package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestKeygenProducesMatchingPKCS8AndPublicIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "keys")
	var output bytes.Buffer
	if err := run([]string{"keygen", "--output", root}, bytes.NewReader(nil), &output); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "private-key.pkcs8.base64"))
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := parsed.(ed25519.PrivateKey)
	public, err := os.ReadFile(filepath.Join(root, "public-key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(bytes.TrimSpace(public)), hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)); got != want {
		t.Fatalf("public key = %s, want %s", got, want)
	}
	if err := run([]string{"keygen", "--output", root}, bytes.NewReader(nil), &output); err == nil {
		t.Fatal("keygen overwrote an existing private key")
	}
}

func TestSignUsesPKCS8SecretWithoutEmittingIt(t *testing.T) {
	seed := bytes.Repeat([]byte{0x19}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NRE_TEST_SIGNING_KEY", base64.StdEncoding.EncodeToString(der))
	digest := bytes.Repeat([]byte{0x7f}, 32)
	request, _ := json.Marshal(map[string]string{
		"digest_sha256": base64.StdEncoding.EncodeToString(digest),
		"identity":      "sakullla-official-root-2026",
	})
	var output bytes.Buffer
	if err := run([]string{"sign", "--key-env", "NRE_TEST_SIGNING_KEY"}, bytes.NewReader(request), &output); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Algorithm string `json:"algorithm"`
		Identity  string `json:"identity"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(response.Signature)
	if err != nil || response.Algorithm != "ed25519" || response.Identity != "sakullla-official-root-2026" {
		t.Fatalf("unexpected signer response: %#v %v", response, err)
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), digest, signature) {
		t.Fatal("provider returned an invalid signature")
	}
	if bytes.Contains(output.Bytes(), []byte(os.Getenv("NRE_TEST_SIGNING_KEY"))) {
		t.Fatal("provider emitted private key material")
	}
}

func TestPublicKeyFileIsCanonical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "official.hex")
	want := bytes.Repeat([]byte{0x31}, ed25519.PublicKeySize)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(want)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := publicKeyFromFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("public key = %x, want %x: %v", got, want, err)
	}
	if err := os.WriteFile(path, []byte("not-a-key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publicKeyFromFile(path); err == nil {
		t.Fatal("invalid public key was accepted")
	}
}
