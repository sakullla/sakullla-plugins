package release

import (
	"strings"
	"testing"
)

func TestSignatureProviderRequiresExternalOfficialIdentity(t *testing.T) {
	t.Setenv("NRE_TEST_PROVIDER", `{"command":"hsm-sign","identity":"test-key","validator_command":"nre-validator"}`)
	if _, _, err := LoadProvider("env:NRE_TEST_PROVIDER"); err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("test identity entered official path: %v", err)
	}
	t.Setenv("NRE_TEST_PROVIDER", `{"command":"hsm-sign","identity":"sakullla-official-root-2026","validator_command":"nre-validator","private_key":"secret"}`)
	if _, _, err := LoadProvider("env:NRE_TEST_PROVIDER"); err == nil {
		t.Fatal("inline private-key field was accepted")
	}
	t.Setenv("NRE_TEST_PROVIDER", `{"command":"hsm-sign","identity":"sakullla-official-root-2026","validator_command":"nre-validator"}`)
	signer, validator, err := LoadProvider("env:NRE_TEST_PROVIDER")
	if err != nil || signer.Identity != "sakullla-official-root-2026" || validator.Command != "nre-validator" {
		t.Fatalf("valid provider config rejected: %#v %#v %v", signer, validator, err)
	}
}
