package dockerapp

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseComposeDocumentAcceptsBoundedLargeEnvironment(t *testing.T) {
	var document strings.Builder
	document.WriteString("services:\n  app:\n    image: example/app:latest\n    environment:\n")
	for index := 0; index < 40; index++ {
		document.WriteString(fmt.Sprintf("      - SETTING_%02d=value-%02d\n", index, index))
	}

	_, app, err := ParseComposeDocument(document.String(), "large-env", "generation-1", "")
	if err != nil {
		t.Fatalf("ParseComposeDocument() error = %v", err)
	}
	if len(app.SecretRefs) != 0 {
		t.Fatalf("ordinary environment settings produced secret refs: %v", app.SecretRefs)
	}
	if strings.Contains(app.Compose, "value-") {
		t.Fatal("ordinary environment values remained in persisted compose")
	}
}

func TestParseComposeDocumentTracksOnlySensitiveEnvironment(t *testing.T) {
	document := `services:
  app:
    image: example/app:latest
    environment:
      - DATABASE_PASSWORD=database-material
      - API_TOKEN=token-material
      - OAUTH_CLIENT_SECRET=oauth-material
      - TOTP_ENCRYPTION_KEY=totp-material
      - JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
      - PUBLIC_KEY=public-material
      - LOG_LEVEL=info
`

	_, app, err := ParseComposeDocument(document, "sensitive-env", "generation-1", "")
	if err != nil {
		t.Fatalf("ParseComposeDocument() error = %v", err)
	}
	want := []string{"API_TOKEN", "DATABASE_PASSWORD", "OAUTH_CLIENT_SECRET", "TOTP_ENCRYPTION_KEY"}
	if fmt.Sprint(app.SecretRefs) != fmt.Sprint(want) {
		t.Fatalf("secret refs = %v, want %v", app.SecretRefs, want)
	}
	for _, material := range []string{"database-material", "token-material", "oauth-material", "totp-material", "public-material"} {
		if strings.Contains(app.Compose, material) {
			t.Fatalf("persisted compose retained environment material %q", material)
		}
	}
}
