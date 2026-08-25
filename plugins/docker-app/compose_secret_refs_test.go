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
	if len(app.SecretRefs) != 40 {
		t.Fatalf("secret refs = %d, want 40", len(app.SecretRefs))
	}
}
