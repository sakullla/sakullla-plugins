package streaming

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRegistryStreamingValidatesLengthAndDigest(t *testing.T) {
	body := bytes.Repeat([]byte("registry-layer-"), 128*1024)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	var destination bytes.Buffer
	written, err := Copy(&destination, bytes.NewReader(body), CopyOptions{ExpectedLength: int64(len(body)), ExpectedDigest: digest})
	if err != nil {
		t.Fatalf("copy registry layer: %v", err)
	}
	if written != int64(len(body)) || !bytes.Equal(destination.Bytes(), body) {
		t.Fatal("streamed body was duplicated or truncated")
	}
}

func TestRegistryStreamingFailureDoesNotAppendErrorContent(t *testing.T) {
	const prefix = "partial-registry-layer"
	var destination bytes.Buffer
	_, err := Copy(&destination, strings.NewReader(prefix), CopyOptions{ExpectedLength: int64(len(prefix) + 10)})
	if !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("expected length mismatch, got %v", err)
	}
	if destination.String() != prefix {
		t.Fatalf("failure appended content: %q", destination.String())
	}
}
