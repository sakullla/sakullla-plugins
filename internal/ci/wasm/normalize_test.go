package wasm

import (
	"bytes"
	"testing"
)

func TestNormalizeEmptyFunctionTable(t *testing.T) {
	module := append([]byte(nil), moduleHeader...)
	module = append(module, 0x04, 0x05, 0x01, 0x70, 0x01, 0x01, 0x01)
	normalized, err := NormalizeEmptyFunctionTable(module)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(normalized, moduleHeader) {
		t.Fatalf("normalized module = %x", normalized)
	}
}

func TestNormalizeRejectsNonEmptyTable(t *testing.T) {
	module := append([]byte(nil), moduleHeader...)
	module = append(module, 0x04, 0x04, 0x01, 0x70, 0x00, 0x02)
	if _, err := NormalizeEmptyFunctionTable(module); err == nil {
		t.Fatal("expected non-empty table rejection")
	}
}

func TestNormalizeRejectsElementSegment(t *testing.T) {
	module := append([]byte(nil), moduleHeader...)
	module = append(module, 0x04, 0x05, 0x01, 0x70, 0x01, 0x01, 0x01)
	module = append(module, 0x09, 0x01, 0x00)
	if _, err := NormalizeEmptyFunctionTable(module); err == nil {
		t.Fatal("expected element segment rejection")
	}
}
