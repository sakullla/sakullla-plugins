// Package wasm contains deterministic post-link normalization for policy artifacts.
package wasm

import (
	"bytes"
	"errors"
	"fmt"
)

var moduleHeader = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

// NormalizeEmptyFunctionTable removes the empty one-slot function table that
// rust-lld emits for no_std cdylibs. Non-empty tables and modules with element
// segments are rejected. The caller must still run the canonical SDK validator
// over the returned module.
func NormalizeEmptyFunctionTable(module []byte) ([]byte, error) {
	if len(module) < len(moduleHeader) || !bytes.Equal(module[:len(moduleHeader)], moduleHeader) {
		return nil, errors.New("invalid WebAssembly version 1 header")
	}
	output := append([]byte(nil), moduleHeader...)
	offset := len(moduleHeader)
	removed := false
	for offset < len(module) {
		sectionStart := offset
		sectionID := module[offset]
		offset++
		sectionSize, width, err := readU32(module[offset:])
		if err != nil {
			return nil, fmt.Errorf("section %d size: %w", sectionID, err)
		}
		offset += width
		sectionEnd := offset + int(sectionSize)
		if sectionEnd < offset || sectionEnd > len(module) {
			return nil, fmt.Errorf("section %d exceeds module", sectionID)
		}
		section := module[offset:sectionEnd]
		switch sectionID {
		case 4:
			if removed {
				return nil, errors.New("multiple WebAssembly table sections")
			}
			if !isRustEmptyFunctionTable(section) {
				return nil, errors.New("WebAssembly function table is not empty")
			}
			removed = true
		case 9:
			return nil, errors.New("WebAssembly element segments require a function table")
		default:
			output = append(output, module[sectionStart:sectionEnd]...)
		}
		offset = sectionEnd
	}
	if !removed {
		return append([]byte(nil), module...), nil
	}
	return output, nil
}

func isRustEmptyFunctionTable(section []byte) bool {
	// vector length 1, funcref, limits with maximum, min=1, max=1.
	return bytes.Equal(section, []byte{0x01, 0x70, 0x01, 0x01, 0x01})
}

func readU32(input []byte) (uint32, int, error) {
	var value uint32
	for index := 0; index < 5; index++ {
		if index >= len(input) {
			return 0, 0, errors.New("truncated unsigned LEB128")
		}
		current := input[index]
		if index == 4 && current > 0x0f {
			return 0, 0, errors.New("unsigned LEB128 overflows u32")
		}
		value |= uint32(current&0x7f) << (7 * index)
		if current&0x80 == 0 {
			return value, index + 1, nil
		}
	}
	return 0, 0, errors.New("unsigned LEB128 is too long")
}
