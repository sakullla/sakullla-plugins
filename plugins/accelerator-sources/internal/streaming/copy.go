// Package streaming owns the response-copy boundary shared by accelerator
// handlers. It deliberately does not buffer response bodies.
package streaming

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

var (
	ErrLengthMismatch = errors.New("stream length mismatch")
	ErrDigestMismatch = errors.New("stream digest mismatch")
	ErrDigestInvalid  = errors.New("stream digest is invalid")
)

// CopyOptions declares integrity information known before a stream starts.
// ExpectedLength may be -1 when the upstream did not advertise a length.
type CopyOptions struct {
	ExpectedLength int64
	ExpectedDigest string
	Flush          func() error
}

// Copy copies src once, hashing bytes while they are written. It never writes
// an error representation to dst, so a failed binary response cannot have a
// JSON or text error concatenated to it.
func Copy(dst io.Writer, src io.Reader, options CopyOptions) (int64, error) {
	hasher, expected, err := digestHasher(options.ExpectedDigest)
	if err != nil {
		return 0, err
	}
	writers := []io.Writer{dst}
	if hasher != nil {
		writers = append(writers, hasher)
	}
	writer := io.MultiWriter(writers...)
	if options.Flush != nil {
		writer = flushingWriter{writer: writer, flush: options.Flush}
	}
	written, err := io.CopyBuffer(writer, src, make([]byte, 32*1024))
	if err != nil {
		return written, err
	}
	if options.ExpectedLength >= 0 && written != options.ExpectedLength {
		return written, fmt.Errorf("%w: got %d bytes, want %d", ErrLengthMismatch, written, options.ExpectedLength)
	}
	if hasher != nil && !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), expected) {
		return written, ErrDigestMismatch
	}
	return written, nil
}

// FlushFunc returns a best-effort response flush operation.
func FlushFunc(writer http.ResponseWriter) func() error {
	return func() error {
		return http.NewResponseController(writer).Flush()
	}
}

type flushingWriter struct {
	writer io.Writer
	flush  func() error
}

func (writer flushingWriter) Write(value []byte) (int, error) {
	written, err := writer.writer.Write(value)
	if err != nil {
		return written, err
	}
	if err := writer.flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return written, err
	}
	return written, nil
}

func digestHasher(value string) (hash.Hash, string, error) {
	if value == "" {
		return nil, "", nil
	}
	algorithm, encoded, found := strings.Cut(value, ":")
	if !found || algorithm != "sha256" || len(encoded) != sha256.Size*2 {
		return nil, "", ErrDigestInvalid
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return nil, "", ErrDigestInvalid
	}
	return sha256.New(), encoded, nil
}
