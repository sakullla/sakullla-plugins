package rpcplugin

import (
	"context"
	"strings"
	"sync"
)

// Record is process-local structured telemetry. It intentionally does not
// claim to be an upstream Host log/status ABI.
type Record struct {
	Level   string
	Message string
	Fields  map[string]string
}

// LogSink receives records only after secret redaction.
type LogSink interface {
	WriteLog(context.Context, Record)
}

type LogSinkFunc func(context.Context, Record)

func (function LogSinkFunc) WriteLog(ctx context.Context, record Record) {
	function(ctx, record)
}

// Redactor owns copies of sensitive byte sequences for one generation.
type Redactor struct {
	mu      sync.RWMutex
	secrets [][]byte
}

func NewRedactor() *Redactor { return &Redactor{} }

func (redactor *Redactor) Add(secret []byte) {
	if redactor == nil || len(secret) == 0 {
		return
	}
	redactor.mu.Lock()
	redactor.secrets = append(redactor.secrets, append([]byte(nil), secret...))
	redactor.mu.Unlock()
}

func (redactor *Redactor) Text(value string) string {
	if redactor == nil || value == "" {
		return value
	}
	redactor.mu.RLock()
	defer redactor.mu.RUnlock()
	for _, secret := range redactor.secrets {
		if len(secret) > 0 {
			value = strings.ReplaceAll(value, string(secret), "[REDACTED]")
		}
	}
	return value
}

func (redactor *Redactor) Sanitize(record Record) Record {
	record.Message = redactor.Text(record.Message)
	record.Fields = cloneFields(record.Fields)
	for key, value := range record.Fields {
		record.Fields[key] = redactor.Text(value)
	}
	return record
}

type SafeLogger struct {
	sink     LogSink
	redactor *Redactor
}

func (logger SafeLogger) Log(ctx context.Context, record Record) {
	if logger.sink == nil {
		return
	}
	logger.sink.WriteLog(ctx, logger.redactor.Sanitize(record))
}

func cloneFields(fields map[string]string) map[string]string {
	result := make(map[string]string, len(fields)+1)
	for key, value := range fields {
		result[key] = value
	}
	return result
}
