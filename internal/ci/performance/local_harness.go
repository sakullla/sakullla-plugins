package performance

import (
	"bytes"
	"context"
	"sync/atomic"
)

// RunLocalHarness measures a deterministic in-process IP→rate→WAF facsimile.
// It is useful for runner/corpus regression only and can never produce release
// evidence; a real Agent must supply both release workloads to Run.
func RunLocalHarness(ctx context.Context) (Summary, error) {
	disabled := func(context.Context) (Workload, error) {
		return &WorkloadFuncs{RunFunc: func(ctx context.Context, _ Sample) error { return ctx.Err() }}, nil
	}
	enabled := func(context.Context) (Workload, error) {
		var counters [1024]atomic.Uint64
		return &WorkloadFuncs{RunFunc: func(ctx context.Context, sample Sample) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Fixed local harness order: source/IP projection, rate state, then WAF
			// body inspection. Results are consumed locally to prevent optimization.
			index := sourceBucket(sample.Source)
			count := counters[index].Add(1)
			blocked := bytes.Contains(sample.Body, []byte("<script"))
			localSink.Store(uint64(index) ^ count ^ boolBit(blocked))
			return nil
		}}, nil
	}
	return Run(ctx, ProfileLocal, CapabilityEvidence{}, disabled, enabled)
}

var localSink atomic.Uint64

func sourceBucket(source string) uint64 {
	const offset64 = uint64(14695981039346656037)
	const prime64 = uint64(1099511628211)
	hash := offset64
	for index := range len(source) {
		hash ^= uint64(source[index])
		hash *= prime64
	}
	return hash % 1024
}

func boolBit(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
