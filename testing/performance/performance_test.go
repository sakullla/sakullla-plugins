package performance_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sakullla/sakullla-plugins/internal/ci/performance"
)

func TestPerformanceFixedCorpusWarmupAndThreeRounds(t *testing.T) {
	first := performance.FixedCorpus()
	second := performance.FixedCorpus()
	first[1].Body[0] = 'z'
	if len(first) != 256 || len(second) != 256 || first[1].Body[0] == second[1].Body[0] {
		t.Fatal("fixed corpus was not independently copied")
	}
	firstDigest, err := performance.CorpusDigest(performance.FixedCorpus())
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := performance.CorpusDigest(performance.FixedCorpus())
	if err != nil || firstDigest != secondDigest {
		t.Fatalf("fixed corpus digest mismatch: %s %s %v", firstDigest, secondDigest, err)
	}

	var disabledCalls, enabledCalls, created, closed atomic.Int64
	factory := func(calls *atomic.Int64) performance.WorkloadFactory {
		return func(context.Context) (performance.Workload, error) {
			created.Add(1)
			var instanceCalls int
			return &performance.WorkloadFuncs{
				RunFunc: func(context.Context, performance.Sample) error {
					instanceCalls++
					if instanceCalls > len(performance.FixedCorpus()) {
						return errors.New("lifecycle state carried over")
					}
					calls.Add(1)
					return nil
				},
				CloseFunc: func(context.Context) error { closed.Add(1); return nil },
			}, nil
		}
	}
	summary, err := performance.Run(context.Background(), performance.ProfileLocal, performance.CapabilityEvidence{},
		factory(&disabledCalls), factory(&enabledCalls),
	)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := int64((performance.WarmupPasses + performance.MeasurementRounds) * summary.CorpusSize)
	if disabledCalls.Load() != wantCalls || enabledCalls.Load() != wantCalls {
		t.Fatalf("workload calls disabled=%d enabled=%d want=%d", disabledCalls.Load(), enabledCalls.Load(), wantCalls)
	}
	if created.Load() != 8 || closed.Load() != 8 {
		t.Fatalf("isolated lifecycle counts created=%d closed=%d want=8", created.Load(), closed.Load())
	}
	if summary.WarmupPasses != 1 || len(summary.Rounds) != 3 || summary.EvidenceClass != "local-harness" || summary.Passed {
		t.Fatalf("local summary shape = %#v", summary)
	}
	for _, round := range summary.Rounds {
		if len(round.DisabledBaseline.RawSamplesNS) != summary.CorpusSize || len(round.Enabled.RawSamplesNS) != summary.CorpusSize {
			t.Fatalf("round %d raw sample counts are incomplete", round.Number)
		}
	}
	encoded, err := performance.MarshalSummary(summary)
	if err != nil || !strings.Contains(string(encoded), `"raw_samples_ns"`) || !strings.Contains(string(encoded), firstDigest) {
		t.Fatalf("raw summary output missing evidence: %v\n%s", err, encoded)
	}
}

func TestPerformanceReleaseCapabilityGateFailsBeforeWorkload(t *testing.T) {
	var calls atomic.Int32
	workload := func(context.Context) (performance.Workload, error) {
		calls.Add(1)
		return &performance.WorkloadFuncs{RunFunc: func(context.Context, performance.Sample) error { return nil }}, nil
	}
	tests := []performance.CapabilityEvidence{
		{},
		{RealAgent: true, AtomicState: true, MonotonicClock: true},
		{RealAgent: true, TrustedSource: true, MonotonicClock: true},
		{RealAgent: true, TrustedSource: true, AtomicState: true},
		{RealAgent: true, TrustedSource: true, AtomicState: true, MonotonicClock: true},
	}
	for _, evidence := range tests {
		_, err := performance.Run(context.Background(), performance.ProfileRelease, evidence, workload, workload)
		if !errors.Is(err, performance.ErrReleaseCapabilities) {
			t.Fatalf("release capability gate error = %v for %#v", err, evidence)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("release gate invoked workload %d time(s)", calls.Load())
	}
	if _, err := performance.Run(context.Background(), performance.ProfileRelease, performance.CapabilityEvidence{}, nil, nil); !errors.Is(err, performance.ErrReleaseCapabilities) {
		t.Fatalf("release gate did not precede workload validation: %v", err)
	}
}

func TestPerformanceLocalPolicyChainHarnessIsNotReleaseEvidence(t *testing.T) {
	summary, err := performance.RunLocalHarness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Profile != performance.ProfileLocal || summary.EvidenceClass != "local-harness" || summary.Passed {
		t.Fatalf("local policy chain summary claimed release evidence: %#v", summary)
	}
}

func TestPerformanceThresholdsApplyToEveryRound(t *testing.T) {
	passing := passingSummary()
	if err := performance.Evaluate(passing); err != nil {
		t.Fatalf("passing threshold summary failed: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*performance.Round)
		needle string
	}{
		{"throughput", func(round *performance.Round) { round.ThroughputRegression = 0.100001 }, "throughput"},
		{"p95", func(round *performance.Round) {
			round.Enabled.P95NS = round.DisabledBaseline.P95NS + int64(time.Millisecond) + 1
		}, "p95"},
		{"p99", func(round *performance.Round) {
			round.Enabled.P99NS = round.DisabledBaseline.P99NS + int64(2*time.Millisecond) + 1
		}, "p99"},
		{"memory", func(round *performance.Round) { round.AdditionalMemoryBytes = 64<<20 + 1 }, "memory"},
		{"raw", func(round *performance.Round) { round.Enabled.RawSamplesNS = nil }, "raw samples"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary := passingSummary()
			test.mutate(&summary.Rounds[1])
			err := performance.Evaluate(summary)
			if err == nil || !strings.Contains(err.Error(), test.needle) || !strings.Contains(err.Error(), "round 2") {
				t.Fatalf("threshold error = %v", err)
			}
		})
	}
}

func TestPerformanceLatencyUsesPositiveBaselineIncrement(t *testing.T) {
	summary := passingSummary()
	summary.Rounds[0].DisabledBaseline.P95NS = int64(5 * time.Millisecond)
	summary.Rounds[0].Enabled.P95NS = int64(6 * time.Millisecond)
	summary.Rounds[0].DisabledBaseline.P99NS = int64(7 * time.Millisecond)
	summary.Rounds[0].Enabled.P99NS = int64(9 * time.Millisecond)
	summary.Rounds[1].DisabledBaseline.P95NS = int64(10 * time.Millisecond)
	summary.Rounds[1].Enabled.P95NS = int64(2 * time.Millisecond)
	if err := performance.Evaluate(summary); err != nil {
		t.Fatalf("nonzero baseline boundary should pass: %v", err)
	}
}

func TestPerformanceRetainedMemoryIsMeasuredPerIsolatedLifecycle(t *testing.T) {
	factory := func(retained uint64) performance.WorkloadFactory {
		return func(context.Context) (performance.Workload, error) {
			retainedBuffer := make([]byte, int(retained))
			for offset := 0; offset < len(retainedBuffer); offset += 4096 {
				retainedBuffer[offset] = byte(offset)
			}
			return &performance.WorkloadFuncs{
				RunFunc:          func(context.Context, performance.Sample) error { return nil },
				CloseFunc:        func(context.Context) error { retainedBuffer = nil; return nil },
				SteadyMemoryFunc: func() uint64 { return uint64(len(retainedBuffer)) },
			}, nil
		}
	}
	summary, err := performance.Run(context.Background(), performance.ProfileLocal, performance.CapabilityEvidence{}, factory(1<<20), factory(66<<20))
	if err != nil {
		t.Fatal(err)
	}
	for _, round := range summary.Rounds {
		if round.AdditionalMemoryBytes != 65<<20 {
			t.Fatalf("round %d additional memory=%d", round.Number, round.AdditionalMemoryBytes)
		}
	}
	if err := performance.Evaluate(summary); err == nil || !strings.Contains(err.Error(), "memory") {
		t.Fatalf("retained allocation was not gated: %v", err)
	}
}

func TestPerformanceCloseUsesLiveBoundedContextAndJoinsRunError(t *testing.T) {
	primaryErr := errors.New("workload run failed")
	closeErr := errors.New("workload close failed")
	ctx, cancel := context.WithCancel(context.Background())
	closed := make(chan struct{})
	factory := func(context.Context) (performance.Workload, error) {
		return &performance.WorkloadFuncs{
			RunFunc: func(context.Context, performance.Sample) error {
				cancel()
				return primaryErr
			},
			CloseFunc: func(closeCtx context.Context) error {
				if closeCtx.Err() != nil {
					t.Fatalf("Close received canceled context: %v", closeCtx.Err())
				}
				if _, ok := closeCtx.Deadline(); !ok {
					t.Fatal("Close context is not bounded")
				}
				close(closed)
				return closeErr
			},
		}, nil
	}
	_, err := performance.Run(ctx, performance.ProfileLocal, performance.CapabilityEvidence{}, factory, factory)
	if !errors.Is(err, primaryErr) || !errors.Is(err, closeErr) {
		t.Fatalf("joined lifecycle error = %v", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not complete")
	}
}

func TestPerformanceCloseRunsAfterCancellationWithoutRunError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var runs atomic.Int32
	var closed atomic.Int32
	factory := func(context.Context) (performance.Workload, error) {
		return &performance.WorkloadFuncs{
			RunFunc: func(context.Context, performance.Sample) error {
				if runs.Add(1) == 1 {
					cancel()
				}
				return nil
			},
			CloseFunc: func(closeCtx context.Context) error {
				if closeCtx.Err() != nil {
					return errors.New("cleanup context was canceled")
				}
				closed.Add(1)
				return nil
			},
		}, nil
	}
	_, err := performance.Run(ctx, performance.ProfileLocal, performance.CapabilityEvidence{}, factory, factory)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if closed.Load() != 1 {
		t.Fatalf("Close calls = %d, want 1", closed.Load())
	}
}

func passingSummary() performance.Summary {
	rounds := make([]performance.Round, performance.MeasurementRounds)
	for index := range rounds {
		rounds[index] = performance.Round{
			Number:           index + 1,
			DisabledBaseline: performance.WorkloadMetrics{ThroughputPerSec: 1000, P95NS: int64(5 * time.Millisecond), P99NS: int64(7 * time.Millisecond), RawSamplesNS: []int64{100}},
			Enabled: performance.WorkloadMetrics{
				ThroughputPerSec: 900, P95NS: int64(6 * time.Millisecond), P99NS: int64(9 * time.Millisecond), RawSamplesNS: []int64{200},
			},
			ThroughputRegression:  0.10,
			AdditionalMemoryBytes: 64 << 20,
		}
	}
	return performance.Summary{Profile: performance.ProfileRelease, Rounds: rounds}
}
