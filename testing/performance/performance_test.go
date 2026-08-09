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

	var disabledCalls atomic.Int64
	var enabledCalls atomic.Int64
	summary, err := performance.Run(context.Background(), performance.ProfileLocal, performance.CapabilityEvidence{},
		func(context.Context, performance.Sample) error { disabledCalls.Add(1); return nil },
		func(context.Context, performance.Sample) error { enabledCalls.Add(1); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := int64((performance.WarmupPasses + performance.MeasurementRounds) * summary.CorpusSize)
	if disabledCalls.Load() != wantCalls || enabledCalls.Load() != wantCalls {
		t.Fatalf("workload calls disabled=%d enabled=%d want=%d", disabledCalls.Load(), enabledCalls.Load(), wantCalls)
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
	workload := func(context.Context, performance.Sample) error { calls.Add(1); return nil }
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
		{"p95", func(round *performance.Round) { round.Enabled.P95NS = int64(time.Millisecond + 1) }, "p95"},
		{"p99", func(round *performance.Round) { round.Enabled.P99NS = int64(2*time.Millisecond + 1) }, "p99"},
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

func passingSummary() performance.Summary {
	rounds := make([]performance.Round, performance.MeasurementRounds)
	for index := range rounds {
		rounds[index] = performance.Round{
			Number:           index + 1,
			DisabledBaseline: performance.WorkloadMetrics{ThroughputPerSec: 1000, RawSamplesNS: []int64{100}},
			Enabled: performance.WorkloadMetrics{
				ThroughputPerSec: 900, P95NS: int64(time.Millisecond), P99NS: int64(2 * time.Millisecond), RawSamplesNS: []int64{200},
			},
			ThroughputRegression:  0.10,
			AdditionalMemoryBytes: 64 << 20,
		}
	}
	return performance.Summary{Profile: performance.ProfileRelease, Rounds: rounds}
}
