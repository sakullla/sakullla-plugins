// Package performance implements the reproducible local measurement harness
// and the stricter real-Agent release evidence gate.
package performance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Profile string

const (
	ProfileLocal   Profile = "local"
	ProfileRelease Profile = "release"

	WarmupPasses      = 1
	MeasurementRounds = 3

	MaxThroughputRegression  = 0.10
	MaxP95Latency            = time.Millisecond
	MaxP99Latency            = 2 * time.Millisecond
	MaxAdditionalMemoryBytes = uint64(64 << 20)
	WorkloadCloseTimeout     = time.Second
)

var ErrReleaseCapabilities = errors.New("real Agent release capabilities are incomplete")

type CapabilityEvidence struct {
	RealAgent      bool `json:"real_agent"`
	TrustedSource  bool `json:"trusted_source"`
	AtomicState    bool `json:"atomic_state"`
	MonotonicClock bool `json:"monotonic_clock"`
	// verified is intentionally not externally constructible or decodable.
	// The current repository has no canonical real-Agent evidence adapter.
	verified bool
}

func (evidence CapabilityEvidence) ValidateRelease() error {
	var missing []string
	if !evidence.RealAgent {
		missing = append(missing, "real-agent")
	}
	if !evidence.verified {
		missing = append(missing, "verified-real-agent-evidence")
	}
	if !evidence.TrustedSource {
		missing = append(missing, "policy.trusted-source")
	}
	if !evidence.AtomicState {
		missing = append(missing, "policy.atomic-state")
	}
	if !evidence.MonotonicClock {
		missing = append(missing, "policy.monotonic-clock")
	}
	if len(missing) != 0 {
		return fmt.Errorf("%w: %s", ErrReleaseCapabilities, strings.Join(missing, ", "))
	}
	return nil
}

type Sample struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Body   []byte `json:"body"`
}

// FixedCorpus returns a fresh copy of the immutable 256-sample corpus.
func FixedCorpus() []Sample {
	result := make([]Sample, 256)
	methods := [...]string{"GET", "POST", "HEAD", "PUT"}
	paths := [...]string{"/", "/api/items", "/stream/segment", "/admin/login", "/health"}
	for index := range result {
		bodySize := index % 97
		body := make([]byte, bodySize)
		for offset := range body {
			body[offset] = byte('a' + (index+offset)%26)
		}
		result[index] = Sample{
			ID: fmt.Sprintf("sample-%03d", index), Source: fmt.Sprintf("192.0.2.%d", index%250+1),
			Path: paths[index%len(paths)], Method: methods[index%len(methods)], Body: body,
		}
	}
	return result
}

func CorpusDigest(corpus []Sample) (string, error) {
	encoded, err := json.Marshal(corpus)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Workload is one isolated disabled or enabled lifecycle. A factory must
// return a fresh instance for warmup and for every measured round.
type Workload interface {
	Run(context.Context, Sample) error
	Close(context.Context) error
	SteadyMemoryBytes() uint64
}

type WorkloadFactory func(context.Context) (Workload, error)

// WorkloadFuncs is a small adapter for deterministic harnesses and tests.
type WorkloadFuncs struct {
	RunFunc          func(context.Context, Sample) error
	CloseFunc        func(context.Context) error
	SteadyMemoryFunc func() uint64
}

func (workload *WorkloadFuncs) Run(ctx context.Context, sample Sample) error {
	return workload.RunFunc(ctx, sample)
}

func (workload *WorkloadFuncs) Close(ctx context.Context) error {
	if workload.CloseFunc == nil {
		return nil
	}
	return workload.CloseFunc(ctx)
}

func (workload *WorkloadFuncs) SteadyMemoryBytes() uint64 {
	if workload.SteadyMemoryFunc == nil {
		return 0
	}
	return workload.SteadyMemoryFunc()
}

type WorkloadMetrics struct {
	Operations        int     `json:"operations"`
	ElapsedNS         int64   `json:"elapsed_ns"`
	ThroughputPerSec  float64 `json:"throughput_per_sec"`
	P95NS             int64   `json:"p95_ns"`
	P99NS             int64   `json:"p99_ns"`
	SteadyMemoryBytes uint64  `json:"steady_memory_bytes"`
	RawSamplesNS      []int64 `json:"raw_samples_ns"`
}

type Round struct {
	Number                int             `json:"number"`
	DisabledBaseline      WorkloadMetrics `json:"disabled_baseline"`
	Enabled               WorkloadMetrics `json:"enabled"`
	ThroughputRegression  float64         `json:"throughput_regression"`
	AdditionalMemoryBytes uint64          `json:"additional_memory_bytes"`
}

type Summary struct {
	Profile       Profile            `json:"profile"`
	EvidenceClass string             `json:"evidence_class"`
	Capabilities  CapabilityEvidence `json:"capabilities"`
	CorpusSHA256  string             `json:"corpus_sha256"`
	CorpusSize    int                `json:"corpus_size"`
	WarmupPasses  int                `json:"warmup_passes"`
	Rounds        []Round            `json:"rounds"`
	Passed        bool               `json:"passed"`
}

// Run executes one disabled/candidate warmup pair and exactly three measured
// disabled/candidate pairs. Local results are reproducible harness evidence,
// never release evidence. Release rejects missing real Agent capabilities
// before invoking either workload.
func Run(ctx context.Context, profile Profile, evidence CapabilityEvidence, disabled, enabled WorkloadFactory) (Summary, error) {
	summary := Summary{Profile: profile, Capabilities: evidence, WarmupPasses: WarmupPasses}
	switch profile {
	case ProfileLocal:
		summary.EvidenceClass = "local-harness"
	case ProfileRelease:
		summary.EvidenceClass = "real-agent-release"
		if err := evidence.ValidateRelease(); err != nil {
			return summary, err
		}
	default:
		return summary, fmt.Errorf("unknown performance profile %q", profile)
	}
	if disabled == nil || enabled == nil {
		return summary, errors.New("disabled and enabled workloads are required")
	}

	corpus := FixedCorpus()
	digest, err := CorpusDigest(corpus)
	if err != nil {
		return summary, err
	}
	summary.CorpusSHA256 = digest
	summary.CorpusSize = len(corpus)
	if err := executeWarmup(ctx, corpus, disabled, enabled); err != nil {
		return summary, err
	}
	for number := 1; number <= MeasurementRounds; number++ {
		baseline, err := measureLifecycle(ctx, corpus, disabled)
		if err != nil {
			return summary, fmt.Errorf("round %d disabled baseline: %w", number, err)
		}
		candidate, err := measureLifecycle(ctx, corpus, enabled)
		if err != nil {
			return summary, fmt.Errorf("round %d enabled: %w", number, err)
		}
		regression := 0.0
		if baseline.ThroughputPerSec > 0 && candidate.ThroughputPerSec < baseline.ThroughputPerSec {
			regression = (baseline.ThroughputPerSec - candidate.ThroughputPerSec) / baseline.ThroughputPerSec
		}
		additionalMemory := uint64(0)
		if candidate.SteadyMemoryBytes > baseline.SteadyMemoryBytes {
			additionalMemory = candidate.SteadyMemoryBytes - baseline.SteadyMemoryBytes
		}
		summary.Rounds = append(summary.Rounds, Round{
			Number: number, DisabledBaseline: baseline, Enabled: candidate,
			ThroughputRegression: regression, AdditionalMemoryBytes: additionalMemory,
		})
	}
	if profile == ProfileLocal {
		return summary, nil
	}
	if err := Evaluate(summary); err != nil {
		return summary, err
	}
	summary.Passed = true
	return summary, nil
}

func executeWarmup(ctx context.Context, corpus []Sample, factories ...WorkloadFactory) error {
	for _, factory := range factories {
		if _, err := runLifecycle(ctx, corpus, factory, false); err != nil {
			return fmt.Errorf("warmup: %w", err)
		}
	}
	return nil
}

func measureLifecycle(ctx context.Context, corpus []Sample, factory WorkloadFactory) (WorkloadMetrics, error) {
	return runLifecycle(ctx, corpus, factory, true)
}

func runLifecycle(ctx context.Context, corpus []Sample, factory WorkloadFactory, measured bool) (metrics WorkloadMetrics, resultErr error) {
	workload, err := factory(ctx)
	if err != nil {
		return metrics, fmt.Errorf("create workload: %w", err)
	}
	if workload == nil {
		return metrics, errors.New("factory returned a nil workload")
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), WorkloadCloseTimeout)
		defer cancel()
		if err := workload.Close(closeCtx); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close workload: %w", err))
		}
	}()
	metrics, resultErr = executeLifecycle(ctx, corpus, workload, measured)
	return metrics, resultErr
}

func executeLifecycle(ctx context.Context, corpus []Sample, workload Workload, measured bool) (WorkloadMetrics, error) {
	runtime.GC()
	latencies := make([]int64, 0, len(corpus))
	started := time.Now()
	for _, sample := range corpus {
		if err := ctx.Err(); err != nil {
			return WorkloadMetrics{}, err
		}
		operationStarted := time.Now()
		if err := workload.Run(ctx, cloneSample(sample)); err != nil {
			return WorkloadMetrics{}, fmt.Errorf("sample %s: %w", sample.ID, err)
		}
		latencies = append(latencies, time.Since(operationStarted).Nanoseconds())
	}
	elapsed := time.Since(started)
	runtime.GC()
	metrics := WorkloadMetrics{
		Operations: len(corpus), ElapsedNS: elapsed.Nanoseconds(), SteadyMemoryBytes: workload.SteadyMemoryBytes(),
		RawSamplesNS: append([]int64(nil), latencies...),
	}
	if !measured {
		return metrics, nil
	}
	if elapsed > 0 {
		metrics.ThroughputPerSec = float64(len(corpus)) / elapsed.Seconds()
	}
	metrics.P95NS = percentile(latencies, 0.95)
	metrics.P99NS = percentile(latencies, 0.99)
	return metrics, nil
}

func percentile(samples []int64, quantile float64) int64 {
	if len(samples) == 0 {
		return 0
	}
	ordered := append([]int64(nil), samples...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	index := int(float64(len(ordered))*quantile+0.999999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return ordered[index]
}

func cloneSample(sample Sample) Sample {
	sample.Body = append([]byte(nil), sample.Body...)
	return sample
}

type ThresholdError struct {
	Violations []string
}

func (failure *ThresholdError) Error() string {
	return "performance release gate failed: " + strings.Join(failure.Violations, "; ")
}

// Evaluate applies the non-configurable release thresholds to every round.
func Evaluate(summary Summary) error {
	var violations []string
	if len(summary.Rounds) != MeasurementRounds {
		violations = append(violations, fmt.Sprintf("got %d rounds, want %d", len(summary.Rounds), MeasurementRounds))
	}
	for _, round := range summary.Rounds {
		if round.ThroughputRegression > MaxThroughputRegression {
			violations = append(violations, fmt.Sprintf("round %d throughput regression %.4f > %.2f", round.Number, round.ThroughputRegression, MaxThroughputRegression))
		}
		p95Increment := positiveDurationDelta(round.Enabled.P95NS, round.DisabledBaseline.P95NS)
		if p95Increment > MaxP95Latency {
			violations = append(violations, fmt.Sprintf("round %d p95 increment %s > %s", round.Number, p95Increment, MaxP95Latency))
		}
		p99Increment := positiveDurationDelta(round.Enabled.P99NS, round.DisabledBaseline.P99NS)
		if p99Increment > MaxP99Latency {
			violations = append(violations, fmt.Sprintf("round %d p99 increment %s > %s", round.Number, p99Increment, MaxP99Latency))
		}
		if round.AdditionalMemoryBytes > MaxAdditionalMemoryBytes {
			violations = append(violations, fmt.Sprintf("round %d additional memory %d > %d", round.Number, round.AdditionalMemoryBytes, MaxAdditionalMemoryBytes))
		}
		if len(round.DisabledBaseline.RawSamplesNS) == 0 || len(round.Enabled.RawSamplesNS) == 0 {
			violations = append(violations, fmt.Sprintf("round %d raw samples are missing", round.Number))
		}
	}
	if len(violations) != 0 {
		return &ThresholdError{Violations: violations}
	}
	return nil
}

func positiveDurationDelta(enabled, baseline int64) time.Duration {
	if enabled <= baseline {
		return 0
	}
	return time.Duration(enabled - baseline)
}

func MarshalSummary(summary Summary) ([]byte, error) {
	return json.MarshalIndent(summary, "", "  ")
}
