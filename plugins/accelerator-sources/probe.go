package acceleratorsources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MaxProbeRedirects     = 4
	MaxProbeResponseBytes = 64 << 10
	MaxProbeConcurrency   = 16
	MaxResolvedPerHop     = 16
	MaxProbeHops          = MaxProbeRedirects + 1
	DefaultProbeTimeout   = 5 * time.Second
)

type ProbeMethod string

const (
	ProbeHEAD ProbeMethod = "HEAD"
	ProbeGET  ProbeMethod = "GET"
)

type ProbePolicy struct {
	Method           ProbeMethod
	MaxRedirects     int
	MaxResponseBytes int64
	Timeout          time.Duration
	Concurrency      int
}

func DefaultProbePolicy() ProbePolicy {
	return ProbePolicy{Method: ProbeHEAD, MaxRedirects: 2, MaxResponseBytes: 4096, Timeout: DefaultProbeTimeout, Concurrency: 4}
}

func (policy ProbePolicy) validate() error {
	if (policy.Method != ProbeHEAD && policy.Method != ProbeGET) || policy.MaxRedirects < 0 || policy.MaxRedirects > MaxProbeRedirects || policy.MaxResponseBytes <= 0 || policy.MaxResponseBytes > MaxProbeResponseBytes || policy.Timeout <= 0 || policy.Timeout > DefaultProbeTimeout || policy.Concurrency <= 0 || policy.Concurrency > MaxProbeConcurrency {
		return ErrBoundExceeded
	}
	return nil
}

// ProbeRequest is a business adapter value, not a Host wire contract. A
// canonical typed NetworkProbe SDK handle may translate it only after enforcing
// these budgets at the broker boundary.
type ProbeRequest struct {
	SourceID         string
	URL              string
	Method           ProbeMethod
	MaxRedirects     int
	MaxResponseBytes int64
	Timeout          time.Duration
}

func (request ProbeRequest) Digest() string {
	wire, _ := json.Marshal(struct {
		SourceID         string      `json:"source_id"`
		URL              string      `json:"url"`
		Method           ProbeMethod `json:"method"`
		MaxRedirects     int         `json:"max_redirects"`
		MaxResponseBytes int64       `json:"max_response_bytes"`
		TimeoutNanos     int64       `json:"timeout_nanos"`
	}{request.SourceID, request.URL, request.Method, request.MaxRedirects, request.MaxResponseBytes, int64(request.Timeout)})
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

type ProbeHop struct {
	URL       string
	Resolved  []netip.Addr
	Connected netip.Addr
}

// ProbeObservation must be host-attested and complete. Connected is the
// address actually pinned for the request; Resolved is the broker-validated
// answer set immediately used for that connection.
type ProbeObservation struct {
	RequestDigest string
	Method        ProbeMethod
	RequestedURL  string
	FinalURL      string
	Hops          []ProbeHop
	StatusCode    int
	ResponseBytes int64
	Latency       time.Duration
	Attested      bool
	Complete      bool
}

type NetworkProbe interface {
	Probe(context.Context, ProbeRequest) (ProbeObservation, error)
}

type NetworkProbeFunc func(context.Context, ProbeRequest) (ProbeObservation, error)

func (function NetworkProbeFunc) Probe(ctx context.Context, request ProbeRequest) (ProbeObservation, error) {
	return function(ctx, request)
}

func CanonicalHTTPSURL(value string) (string, error) {
	if len(value) == 0 || len(value) > MaxSourceURLBytes || strings.TrimSpace(value) != value {
		return "", ErrInvalidSource
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" || parsed.Host == "" || parsed.Port() != "" {
		return "", ErrInvalidSource
	}
	hostname := parsed.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || strings.HasSuffix(hostname, ".") || !validPublicHostSyntax(hostname) {
		return "", ErrInvalidSource
	}
	wantHost := hostname
	if address, err := netip.ParseAddr(hostname); err == nil {
		address = address.Unmap()
		if !publicProbeAddress(address) {
			return "", ErrInvalidSource
		}
		if address.Is6() {
			wantHost = "[" + address.String() + "]"
		} else {
			wantHost = address.String()
		}
	}
	if parsed.Host != wantHost {
		return "", ErrInvalidSource
	}
	cleanPath := parsed.Path
	if cleanPath != "" {
		cleanPath = path.Clean(cleanPath)
		if cleanPath == "." {
			cleanPath = ""
		}
	}
	if parsed.Path == "/" || strings.HasSuffix(parsed.Path, "/") || parsed.Path != cleanPath || parsed.String() != value {
		return "", ErrInvalidSource
	}
	return value, nil
}

func validPublicHostSyntax(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return publicProbeAddress(address.Unmap())
	}
	if strings.IndexFunc(host, func(current rune) bool { return current != '.' && (current < '0' || current > '9') }) == -1 {
		return false
	}
	if len(host) > 253 || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, current := range label {
			if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
				return false
			}
		}
	}
	return true
}

var rejectedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func publicProbeAddress(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsInterfaceLocalMulticast() {
		return false
	}
	for _, prefix := range rejectedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.IsGlobalUnicast()
}

func ValidateProbeObservation(request ProbeRequest, observation ProbeObservation) error {
	if observation.RequestDigest != request.Digest() || !observation.Attested || !observation.Complete || observation.Method != request.Method || observation.RequestedURL != request.URL || len(observation.Hops) == 0 || len(observation.Hops) > request.MaxRedirects+1 || len(observation.Hops) > MaxProbeHops || observation.ResponseBytes < 0 || observation.ResponseBytes > request.MaxResponseBytes || observation.Latency < 0 || observation.Latency > request.Timeout || observation.StatusCode < 200 || observation.StatusCode >= 400 {
		return ErrProbeRejected
	}
	requested, err := CanonicalHTTPSURL(observation.RequestedURL)
	if err != nil || requested != request.URL {
		return ErrProbeRejected
	}
	final, err := CanonicalHTTPSURL(observation.FinalURL)
	if err != nil {
		return ErrProbeRejected
	}
	seenURLs := make(map[string]struct{}, len(observation.Hops))
	hostAnswers := make(map[string]string)
	for index, hop := range observation.Hops {
		canonical, err := CanonicalHTTPSURL(hop.URL)
		if err != nil || canonical != hop.URL || len(hop.Resolved) == 0 || len(hop.Resolved) > MaxResolvedPerHop || !publicProbeAddress(hop.Connected) {
			return ErrProbeRejected
		}
		if index == 0 && hop.URL != request.URL {
			return ErrProbeRejected
		}
		if _, duplicate := seenURLs[hop.URL]; duplicate {
			return ErrProbeRejected
		}
		seenURLs[hop.URL] = struct{}{}
		answers := make([]string, 0, len(hop.Resolved))
		connected := hop.Connected.Unmap()
		foundConnected := false
		seenAddresses := make(map[netip.Addr]struct{}, len(hop.Resolved))
		for _, address := range hop.Resolved {
			address = address.Unmap()
			if !publicProbeAddress(address) {
				return ErrProbeRejected
			}
			if _, duplicate := seenAddresses[address]; duplicate {
				return ErrProbeRejected
			}
			seenAddresses[address] = struct{}{}
			answers = append(answers, address.String())
			foundConnected = foundConnected || address == connected
		}
		if !foundConnected {
			return ErrProbeRejected
		}
		sort.Strings(answers)
		hopURL, _ := url.Parse(hop.URL)
		answerKey := strings.Join(answers, ",")
		if prior, exists := hostAnswers[hopURL.Hostname()]; exists && prior != answerKey {
			return ErrProbeRejected
		}
		hostAnswers[hopURL.Hostname()] = answerKey
	}
	if observation.Hops[len(observation.Hops)-1].URL != final {
		return ErrProbeRejected
	}
	return nil
}

type probeResult struct {
	observation ProbeObservation
	err         error
}

// ProbeEnabled schedules an isolated, bounded pass. A non-cooperative broker
// can leave at most policy.Concurrency calls in flight; the manager rejects a
// new pass until those calls return, preventing unbounded goroutine growth.
func (manager *Manager) ProbeEnabled(ctx context.Context, probe NetworkProbe, policy ProbePolicy) map[string]error {
	results := make(map[string]error)
	if probe == nil {
		results[""] = manager.denied(ctx, "probe-schedule", "", ErrTypedHandlesUnavailable)
		return results
	}
	if err := policy.validate(); err != nil {
		results[""] = manager.denied(ctx, "probe-schedule", "", err)
		return results
	}
	manager.probeMu.Lock()
	if manager.probeActive {
		manager.probeMu.Unlock()
		results[""] = manager.denied(ctx, "probe-schedule", "", ErrSchedulerBusy)
		return results
	}
	manager.probeActive = true
	manager.probeMu.Unlock()

	records := manager.Snapshot()
	jobs := make(chan Source)
	var workers sync.WaitGroup
	var brokerCalls sync.WaitGroup
	var activeBrokerCalls atomic.Int32
	var resultsMu sync.Mutex
	workerCount := policy.Concurrency
	if workerCount > len(records) {
		workerCount = len(records)
	}
	for index := 0; index < workerCount; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for source := range jobs {
				preflightCtx, preflightCancel := context.WithTimeout(context.Background(), time.Second)
				preflightErr := manager.auditAttempt(preflightCtx, "probe", "authorized", source.ID)
				if preflightErr == nil && manager.ui == nil {
					preflightErr = ErrDynamicUIRequired
				}
				preflightCancel()
				if preflightErr != nil {
					resultsMu.Lock()
					results[source.ID] = preflightErr
					resultsMu.Unlock()
					continue
				}
				request := ProbeRequest{SourceID: source.ID, URL: source.URL, Method: policy.Method, MaxRedirects: policy.MaxRedirects, MaxResponseBytes: policy.MaxResponseBytes, Timeout: policy.Timeout}
				callCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
				resultChannel := make(chan probeResult, 1)
				brokerCalls.Add(1)
				activeBrokerCalls.Add(1)
				go func() {
					defer brokerCalls.Done()
					defer activeBrokerCalls.Add(-1)
					observation, err := probe.Probe(callCtx, request)
					resultChannel <- probeResult{observation: observation, err: err}
				}()
				var result probeResult
				select {
				case result = <-resultChannel:
				case <-callCtx.Done():
					result.err = callCtx.Err()
				}
				cancel()
				status := SourceStatus{Availability: AvailabilityUnavailable, Failure: ProbeFailureTransport}
				returned := ErrProbeFailed
				if result.err != nil && errorsIsTimeout(result.err) {
					status.Failure = ProbeFailureTimeout
				} else if result.err == nil {
					if err := ValidateProbeObservation(request, result.observation); err != nil {
						status.Failure = ProbeFailureUntrusted
						returned = ErrProbeRejected
					} else {
						status.Availability = AvailabilityAvailable
						status.LatencyNanos = int64(result.observation.Latency)
						status.Failure = ProbeFailureNone
						returned = nil
					}
				}
				statusCtx, statusCancel := context.WithTimeout(context.Background(), time.Second)
				if err := manager.updateStatus(statusCtx, source.ID, status); err != nil {
					returned = err
				}
				statusCancel()
				resultsMu.Lock()
				results[source.ID] = returned
				resultsMu.Unlock()
			}
		}()
	}
	for _, record := range records {
		if record.Source.Enabled {
			jobs <- record.Source
		}
	}
	close(jobs)
	workers.Wait()
	clearActive := func() {
		manager.probeMu.Lock()
		manager.probeActive = false
		manager.probeMu.Unlock()
	}
	if activeBrokerCalls.Load() == 0 {
		clearActive()
	} else {
		go func() {
			brokerCalls.Wait()
			clearActive()
		}()
	}
	return results
}

func errorsIsTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
