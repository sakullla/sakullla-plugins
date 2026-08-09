package acceleratorsources_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	acceleratorsources "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources"
)

func TestHTTPSCanonicalizationAndSSRFRejection(t *testing.T) {
	for _, accepted := range []string{
		"https://mirror.example.com",
		"https://mirror.example.com/base",
		"https://8.8.8.8",
		"https://[2606:4700:4700::1111]",
	} {
		if got, err := acceleratorsources.CanonicalHTTPSURL(accepted); err != nil || got != accepted {
			t.Fatalf("canonical URL %q => %q, %v", accepted, got, err)
		}
	}
	for _, rejected := range []string{
		"http://mirror.example.com",
		"https://Mirror.example.com",
		"https://mirror.example.com/",
		"https://mirror.example.com/a/../b",
		"https://mirror.example.com:443",
		"https://user:secret@mirror.example.com",
		"https://mirror.example.com/path?token=secret",
		"https://mirror.example.com/path#fragment",
		"https://localhost",
		"https://service.internal",
		"https://127.0.0.1",
		"https://127.1",
		"https://10.0.0.1",
		"https://169.254.1.1",
		"https://100.64.0.1",
		"https://192.0.2.1",
		"https://[::1]",
		"https://[2001:db8::1]",
	} {
		if _, err := acceleratorsources.CanonicalHTTPSURL(rejected); !errors.Is(err, acceleratorsources.ErrInvalidSource) {
			t.Fatalf("unsafe URL %q accepted: %v", rejected, err)
		}
	}
}

func TestProbeAttestationSSRFRebindingAndBudgets(t *testing.T) {
	request := acceleratorsources.ProbeRequest{SourceID: "mirror", URL: "https://mirror.example.com", Method: acceleratorsources.ProbeHEAD, MaxRedirects: 2, MaxResponseBytes: 4096, Timeout: time.Second}
	publicA := netip.MustParseAddr("1.1.1.1")
	valid := acceleratorsources.ProbeObservation{
		RequestDigest: request.Digest(), Method: request.Method, RequestedURL: request.URL, FinalURL: request.URL,
		Hops:       []acceleratorsources.ProbeHop{{URL: request.URL, Resolved: []netip.Addr{publicA}, Connected: publicA, StatusCode: 204}},
		StatusCode: 204, Latency: 10 * time.Millisecond, Attested: true, Complete: true,
	}
	if err := acceleratorsources.ValidateProbeObservation(request, valid); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
	mutate := func(change func(*acceleratorsources.ProbeObservation)) acceleratorsources.ProbeObservation {
		copy := valid
		copy.Hops = append([]acceleratorsources.ProbeHop(nil), valid.Hops...)
		copy.Hops[0].Resolved = append([]netip.Addr(nil), valid.Hops[0].Resolved...)
		change(&copy)
		return copy
	}
	private := netip.MustParseAddr("10.0.0.9")
	publicB := netip.MustParseAddr("8.8.8.8")
	for name, observation := range map[string]acceleratorsources.ProbeObservation{
		"unattested":    mutate(func(value *acceleratorsources.ProbeObservation) { value.Attested = false }),
		"incomplete":    mutate(func(value *acceleratorsources.ProbeObservation) { value.Complete = false }),
		"request-drift": mutate(func(value *acceleratorsources.ProbeObservation) { value.RequestDigest = strings.Repeat("0", 64) }),
		"private-answer": mutate(func(value *acceleratorsources.ProbeObservation) {
			value.Hops[0].Resolved = []netip.Addr{private}
			value.Hops[0].Connected = private
		}),
		"rebound-connected": mutate(func(value *acceleratorsources.ProbeObservation) { value.Hops[0].Connected = publicB }),
		"oversize":          mutate(func(value *acceleratorsources.ProbeObservation) { value.ResponseBytes = request.MaxResponseBytes + 1 }),
		"late":              mutate(func(value *acceleratorsources.ProbeObservation) { value.Latency = request.Timeout + 1 }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := acceleratorsources.ValidateProbeObservation(request, observation); !errors.Is(err, acceleratorsources.ErrProbeRejected) {
				t.Fatalf("unsafe observation accepted: %v", err)
			}
		})
	}

	rebound := valid
	rebound.FinalURL = "https://mirror.example.com/next"
	rebound.Hops = []acceleratorsources.ProbeHop{
		{URL: request.URL, Resolved: []netip.Addr{publicA}, Connected: publicA, StatusCode: 302, RedirectTo: rebound.FinalURL},
		{URL: rebound.FinalURL, Resolved: []netip.Addr{publicB}, Connected: publicB, StatusCode: 204},
	}
	if err := acceleratorsources.ValidateProbeObservation(request, rebound); !errors.Is(err, acceleratorsources.ErrProbeRejected) {
		t.Fatalf("same-host DNS rebinding accepted: %v", err)
	}

	redirectPrivate := valid
	redirectPrivate.FinalURL = "https://10.0.0.9"
	redirectPrivate.Hops = []acceleratorsources.ProbeHop{
		{URL: request.URL, Resolved: []netip.Addr{publicA}, Connected: publicA, StatusCode: 302, RedirectTo: redirectPrivate.FinalURL},
		{URL: redirectPrivate.FinalURL, Resolved: []netip.Addr{private}, Connected: private, StatusCode: 204},
	}
	if err := acceleratorsources.ValidateProbeObservation(request, redirectPrivate); !errors.Is(err, acceleratorsources.ErrProbeRejected) {
		t.Fatalf("private redirect accepted: %v", err)
	}
}

func TestProbeTimeoutIsolationAndNoncooperativeBound(t *testing.T) {
	manager := trustedManager()
	for _, source := range []acceleratorsources.Source{
		{ID: "blocked", Category: acceleratorsources.CategoryDocker, URL: "https://blocked.example.com", Enabled: true},
		{ID: "healthy", Category: acceleratorsources.CategoryDocker, URL: "https://healthy.example.com", Enabled: true},
	} {
		if err := manager.Create(context.Background(), source); err != nil {
			t.Fatal(err)
		}
	}
	policy := acceleratorsources.DefaultProbePolicy()
	policy.Timeout = 25 * time.Millisecond
	policy.Concurrency = 2
	probe := acceleratorsources.NetworkProbeFunc(func(ctx context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		if request.SourceID == "blocked" {
			<-ctx.Done()
			return acceleratorsources.ProbeObservation{}, ctx.Err()
		}
		return validObservation(request, "1.1.1.1", 2*time.Millisecond), nil
	})
	started := time.Now()
	results := manager.ProbeEnabled(context.Background(), probe, policy)
	if time.Since(started) > time.Second || !errors.Is(results["blocked"], acceleratorsources.ErrProbeFailed) || results["healthy"] != nil {
		t.Fatalf("isolated probe results=%v elapsed=%v", results, time.Since(started))
	}
	snapshot := recordsByID(manager.Snapshot())
	if snapshot["blocked"].Status.Failure != acceleratorsources.ProbeFailureTimeout || snapshot["healthy"].Status.Availability != acceleratorsources.AvailabilityAvailable || len(snapshot) != 2 {
		t.Fatalf("source-isolated status=%#v", snapshot)
	}

	bounded := trustedManager()
	if err := bounded.Create(context.Background(), acceleratorsources.Source{ID: "stuck", Category: acceleratorsources.CategoryDocker, URL: "https://stuck.example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	noncooperative := acceleratorsources.NetworkProbeFunc(func(_ context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		once.Do(func() { close(entered) })
		<-release
		return validObservation(request, "1.1.1.1", time.Millisecond), nil
	})
	results = bounded.ProbeEnabled(context.Background(), noncooperative, policy)
	<-entered
	if !errors.Is(results["stuck"], acceleratorsources.ErrProbeFailed) {
		t.Fatalf("noncooperative timeout=%v", results)
	}
	if next := bounded.ProbeEnabled(context.Background(), noncooperative, policy); !errors.Is(next[""], acceleratorsources.ErrSchedulerBusy) {
		t.Fatalf("legacy call did not bound next schedule: %v", next)
	}
	timeoutStatus := bounded.Snapshot()[0].Status
	if timeoutStatus.Failure != acceleratorsources.ProbeFailureTimeout {
		t.Fatalf("noncooperative timeout status=%#v", timeoutStatus)
	}
	close(release)
	time.Sleep(10 * time.Millisecond)
	if late := bounded.Snapshot()[0].Status; late != timeoutStatus {
		t.Fatalf("late noncooperative result overwrote timeout: before=%#v after=%#v", timeoutStatus, late)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if next := bounded.ProbeEnabled(context.Background(), acceleratorsources.NetworkProbeFunc(func(_ context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
			return validObservation(request, "1.1.1.1", time.Millisecond), nil
		}), policy); next["stuck"] == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("scheduler did not release after legacy broker returned")
}

func TestSortStableManualAvailabilityLatencyTieBreak(t *testing.T) {
	records := []acceleratorsources.SourceRecord{
		{Source: acceleratorsources.Source{ID: "z", ManualPriority: 0}, Status: acceleratorsources.SourceStatus{Availability: acceleratorsources.AvailabilityAvailable, LatencyNanos: 20}},
		{Source: acceleratorsources.Source{ID: "a", ManualPriority: 0}, Status: acceleratorsources.SourceStatus{Availability: acceleratorsources.AvailabilityAvailable, LatencyNanos: 20}},
		{Source: acceleratorsources.Source{ID: "priority", ManualPriority: -1}, Status: acceleratorsources.SourceStatus{Availability: acceleratorsources.AvailabilityUnknown}},
		{Source: acceleratorsources.Source{ID: "fast", ManualPriority: 10}, Status: acceleratorsources.SourceStatus{Availability: acceleratorsources.AvailabilityAvailable, LatencyNanos: 1}},
		{Source: acceleratorsources.Source{ID: "down", ManualPriority: -10}, Status: acceleratorsources.SourceStatus{Availability: acceleratorsources.AvailabilityUnavailable}},
	}
	if got := recordIDs(acceleratorsources.SortRecords(records, acceleratorsources.SortManual)); strings.Join(got, ",") != "down,priority,a,z,fast" {
		t.Fatalf("manual order=%v", got)
	}
	if got := recordIDs(acceleratorsources.SortRecords(records, acceleratorsources.SortAvailability)); strings.Join(got, ",") != "a,z,fast,priority,down" {
		t.Fatalf("availability order=%v", got)
	}
	if got := recordIDs(acceleratorsources.SortRecords(records, acceleratorsources.SortLatency)); strings.Join(got, ",") != "fast,a,z,priority,down" {
		t.Fatalf("latency order=%v", got)
	}
}

func TestGenerateDockerAndGitHubDeterministicWithoutApply(t *testing.T) {
	manager := trustedManager()
	sources := []acceleratorsources.Source{
		{ID: "docker-a", Category: acceleratorsources.CategoryDocker, URL: "https://a.example.com", Enabled: true, ManualPriority: 2},
		{ID: "docker-b", Category: acceleratorsources.CategoryDocker, URL: "https://b.example.com", Enabled: true, ManualPriority: 1},
		{ID: "docker-disabled", Category: acceleratorsources.CategoryDocker, URL: "https://disabled.example.com", Enabled: false},
		{ID: "github-a", Category: acceleratorsources.CategoryGitHub, URL: "https://gh-a.example.com", Enabled: true},
		{ID: "github-disabled", Category: acceleratorsources.CategoryGitHub, URL: "https://gh-disabled.example.com", Enabled: false},
	}
	for _, source := range sources {
		if err := manager.Create(context.Background(), source); err != nil {
			t.Fatal(err)
		}
	}
	policy := acceleratorsources.DefaultProbePolicy()
	manager.ProbeEnabled(context.Background(), acceleratorsources.NetworkProbeFunc(func(_ context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		if request.SourceID == "docker-a" {
			return acceleratorsources.ProbeObservation{}, errors.New("secret transport material")
		}
		return validObservation(request, "1.1.1.1", time.Millisecond), nil
	}), policy)
	wire, err := manager.GenerateDocker(context.Background(), acceleratorsources.GenerationPolicy{Sort: acceleratorsources.SortManual})
	if err != nil {
		t.Fatal(err)
	}
	var configuration acceleratorsources.DockerDaemonConfiguration
	if err := json.Unmarshal(wire, &configuration); err != nil || strings.Join(configuration.RegistryMirrors, ",") != "https://b.example.com" || strings.Contains(string(wire), "disabled") || strings.Contains(string(wire), "secret") {
		t.Fatalf("Docker output=%s err=%v", wire, err)
	}
	github, err := manager.GenerateGitHub(context.Background(), "https://github.com/org/repo", acceleratorsources.GenerationPolicy{Sort: acceleratorsources.SortManual})
	if err != nil || len(github.Replacements) != 1 || github.Replacements[0].URL != "https://gh-a.example.com/github.com/org/repo" || github.Text != github.Replacements[0].URL {
		t.Fatalf("GitHub output=%#v err=%v", github, err)
	}
	if _, err := manager.GenerateGitHub(context.Background(), "https://github.com/org/repo?secret=value", acceleratorsources.GenerationPolicy{}); !errors.Is(err, acceleratorsources.ErrInvalidSource) {
		t.Fatalf("unsafe original accepted: %v", err)
	}
}

func TestAuditAndDynamicUIFailClosedBeforeState(t *testing.T) {
	secret := "super-secret-audit-cause"
	auditor := acceleratorsources.AuditorFunc(func(context.Context, acceleratorsources.AuditRecord) error { return errors.New(secret) })
	manager := acceleratorsources.NewManager(auditor, acceleratorsources.DynamicUIFunc(func(context.Context, acceleratorsources.DynamicEvent) error { return nil }))
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
	if err := manager.Create(context.Background(), source); !errors.Is(err, acceleratorsources.ErrAuditUnavailable) || strings.Contains(err.Error(), secret) || len(manager.Snapshot()) != 0 {
		t.Fatalf("audit boundary err=%v snapshot=%v", err, manager.Snapshot())
	}
	manager = acceleratorsources.NewManager(acceleratorsources.AuditorFunc(func(context.Context, acceleratorsources.AuditRecord) error { return nil }), nil)
	if err := manager.Create(context.Background(), source); !errors.Is(err, acceleratorsources.ErrDynamicUIRequired) || len(manager.Snapshot()) != 0 {
		t.Fatalf("UI boundary err=%v snapshot=%v", err, manager.Snapshot())
	}
}

func TestAuditSourceCRUDEnableMigrationCleanupAndBounds(t *testing.T) {
	manager := trustedManager()
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
	if err := manager.Create(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	source.ManualPriority = -10
	if err := manager.Update(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetEnabled(context.Background(), source.ID, false); err != nil || manager.Snapshot()[0].Source.Enabled {
		t.Fatalf("disable err=%v snapshot=%v", err, manager.Snapshot())
	}
	if err := manager.Delete(context.Background(), source.ID); err != nil || len(manager.Snapshot()) != 0 {
		t.Fatalf("delete err=%v snapshot=%v", err, manager.Snapshot())
	}
	legacy := []acceleratorsources.Source{{ID: "legacy", Category: acceleratorsources.CategoryGitHub, URL: "https://legacy.example.com", Enabled: true}}
	if err := manager.ReplaceFromV1(context.Background(), legacy); err != nil || len(manager.Snapshot()) != 1 {
		t.Fatalf("migration err=%v snapshot=%v", err, manager.Snapshot())
	}
	bad := make([]acceleratorsources.Source, acceleratorsources.MaxSources+1)
	if err := manager.ReplaceFromV1(context.Background(), bad); !errors.Is(err, acceleratorsources.ErrBoundExceeded) || len(manager.Snapshot()) != 1 {
		t.Fatalf("bounded migration err=%v snapshot=%v", err, manager.Snapshot())
	}
	if err := manager.Cleanup(context.Background()); err != nil || len(manager.Snapshot()) != 0 {
		t.Fatalf("cleanup err=%v snapshot=%v", err, manager.Snapshot())
	}
}

func TestProbeAuditFailureDoesNotOverwriteLatestStatus(t *testing.T) {
	var fail atomic.Bool
	manager := acceleratorsources.NewManager(acceleratorsources.AuditorFunc(func(context.Context, acceleratorsources.AuditRecord) error {
		if fail.Load() {
			return errors.New("sensitive audit backend")
		}
		return nil
	}), acceleratorsources.DynamicUIFunc(func(context.Context, acceleratorsources.DynamicEvent) error { return nil }))
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
	if err := manager.Create(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	probe := acceleratorsources.NetworkProbeFunc(func(_ context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		return validObservation(request, "1.1.1.1", time.Millisecond), nil
	})
	if got := manager.ProbeEnabled(context.Background(), probe, acceleratorsources.DefaultProbePolicy()); got[source.ID] != nil {
		t.Fatal(got)
	}
	prior := manager.Snapshot()[0].Status
	fail.Store(true)
	if got := manager.ProbeEnabled(context.Background(), probe, acceleratorsources.DefaultProbePolicy()); !errors.Is(got[source.ID], acceleratorsources.ErrAuditUnavailable) {
		t.Fatalf("probe audit failure=%v", got)
	}
	if current := manager.Snapshot()[0].Status; current != prior {
		t.Fatalf("audit failure overwrote status: prior=%#v current=%#v", prior, current)
	}
}

func TestRevisionRejectsStaleProbeAfterUpdateRecreateAndDisable(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *acceleratorsources.Manager, acceleratorsources.Source)
	}{
		{name: "url-update", mutate: func(t *testing.T, manager *acceleratorsources.Manager, source acceleratorsources.Source) {
			source.URL = "https://changed.example.com"
			if err := manager.Update(context.Background(), source); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "delete-recreate-same-id", mutate: func(t *testing.T, manager *acceleratorsources.Manager, source acceleratorsources.Source) {
			if err := manager.Delete(context.Background(), source.ID); err != nil {
				t.Fatal(err)
			}
			if err := manager.Create(context.Background(), source); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "disable", mutate: func(t *testing.T, manager *acceleratorsources.Manager, source acceleratorsources.Source) {
			if err := manager.SetEnabled(context.Background(), source.ID, false); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			trace := &eventTrace{}
			manager := tracedManager(trace)
			source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
			if err := manager.Create(context.Background(), source); err != nil {
				t.Fatal(err)
			}
			initial := manager.Snapshot()[0]
			entered := make(chan acceleratorsources.ProbeRequest, 1)
			release := make(chan struct{})
			done := make(chan map[string]error, 1)
			go func() {
				done <- manager.ProbeEnabled(context.Background(), acceleratorsources.NetworkProbeFunc(func(_ context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
					entered <- request
					<-release
					return validObservation(request, "1.1.1.1", time.Millisecond), nil
				}), acceleratorsources.DefaultProbePolicy())
			}()
			request := <-entered
			if request.SourceRevision != initial.Revision || request.URL != initial.Source.URL || request.Category != initial.Source.Category || !request.Enabled {
				t.Fatalf("request did not bind snapshot: %#v initial=%#v", request, initial)
			}
			test.mutate(t, manager, source)
			current := manager.Snapshot()[0]
			if current.Revision <= initial.Revision {
				t.Fatalf("revision did not advance: initial=%d current=%d", initial.Revision, current.Revision)
			}
			close(release)
			if result := <-done; !errors.Is(result[source.ID], acceleratorsources.ErrSourceChanged) {
				t.Fatalf("stale probe result=%v", result)
			}
			current = manager.Snapshot()[0]
			if current.Status.Availability != acceleratorsources.AvailabilityUnknown || current.Status.Sequence != 0 || trace.count("ui:probe") != 0 {
				t.Fatalf("stale probe committed status/events: record=%#v trace=%v", current, trace.snapshot())
			}
		})
	}
}

func TestRevisionRemainsMonotonicAcrossMigrationCleanupAndABA(t *testing.T) {
	manager := trustedManager()
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
	if err := manager.Create(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	first := manager.Snapshot()[0].Revision
	if err := manager.Delete(context.Background(), source.ID); err != nil {
		t.Fatal(err)
	}
	if err := manager.Create(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	second := manager.Snapshot()[0].Revision
	if second <= first {
		t.Fatalf("delete/recreate reused revision: first=%d second=%d", first, second)
	}
	if err := manager.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ReplaceFromV1(context.Background(), []acceleratorsources.Source{source}); err != nil {
		t.Fatal(err)
	}
	third := manager.Snapshot()[0].Revision
	if third <= second {
		t.Fatalf("cleanup/migration reused revision: second=%d third=%d", second, third)
	}
}

func TestCancelEpochPreCanceledAndInFlightNeverCommitsStatus(t *testing.T) {
	manager := trustedManager()
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
	if err := manager.Create(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	preCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	result := manager.ProbeEnabled(preCanceled, acceleratorsources.NetworkProbeFunc(func(context.Context, acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		calls.Add(1)
		return acceleratorsources.ProbeObservation{}, nil
	}), acceleratorsources.DefaultProbePolicy())
	if !errors.Is(result[""], acceleratorsources.ErrProbeCanceled) || calls.Load() != 0 || manager.Snapshot()[0].Status.Sequence != 0 {
		t.Fatalf("pre-cancel result=%v calls=%d status=%#v", result, calls.Load(), manager.Snapshot()[0].Status)
	}

	callCtx, revoke := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan map[string]error, 1)
	go func() {
		done <- manager.ProbeEnabled(callCtx, acceleratorsources.NetworkProbeFunc(func(_ context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
			calls.Add(1)
			close(entered)
			<-release
			return validObservation(request, "1.1.1.1", time.Millisecond), nil
		}), acceleratorsources.DefaultProbePolicy())
	}()
	<-entered
	revoke()
	result = <-done
	if !errors.Is(result[source.ID], acceleratorsources.ErrProbeCanceled) || manager.Snapshot()[0].Status.Sequence != 0 {
		t.Fatalf("revoked result=%v status=%#v", result, manager.Snapshot()[0].Status)
	}
	close(release)
	time.Sleep(10 * time.Millisecond)
	if manager.Snapshot()[0].Status.Sequence != 0 {
		t.Fatalf("late result committed after revoke: %#v", manager.Snapshot()[0])
	}
}

func TestHTTPStatusClassificationAndCompleteRedirectChain(t *testing.T) {
	request := acceleratorsources.ProbeRequest{SourceID: "mirror", SourceRevision: 1, Category: acceleratorsources.CategoryDocker, Enabled: true, URL: "https://mirror.example.com", Method: acceleratorsources.ProbeHEAD, MaxRedirects: 2, MaxResponseBytes: 4096, Timeout: time.Second}
	for _, status := range []int{301, 302, 404, 500} {
		observation := validObservation(request, "1.1.1.1", time.Millisecond)
		observation.StatusCode = status
		observation.Hops[0].StatusCode = status
		if err := acceleratorsources.ValidateProbeObservation(request, observation); err != nil {
			t.Fatalf("HTTP %d was treated as untrusted: %v", status, err)
		}
		classified, err := acceleratorsources.ClassifyProbeObservation(request, observation)
		if !errors.Is(err, acceleratorsources.ErrProbeFailed) || classified.Failure != acceleratorsources.ProbeFailureHTTPStatus || classified.Availability != acceleratorsources.AvailabilityUnavailable {
			t.Fatalf("HTTP %d classification=%#v err=%v", status, classified, err)
		}
	}

	target := "https://target.example.com/final"
	publicA, publicB := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")
	redirected := acceleratorsources.ProbeObservation{
		RequestDigest: request.Digest(), Method: request.Method, RequestedURL: request.URL, FinalURL: target,
		Hops: []acceleratorsources.ProbeHop{
			{URL: request.URL, Resolved: []netip.Addr{publicA}, Connected: publicA, StatusCode: 302, RedirectTo: target},
			{URL: target, Resolved: []netip.Addr{publicB}, Connected: publicB, StatusCode: 204},
		},
		StatusCode: 204, Latency: 2 * time.Millisecond, Attested: true, Complete: true,
	}
	classified, err := acceleratorsources.ClassifyProbeObservation(request, redirected)
	if err != nil || classified.Availability != acceleratorsources.AvailabilityAvailable {
		t.Fatalf("complete redirect classification=%#v err=%v", classified, err)
	}
	broken := redirected
	broken.Hops = append([]acceleratorsources.ProbeHop(nil), redirected.Hops...)
	broken.Hops[0].RedirectTo = "https://other.example.com"
	classified, err = acceleratorsources.ClassifyProbeObservation(request, broken)
	if !errors.Is(err, acceleratorsources.ErrProbeRejected) || classified.Failure != acceleratorsources.ProbeFailureUntrusted {
		t.Fatalf("broken redirect classification=%#v err=%v", classified, err)
	}

	manager := trustedManager()
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: request.URL, Enabled: true}
	if err := manager.Create(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	result := manager.ProbeEnabled(context.Background(), acceleratorsources.NetworkProbeFunc(func(_ context.Context, bound acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		observation := validObservation(bound, "1.1.1.1", time.Millisecond)
		observation.StatusCode = 404
		observation.Hops[0].StatusCode = 404
		return observation, nil
	}), acceleratorsources.DefaultProbePolicy())
	status := manager.Snapshot()[0].Status
	if !errors.Is(result[source.ID], acceleratorsources.ErrProbeFailed) || status.Failure != acceleratorsources.ProbeFailureHTTPStatus || status.Availability != acceleratorsources.AvailabilityUnavailable {
		t.Fatalf("scheduled HTTP classification result=%v status=%#v", result, status)
	}
}

func TestTerminalAuditAndDynamicUISequenceForCRUDGenerateAndProbe(t *testing.T) {
	trace := &eventTrace{}
	manager := tracedManager(trace)
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
	if err := manager.Create(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	assertTrace(t, trace.snapshot(), []string{"audit:create:started", "ui:create", "audit:create:succeeded"})
	trace.reset()
	if _, err := manager.GenerateDocker(context.Background(), acceleratorsources.GenerationPolicy{Sort: acceleratorsources.SortManual}); err != nil {
		t.Fatal(err)
	}
	assertTrace(t, trace.snapshot(), []string{"audit:generate-docker:started", "ui:generate-docker", "audit:generate-docker:succeeded"})
	trace.reset()
	result := manager.ProbeEnabled(context.Background(), acceleratorsources.NetworkProbeFunc(func(_ context.Context, request acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		trace.add("broker:probe")
		return validObservation(request, "1.1.1.1", time.Millisecond), nil
	}), acceleratorsources.DefaultProbePolicy())
	if result[source.ID] != nil {
		t.Fatal(result)
	}
	assertTrace(t, trace.snapshot(), []string{"audit:probe:started", "ui:probe-start", "broker:probe", "ui:probe", "audit:probe:succeeded"})
	trace.reset()
	result = manager.ProbeEnabled(context.Background(), acceleratorsources.NetworkProbeFunc(func(context.Context, acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
		trace.add("broker:probe-failed")
		return acceleratorsources.ProbeObservation{}, errors.New("raw secret transport cause")
	}), acceleratorsources.DefaultProbePolicy())
	if !errors.Is(result[source.ID], acceleratorsources.ErrProbeFailed) || strings.Contains(result[source.ID].Error(), "secret") {
		t.Fatalf("probe failure=%v", result)
	}
	assertTrace(t, trace.snapshot(), []string{"audit:probe:started", "ui:probe-start", "broker:probe-failed", "ui:probe", "audit:probe:failed"})
	trace.reset()
	missing := source
	missing.ID = "missing"
	if err := manager.Update(context.Background(), missing); !errors.Is(err, acceleratorsources.ErrSourceNotFound) {
		t.Fatal(err)
	}
	assertTrace(t, trace.snapshot(), []string{"audit:update:started", "audit:update:failed"})
}

func TestTerminalAuditPendingRecordsCompletedOutcomeWithoutEffectRetry(t *testing.T) {
	trace := &eventTrace{}
	var failTerminal atomic.Bool
	failTerminal.Store(true)
	manager := acceleratorsources.NewManager(
		acceleratorsources.AuditorFunc(func(_ context.Context, record acceleratorsources.AuditRecord) error {
			trace.add("audit:" + record.Action + ":" + record.Outcome)
			if record.Outcome == "succeeded" && failTerminal.Load() {
				return errors.New("raw audit backend secret")
			}
			return nil
		}),
		acceleratorsources.DynamicUIFunc(func(_ context.Context, event acceleratorsources.DynamicEvent) error {
			trace.add("ui:" + event.Action)
			return nil
		}),
	)
	source := acceleratorsources.Source{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://mirror.example.com", Enabled: true}
	err := manager.Create(context.Background(), source)
	if !errors.Is(err, acceleratorsources.ErrTerminalAuditPending) || strings.Contains(err.Error(), "secret") || len(manager.Snapshot()) != 1 || manager.PendingTerminalAudits() != 1 {
		t.Fatalf("terminal pending err=%v snapshot=%v pending=%d", err, manager.Snapshot(), manager.PendingTerminalAudits())
	}
	if trace.count("ui:create") != 1 {
		t.Fatalf("effect/UI repeated before flush: %v", trace.snapshot())
	}
	failTerminal.Store(false)
	if err := manager.FlushTerminalAudits(context.Background()); err != nil || manager.PendingTerminalAudits() != 0 || trace.count("ui:create") != 1 {
		t.Fatalf("flush err=%v pending=%d trace=%v", err, manager.PendingTerminalAudits(), trace.snapshot())
	}
}

func trustedManager() *acceleratorsources.Manager {
	return acceleratorsources.NewManager(
		acceleratorsources.AuditorFunc(func(context.Context, acceleratorsources.AuditRecord) error { return nil }),
		acceleratorsources.DynamicUIFunc(func(context.Context, acceleratorsources.DynamicEvent) error { return nil }),
	)
}

func validObservation(request acceleratorsources.ProbeRequest, address string, latency time.Duration) acceleratorsources.ProbeObservation {
	resolved := netip.MustParseAddr(address)
	return acceleratorsources.ProbeObservation{
		RequestDigest: request.Digest(), Method: request.Method, RequestedURL: request.URL, FinalURL: request.URL,
		Hops:       []acceleratorsources.ProbeHop{{URL: request.URL, Resolved: []netip.Addr{resolved}, Connected: resolved, StatusCode: 204}},
		StatusCode: 204, Latency: latency, Attested: true, Complete: true,
	}
}

func recordsByID(records []acceleratorsources.SourceRecord) map[string]acceleratorsources.SourceRecord {
	result := make(map[string]acceleratorsources.SourceRecord, len(records))
	for _, record := range records {
		result[record.Source.ID] = record
	}
	return result
}

func recordIDs(records []acceleratorsources.SourceRecord) []string {
	result := make([]string, len(records))
	for index, record := range records {
		result[index] = record.Source.ID
	}
	return result
}

type eventTrace struct {
	mu      sync.Mutex
	entries []string
}

func (trace *eventTrace) add(value string) {
	trace.mu.Lock()
	trace.entries = append(trace.entries, value)
	trace.mu.Unlock()
}

func (trace *eventTrace) snapshot() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]string(nil), trace.entries...)
}

func (trace *eventTrace) count(value string) int {
	count := 0
	for _, entry := range trace.snapshot() {
		if entry == value {
			count++
		}
	}
	return count
}

func (trace *eventTrace) reset() {
	trace.mu.Lock()
	trace.entries = nil
	trace.mu.Unlock()
}

func assertTrace(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("event sequence=%v, want=%v", got, want)
	}
}

func tracedManager(trace *eventTrace) *acceleratorsources.Manager {
	return acceleratorsources.NewManager(
		acceleratorsources.AuditorFunc(func(_ context.Context, record acceleratorsources.AuditRecord) error {
			trace.add("audit:" + record.Action + ":" + record.Outcome)
			return nil
		}),
		acceleratorsources.DynamicUIFunc(func(_ context.Context, event acceleratorsources.DynamicEvent) error {
			trace.add("ui:" + event.Action)
			return nil
		}),
	)
}
