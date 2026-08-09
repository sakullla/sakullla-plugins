package acceleratorsources_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	acceleratorsources "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources"
)

func TestProbeControllerRPCGrantsGenerationRevokeAndDefaultFailClosed(t *testing.T) {
	controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	missing := handshake([]string{"dynamic-ui", "network-probe", "scheduler"})
	if _, err := controller.Handshake(context.Background(), missing); err == nil {
		t.Fatal("missing audit grant was accepted")
	}

	controller, err = acceleratorsources.NewController(acceleratorsources.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil || response.ABI != pluginsdk.RPCABIV1 {
		t.Fatalf("handshake response=%#v err=%v", response, err)
	}
	wire := configurationWire(t, "generation-1", 1)
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); response.Error != nil || len(controller.Sources()) != 1 {
		t.Fatalf("prepare response=%#v sources=%v", response, controller.Sources())
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error == nil || len(controller.Sources()) != 0 {
		t.Fatalf("default admission response=%#v sources=%v", response, controller.Sources())
	}
}

func TestProbeControllerInjectedHandlesScheduleAuditAndStopCleanup(t *testing.T) {
	var commits, aborts, schedules, audits atomic.Int32
	var activationOperationKey string
	controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		ActivationAuditor: acceleratorsources.AuditorFunc(func(_ context.Context, record acceleratorsources.AuditRecord) error {
			if record.Action != "activate" {
				t.Fatalf("activation audit=%#v", record)
			}
			if record.Outcome == "started" {
				activationOperationKey = strings.TrimSuffix(record.OperationKey, ":started")
			}
			wantKey := activationOperationKey + ":terminal"
			if record.Outcome == "started" {
				wantKey = activationOperationKey + ":started"
			}
			if activationOperationKey == "" || record.OperationKey != wantKey {
				t.Fatalf("unstable activation operation key: %#v", record)
			}
			audits.Add(1)
			return nil
		}),
		Admission: acceleratorsources.TypedHandleAdmissionFunc(func(_ context.Context, request pluginsdk.RPCHandshakeRequest, configuration acceleratorsources.Configuration) (acceleratorsources.PreparedAdmission, error) {
			if request.Generation != configuration.Generation {
				t.Fatal("admission generation drift")
			}
			return acceleratorsources.PreparedAdmissionFuncs{
				CommitFunc: func(context.Context) (acceleratorsources.RuntimeAdapters, error) {
					commits.Add(1)
					return acceleratorsources.RuntimeAdapters{
						Probe: acceleratorsources.NetworkProbeFunc(func(context.Context, acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
							return acceleratorsources.ProbeObservation{}, nil
						}),
						Scheduler: acceleratorsources.SchedulerFunc(func(_ context.Context, registration acceleratorsources.SchedulerRegistration) error {
							if registration.Generation != "generation-1" || registration.Interval != time.Minute || registration.MaxConcurrency != 2 || registration.OperationKey != activationOperationKey {
								t.Fatalf("scheduler registration=%#v", registration)
							}
							schedules.Add(1)
							return nil
						}),
						UI:      acceleratorsources.DynamicUIFunc(func(context.Context, acceleratorsources.DynamicEvent) error { return nil }),
						Auditor: acceleratorsources.AuditorFunc(func(context.Context, acceleratorsources.AuditRecord) error { return nil }),
					}, nil
				},
				AbortFunc: func() { aborts.Add(1) },
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, "generation-1", 2)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if commits.Load() != 1 || schedules.Load() != 1 || audits.Load() != 2 || len(controller.Sources()) != 2 {
		t.Fatalf("commits=%d schedules=%d audits=%d sources=%v", commits.Load(), schedules.Load(), audits.Load(), controller.Sources())
	}
	if response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil || aborts.Load() != 1 || len(controller.Sources()) != 0 {
		t.Fatalf("stop=%#v aborts=%d sources=%v", response, aborts.Load(), controller.Sources())
	}
}

func TestProbeControllerLateAdmissionDeadlineAbortsAndCannotCommit(t *testing.T) {
	var aborts, lasting atomic.Int32
	trace := &eventTrace{}
	started, release := make(chan struct{}), make(chan struct{})
	controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", ActivateTimeout: 20 * time.Millisecond, DrainTimeout: 20 * time.Millisecond,
		ActivationAuditor: acceleratorsources.AuditorFunc(func(_ context.Context, record acceleratorsources.AuditRecord) error {
			trace.add("audit:" + record.Action + ":" + record.Outcome)
			return nil
		}),
		Admission: acceleratorsources.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, acceleratorsources.Configuration) (acceleratorsources.PreparedAdmission, error) {
			return acceleratorsources.PreparedAdmissionFuncs{
				CommitFunc: func(context.Context) (acceleratorsources.RuntimeAdapters, error) {
					lasting.Store(1)
					close(started)
					<-release
					return validRuntimeAdapters(), nil
				},
				AbortFunc: func() { lasting.Store(0); aborts.Add(1) },
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, "generation-1", 1)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	result := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		result <- controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}()
	<-started
	response := <-result
	if response.Error == nil || aborts.Load() != 1 || lasting.Load() != 0 || len(controller.Sources()) != 0 {
		t.Fatalf("deadline response=%#v aborts=%d lasting=%d sources=%v", response, aborts.Load(), lasting.Load(), controller.Sources())
	}
	assertTrace(t, trace.snapshot(), []string{"audit:activate:started", "audit:activate:failed"})
	close(release)
	time.Sleep(30 * time.Millisecond)
	if aborts.Load() != 1 || lasting.Load() != 0 || len(controller.Sources()) != 0 {
		t.Fatalf("late result committed: aborts=%d lasting=%d sources=%v", aborts.Load(), lasting.Load(), controller.Sources())
	}
}

func TestProbeControllerStrictBoundsGenerationAndSecretSafeErrors(t *testing.T) {
	secret := "url-password-material"
	for name, wire := range map[string][]byte{
		"unknown":    append(configurationWire(t, "generation-1", 0)[:len(configurationWire(t, "generation-1", 0))-1], []byte(`,"unknown":true}`)...),
		"generation": configurationWire(t, "other-generation", 0),
		"bound":      configurationWire(t, "generation-1", acceleratorsources.MaxSources+1),
		"secret":     unsafeConfigurationWire(t, secret),
	} {
		t.Run(name, func(t *testing.T) {
			controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
				t.Fatal(err)
			}
			response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire})
			if response.Error == nil || strings.Contains(response.Error.Error(), secret) || len(controller.Sources()) != 0 {
				t.Fatalf("unsafe config response=%#v sources=%v", response, controller.Sources())
			}
		})
	}
}

func TestProbeEntrypointCanonicalRPCHandshakeAndRuntimeFailClosed(t *testing.T) {
	var output bytes.Buffer
	if err := acceleratorsources.RunEntrypoint(context.Background(), []string{acceleratorsources.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("CI handshake output=%q err=%v", output.String(), err)
	}
	if err := acceleratorsources.RunEntrypoint(context.Background(), nil, &output); !errors.Is(err, acceleratorsources.ErrTypedHandlesUnavailable) {
		t.Fatalf("runtime did not fail closed: %v", err)
	}
}

func TestTerminalActivationAuditSequenceSuccessAndFailures(t *testing.T) {
	for _, test := range []struct {
		name                                          string
		admissionFail, scheduleFail, successAuditFail bool
		wantError                                     bool
		want                                          []string
	}{
		{name: "success", want: []string{"audit:activate:started", "admission:prepare", "ui:activate-start", "scheduler:register", "audit:activate:succeeded"}},
		{name: "admission-failure", admissionFail: true, wantError: true, want: []string{"audit:activate:started", "admission:prepare", "audit:activate:failed"}},
		{name: "scheduler-failure", scheduleFail: true, wantError: true, want: []string{"audit:activate:started", "admission:prepare", "ui:activate-start", "scheduler:register", "admission:abort", "audit:activate:failed"}},
		{name: "ambiguous-terminal-audit-compensates", successAuditFail: true, wantError: true, want: []string{"audit:activate:started", "admission:prepare", "ui:activate-start", "scheduler:register", "audit:activate:succeeded", "admission:abort", "audit:activate:succeeded"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			trace := &eventTrace{}
			var lasting atomic.Int32
			var auditFailed atomic.Bool
			controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{
				PackageDigest: "package", ArtifactDigest: "artifact",
				ActivationAuditor: acceleratorsources.AuditorFunc(func(_ context.Context, record acceleratorsources.AuditRecord) error {
					trace.add("audit:" + record.Action + ":" + record.Outcome)
					if test.successAuditFail && record.Outcome == "succeeded" && auditFailed.CompareAndSwap(false, true) {
						return errors.New("raw audit secret")
					}
					return nil
				}),
				Admission: acceleratorsources.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, acceleratorsources.Configuration) (acceleratorsources.PreparedAdmission, error) {
					trace.add("admission:prepare")
					if test.admissionFail {
						return nil, errors.New("raw admission secret")
					}
					return acceleratorsources.PreparedAdmissionFuncs{
						CommitFunc: func(context.Context) (acceleratorsources.RuntimeAdapters, error) {
							lasting.Store(1)
							return acceleratorsources.RuntimeAdapters{
								Probe: acceleratorsources.NetworkProbeFunc(func(context.Context, acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
									return acceleratorsources.ProbeObservation{}, nil
								}),
								Scheduler: acceleratorsources.SchedulerFunc(func(context.Context, acceleratorsources.SchedulerRegistration) error {
									trace.add("scheduler:register")
									if test.scheduleFail {
										return errors.New("raw scheduler secret")
									}
									return nil
								}),
								UI: acceleratorsources.DynamicUIFunc(func(_ context.Context, event acceleratorsources.DynamicEvent) error {
									trace.add("ui:" + event.Action)
									return nil
								}),
								Auditor: acceleratorsources.AuditorFunc(func(context.Context, acceleratorsources.AuditRecord) error { return nil }),
							}, nil
						},
						AbortFunc: func() { lasting.Store(0); trace.add("admission:abort") },
					}, nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
				t.Fatal(err)
			}
			if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, "generation-1", 1)}); response.Error != nil {
				t.Fatal(response.Error)
			}
			response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
			if (response.Error != nil) != test.wantError || (response.Error != nil && strings.Contains(response.Error.Error(), "secret")) {
				t.Fatalf("activation response=%#v", response)
			}
			assertTrace(t, trace.snapshot(), test.want)
			if test.wantError && lasting.Load() != 0 {
				t.Fatalf("failed activation left lasting effect=%d", lasting.Load())
			}
			if !test.wantError {
				if response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
					t.Fatal(response.Error)
				}
			}
		})
	}
}

func TestActivationAmbiguousSucceededAuditRetriesIdempotentRecord(t *testing.T) {
	auditor := newActivationAuditFixture(true, nil)
	var lasting, aborts atomic.Int32
	var schedulerOperationKey string
	controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", ActivationAuditor: auditor,
		Admission: acceleratorsources.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, acceleratorsources.Configuration) (acceleratorsources.PreparedAdmission, error) {
			return acceleratorsources.PreparedAdmissionFuncs{
				CommitFunc: func(context.Context) (acceleratorsources.RuntimeAdapters, error) {
					lasting.Store(1)
					runtime := validRuntimeAdapters()
					runtime.Scheduler = acceleratorsources.SchedulerFunc(func(_ context.Context, registration acceleratorsources.SchedulerRegistration) error {
						schedulerOperationKey = registration.OperationKey
						return nil
					})
					return runtime, nil
				},
				AbortFunc: func() { lasting.Store(0); aborts.Add(1) },
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, "generation-1", 1)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if response.Error == nil || strings.Contains(response.Error.Error(), "raw audit secret") {
		t.Fatalf("ambiguous activation response=%#v", response)
	}
	if lasting.Load() != 0 || aborts.Load() != 1 || len(controller.Sources()) != 0 {
		t.Fatalf("compensation lasting=%d aborts=%d sources=%v", lasting.Load(), aborts.Load(), controller.Sources())
	}
	attempts, committed := auditor.snapshot()
	assertSingleTerminalRecord(t, attempts, committed, "succeeded", schedulerOperationKey+":terminal")
}

func TestActivationConcurrentFailureAndRevokeKeepOneTerminalOutcome(t *testing.T) {
	release := make(chan struct{})
	auditor := newActivationAuditFixture(true, release)
	controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", ActivationAuditor: auditor,
		ActivateTimeout: 20 * time.Millisecond, DrainTimeout: 20 * time.Millisecond,
		Admission: acceleratorsources.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, acceleratorsources.Configuration) (acceleratorsources.PreparedAdmission, error) {
			return nil, errors.New("raw admission secret")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, "generation-1", 1)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	result := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		result <- controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}()
	select {
	case <-auditor.terminalEntered:
	case <-time.After(time.Second):
		t.Fatal("terminal audit was not entered")
	}
	// Let the lifecycle deadline race generation revoke/close with the hook's
	// in-flight terminal write, then allow both to finish deterministically.
	time.Sleep(40 * time.Millisecond)
	close(release)
	response := <-result
	if response.Error == nil || strings.Contains(response.Error.Error(), "raw") || len(controller.Sources()) != 0 {
		t.Fatalf("concurrent failure response=%#v sources=%v", response, controller.Sources())
	}
	attempts, committed := auditor.snapshot()
	assertSingleTerminalRecord(t, attempts, committed, "failed", "")
}

type activationAuditFixture struct {
	mu                  sync.Mutex
	attempts            []acceleratorsources.AuditRecord
	committed           map[string]acceleratorsources.AuditRecord
	failFirstTerminal   bool
	failedTerminalOnce  bool
	terminalEntered     chan struct{}
	terminalEnteredOnce sync.Once
	terminalRelease     <-chan struct{}
}

func newActivationAuditFixture(failFirstTerminal bool, release <-chan struct{}) *activationAuditFixture {
	return &activationAuditFixture{committed: make(map[string]acceleratorsources.AuditRecord), failFirstTerminal: failFirstTerminal, terminalEntered: make(chan struct{}), terminalRelease: release}
}

func (fixture *activationAuditFixture) Audit(ctx context.Context, record acceleratorsources.AuditRecord) error {
	fixture.mu.Lock()
	if previous, exists := fixture.committed[record.OperationKey]; exists && previous != record {
		fixture.mu.Unlock()
		return errors.New("raw conflicting terminal record")
	}
	fixture.attempts = append(fixture.attempts, record)
	fixture.committed[record.OperationKey] = record
	if record.Outcome == "started" {
		fixture.mu.Unlock()
		return nil
	}
	shouldFail := fixture.failFirstTerminal && !fixture.failedTerminalOnce
	if shouldFail {
		fixture.failedTerminalOnce = true
	}
	release := fixture.terminalRelease
	fixture.mu.Unlock()
	fixture.terminalEnteredOnce.Do(func() { close(fixture.terminalEntered) })
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if shouldFail {
		return errors.New("raw audit secret")
	}
	return nil
}

func (fixture *activationAuditFixture) snapshot() ([]acceleratorsources.AuditRecord, map[string]acceleratorsources.AuditRecord) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	attempts := append([]acceleratorsources.AuditRecord(nil), fixture.attempts...)
	committed := make(map[string]acceleratorsources.AuditRecord, len(fixture.committed))
	for key, record := range fixture.committed {
		committed[key] = record
	}
	return attempts, committed
}

func assertSingleTerminalRecord(t *testing.T, attempts []acceleratorsources.AuditRecord, committed map[string]acceleratorsources.AuditRecord, outcome, operationKey string) {
	t.Helper()
	var terminal []acceleratorsources.AuditRecord
	for _, record := range attempts {
		if record.Action != "activate" || record.OperationKey == "" {
			t.Fatalf("unsafe audit record=%#v", record)
		}
		if record.Outcome != "started" {
			if operationKey == "" {
				operationKey = record.OperationKey
			}
			if record.OperationKey != operationKey {
				t.Fatalf("unstable terminal operation keys: want %q, record=%#v", operationKey, record)
			}
			terminal = append(terminal, record)
		}
	}
	if len(terminal) != 2 || terminal[0] != terminal[1] || terminal[0].Outcome != outcome {
		t.Fatalf("terminal attempts=%#v", terminal)
	}
	if committed[operationKey] != terminal[0] {
		t.Fatalf("logical terminals=%#v operation=%q", committed, operationKey)
	}
	for key, record := range committed {
		if record.Outcome != "started" && key != operationKey {
			t.Fatalf("conflicting terminal record=%#v", record)
		}
	}
}

func requiredGrants() []string {
	return []string{"audit", "dynamic-ui", "network-probe", "scheduler"}
}

func handshake(grants []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: acceleratorsources.PluginID, PluginVersion: acceleratorsources.PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: "generation-1",
	}
}

func configurationWire(t *testing.T, generation string, count int) []byte {
	t.Helper()
	sources := make([]acceleratorsources.Source, count)
	for index := range sources {
		sources[index] = acceleratorsources.Source{ID: sourceID(index), Category: acceleratorsources.CategoryDocker, URL: "https://mirror-" + sourceID(index) + ".example.com", Enabled: true, ManualPriority: index}
	}
	wire, err := json.Marshal(acceleratorsources.Configuration{
		Generation: generation, ScheduleSeconds: 60,
		Probe:   acceleratorsources.ProbeConfig{Method: acceleratorsources.ProbeHEAD, MaxRedirects: 2, MaxResponseBytes: 4096, TimeoutMillis: 1000, Concurrency: 2},
		Sources: sources,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func unsafeConfigurationWire(t *testing.T, secret string) []byte {
	t.Helper()
	document := acceleratorsources.Configuration{
		Generation: "generation-1", ScheduleSeconds: 60,
		Probe:   acceleratorsources.ProbeConfig{Method: acceleratorsources.ProbeHEAD, MaxRedirects: 2, MaxResponseBytes: 4096, TimeoutMillis: 1000, Concurrency: 2},
		Sources: []acceleratorsources.Source{{ID: "mirror", Category: acceleratorsources.CategoryDocker, URL: "https://user:" + secret + "@mirror.example.com", Enabled: true}},
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func sourceID(index int) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if index == 0 {
		return "source-0"
	}
	value := ""
	for index > 0 {
		value = string(digits[index%len(digits)]) + value
		index /= len(digits)
	}
	return "source-" + value
}

func validRuntimeAdapters() acceleratorsources.RuntimeAdapters {
	return acceleratorsources.RuntimeAdapters{
		Probe: acceleratorsources.NetworkProbeFunc(func(context.Context, acceleratorsources.ProbeRequest) (acceleratorsources.ProbeObservation, error) {
			return acceleratorsources.ProbeObservation{}, nil
		}),
		Scheduler: acceleratorsources.SchedulerFunc(func(context.Context, acceleratorsources.SchedulerRegistration) error { return nil }),
		UI:        acceleratorsources.DynamicUIFunc(func(context.Context, acceleratorsources.DynamicEvent) error { return nil }),
		Auditor:   acceleratorsources.AuditorFunc(func(context.Context, acceleratorsources.AuditRecord) error { return nil }),
	}
}
