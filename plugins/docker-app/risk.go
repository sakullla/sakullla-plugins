package dockerapp

import (
	"context"
	"errors"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type ComposeService struct {
	Name            string
	Image           string
	Privileged      bool
	HostMounts      []string
	RelativeBinds   []string
	AddCapabilities []string
	Networks        []string
	Volumes         []string
	SecretRefs      []string
	PublishedPorts  []uint16
}

type ComposePlan struct {
	AppID       string
	Generation  string
	Project     string
	Image       string
	RuleRef     string
	Services    []ComposeService
	RuleImpacts []string
	SecretRefs  []string
}

type RiskKind string

const (
	RiskPrivileged RiskKind = "privileged"
	RiskHostMount  RiskKind = "host-mount"
	RiskCapability RiskKind = "capability"
	RiskNetwork    RiskKind = "network"
	RiskVolume     RiskKind = "volume"
	RiskRule       RiskKind = "rule"
)

type RiskItem struct {
	Kind   RiskKind
	Target string
}

type RiskPreview struct {
	AppID, Generation, Project, Digest string
	Items                              []RiskItem
}

func PreviewCompose(plan ComposePlan) (RiskPreview, error) {
	normalized, err := canonicalComposePlan(plan)
	if err != nil {
		return RiskPreview{}, err
	}
	plan = normalized
	preview := RiskPreview{AppID: plan.AppID, Generation: plan.Generation, Project: plan.Project}
	for _, service := range plan.Services {
		if service.Privileged {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskPrivileged, Target: service.Name})
		}
		for _, target := range service.HostMounts {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskHostMount, Target: service.Name + ":" + target})
		}
		for _, target := range service.AddCapabilities {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskCapability, Target: service.Name + ":" + target})
		}
		for _, target := range service.Networks {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskNetwork, Target: target})
		}
		for _, target := range service.Volumes {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskVolume, Target: target})
		}
	}
	for _, target := range plan.RuleImpacts {
		preview.Items = append(preview.Items, RiskItem{Kind: RiskRule, Target: target})
	}
	if len(preview.Items) > MaxCollectionItems {
		return RiskPreview{}, ErrBoundExceeded
	}
	sort.Slice(preview.Items, func(i, j int) bool {
		if preview.Items[i].Kind == preview.Items[j].Kind {
			return preview.Items[i].Target < preview.Items[j].Target
		}
		return preview.Items[i].Kind < preview.Items[j].Kind
	})
	digest, err := canonicalDigest(struct {
		AppID, Generation, Project string
		Items                      []RiskItem
	}{preview.AppID, preview.Generation, preview.Project, preview.Items})
	if err != nil {
		return RiskPreview{}, ErrInvalidPreview
	}
	preview.Digest = digest
	return preview, nil
}

func RequiresRiskConfirmation(preview RiskPreview) bool {
	for _, item := range preview.Items {
		switch item.Kind {
		case RiskPrivileged, RiskHostMount, RiskCapability:
			return true
		}
	}
	return false
}

func ConfirmComposeRisk(plan ComposePlan, confirm string) (RiskPreview, error) {
	preview, err := PreviewCompose(plan)
	if err != nil {
		return RiskPreview{}, err
	}
	if !RequiresRiskConfirmation(preview) {
		return preview, nil
	}
	if confirm != preview.Digest {
		return preview, ErrInvalidPreview
	}
	return preview, nil
}

func PreviewComposeDocument(appID, generation, document, ruleRef string) (RiskPreview, error) {
	plan, _, err := ParseComposeDocument(document, appID, generation, ruleRef)
	if err != nil {
		return RiskPreview{}, err
	}
	return PreviewCompose(plan)
}

func canonicalComposePlan(plan ComposePlan) (ComposePlan, error) {
	if !validID(plan.AppID) || !boundedText(plan.Generation, 128) || !validID(plan.Project) || len(plan.Services) > MaxComposeServices || len(plan.RuleImpacts) > MaxCollectionItems {
		return ComposePlan{}, ErrBoundExceeded
	}
	normalized := plan
	normalized.Services = append([]ComposeService(nil), plan.Services...)
	for index := range normalized.Services {
		service := &normalized.Services[index]
		if !validID(service.Name) {
			return ComposePlan{}, errors.New("compose service is invalid")
		}
		if service.Image != "" && !boundedText(service.Image, 512) {
			return ComposePlan{}, errors.New("compose image is invalid")
		}
		var err error
		if service.SecretRefs, err = sortedUnique(service.SecretRefs, MaxSecretRefs); err != nil {
			return ComposePlan{}, err
		}
		if service.HostMounts, err = sortedUnique(service.HostMounts, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		if service.RelativeBinds, err = sortedUnique(service.RelativeBinds, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		if service.AddCapabilities, err = sortedUnique(service.AddCapabilities, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		if service.Networks, err = sortedUnique(service.Networks, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		if service.Volumes, err = sortedUnique(service.Volumes, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		service.PublishedPorts = mergePorts(nil, service.PublishedPorts)
	}
	sort.Slice(normalized.Services, func(i, j int) bool { return normalized.Services[i].Name < normalized.Services[j].Name })
	for index := 1; index < len(normalized.Services); index++ {
		if normalized.Services[index-1].Name == normalized.Services[index].Name {
			return ComposePlan{}, errors.New("compose service is duplicated")
		}
	}
	if plan.Image != "" && !boundedText(plan.Image, 512) {
		return ComposePlan{}, errors.New("compose image is invalid")
	}
	if plan.RuleRef != "" && !boundedText(plan.RuleRef, 128) {
		return ComposePlan{}, errors.New("rule_ref is invalid")
	}
	var err error
	if normalized.RuleImpacts, err = sortedUnique(plan.RuleImpacts, MaxCollectionItems); err != nil {
		return ComposePlan{}, err
	}
	refs := append([]string(nil), plan.SecretRefs...)
	for _, service := range normalized.Services {
		refs = append(refs, service.SecretRefs...)
	}
	if normalized.SecretRefs, err = sortedUnique(refs, MaxSecretRefs); err != nil {
		return ComposePlan{}, err
	}
	if normalized.Image == "" && len(normalized.Services) > 0 {
		normalized.Image = normalized.Services[0].Image
	}
	return normalized, nil
}

// ComposeExecutor is an injectable business-test boundary. The operation key
// must be applied idempotently so a journal-write failure can safely resume.
// It is not a Host API or wire contract; production remains gated on future
// typed SDK handles.
type ComposeExecutor interface {
	ApplyCompose(context.Context, string, ComposePlan) error
}
type ComposeExecutorFunc func(context.Context, string, ComposePlan) error

func (function ComposeExecutorFunc) ApplyCompose(ctx context.Context, operation string, plan ComposePlan) error {
	return function(ctx, operation, plan)
}

type ComposeInventory interface {
	CurrentCompose(context.Context, string, string) (ComposePlan, error)
}
type ComposeInventoryFunc func(context.Context, string, string) (ComposePlan, error)

func (function ComposeInventoryFunc) CurrentCompose(ctx context.Context, appID, generation string) (ComposePlan, error) {
	return function(ctx, appID, generation)
}

type AuditRecord struct{ Action, Outcome, Detail string }
type Auditor interface{ Record(AuditRecord) }
type AuditorFunc func(AuditRecord)

func (function AuditorFunc) Record(record AuditRecord) { function(record) }

func ExecuteCompose(ctx context.Context, shown RiskPreview, authorization Authorization, inventory ComposeInventory, verifier AuthorizationVerifier, executor ComposeExecutor, journal ProgressJournal, auditor Auditor) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if inventory == nil || verifier == nil || executor == nil || journal == nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	plan, err := inventory.CurrentCompose(ctx, shown.AppID, shown.Generation)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	normalized, err := canonicalComposePlan(plan)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return safeFailure(ErrInvalidPreview, err)
	}
	trusted, err := PreviewCompose(normalized)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return safeFailure(ErrInvalidPreview, err)
	}
	shownDigest, _ := canonicalDigest(struct {
		AppID, Generation, Project string
		Items                      []RiskItem
	}{shown.AppID, shown.Generation, shown.Project, shown.Items})
	if shownDigest != shown.Digest || shown.AppID != trusted.AppID || shown.Generation != trusted.Generation || shown.Digest != trusted.Digest || authorization.AppID != trusted.AppID || authorization.Generation != trusted.Generation || authorization.PreviewDigest != trusted.Digest {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ErrInvalidPreview
	}
	if err := verifier.Verify(ctx, authorization, trusted.AppID, trusted.Generation, trusted.Digest); err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrUnauthorized.Error()})
		return safeFailure(ErrUnauthorized, err)
	}
	operation, err := canonicalDigest(normalized)
	if err != nil {
		return ErrInvalidPreview
	}
	completed, err := journal.Completed(ctx, operation, "compose")
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	if completed {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "succeeded", Detail: "already completed"})
		return nil
	}
	audit(auditor, AuditRecord{Action: "compose.progress", Outcome: "applying", Detail: operation})
	err = executor.ApplyCompose(ctx, operation, normalized)
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	audit(auditor, AuditRecord{Action: "compose.apply", Outcome: outcome, Detail: map[bool]string{true: ErrOperationFailed.Error(), false: ""}[err != nil]})
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if err := journal.MarkCompleted(ctx, operation, "compose"); err != nil {
		audit(auditor, AuditRecord{Action: "compose.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	return nil
}

func audit(auditor Auditor, record AuditRecord) {
	if auditor == nil {
		return
	}
	auditor.Record(record)
}

const (
	RuntimeStatusRunning = "running"
	RuntimeStatusStopped = "stopped"
)

// ManageSpec is a pasted compose document or docker run command plus the
// identifiers that become the managed app after authorization.
type ManageSpec struct {
	AppID, Generation, Project, RuleRef, Source string
}

type ManagedApp struct {
	App     App
	Running bool
	Status  string
}

type AppRuntime struct {
	Running bool
	Status  string
}

// RuntimeObserver is an injectable business-test boundary for post-apply
// running status. It is not a Host API or wire contract.
type RuntimeObserver interface {
	CurrentRuntime(context.Context, string) (AppRuntime, error)
}
type RuntimeObserverFunc func(context.Context, string) (AppRuntime, error)

func (function RuntimeObserverFunc) CurrentRuntime(ctx context.Context, appID string) (AppRuntime, error) {
	return function(ctx, appID)
}

// PlanFromSource turns a pasted compose document or docker run command into a
// compose plan. Credential values are discarded; only secret_refs remain.
func PlanFromSource(spec ManageSpec) (ComposePlan, error) {
	if !validID(spec.AppID) || !boundedText(spec.Generation, 128) {
		return ComposePlan{}, ErrBoundExceeded
	}
	if len(spec.Source) == 0 {
		return ComposePlan{}, errors.New("manage source is invalid")
	}
	if len(spec.Source) > MaxConfigBytes {
		return ComposePlan{}, ErrBoundExceeded
	}
	if spec.RuleRef != "" && !boundedText(spec.RuleRef, 128) {
		return ComposePlan{}, errors.New("rule_ref is invalid")
	}
	project := spec.Project
	if project == "" {
		project = spec.AppID
	}
	if !validID(project) {
		return ComposePlan{}, errors.New("compose project is invalid")
	}
	var plan ComposePlan
	var err error
	if looksLikeDockerRun(spec.Source) {
		plan, err = planFromDockerRun(spec)
	} else {
		plan, err = planFromComposeYAML(spec)
	}
	if err != nil {
		return ComposePlan{}, err
	}
	plan.AppID = spec.AppID
	plan.Generation = spec.Generation
	plan.Project = project
	if spec.RuleRef != "" {
		plan.RuleRef = spec.RuleRef
	}
	return canonicalComposePlan(plan)
}

// PreviewSource parses a compose document or docker run command and builds the
// authorization preview. The returned plan contains secret_refs only.
func PreviewSource(spec ManageSpec) (ComposePlan, RiskPreview, error) {
	plan, err := PlanFromSource(spec)
	if err != nil {
		return ComposePlan{}, RiskPreview{}, err
	}
	preview, err := PreviewCompose(plan)
	if err != nil {
		return ComposePlan{}, RiskPreview{}, err
	}
	return plan, preview, nil
}

// AppFromPlan projects configuration for apps[]. Image, rule_ref, and
// secret_refs come from the plan; credential material is never copied.
func AppFromPlan(plan ComposePlan) (App, error) {
	normalized, err := canonicalComposePlan(plan)
	if err != nil {
		return App{}, err
	}
	app := App{
		ID:         normalized.AppID,
		Image:      normalized.Image,
		RuleRef:    normalized.RuleRef,
		Generation: normalized.Generation,
		SecretRefs: append([]string(nil), normalized.SecretRefs...),
	}
	if err := app.Validate(); err != nil {
		return App{}, err
	}
	return app, nil
}

// ExecuteManaged applies an authorized compose or docker run plan, then
// projects the managed app and its current running status.
func ExecuteManaged(ctx context.Context, plan ComposePlan, shown RiskPreview, authorization Authorization, inventory ComposeInventory, verifier AuthorizationVerifier, executor ComposeExecutor, journal ProgressJournal, auditor Auditor, observer RuntimeObserver) (ManagedApp, error) {
	if auditor == nil {
		return ManagedApp{}, ErrAuditRequired
	}
	if observer == nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ManagedApp{}, ErrTypedHandlesUnavailable
	}
	trusted, err := PreviewCompose(plan)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ManagedApp{}, safeFailure(ErrInvalidPreview, err)
	}
	if trusted.Digest != shown.Digest || trusted.AppID != shown.AppID || trusted.Generation != shown.Generation {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ManagedApp{}, ErrInvalidPreview
	}
	if err := ExecuteCompose(ctx, shown, authorization, inventory, verifier, executor, journal, auditor); err != nil {
		return ManagedApp{}, err
	}
	app, err := AppFromPlan(plan)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return ManagedApp{}, safeFailure(ErrOperationFailed, err)
	}
	runtime, err := observer.CurrentRuntime(ctx, app.ID)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return ManagedApp{}, safeFailure(ErrOperationFailed, err)
	}
	status := runtime.Status
	if status == "" {
		if runtime.Running {
			status = RuntimeStatusRunning
		} else {
			status = RuntimeStatusStopped
		}
	}
	return ManagedApp{App: app, Running: runtime.Running, Status: status}, nil
}

func looksLikeDockerRun(source string) bool {
	line := firstMeaningfulLine(source)
	line = strings.TrimSpace(strings.TrimPrefix(line, "sudo "))
	return strings.HasPrefix(line, "docker run") || strings.HasPrefix(line, "docker container run")
}

func firstMeaningfulLine(source string) string {
	source = strings.TrimPrefix(source, "\ufeff")
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

func planFromDockerRun(spec ManageSpec) (ComposePlan, error) {
	tokens, err := splitCommand(spec.Source)
	if err != nil {
		return ComposePlan{}, err
	}
	index := 0
	if index < len(tokens) && tokens[index] == "sudo" {
		index++
	}
	if index >= len(tokens) || tokens[index] != "docker" {
		return ComposePlan{}, errors.New("docker run command is invalid")
	}
	index++
	if index < len(tokens) && tokens[index] == "container" {
		index++
	}
	if index >= len(tokens) || tokens[index] != "run" {
		return ComposePlan{}, errors.New("docker run command is invalid")
	}
	index++
	service := ComposeService{}
	var envKeys, envFiles []string
	var named bool
	var image string
	for index < len(tokens) {
		token := tokens[index]
		if token == "--" {
			index++
			break
		}
		if !strings.HasPrefix(token, "-") {
			image = token
			index++
			break
		}
		name, value, hasValue := splitRunFlag(token)
		takesValue := dockerRunTakesValue(name)
		if !takesValue && strings.HasPrefix(token, "--") && !hasValue && !dockerRunBoolean(name) {
			if index+1 < len(tokens) && !strings.HasPrefix(tokens[index+1], "-") {
				index++
			}
			index++
			continue
		}
		if takesValue {
			if !hasValue {
				index++
				if index >= len(tokens) || strings.HasPrefix(tokens[index], "-") {
					return ComposePlan{}, errors.New("docker run command is invalid")
				}
				value = tokens[index]
			}
			switch name {
			case "name":
				if !validID(value) {
					return ComposePlan{}, errors.New("docker run command is invalid")
				}
				service.Name = value
				named = true
			case "v", "volume":
				assignVolume(&service, value)
			case "mount":
				if err := assignMount(&service, value); err != nil {
					return ComposePlan{}, err
				}
			case "cap-add":
				service.AddCapabilities = append(service.AddCapabilities, value)
			case "network", "net":
				service.Networks = append(service.Networks, value)
			case "e", "env":
				key, _, _ := strings.Cut(value, "=")
				if key == "" || !boundedText(key, 128) {
					return ComposePlan{}, errors.New("docker run command is invalid")
				}
				envKeys = append(envKeys, key)
			case "env-file":
				base := envFileBase(value)
				if base == "" {
					return ComposePlan{}, errors.New("docker run command is invalid")
				}
				envFiles = append(envFiles, base)
			case "device":
				service.HostMounts = append(service.HostMounts, value)
			case "security-opt", "pid", "ipc":
				service.AddCapabilities = append(service.AddCapabilities, name+":"+value)
			}
			index++
			continue
		}
		if name == "privileged" {
			service.Privileged = true
		}
		index++
	}
	if image == "" || !boundedText(image, 512) || !named || !validID(service.Name) {
		return ComposePlan{}, errors.New("docker run command is invalid")
	}
	service.Image = image
	refNames := append(sensitiveEnvironmentNames(envKeys), envFiles...)
	refs, err := BindSecretRefs(namedCredentials(refNames))
	if err != nil {
		return ComposePlan{}, err
	}
	service.SecretRefs = refs
	return ComposePlan{Image: image, Services: []ComposeService{service}}, nil
}

func planFromComposeYAML(spec ManageSpec) (ComposePlan, error) {
	var document map[string]any
	if err := yaml.Unmarshal([]byte(spec.Source), &document); err != nil || document == nil {
		return ComposePlan{}, errors.New("compose document is invalid")
	}
	rawServices, ok := document["services"].(map[string]any)
	if !ok || len(rawServices) == 0 {
		return ComposePlan{}, errors.New("compose document is invalid")
	}
	if len(rawServices) > MaxComposeServices {
		return ComposePlan{}, ErrBoundExceeded
	}
	plan := ComposePlan{Services: make([]ComposeService, 0, len(rawServices))}
	for name, raw := range rawServices {
		body, ok := raw.(map[string]any)
		if !ok {
			return ComposePlan{}, errors.New("compose document is invalid")
		}
		if !validID(name) {
			return ComposePlan{}, errors.New("compose service is invalid")
		}
		service := ComposeService{Name: name}
		if image, _ := mapString(body, "image"); image != "" {
			if !boundedText(image, 512) {
				return ComposePlan{}, errors.New("compose image is invalid")
			}
			service.Image = image
		}
		if privileged, _ := body["privileged"].(bool); privileged {
			service.Privileged = true
		}
		caps, err := stringList(body["cap_add"])
		if err != nil {
			return ComposePlan{}, errors.New("compose document is invalid")
		}
		service.AddCapabilities = caps
		networks, err := composeNetworks(body["networks"])
		if err != nil {
			return ComposePlan{}, errors.New("compose document is invalid")
		}
		service.Networks = networks
		if err := assignComposeVolumes(&service, body["volumes"]); err != nil {
			return ComposePlan{}, err
		}
		envKeys, err := composeEnvKeys(body["environment"])
		if err != nil {
			return ComposePlan{}, err
		}
		files, err := composeEnvFiles(body["env_file"])
		if err != nil {
			return ComposePlan{}, err
		}
		secrets, err := composeSecretNames(body["secrets"])
		if err != nil {
			return ComposePlan{}, err
		}
		refNames := append(sensitiveEnvironmentNames(envKeys), files...)
		refNames = append(refNames, secrets...)
		refs, err := BindSecretRefs(namedCredentials(refNames))
		if err != nil {
			return ComposePlan{}, err
		}
		service.SecretRefs = refs
		plan.Services = append(plan.Services, service)
	}
	return plan, nil
}

func namedCredentials(names []string) []TransientCredential {
	credentials := make([]TransientCredential, 0, len(names))
	for _, name := range names {
		credentials = append(credentials, TransientCredential{Name: name})
	}
	return credentials
}

func splitCommand(source string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	var quote rune
	escaped := false
	started := false
	skipComment := false
	for _, r := range source {
		if skipComment {
			if r == '\n' {
				skipComment = false
			}
			continue
		}
		if escaped {
			if r != '\n' && r != '\r' {
				current.WriteRune(r)
				started = true
			}
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
			started = true
			continue
		}
		if r == '#' && !started {
			skipComment = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if started {
				tokens = append(tokens, current.String())
				current.Reset()
				started = false
			}
			continue
		}
		current.WriteRune(r)
		started = true
	}
	if quote != 0 || escaped {
		return nil, errors.New("docker run command is invalid")
	}
	if started {
		tokens = append(tokens, current.String())
	}
	if len(tokens) == 0 {
		return nil, errors.New("docker run command is invalid")
	}
	if len(tokens) > MaxCollectionItems {
		return nil, ErrBoundExceeded
	}
	return tokens, nil
}

func splitRunFlag(token string) (name, value string, hasValue bool) {
	if strings.HasPrefix(token, "--") {
		body := strings.TrimPrefix(token, "--")
		name, value, hasValue = strings.Cut(body, "=")
		return name, value, hasValue
	}
	body := strings.TrimPrefix(token, "-")
	if name, value, ok := strings.Cut(body, "="); ok {
		return name, value, true
	}
	return body, "", false
}

func dockerRunTakesValue(name string) bool {
	switch name {
	case "name", "v", "volume", "mount", "cap-add", "network", "net", "e", "env", "env-file", "device", "security-opt", "pid", "ipc":
		return true
	case "p", "publish", "label", "hostname", "user", "w", "workdir", "entrypoint", "m", "memory", "cpus", "restart", "add-host", "log-driver", "log-opt", "pull", "runtime", "platform":
		return true
	default:
		return false
	}
}

func dockerRunBoolean(name string) bool {
	switch name {
	case "d", "detach", "rm", "privileged", "i", "t", "it", "ti", "interactive", "tty", "init", "P", "publish-all", "read-only", "q", "quiet", "sig-proxy", "no-healthcheck":
		return true
	default:
		return false
	}
}

func assignVolume(service *ComposeService, spec string) {
	host, named, relative := classifyVolume(spec)
	if relative != "" {
		service.RelativeBinds = append(service.RelativeBinds, relative)
		return
	}
	if host != "" {
		service.HostMounts = append(service.HostMounts, host)
		return
	}
	if named != "" {
		service.Volumes = append(service.Volumes, named)
	}
}

func assignMount(service *ComposeService, spec string) error {
	fields := strings.Split(spec, ",")
	var kind, source string
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return errors.New("docker run command is invalid")
		}
		switch strings.TrimSpace(key) {
		case "type":
			kind = strings.TrimSpace(value)
		case "source", "src":
			source = strings.TrimSpace(value)
		}
	}
	if source == "" {
		return errors.New("docker run command is invalid")
	}
	switch classifyBindSource(source) {
	case bindRelative:
		service.RelativeBinds = append(service.RelativeBinds, source)
		return nil
	case bindHost:
		if kind == "bind" || kind == "" {
			service.HostMounts = append(service.HostMounts, source)
			return nil
		}
	}
	if kind == "bind" {
		service.HostMounts = append(service.HostMounts, source)
		return nil
	}
	service.Volumes = append(service.Volumes, source)
	return nil
}

func assignComposeVolumes(service *ComposeService, raw any) error {
	if raw == nil {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return errors.New("compose document is invalid")
	}
	for _, item := range items {
		switch volume := item.(type) {
		case string:
			assignVolume(service, volume)
		case map[string]any:
			kind, _ := mapString(volume, "type")
			source, _ := mapString(volume, "source")
			if source == "" {
				source, _ = mapString(volume, "src")
			}
			target, _ := mapString(volume, "target")
			spec := source
			if target != "" {
				spec = source + ":" + target
			}
			class := classifyBindSource(source)
			if class == bindRelative {
				if source == "" {
					return errors.New("compose document is invalid")
				}
				service.RelativeBinds = append(service.RelativeBinds, spec)
				continue
			}
			if kind == "bind" || source != "" && class == bindHost {
				if source == "" {
					return errors.New("compose document is invalid")
				}
				service.HostMounts = append(service.HostMounts, spec)
				continue
			}
			if source != "" {
				service.Volumes = append(service.Volumes, source)
			}
		default:
			return errors.New("compose document is invalid")
		}
	}
	return nil
}

func composeNetworks(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	switch networks := raw.(type) {
	case []any:
		return stringList(networks)
	case map[string]any:
		names := make([]string, 0, len(networks))
		for name := range networks {
			names = append(names, name)
		}
		return names, nil
	default:
		return nil, errors.New("compose document is invalid")
	}
}

func composeEnvKeys(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	switch env := raw.(type) {
	case map[string]any:
		keys := make([]string, 0, len(env))
		for key := range env {
			if key == "" || !boundedText(key, 128) {
				return nil, errors.New("compose document is invalid")
			}
			keys = append(keys, key)
		}
		return keys, nil
	case []any:
		keys := make([]string, 0, len(env))
		for _, item := range env {
			value, ok := item.(string)
			if !ok {
				return nil, errors.New("compose document is invalid")
			}
			key, _, _ := strings.Cut(value, "=")
			if key == "" || !boundedText(key, 128) {
				return nil, errors.New("compose document is invalid")
			}
			keys = append(keys, key)
		}
		return keys, nil
	default:
		return nil, errors.New("compose document is invalid")
	}
}

func composeEnvFiles(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	if value, ok := raw.(string); ok {
		base := envFileBase(value)
		if base == "" {
			return nil, errors.New("compose document is invalid")
		}
		return []string{base}, nil
	}
	items, err := stringList(raw)
	if err != nil {
		return nil, errors.New("compose document is invalid")
	}
	files := make([]string, 0, len(items))
	for _, item := range items {
		base := envFileBase(item)
		if base == "" {
			return nil, errors.New("compose document is invalid")
		}
		files = append(files, base)
	}
	return files, nil
}

func composeSecretNames(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, errors.New("compose document is invalid")
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		switch secret := item.(type) {
		case string:
			if secret == "" || !boundedText(secret, 128) {
				return nil, errors.New("compose document is invalid")
			}
			names = append(names, secret)
		case map[string]any:
			name, _ := mapString(secret, "source")
			if name == "" {
				name, _ = mapString(secret, "target")
			}
			if name == "" || !boundedText(name, 128) {
				return nil, errors.New("compose document is invalid")
			}
			names = append(names, name)
		default:
			return nil, errors.New("compose document is invalid")
		}
	}
	return names, nil
}

func stringList(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	if value, ok := raw.(string); ok {
		if !boundedText(value, 512) {
			return nil, errors.New("list is invalid")
		}
		return []string{value}, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, errors.New("list is invalid")
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok || !boundedText(value, 512) {
			return nil, errors.New("list is invalid")
		}
		values = append(values, value)
	}
	return values, nil
}

func mapString(values map[string]any, key string) (string, bool) {
	raw, ok := values[key]
	if !ok || raw == nil {
		return "", false
	}
	value, ok := raw.(string)
	if !ok {
		return "", false
	}
	return value, true
}

func envFileBase(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\\", "/")
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	base := parts[len(parts)-1]
	if base == "" || !boundedText(base, 128) {
		return ""
	}
	return base
}
