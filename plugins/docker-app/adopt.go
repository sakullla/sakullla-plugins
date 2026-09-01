package dockerapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	ErrInvalidAdoptSource = errors.New("adopt source is invalid")
	ErrNotCandidate       = errors.New("container is not an adoptable candidate")
)

type AppStatus string

const (
	AppStatusRunning AppStatus = "running"
	AppStatusStopped AppStatus = "stopped"
)

type RuntimeObservation struct {
	ContainerID string
	Running     bool
}

type CatalogItem struct {
	App            App
	Running        bool
	Status         AppStatus
	Services       []string
	PublishedPorts []uint16
}

type CatalogView struct {
	Managed    []CatalogItem
	Candidates []Discovery
}

type StopExecutor interface {
	Stop(context.Context, App) error
}
type StopExecutorFunc func(context.Context, App) error

func (function StopExecutorFunc) Stop(ctx context.Context, app App) error {
	return function(ctx, app)
}

// ParseComposeDocument turns pasted compose YAML into a risk plan and app.
// Sensitive environment values become secret_refs via BindSecretRefs. All
// environment values are wiped from the stored compose document.
func ParseComposeDocument(document, appID, generation, ruleRef string) (ComposePlan, App, error) {
	if len(document) > MaxConfigBytes {
		return ComposePlan{}, App{}, fmt.Errorf("%w: adopt source exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	if !validID(appID) || !boundedText(generation, 128) || (ruleRef != "" && !boundedText(ruleRef, 128)) {
		return ComposePlan{}, App{}, ErrInvalidAdoptSource
	}
	decoder := yaml.NewDecoder(bytes.NewReader([]byte(document)))
	var file composeDocument
	if err := decoder.Decode(&file); err != nil {
		return ComposePlan{}, App{}, ErrInvalidCompose
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ComposePlan{}, App{}, ErrInvalidCompose
	}
	if len(file.Services) == 0 || len(file.Services) > MaxComposeServices {
		return ComposePlan{}, App{}, ErrInvalidCompose
	}
	plan := ComposePlan{AppID: appID, Generation: generation, Project: appID}
	if ruleRef != "" {
		plan.RuleRef = ruleRef
		plan.RuleImpacts = []string{ruleRef}
	}
	var credentials []TransientCredential
	var images []ServiceImage
	for name, service := range file.Services {
		parsed, serviceCreds, err := composeServiceFromYAML(name, service)
		if err != nil {
			wipeCredentials(serviceCreds)
			wipeCredentials(credentials)
			return ComposePlan{}, App{}, err
		}
		images = append(images, ServiceImage{Name: name, Image: parsed.image})
		plan.Services = append(plan.Services, parsed.service)
		credentials = append(credentials, serviceCreds...)
	}
	if len(images) == 0 {
		wipeCredentials(credentials)
		return ComposePlan{}, App{}, ErrMissingComposeImage
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Name < images[j].Name })
	image := images[0].Image
	redacted, err := redactComposeYAML(document)
	if err != nil {
		wipeCredentials(credentials)
		return ComposePlan{}, App{}, err
	}
	app, err := AppWithBoundSecrets(App{ID: appID, Image: image, ServiceImages: images, RuleRef: ruleRef, Generation: generation, Compose: redacted}, credentials)
	if err != nil {
		return ComposePlan{}, App{}, err
	}
	return plan, app, nil
}

// ParseDockerRun turns a docker run command into a risk plan and app.
// Flag values that carry credentials become secret_refs and are wiped.
func ParseDockerRun(command, generation, ruleRef string) (ComposePlan, App, error) {
	if len(command) > MaxConfigBytes {
		return ComposePlan{}, App{}, fmt.Errorf("%w: adopt source exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	if !boundedText(generation, 128) || !boundedText(ruleRef, 128) {
		return ComposePlan{}, App{}, ErrInvalidAdoptSource
	}
	tokens, err := splitCommandLine(command)
	if err != nil {
		return ComposePlan{}, App{}, ErrInvalidAdoptSource
	}
	if len(tokens) < 3 || tokens[0] != "docker" || tokens[1] != "run" {
		return ComposePlan{}, App{}, ErrInvalidAdoptSource
	}
	parsed, credentials, err := parseDockerRunTokens(tokens[2:])
	if err != nil {
		wipeCredentials(credentials)
		return ComposePlan{}, App{}, err
	}
	if !validID(parsed.name) || !boundedText(parsed.image, 512) {
		wipeCredentials(credentials)
		return ComposePlan{}, App{}, ErrInvalidAdoptSource
	}
	parsed.service.Name = parsed.name
	plan := ComposePlan{
		AppID: parsed.name, Generation: generation, Project: parsed.name,
		Services:    []ComposeService{parsed.service},
		RuleImpacts: []string{ruleRef},
	}
	app, err := AppWithBoundSecrets(App{ID: parsed.name, Image: parsed.image, ServiceImages: []ServiceImage{{Name: parsed.name, Image: parsed.image}}, RuleRef: ruleRef, Generation: generation}, credentials)
	if err != nil {
		return ComposePlan{}, App{}, err
	}
	return plan, app, nil
}

// AdoptCandidate appends an unlabeled exposed-port container to the managed
// app list. Discoveries without Candidate remain excluded.
func AdoptCandidate(observations []ContainerObservation, apps []App, containerID string, app App) ([]App, error) {
	if !boundedText(containerID, 128) {
		return nil, ErrNotCandidate
	}
	found := false
	for _, observation := range observations {
		if observation.ID == containerID {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotCandidate
	}
	discoveries, err := Discover(observations)
	if err != nil {
		return nil, err
	}
	for _, discovery := range discoveries {
		if discovery.ContainerID == containerID && discovery.Candidate && discovery.AppID == "" {
			return RegisterManaged(apps, app)
		}
	}
	return nil, ErrNotCandidate
}

// RegisterManaged appends a validated app to the managed list. Candidates are
// not inserted here; callers must go through AdoptCandidate or authorized apply.
func RegisterManaged(apps []App, app App) ([]App, error) {
	if err := app.Validate(); err != nil {
		return nil, err
	}
	if len(apps)+1 > MaxApps {
		return nil, fmt.Errorf("%w: apps maximum is %d", ErrBoundExceeded, MaxApps)
	}
	for _, existing := range apps {
		if existing.ID == app.ID {
			return nil, errors.New("app id is duplicated")
		}
	}
	return append(cloneApps(apps), cloneApp(app)), nil
}

func RemoveManaged(apps []App, appID string) []App {
	result := make([]App, 0, len(apps))
	for _, app := range apps {
		if app.ID == appID {
			continue
		}
		result = append(result, cloneApp(app))
	}
	return result
}

// ProjectCatalog keeps managed apps and candidates in separate lists.
// Unlabeled exposed ports stay candidates until AdoptCandidate plus a label.
func ProjectCatalog(observations []ContainerObservation, runtimes []RuntimeObservation, apps []App) (CatalogView, error) {
	discoveries, err := Discover(observations)
	if err != nil {
		return CatalogView{}, err
	}
	runningByContainer := make(map[string]bool, len(runtimes))
	for _, runtime := range runtimes {
		if runtime.ContainerID == "" {
			continue
		}
		runningByContainer[runtime.ContainerID] = runtime.Running
	}
	view := CatalogView{Managed: make([]CatalogItem, 0, len(apps))}
	for _, app := range apps {
		item := CatalogItem{App: cloneApp(app), Status: AppStatusStopped, Services: composeServiceNames(app.Compose), PublishedPorts: composePublishedPorts(app.Compose)}
		for _, observation := range observations {
			if observation.Labels[AppLabel] != app.ID {
				continue
			}
			item.PublishedPorts = mergePorts(item.PublishedPorts, observation.ExposedPorts)
			if runningByContainer[observation.ID] {
				item.Running = true
				item.Status = AppStatusRunning
			}
		}
		view.Managed = append(view.Managed, item)
	}
	for _, discovery := range discoveries {
		if discovery.Candidate {
			view.Candidates = append(view.Candidates, discovery)
		}
	}
	return view, nil
}

func LabelObservation(observation ContainerObservation, appID string) ContainerObservation {
	labels := make(map[string]string, len(observation.Labels)+1)
	for key, value := range observation.Labels {
		labels[key] = value
	}
	labels[AppLabel] = appID
	observation.Labels = labels
	observation.ExposedPorts = append([]uint16(nil), observation.ExposedPorts...)
	return observation
}

func StopManaged(ctx context.Context, app App, executor StopExecutor, auditor Auditor) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if executor == nil {
		audit(auditor, AuditRecord{Action: "app.stop", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	if err := executor.Stop(ctx, app); err != nil {
		audit(auditor, AuditRecord{Action: "app.stop", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	audit(auditor, AuditRecord{Action: "app.stop", Outcome: "succeeded", Detail: app.ID})
	return nil
}

func cloneApp(app App) App {
	app.SecretRefs = append([]string(nil), app.SecretRefs...)
	app.AutoUpdate = cloneBool(app.AutoUpdate)
	app.ServiceImages = append([]ServiceImage(nil), app.ServiceImages...)
	app.ImageLocks = cloneStringMap(app.ImageLocks)
	app.IgnoredUpdates = cloneStringSlicesMap(app.IgnoredUpdates)
	return app
}

type composeDocument struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Image       string   `yaml:"image"`
	Privileged  bool     `yaml:"privileged"`
	CapAdd      []string `yaml:"cap_add"`
	Volumes     []string `yaml:"volumes"`
	Ports       any      `yaml:"ports"`
	Networks    any      `yaml:"networks"`
	Environment any      `yaml:"environment"`
}

type parsedComposeService struct {
	service ComposeService
	image   string
}

func composeServiceFromYAML(name string, raw composeService) (parsedComposeService, []TransientCredential, error) {
	if !validID(name) {
		return parsedComposeService{}, nil, ErrInvalidAdoptSource
	}
	if raw.Image == "" {
		return parsedComposeService{}, nil, ErrMissingComposeImage
	}
	if !boundedText(raw.Image, 512) {
		return parsedComposeService{}, nil, ErrInvalidAdoptSource
	}
	networks, err := collectNames(raw.Networks)
	if err != nil {
		return parsedComposeService{}, nil, ErrInvalidAdoptSource
	}
	hosts, volumes, relatives := classifyVolumes(raw.Volumes)
	credentials, err := collectEnvironment(raw.Environment)
	if err != nil {
		wipeCredentials(credentials)
		return parsedComposeService{}, nil, ErrInvalidAdoptSource
	}
	return parsedComposeService{
		service: ComposeService{
			Name:            name,
			Privileged:      raw.Privileged,
			HostMounts:      hosts,
			RelativeBinds:   relatives,
			AddCapabilities: append([]string(nil), raw.CapAdd...),
			Networks:        networks,
			Volumes:         volumes,
			PublishedPorts:  publishedPortsFromYAML(raw.Ports),
		},
		image: raw.Image,
	}, credentials, nil
}

type parsedDockerRun struct {
	name, image string
	service     ComposeService
}

func parseDockerRunTokens(tokens []string) (parsedDockerRun, []TransientCredential, error) {
	var parsed parsedDockerRun
	var credentials []TransientCredential
	index := 0
	for index < len(tokens) {
		token := tokens[index]
		if token == "--" {
			index++
			break
		}
		if token == "" || token[0] != '-' {
			break
		}
		flag, attached, hasAttached := cutFlag(token)
		switch flag {
		case "-d", "--detach", "--rm", "-i", "--interactive", "-t", "--tty", "-it", "-P", "--publish-all", "--read-only", "--init":
			if hasAttached {
				return parsedDockerRun{}, credentials, ErrInvalidAdoptSource
			}
			index++
		case "--privileged":
			if hasAttached {
				return parsedDockerRun{}, credentials, ErrInvalidAdoptSource
			}
			parsed.service.Privileged = true
			index++
		case "--name", "-e", "--env", "-v", "--volume", "--cap-add", "--network", "--net", "-p", "--publish", "--env-file", "-l", "--label":
			value := attached
			if !hasAttached {
				index++
				if index >= len(tokens) || tokens[index] == "" || (tokens[index][0] == '-' && tokens[index] != "-") {
					return parsedDockerRun{}, credentials, ErrInvalidAdoptSource
				}
				value = tokens[index]
			}
			switch flag {
			case "--name":
				if parsed.name != "" {
					return parsedDockerRun{}, credentials, ErrInvalidAdoptSource
				}
				parsed.name = value
			case "-e", "--env":
				name, material, _ := strings.Cut(value, "=")
				if !boundedText(name, 128) {
					return parsedDockerRun{}, credentials, ErrInvalidAdoptSource
				}
				if sensitiveEnvironmentName(name) {
					credentials = append(credentials, TransientCredential{Name: name, Material: []byte(material)})
				}
			case "-v", "--volume":
				host, named, relative := classifyVolume(value)
				if host != "" {
					parsed.service.HostMounts = append(parsed.service.HostMounts, host)
				}
				if named != "" {
					parsed.service.Volumes = append(parsed.service.Volumes, named)
				}
				if relative != "" {
					parsed.service.RelativeBinds = append(parsed.service.RelativeBinds, relative)
				}
			case "--cap-add":
				parsed.service.AddCapabilities = append(parsed.service.AddCapabilities, value)
			case "--network", "--net":
				parsed.service.Networks = append(parsed.service.Networks, value)
			}
			index++
		default:
			if !hasAttached && strings.HasPrefix(flag, "--") && index+1 < len(tokens) && tokens[index+1] != "" && tokens[index+1][0] != '-' {
				index += 2
				continue
			}
			index++
		}
	}
	if index >= len(tokens) || tokens[index] == "" || tokens[index][0] == '-' {
		return parsedDockerRun{}, credentials, ErrInvalidAdoptSource
	}
	parsed.image = tokens[index]
	return parsed, credentials, nil
}

func cutFlag(token string) (flag, value string, hasValue bool) {
	if strings.HasPrefix(token, "--") {
		flag, value, hasValue = strings.Cut(token, "=")
		return flag, value, hasValue
	}
	if len(token) > 2 {
		if boolShortCluster(token[1:]) {
			return token, "", false
		}
		return token[:2], token[2:], true
	}
	return token, "", false
}

func boolShortCluster(letters string) bool {
	if letters == "" {
		return false
	}
	for _, letter := range letters {
		switch letter {
		case 'd', 'i', 't', 'P', 'q':
		default:
			return false
		}
	}
	return true
}

func splitCommandLine(command string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	quote := byte(0)
	escaped := false
	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, current.String())
		current.Reset()
	}
	for index := 0; index < len(command); index++ {
		ch := command[index]
		if escaped {
			if ch == '\n' || ch == '\r' {
				escaped = false
				continue
			}
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
				continue
			}
			current.WriteByte(ch)
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			current.WriteByte(ch)
		}
	}
	if quote != 0 || escaped {
		return nil, ErrInvalidAdoptSource
	}
	flush()
	if len(tokens) > MaxCollectionItems {
		return nil, ErrBoundExceeded
	}
	return tokens, nil
}

func collectNames(value any) ([]string, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		if typed == "" {
			return nil, nil
		}
		return []string{typed}, nil
	case []string:
		return append([]string(nil), typed...), nil
	case []any:
		names := make([]string, 0, len(typed))
		for _, item := range typed {
			name, ok := item.(string)
			if !ok {
				return nil, ErrInvalidAdoptSource
			}
			names = append(names, name)
		}
		return names, nil
	case map[string]any:
		names := make([]string, 0, len(typed))
		for name := range typed {
			names = append(names, name)
		}
		return names, nil
	default:
		return nil, ErrInvalidAdoptSource
	}
}

func collectEnvironment(value any) ([]TransientCredential, error) {
	credentials := make([]TransientCredential, 0)
	appendCredential := func(name string, material []byte) error {
		name = strings.TrimSpace(name)
		if !boundedText(name, 128) {
			return ErrInvalidAdoptSource
		}
		if sensitiveEnvironmentName(name) {
			credentials = append(credentials, TransientCredential{Name: name, Material: material})
		}
		return nil
	}
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		for name, raw := range typed {
			if err := appendCredential(name, materialBytes(raw)); err != nil {
				return credentials, err
			}
		}
		return credentials, nil
	case map[string]string:
		for name, raw := range typed {
			if err := appendCredential(name, []byte(raw)); err != nil {
				return credentials, err
			}
		}
		return credentials, nil
	case []any:
		for _, item := range typed {
			entry, ok := item.(string)
			if !ok {
				return credentials, ErrInvalidAdoptSource
			}
			name, material, _ := strings.Cut(entry, "=")
			if err := appendCredential(name, []byte(material)); err != nil {
				return credentials, err
			}
		}
		return credentials, nil
	case []string:
		for _, entry := range typed {
			name, material, _ := strings.Cut(entry, "=")
			if err := appendCredential(name, []byte(material)); err != nil {
				return credentials, err
			}
		}
		return credentials, nil
	default:
		return nil, ErrInvalidAdoptSource
	}
}

func materialBytes(value any) []byte {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return []byte(typed)
	case []byte:
		return append([]byte(nil), typed...)
	default:
		return []byte(fmt.Sprint(typed))
	}
}

func redactComposeYAML(document string) (string, error) {
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(document), &raw); err != nil || raw == nil {
		return "", ErrInvalidCompose
	}
	services, _ := raw["services"].(map[string]any)
	for _, service := range services {
		body, ok := service.(map[string]any)
		if !ok {
			continue
		}
		switch env := body["environment"].(type) {
		case map[string]any:
			for key := range env {
				env[key] = ""
			}
		case []any:
			for index, item := range env {
				text, ok := item.(string)
				if !ok {
					continue
				}
				name, _, found := strings.Cut(text, "=")
				if found {
					env[index] = name
				}
			}
		}
	}
	encoded, err := yaml.Marshal(raw)
	if err != nil {
		return "", ErrInvalidCompose
	}
	return string(encoded), nil
}

func ComposeServiceNames(document string) []string {
	return composeServiceNames(document)
}

func ComposeServiceImages(document string) []ServiceImage {
	return composeServiceImages(document)
}

func composeServiceImages(document string) []ServiceImage {
	if strings.TrimSpace(document) == "" {
		return nil
	}
	var file composeDocument
	if err := yaml.Unmarshal([]byte(document), &file); err != nil || len(file.Services) == 0 {
		return nil
	}
	names := make([]string, 0, len(file.Services))
	for name, service := range file.Services {
		if strings.TrimSpace(service.Image) == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	images := make([]ServiceImage, 0, len(names))
	for _, name := range names {
		images = append(images, ServiceImage{Name: name, Image: strings.TrimSpace(file.Services[name].Image)})
	}
	return images
}

func composeServiceNames(document string) []string {
	if document == "" {
		return nil
	}
	var file composeDocument
	if err := yaml.Unmarshal([]byte(document), &file); err != nil || len(file.Services) == 0 {
		return nil
	}
	names := make([]string, 0, len(file.Services))
	for name := range file.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func composePublishedPorts(document string) []uint16 {
	if document == "" {
		return nil
	}
	var file composeDocument
	if err := yaml.Unmarshal([]byte(document), &file); err != nil || len(file.Services) == 0 {
		return nil
	}
	var ports []uint16
	for _, service := range file.Services {
		ports = mergePorts(ports, publishedPortsFromYAML(service.Ports))
	}
	return ports
}

func publishedPortsFromYAML(value any) []uint16 {
	switch typed := value.(type) {
	case nil:
		return nil
	case []any:
		var ports []uint16
		for _, item := range typed {
			ports = mergePorts(ports, publishedPortsFromYAML(item))
		}
		return ports
	case []string:
		var ports []uint16
		for _, item := range typed {
			ports = mergePorts(ports, publishedPortsFromYAML(item))
		}
		return ports
	case map[string]any:
		return publishedFieldPort(typed["published"])
	case map[any]any:
		return publishedFieldPort(typed["published"])
	case string:
		if port, ok := parsePublishMapping(typed); ok {
			return []uint16{port}
		}
		return nil
	default:
		return nil
	}
}

func publishedFieldPort(value any) []uint16 {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case string:
		typed = strings.TrimSpace(typed)
		if slash := strings.LastIndex(typed, "/"); slash >= 0 {
			typed = typed[:slash]
		}
		if typed == "" || strings.ContainsAny(typed, ":-") {
			return nil
		}
		if port, ok := parsePortNumber(typed); ok {
			return []uint16{port}
		}
		return nil
	default:
		if port, ok := yamlPortNumber(typed); ok {
			return []uint16{port}
		}
		return nil
	}
}

func yamlPortNumber(value any) (uint16, bool) {
	switch typed := value.(type) {
	case int:
		return portNumber(typed)
	case int64:
		return portNumber(int(typed))
	case uint64:
		if typed == 0 || typed > 65535 {
			return 0, false
		}
		return uint16(typed), true
	case uint16:
		return typed, typed != 0
	case float64:
		if typed != float64(int(typed)) {
			return 0, false
		}
		return portNumber(int(typed))
	default:
		return 0, false
	}
}

func parsePublishMapping(value string) (uint16, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if slash := strings.LastIndex(value, "/"); slash >= 0 {
		value = value[:slash]
	}
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 {
			return 0, false
		}
		rest := strings.TrimPrefix(value[end+1:], ":")
		return parsePublishMapping(rest)
	}
	if strings.Contains(value, "-") {
		return 0, false
	}
	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return 0, false
	}
	hostPort := parts[len(parts)-2]
	if hostPort == "" {
		return 0, false
	}
	return parsePortNumber(hostPort)
}

func parsePortNumber(value string) (uint16, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	return portNumber(port)
}

func portNumber(value int) (uint16, bool) {
	if value <= 0 || value > 65535 {
		return 0, false
	}
	return uint16(value), true
}
