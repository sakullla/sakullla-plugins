package dockerapp

import (
	"fmt"
	"strings"
)

const (
	PluginDisplayName = "Docker 应用"
	OpsConfigEntry    = "打开配置"
	OpsPluginUsage    = "选择一台机器后，可以看到 Docker 是否就绪。把 compose YAML 贴进来就能部署应用，需要改设置时打开配置。"
	OpsAppUsage       = "可以启动、停止、重启或删除这个应用，也可以按服务查看日志。有发布端口时可以填写入口域名挂 HTTP 规则。"

	OpsStatusRunning         = "运行中"
	OpsStatusStopped         = "已停止"
	OpsStatusUpdateAvailable = "有新版本"
	OpsStatusPublishing      = "发布中"
	OpsStatusUnhealthy       = "异常"

	OpsActionConfigure = "configure"
	OpsActionEnable    = "enable"
	OpsActionDisable   = "disable"
	OpsActionStart     = "start"
	OpsActionStop      = "stop"
	OpsActionRestart   = "restart"
	OpsActionUpdate    = "update"
	OpsActionRollback  = "rollback"
	OpsActionDelete    = "delete"
)

// OpsAction is a user-facing button. Labels are popular Chinese; IDs are
// stable verbs for ui.dynamic. Audit, event, and lifecycle IDs stay out.
type OpsAction struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// OpsDocument is the default zero-basic view submitted through ui.dynamic.
// It only carries name, popular status, version, config entry, usage, and
// executable actions. Events, audit blocks, rollout phases, and error codes
// are not fields and are never copied in.
type OpsDocument struct {
	Name        string      `json:"name"`
	Status      string      `json:"status"`
	Version     string      `json:"version"`
	ConfigEntry string      `json:"config_entry"`
	Usage       string      `json:"usage"`
	Actions     []OpsAction `json:"actions"`
}

// DefaultOpsFields is the closed default-view key set.
func DefaultOpsFields() []string {
	return []string{"name", "status", "version", "config_entry", "usage", "actions"}
}

// ProjectPopularStatus maps an internal AppStatus onto the five popular
// Chinese values. Unknown or phase-like values collapse to 已停止.
func ProjectPopularStatus(status AppStatus) string {
	switch status {
	case AppStatusRunning:
		return OpsStatusRunning
	case AppStatusStopped:
		return OpsStatusStopped
	case AppStatusUpdateAvailable:
		return OpsStatusUpdateAvailable
	case AppStatusPublishing:
		return OpsStatusPublishing
	case AppStatusUnhealthy:
		return OpsStatusUnhealthy
	default:
		return OpsStatusStopped
	}
}

// ProjectOpsStatus projects rollout plus engine observations to a popular
// status. Internal phases stay inside ProjectManagedStatus and are not
// returned.
func ProjectOpsStatus(running, unhealthy bool, deployment Deployment, policy UpdatePolicy, latestDigest string) string {
	return ProjectPopularStatus(ProjectManagedStatus(running, unhealthy, deployment, policy, latestDigest))
}

// ProjectPluginOpsDocument is the plugin detail default view. Enable/disable
// and the config entry are the only actions; no event or audit entry.
func ProjectPluginOpsDocument(enabled bool) OpsDocument {
	status := OpsStatusStopped
	if enabled {
		status = OpsStatusRunning
	}
	return OpsDocument{
		Name:        PluginDisplayName,
		Status:      status,
		Version:     PluginVersion,
		ConfigEntry: OpsConfigEntry,
		Usage:       OpsPluginUsage,
		Actions: []OpsAction{
			{ID: OpsActionConfigure, Label: OpsConfigEntry},
			{ID: OpsActionEnable, Label: "启用"},
			{ID: OpsActionDisable, Label: "停用"},
		},
	}
}

// ProjectOpsDocument builds the default view for one managed app. The raw
// AppStatus enum is not copied; version is the image tag plus a shortened
// digest when one is present. latest is shown like any other tag.
func ProjectOpsDocument(app App, status AppStatus) OpsDocument {
	name := app.ID
	if name == "" {
		name = "未命名应用"
	}
	return OpsDocument{
		Name:        name,
		Status:      ProjectPopularStatus(status),
		Version:     displayImageVersion(app.Image, ""),
		ConfigEntry: OpsConfigEntry,
		Usage:       OpsAppUsage,
		Actions:     opsActions(status),
	}
}

// ProjectOpsDocumentFromRuntime uses rollout state only to choose a popular
// status and whether 回滚 is offered. Phase, LastFailure, and audit fields
// are not copied onto the document.
func ProjectOpsDocumentFromRuntime(app App, running, unhealthy bool, deployment Deployment, policy UpdatePolicy, latestDigest string) OpsDocument {
	status := ProjectManagedStatus(running, unhealthy, deployment, policy, latestDigest)
	document := ProjectOpsDocument(app, status)
	document.Version = displayImageVersion(app.Image, deployment.ImageDigest)
	if canRollback(deployment) && document.Status != OpsStatusPublishing {
		document.Actions = append(document.Actions, OpsAction{ID: OpsActionRollback, Label: "回滚"})
	}
	return document
}

func opsActions(status AppStatus) []OpsAction {
	configure := OpsAction{ID: OpsActionConfigure, Label: OpsConfigEntry}
	var actions []OpsAction
	switch ProjectPopularStatus(status) {
	case OpsStatusRunning:
		actions = []OpsAction{{ID: OpsActionStop, Label: "停止"}, {ID: OpsActionRestart, Label: "重启"}, configure}
	case OpsStatusStopped:
		actions = []OpsAction{{ID: OpsActionStart, Label: "启动"}, configure}
	case OpsStatusUpdateAvailable:
		actions = []OpsAction{{ID: OpsActionUpdate, Label: "更新"}, {ID: OpsActionStop, Label: "停止"}, configure}
	case OpsStatusPublishing:
		return []OpsAction{configure}
	case OpsStatusUnhealthy:
		actions = []OpsAction{{ID: OpsActionUpdate, Label: "恢复"}, {ID: OpsActionStop, Label: "停止"}, configure}
	default:
		return []OpsAction{configure}
	}
	return appendDeleteAction(actions)
}

func canRollback(deployment Deployment) bool {
	return len(deployment.History) > 0 || deployment.PriorInstance != "" || deployment.PriorImage != ""
}

const shortDigestHex = 12

func displayAppVersion(app App, digest string, hasUpdate bool) string {
	images := app.ServiceImages
	if len(images) == 0 {
		images = composeServiceImages(app.Compose)
	}
	if len(images) <= 1 {
		image := app.Image
		if image == "" && len(images) == 1 {
			image = images[0].Image
		}
		return displayImageVersion(image, digest)
	}
	if hasUpdate {
		return fmt.Sprintf("%d 个服务 · 部分有更新", len(images))
	}
	return fmt.Sprintf("%d 个服务", len(images))
}

func displayImageVersion(image, digest string) string {
	tag, imageDigest := splitImageDigest(image)
	if digest == "" {
		digest = imageDigest
	}
	if tag == "" {
		return digest
	}
	if digest == "" {
		return tag
	}
	return tag + " " + shortenDigest(digest)
}

func splitImageDigest(image string) (tag, digest string) {
	at := strings.LastIndex(image, "@")
	if at < 0 {
		return image, ""
	}
	return image[:at], image[at+1:]
}

func shortenDigest(digest string) string {
	algo, hex, found := strings.Cut(digest, ":")
	if !found {
		if len(digest) > shortDigestHex {
			return digest[:shortDigestHex]
		}
		return digest
	}
	if len(hex) > shortDigestHex {
		hex = hex[:shortDigestHex]
	}
	return algo + ":" + hex
}
