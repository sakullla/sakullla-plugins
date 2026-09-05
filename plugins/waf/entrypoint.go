package waf

import (
	"context"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

// dualFaceRuntimeServices is the WAF management-face UI declaration. The Agent
// policy face is the nested wasm guest; it must not bind the plugin UI socket.
func dualFaceRuntimeServices() pluginsdk.RPCServiceDeclaration {
	if pluginsdk.AgentExecutionFace() {
		return pluginsdk.RPCServiceDeclaration{}
	}
	return pluginsdk.RPCServiceDeclaration{UI: true, UIOptional: true}
}

func wafHandshakeDeclaration() pluginsdk.RPCPluginDeclaration {
	return pluginsdk.RPCPluginDeclaration{
		PluginID:             PluginID,
		PluginVersion:        PluginVersion,
		RequiredCapabilities: requiredGrants(),
		SupportedFeatures:    []string{pluginsdk.RPCFeatureDurableActionsV1},
	}
}

func newProbeController(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
	return NewController(ControllerConfig{
		PackageDigest:  request.PackageDigest,
		ArtifactDigest: request.ArtifactDigest,
	})
}

func newRuntimeController() (pluginsdk.RPCLifecycle, error) {
	return NewController(bindProductionHostCapabilities(ControllerConfig{}))
}

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{
		Declaration:         wafHandshakeDeclaration(),
		NewProbeLifecycle:   newProbeController,
		NewRuntimeLifecycle: newRuntimeController,
		Services:            dualFaceRuntimeServices(),
	})
}
