package ippolicy

import (
	"context"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

func runtimeServices() pluginsdk.RPCServiceDeclaration {
	if pluginsdk.AgentExecutionFace() {
		return pluginsdk.RPCServiceDeclaration{}
	}
	return pluginsdk.RPCServiceDeclaration{UI: true, UIOptional: true}
}

func handshakeDeclaration() pluginsdk.RPCPluginDeclaration {
	return pluginsdk.RPCPluginDeclaration{PluginID: PluginID, PluginVersion: PluginVersion, RequiredCapabilities: requiredGrants(), SupportedFeatures: controlPlaneFeatures()}
}

func newProbeController(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
	return NewController(ControllerConfig{PackageDigest: request.PackageDigest, ArtifactDigest: request.ArtifactDigest})
}

func newRuntimeController() (pluginsdk.RPCLifecycle, error) {
	return NewController(bindProductionRuntime(ControllerConfig{}))
}

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{Declaration: handshakeDeclaration(), NewProbeLifecycle: newProbeController, NewRuntimeLifecycle: newRuntimeController, Services: runtimeServices()})
}
