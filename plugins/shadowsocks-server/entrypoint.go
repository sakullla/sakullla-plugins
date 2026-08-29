package shadowsocksserver

import (
	"context"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

func productionControllerConfig() ControllerConfig {
	return bindProductionHostCapabilities(ControllerConfig{})
}

func runtimeServices() pluginsdk.RPCServiceDeclaration {
	services := pluginsdk.RPCServiceDeclaration{UI: true, UIOptional: true}
	if agentExecutionFace() {
		// Agent still receives NRE_PLUGIN_UI_ENDPOINT because ui.route is on the
		// package. Serving UI there races the RPC listener; the first failed
		// server cancels its sibling and the host excludes the candidate.
		services.UI = false
	}
	return services
}

func agentExecutionFace() bool {
	return pluginsdk.AgentExecutionFace()
}

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	declaration := pluginsdk.RPCPluginDeclaration{
		PluginID: PluginID, PluginVersion: PluginVersion,
		RequiredCapabilities: requiredGrants(),
	}
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{
		Declaration: declaration,
		NewProbeLifecycle: func(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
			return NewController(ControllerConfig{
				PackageDigest: request.PackageDigest, ArtifactDigest: request.ArtifactDigest,
			})
		},
		NewRuntimeLifecycle: func() (pluginsdk.RPCLifecycle, error) {
			return NewController(productionControllerConfig())
		},
		Services: runtimeServices(),
	})
}
