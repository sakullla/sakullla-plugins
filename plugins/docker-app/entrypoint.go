package dockerapp

import (
	"context"
	"io"
	"os"
	"strings"

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
	if strings.TrimSpace(os.Getenv("NRE_PLUGIN_DOCKER_PROXY_ENDPOINT")) != "" {
		return true
	}
	return strings.TrimSpace(os.Getenv(pluginsdk.EnvPluginHostEndpoint)) == ""
}

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	declaration := pluginsdk.RPCPluginDeclaration{
		PluginID: PluginID, PluginVersion: PluginVersion,
		RequiredCapabilities: requiredGrants(),
		SupportedFeatures:    []string{pluginsdk.RPCFeatureDurableActionsV1},
	}
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{
		Declaration: declaration,
		NewProbeLifecycle: func(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
			return NewController(ControllerConfig{
				PackageDigest: request.PackageDigest, ArtifactDigest: request.ArtifactDigest,
				Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
					return PreparedAdmissionFuncs{}, nil
				}),
			})
		},
		NewRuntimeLifecycle: func() (pluginsdk.RPCLifecycle, error) { return NewController(productionControllerConfig()) },
		Services:            runtimeServices(),
	})
}
