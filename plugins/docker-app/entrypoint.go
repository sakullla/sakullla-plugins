package dockerapp

import (
	"context"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

func productionControllerConfig() ControllerConfig {
	return bindProductionHostCapabilities(ControllerConfig{})
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
				Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
					return PreparedAdmissionFuncs{}, nil
				}),
			})
		},
		NewRuntimeLifecycle: func() (pluginsdk.RPCLifecycle, error) { return NewController(productionControllerConfig()) },
		Services:            pluginsdk.RPCServiceDeclaration{UI: true, UIOptional: true},
	})
}
