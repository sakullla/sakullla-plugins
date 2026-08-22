package reversel4

import (
	"context"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// CIHandshakeFlag is the canonical build-time handshake probe argument.
const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

// RunEntrypoint runs the canonical RPC plugin process: the build-time
// handshake probe with an isolated lifecycle, or the supervised runtime whose
// mapping orchestration talks to the host through the public SDK runtime
// client only. The runtime lifecycle also serves the plugin-owned management
// page on the host-provisioned private UI endpoint.
func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{
		Declaration: pluginsdk.RPCPluginDeclaration{
			PluginID: PluginID, PluginVersion: PluginVersion,
			RequiredCapabilities: requiredGrants(),
		},
		NewProbeLifecycle: func(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
			return NewController(ControllerConfig{
				PackageDigest: request.PackageDigest, ArtifactDigest: request.ArtifactDigest,
			})
		},
		NewRuntimeLifecycle: func() (pluginsdk.RPCLifecycle, error) { return NewController(ControllerConfig{}) },
		Services:            pluginsdk.RPCServiceDeclaration{UI: true, UIOptional: true},
	})
}
