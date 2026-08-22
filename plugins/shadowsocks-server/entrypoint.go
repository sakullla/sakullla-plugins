package shadowsocksserver

import (
	"context"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{
		Declaration: pluginsdk.RPCPluginDeclaration{
			PluginID: PluginID, PluginVersion: PluginVersion,
			RequiredCapabilities: requiredGrants(),
		},
		NewProbeLifecycle: func(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
			return NewController(ControllerConfig{PackageDigest: request.PackageDigest, ArtifactDigest: request.ArtifactDigest})
		},
		Run: func(context.Context) error { return ErrTypedHandlesUnavailable },
	})
}
