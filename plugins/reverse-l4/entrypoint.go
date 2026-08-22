package reversel4

import (
	"context"
	"io"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

type fixedValidationClock struct{}

func (fixedValidationClock) Now() time.Time { return time.Time{} }

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{
		Declaration: pluginsdk.RPCPluginDeclaration{
			PluginID: PluginID, PluginVersion: PluginVersion,
			RequiredCapabilities: []string{"reverse-session"},
		},
		NewProbeLifecycle: func(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
			return NewController(ControllerConfig{
				PackageDigest: request.PackageDigest, ArtifactDigest: request.ArtifactDigest,
				Clock: fixedValidationClock{}, Backoff: Backoff{Minimum: time.Millisecond, Maximum: time.Second, Factor: 2},
			})
		},
		Run: func(context.Context) error {
			return AdmitRuntime(pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1})
		},
	})
}
