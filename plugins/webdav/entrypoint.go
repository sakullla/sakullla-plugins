package webdav

import (
	"context"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	declaration := pluginsdk.RPCPluginDeclaration{
		PluginID: PluginID, PluginVersion: PluginVersion,
		RequiredCapabilities: []string{pluginsdk.PermissionHTTPOutbound, pluginsdk.PermissionStorageWrite},
		SupportedFeatures:    []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
	}
	return pluginsdk.RunRPCEntrypoint(ctx, args, output, pluginsdk.RPCEntrypointConfig{
		Declaration: declaration,
		NewProbeLifecycle: func(request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCLifecycle, error) {
			return NewController(ControllerConfig{PackageDigest: request.PackageDigest, ArtifactDigest: request.ArtifactDigest})
		},
		NewRuntimeLifecycle: func() (pluginsdk.RPCLifecycle, error) { return NewController(ControllerConfig{}) },
		Services:            pluginsdk.RPCServiceDeclaration{HTTPBackendProviderIDs: []string{ProviderID}},
	})
}
