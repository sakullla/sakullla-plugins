package shadowsocksserver

import (
	"context"
	"errors"
	"fmt"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	probeIdentity, probe, err := pluginsdk.ResolveRPCHandshakeProbe(args, pluginsdk.RPCPluginDeclaration{PluginID: PluginID, PluginVersion: PluginVersion})
	if err != nil {
		return err
	}
	if probe {
		controller, err := NewController(ControllerConfig{PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact"})
		if err != nil {
			return err
		}
		response, err := controller.Handshake(ctx, pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: probeIdentity.PluginID, PluginVersion: probeIdentity.PluginVersion, PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact", GrantedScopes: requiredGrants(), Generation: "nre-ci-generation"})
		if err != nil {
			return err
		}
		if response.ABI != pluginsdk.RPCABIV1 {
			return errors.New("canonical RPC handshake ABI mismatch")
		}
		_, err = fmt.Fprintln(output, response.ABI)
		return err
	}
	if len(args) != 0 {
		return errors.New("unexpected Shadowsocks arguments")
	}
	return ErrTypedHandlesUnavailable
}
