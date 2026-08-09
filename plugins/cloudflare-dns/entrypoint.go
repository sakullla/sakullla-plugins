package cloudflaredns

import (
	"context"
	"errors"
	"fmt"
	"io"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = "--nre-ci-rpc-handshake"

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 1 && args[0] == CIHandshakeFlag {
		controller, err := NewController(ControllerConfig{PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact"})
		if err != nil {
			return err
		}
		response, err := controller.Handshake(ctx, pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact", GrantedScopes: requiredGrants(), Generation: "nre-ci-generation"})
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
		return errors.New("unexpected Cloudflare DNS arguments")
	}
	return ErrTypedHandlesUnavailable
}
