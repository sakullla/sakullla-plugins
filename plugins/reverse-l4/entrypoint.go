package reversel4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = "--nre-ci-rpc-handshake"

type fixedValidationClock struct{}

func (fixedValidationClock) Now() time.Time { return time.Time{} }

// RunEntrypoint exposes only a build-time canonical handshake self-check until
// the public SDK owns an RPC transport and typed L4 Host handles. It does not
// define a replacement wire protocol.
func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 1 && args[0] == CIHandshakeFlag {
		controller, err := NewController(ControllerConfig{
			PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact",
			Clock: fixedValidationClock{}, Backoff: Backoff{Minimum: time.Millisecond, Maximum: time.Second, Factor: 2},
		})
		if err != nil {
			return err
		}
		response, err := controller.Handshake(ctx, pluginsdk.RPCHandshakeRequest{
			ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
			PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact",
			GrantedScopes: []string{"reverse-session"}, Generation: "nre-ci-generation",
		})
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
		return fmt.Errorf("unexpected reverse-l4 arguments: %v", args)
	}
	return AdmitRuntime(pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1})
}
