package acceleratorsources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = "--nre-ci-rpc-handshake"

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 1 && args[0] == CIHandshakeFlag {
		controller, err := NewController(ControllerConfig{PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact"})
		if err != nil {
			return err
		}
		response, err := controller.Handshake(ctx, pluginsdk.RPCHandshakeRequest{
			ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
			PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact",
			GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound}, Generation: "nre-ci-generation",
			RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
		})
		if err != nil {
			return err
		}
		if response.ABI != pluginsdk.RPCABIV1 || len(response.Features) != 1 || response.Features[0] != pluginsdk.RPCFeatureHTTPBackendProviderV1 {
			return errors.New("canonical RPC handshake mismatch")
		}
		_, err = fmt.Fprintln(output, response.ABI)
		return err
	}
	if len(args) != 0 {
		return errors.New("unexpected accelerator-sources arguments")
	}
	controller, err := NewController(ControllerConfig{})
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- ServeLifecycleRPC(runCtx, controller) }()
	go func() {
		errorsCh <- pluginsdk.ServeHTTPBackendProviders(runCtx, map[string]http.Handler{ProviderID: controller})
	}()
	first := <-errorsCh
	cancel()
	second := <-errorsCh
	if first != nil {
		return first
	}
	return second
}
