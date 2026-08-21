package dockerapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const CIHandshakeFlag = pluginsdk.RPCHandshakeProbeFlag

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	probeIdentity, probe, err := pluginsdk.ResolveRPCHandshakeProbe(args, pluginsdk.RPCPluginDeclaration{PluginID: PluginID, PluginVersion: PluginVersion})
	if err != nil {
		return err
	}
	if probe {
		controller, err := NewController(ControllerConfig{PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact", Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{}, nil
		})})
		if err != nil {
			return err
		}
		response, err := controller.Handshake(ctx, pluginsdk.RPCHandshakeRequest{
			ABI: pluginsdk.RPCABIV1, PluginID: probeIdentity.PluginID, PluginVersion: probeIdentity.PluginVersion, PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact",
			GrantedScopes: requiredGrants(), Generation: "nre-ci-generation",
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
		return fmt.Errorf("unexpected docker-app arguments: %v", args)
	}
	controller, err := NewController(ControllerConfig{})
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- pluginsdk.ServeRPCPlugin(runCtx, controller) }()
	go func() {
		errorsCh <- pluginsdk.ServeHTTPBackendProviders(runCtx, map[string]http.Handler{
			"default": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "docker application provider is unavailable", http.StatusServiceUnavailable)
			}),
		})
	}()
	first := <-errorsCh
	cancel()
	second := <-errorsCh
	return errors.Join(first, second)
}
