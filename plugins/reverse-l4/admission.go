package reversel4

import (
	"context"
	"errors"
	"fmt"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

var ErrTypedServiceHandlesUnavailable = errors.New("canonical public SDK has no typed reverse-session, tunnel, listener, L4, or traffic handles")

// TypedHandleAdmission is an internal activation gate, not a Host wire
// contract. An implementation may only attest that all required typed public
// SDK handles were atomically admitted; the current SDK has no such types.
type TypedHandleAdmission interface {
	Admit(context.Context, pluginsdk.RPCHandshakeRequest, []Mapping) error
}

type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, []Mapping) error

func (function TypedHandleAdmissionFunc) Admit(ctx context.Context, request pluginsdk.RPCHandshakeRequest, mappings []Mapping) error {
	return function(ctx, request, mappings)
}

type publicSDKHandleAdmission struct{}

func (publicSDKHandleAdmission) Admit(_ context.Context, request pluginsdk.RPCHandshakeRequest, _ []Mapping) error {
	return AdmitRuntime(request)
}

// AdmitRuntime is the real-start gate. A grant string cannot substitute for
// compile-time public SDK types, so current builds always fail closed after
// validating the canonical ABI. No private Host contract is accepted here.
func AdmitRuntime(handshake pluginsdk.RPCHandshakeRequest) error {
	if handshake.ABI != pluginsdk.RPCABIV1 {
		return &pluginsdk.RuntimeError{
			Code: pluginsdk.ErrorIncompatibleABI, Message: fmt.Sprintf("unsupported RPC ABI %q", handshake.ABI),
		}
	}
	return ErrTypedServiceHandlesUnavailable
}
