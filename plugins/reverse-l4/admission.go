package reversel4

import (
	"errors"
	"fmt"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

var ErrTypedServiceHandlesUnavailable = errors.New("canonical public SDK has no typed reverse-session, tunnel, listener, L4, or traffic handles")

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
