// Package hostfixture contains public-SDK-only host test doubles used by
// official plugins. It must not copy private control-plane or Agent host ABIs.
package hostfixture

import (
	"context"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// FakePolicyHost implements the complete current public pluginsdk.PolicyHost.
// Function fields make missing behavior explicit in each test.
type FakePolicyHost struct {
	ReadFieldFunc      func(context.Context, string) ([]byte, error)
	ReadBodyWindowFunc func(context.Context, uint32, uint32) ([]byte, error)
	StateGetFunc       func(context.Context, string) ([]byte, bool, error)
	StatePutFunc       func(context.Context, string, []byte) error
	EmitEventFunc      func(context.Context, pluginsdk.PolicySecurityEvent) error
	AddMetricFunc      func(context.Context, string, int64) error
}

var _ pluginsdk.PolicyHost = (*FakePolicyHost)(nil)

func (host *FakePolicyHost) ReadField(ctx context.Context, name string) ([]byte, error) {
	if host.ReadFieldFunc == nil {
		return nil, nil
	}
	return host.ReadFieldFunc(ctx, name)
}

func (host *FakePolicyHost) ReadBodyWindow(ctx context.Context, offset, length uint32) ([]byte, error) {
	if host.ReadBodyWindowFunc == nil {
		return nil, nil
	}
	return host.ReadBodyWindowFunc(ctx, offset, length)
}

func (host *FakePolicyHost) StateGet(ctx context.Context, key string) ([]byte, bool, error) {
	if host.StateGetFunc == nil {
		return nil, false, nil
	}
	return host.StateGetFunc(ctx, key)
}

func (host *FakePolicyHost) StatePut(ctx context.Context, key string, value []byte) error {
	if host.StatePutFunc == nil {
		return nil
	}
	return host.StatePutFunc(ctx, key, value)
}

func (host *FakePolicyHost) EmitEvent(ctx context.Context, event pluginsdk.PolicySecurityEvent) error {
	if host.EmitEventFunc == nil {
		return nil
	}
	return host.EmitEventFunc(ctx, event)
}

func (host *FakePolicyHost) AddMetric(ctx context.Context, name string, delta int64) error {
	if host.AddMetricFunc == nil {
		return nil
	}
	return host.AddMetricFunc(ctx, name, delta)
}
