package shadowsocksserver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type shareHost struct {
	node   NodeAddresses
	listen ListenBinding
}

func (shareHost) Register(context.Context, string, *Service) error { return nil }

func (h shareHost) NodeAddresses(context.Context) (NodeAddresses, error) {
	return h.node, nil
}

func (h shareHost) ListenBinding(_ context.Context, ref string) (ListenBinding, error) {
	if ref == "" {
		return ListenBinding{}, ErrInvalid
	}
	return h.listen, nil
}

func newShareService(t *testing.T, node NodeAddresses, listen ListenBinding) *Service {
	t.Helper()
	runtime := &testRuntime{now: 10, used: map[string]uint64{}, refs: map[string]string{}, replay: map[string]bool{}, accountVault: true}
	adapters := adapters(runtime)
	adapters.Listener = shareHost{node: node, listen: listen}
	service, err := NewService(accountConfig(), adapters)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = service.RefreshListenShare(context.Background()); err != nil {
		t.Fatal(err)
	}
	return service
}

func TestShareHostPrefersDDNSThenIPv4ThenIPv6(t *testing.T) {
	binding, err := DualStackListen(8388, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		node   NodeAddresses
		want   string
		source string
	}{
		{name: "ddns", node: NodeAddresses{DDNS: "ss.example.com", IPv4: "203.0.113.10", IPv6: "2001:db8::10"}, want: "ss.example.com", source: ShareHostSourceDDNS},
		{name: "ipv4", node: NodeAddresses{IPv4: "203.0.113.10", IPv6: "2001:db8::10"}, want: "203.0.113.10", source: ShareHostSourceIPv4},
		{name: "ipv6", node: NodeAddresses{IPv6: "2001:db8::10"}, want: "2001:db8::10", source: ShareHostSourceIPv6},
		{name: "bracket-ipv6", node: NodeAddresses{IPv6: "[2001:db8::1]"}, want: "2001:db8::1", source: ShareHostSourceIPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, ok := SelectPublicHost(test.node)
			if !ok || host != test.want {
				t.Fatalf("host=%q ok=%v want=%q", host, ok, test.want)
			}
			endpoint := ProjectShareEndpoint(binding, test.node)
			if !endpoint.Available || endpoint.Host != test.want || endpoint.Port != 8388 || endpoint.Source != test.source {
				t.Fatalf("endpoint=%+v", endpoint)
			}
			if !endpoint.TCP || !endpoint.UDP {
				t.Fatalf("protocols=%+v", endpoint)
			}
		})
	}
}

func TestShareHostRejectsWildcardAndLoopback(t *testing.T) {
	for _, test := range []struct {
		name string
		node NodeAddresses
		bind string
	}{
		{name: "unspecified-v4", node: NodeAddresses{IPv4: "0.0.0.0"}, bind: "0.0.0.0"},
		{name: "unspecified-v6", node: NodeAddresses{IPv6: "::"}, bind: "::"},
		{name: "loopback-v4", node: NodeAddresses{IPv4: "127.0.0.1"}, bind: "127.0.0.1"},
		{name: "loopback-v6", node: NodeAddresses{IPv6: "::1"}, bind: "::1"},
		{name: "localhost", node: NodeAddresses{DDNS: "localhost"}, bind: "0.0.0.0"},
		{name: "markup-ddns", node: NodeAddresses{DDNS: `<img src=x onerror=alert(1)>.example.com`}, bind: "0.0.0.0"},
		{name: "unusable-all", node: NodeAddresses{DDNS: "0.0.0.0", IPv4: "127.0.0.1", IPv6: "::1"}, bind: "0.0.0.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if host, ok := SelectPublicHost(test.node); ok {
				t.Fatalf("host=%q", host)
			}
			listen, listenErr := DualStackListen(8388, test.bind)
			if listenErr != nil {
				t.Fatal(listenErr)
			}
			endpoint := listen.Share(test.node)
			if endpoint.Available || endpoint.Host != "" || endpoint.HostPort != "" {
				t.Fatalf("endpoint=%+v", endpoint)
			}
			if endpoint.Reason != MissingShareHost {
				t.Fatalf("reason=%q", endpoint.Reason)
			}
			if _, copyErr := endpoint.CopyableHostPort(); !errors.Is(copyErr, ErrMissingShareHost) {
				t.Fatalf("copy=%v", copyErr)
			}
		})
	}
}

func TestShareHostSkipsUnusableDDNSAndFallsBack(t *testing.T) {
	binding, err := DualStackListen(443, "::")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := ProjectShareEndpoint(binding, NodeAddresses{
		DDNS: "0.0.0.0",
		IPv4: "127.0.0.1",
		IPv6: "2001:db8::20",
	})
	if !endpoint.Available || endpoint.Host != "2001:db8::20" || endpoint.Port != 443 || endpoint.Source != ShareHostSourceIPv6 {
		t.Fatalf("endpoint=%+v", endpoint)
	}
}

func TestListenSharePortEqualsBindingForTCPAndUDP(t *testing.T) {
	for _, port := range []int{1, 443, 8388, 65535} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			binding, err := DualStackListen(port, "0.0.0.0")
			if err != nil {
				t.Fatal(err)
			}
			if !binding.TCP || !binding.UDP || binding.Port != port {
				t.Fatalf("binding=%+v", binding)
			}
			endpoint := ProjectShareEndpoint(binding, NodeAddresses{IPv4: "198.51.100.8"})
			if !endpoint.TCP || !endpoint.UDP || endpoint.Port != port {
				t.Fatalf("endpoint=%+v", endpoint)
			}
			if endpoint.HostPort != net.JoinHostPort("198.51.100.8", strconv.Itoa(port)) {
				t.Fatalf("hostport=%q", endpoint.HostPort)
			}
		})
	}
	if _, err := DualStackListen(0, "0.0.0.0"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("port 0: %v", err)
	}
}

func TestShareCopyAddressFitsL4Backend(t *testing.T) {
	for _, test := range []struct {
		name string
		node NodeAddresses
		port int
		host string
	}{
		{name: "hostname", node: NodeAddresses{DDNS: "edge.example.com"}, port: 9443, host: "edge.example.com"},
		{name: "ipv4", node: NodeAddresses{IPv4: "203.0.113.50"}, port: 8388, host: "203.0.113.50"},
		{name: "ipv6", node: NodeAddresses{IPv6: "2001:db8::50"}, port: 443, host: "2001:db8::50"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, err := DualStackListen(test.port, "0.0.0.0")
			if err != nil {
				t.Fatal(err)
			}
			endpoint := ProjectShareEndpoint(binding, test.node)
			backend, err := endpoint.L4Backend()
			if err != nil || backend.BackendHost != test.host || int(backend.BackendPort) != test.port {
				t.Fatalf("l4=%+v err=%v", backend, err)
			}
			if !validL4BackendHost(backend.BackendHost) {
				t.Fatalf("backend_host=%q", backend.BackendHost)
			}
			copyAddr, err := endpoint.CopyableHostPort()
			if err != nil || copyAddr != net.JoinHostPort(test.host, strconv.Itoa(test.port)) {
				t.Fatalf("copy=%q err=%v", copyAddr, err)
			}
			if test.name == "ipv6" && !strings.HasPrefix(copyAddr, "[") {
				t.Fatalf("ipv6 copy=%q", copyAddr)
			}
		})
	}
}

func TestShareUnavailableWithoutPublicAddressKeepsAccount(t *testing.T) {
	binding, err := DualStackListen(8388, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	service := newShareService(t, NodeAddresses{}, binding)
	user, password := createAccount(t, service, "legacy-share", "aes-256-gcm")
	_ = password
	share, err := service.ShareAccount(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if share.Available || share.Share.URI != "" || share.Share.QR.Content != "" || len(share.Share.QR.PNG) != 0 {
		t.Fatalf("share=%+v", share)
	}
	if share.Reason != MissingShareHost || share.Endpoint.Reason != MissingShareHost {
		t.Fatalf("reason=%q endpoint=%+v", share.Reason, share.Endpoint)
	}
	if share.Account.ID != user.ID || !share.Account.Enabled {
		t.Fatalf("account=%+v", share.Account)
	}
	if share.Endpoint.Port != 8388 || !share.Endpoint.TCP || !share.Endpoint.UDP {
		t.Fatalf("listen=%+v", share.Endpoint)
	}
	accounts := service.ListAccounts()
	if len(accounts) != 1 || accounts[0].ID != user.ID || !accounts[0].Enabled {
		t.Fatalf("accounts=%+v", accounts)
	}
	assertGenerationLive(t, service)
}

func TestShareListenHostUsesProjectedAddressNotBind(t *testing.T) {
	binding, err := DualStackListen(8388, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	service := newShareService(t, NodeAddresses{DDNS: "ss.example.com", IPv4: "203.0.113.9"}, binding)
	user, password := createAccount(t, service, "legacy-share", "aes-256-gcm")
	_ = password
	endpoint := service.ShareEndpoint()
	if !endpoint.Available || endpoint.Host != "ss.example.com" || endpoint.Port != 8388 || !endpoint.TCP || !endpoint.UDP {
		t.Fatalf("endpoint=%+v", endpoint)
	}
	if endpoint.HostPort != "ss.example.com:8388" {
		t.Fatalf("hostport=%q", endpoint.HostPort)
	}
	backend, err := endpoint.L4Backend()
	if err != nil || backend.BackendHost != "ss.example.com" || backend.BackendPort != 8388 {
		t.Fatalf("l4=%+v err=%v", backend, err)
	}
	share, err := service.ShareAccount(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !share.Available || share.Share.URI == "" || share.Share.QR.Content != share.Share.URI {
		t.Fatalf("share=%+v", share)
	}
	_, _, host, port := parseSIP002(t, share.Share.URI)
	if host != "ss.example.com" || port != 8388 {
		t.Fatalf("uri=%q", share.Share.URI)
	}
}

func TestShareAccountUsesListenRulePortAndNodeHost(t *testing.T) {
	binding, err := DualStackListen(8388, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	service := newShareService(t, NodeAddresses{DDNS: "ss.example.com", IPv4: "203.0.113.9"}, binding)
	legacy, _ := createAccount(t, service, "legacy-share", "aes-256-gcm")
	modern, _ := createAccount(t, service, "ss2022-share", DefaultSS2022Method)
	legacyShare, err := service.ShareAccount(context.Background(), legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	modernShare, err := service.ShareAccount(context.Background(), modern.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !legacyShare.Available || !modernShare.Available {
		t.Fatalf("legacy=%+v modern=%+v", legacyShare, modernShare)
	}
	_, _, host, port := parseSIP002(t, legacyShare.Share.URI)
	if host != "ss.example.com" || port != 8388 || legacyShare.Endpoint.Port != 8388 {
		t.Fatalf("legacy uri=%q endpoint=%+v", legacyShare.Share.URI, legacyShare.Endpoint)
	}
	_, _, host, port = parseSIP002(t, modernShare.Share.URI)
	if host != "ss.example.com" || port != 8488 || modernShare.Endpoint.Port != 8488 {
		t.Fatalf("modern uri=%q endpoint=%+v", modernShare.Share.URI, modernShare.Endpoint)
	}
	if service.ShareEndpoint().Port == modernShare.Endpoint.Port {
		t.Fatalf("second listen share reused first listener port: %+v", service.ShareEndpoint())
	}
}

type sdkShareHost struct {
	node   pluginsdk.NodeAddresses
	listen pluginsdk.DualStackListenBinding
}

func (sdkShareHost) Register(context.Context, string, *Service) error { return nil }

func (h sdkShareHost) Binding(_ context.Context, ref string) (pluginsdk.DualStackListenBinding, error) {
	if ref == "" {
		return pluginsdk.DualStackListenBinding{}, ErrInvalid
	}
	return h.listen, nil
}

func (h sdkShareHost) NodeAddresses(context.Context) (pluginsdk.NodeAddresses, error) {
	return h.node, nil
}

func TestRefreshListenShareConsumesPublishedSDKHandles(t *testing.T) {
	var _ pluginsdk.DualStackListener = sdkShareHost{}
	var _ pluginsdk.NodeAddressSource = sdkShareHost{}
	runtime := &testRuntime{now: 10, used: map[string]uint64{}, refs: map[string]string{}, replay: map[string]bool{}, accountVault: true}
	adapters := adapters(runtime)
	adapters.Listener = sdkShareHost{
		node:   pluginsdk.NodeAddresses{DDNS: "ss.example.com", IPv4: "203.0.113.10"},
		listen: pluginsdk.DualStackListenBinding{Port: 8488, BindHost: "0.0.0.0", TCP: true, UDP: true},
	}
	service, err := NewService(accountConfig(), adapters)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = service.RefreshListenShare(context.Background()); err != nil {
		t.Fatal(err)
	}
	endpoint := service.ShareEndpoint()
	if !endpoint.Available || endpoint.Host != "ss.example.com" || endpoint.Port != 8488 || endpoint.HostPort != "ss.example.com:8488" {
		t.Fatalf("endpoint=%+v", endpoint)
	}
}

func TestListenShareRequiresHostBinding(t *testing.T) {
	service := newAccountService(t)
	endpoint := service.ShareEndpoint()
	if endpoint.Available || endpoint.Reason != MissingShareHost {
		t.Fatalf("endpoint=%+v", endpoint)
	}
	user, password := createAccount(t, service, "legacy-share", "aes-256-gcm")
	_ = password
	share, err := service.ShareAccount(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if share.Available || share.Share.URI != "" || share.Reason != MissingShareHost {
		t.Fatalf("share=%+v", share)
	}
	if got := service.ListAccounts(); len(got) != 1 || got[0].ID != user.ID {
		t.Fatalf("accounts=%+v", got)
	}
}
