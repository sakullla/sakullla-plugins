package cloudflaredns

import (
	"errors"
	"testing"
)

func TestGuardMappingsLocked(t *testing.T) {
	t.Parallel()
	service := &Service{}
	if err := service.guardMappingsLocked(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("nil map err=%v", err)
	}
	service.mappings = map[string]storedMapping{}
	if err := service.guardMappingsLocked(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("unlive err=%v", err)
	}
	service.live.Store(true)
	if err := service.guardMappingsLocked(); err != nil {
		t.Fatalf("live err=%v", err)
	}
}

func TestReserveMappingRejectsUnliveAndNil(t *testing.T) {
	t.Parallel()
	service := &Service{mappings: map[string]storedMapping{}}
	if err := service.reserveMapping("example.com", 1); !errors.Is(err, ErrRevoked) {
		t.Fatalf("unlive reserve err=%v", err)
	}
	service.live.Store(true)
	service.mappings = nil
	if err := service.reserveMapping("example.com", 1); !errors.Is(err, ErrRevoked) {
		t.Fatalf("nil reserve err=%v", err)
	}
}

func TestDomesticProviderGuard(t *testing.T) {
	t.Parallel()
	if isDomesticProvider("") || isDomesticProvider(ProviderCloudflare) || isDomesticProvider("route53") {
		t.Fatal("non-domestic provider was accepted")
	}
	for _, provider := range []string{ProviderAliyun, ProviderDNSPodCN, ProviderDNSPodCOM, ProviderTencentDNS} {
		if !isDomesticProvider(provider) {
			t.Fatalf("%s was not domestic", provider)
		}
	}
}
