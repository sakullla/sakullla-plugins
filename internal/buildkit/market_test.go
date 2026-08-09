package buildkit

import (
	"strings"
	"testing"
)

func TestMarketRenderingIsStableAndSorted(t *testing.T) {
	t.Parallel()
	market := Market{
		SchemaVersion: 1,
		Commit:        strings.Repeat("a", 40),
		SDKABI:        "nre:policy/v1",
		Packages: []MarketPackage{
			{ID: "waf", Version: "1.0.0", Runtime: "wasm-policy", ABI: "nre:policy/v1", PackageSHA256: strings.Repeat("b", 64), PackageURL: "https://example.invalid/waf.nrepkg", SignerIdentity: "official://release"},
			{ID: "ip-policy", Version: "1.0.0", Runtime: "wasm-policy", ABI: "nre:policy/v1", PackageSHA256: strings.Repeat("c", 64), PackageURL: "https://example.invalid/ip.nrepkg", SignerIdentity: "official://release"},
		},
	}
	first, err := RenderMarket(market)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderMarket(market)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("market rendering changed between calls")
	}
	if !strings.HasSuffix(string(first), "\n") || strings.Contains(string(first), "\r") {
		t.Fatalf("market is not canonical LF text: %q", first)
	}
	if strings.Index(string(first), `id: "ip-policy"`) > strings.Index(string(first), `id: "waf"`) {
		t.Fatal("market packages are not sorted")
	}
}

func TestMarketRejectsDuplicateProjection(t *testing.T) {
	t.Parallel()
	pkg := MarketPackage{ID: "waf", Version: "1", Runtime: "wasm-policy", ABI: "nre:policy/v1", PackageSHA256: "digest", PackageURL: "url", SignerIdentity: "signer"}
	_, err := RenderMarket(Market{SchemaVersion: 1, Commit: "oid", SDKABI: "nre:policy/v1", Packages: []MarketPackage{pkg, pkg}})
	if err == nil {
		t.Fatal("duplicate market projection was accepted")
	}
}
