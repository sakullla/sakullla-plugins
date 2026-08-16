package buildkit

import (
	"strings"
	"testing"
)

func TestMarketRenderingIsStableAndSorted(t *testing.T) {
	t.Parallel()
	market := Market{
		SchemaVersion: 2,
		Commit:        strings.Repeat("a", 40),
		SDKABI:        "nre:policy/v1",
		Packages: []MarketPackage{
			validMarketPackage("waf", strings.Repeat("b", 64)),
			validMarketPackage("ip-policy", strings.Repeat("c", 64)),
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
	pkg := validMarketPackage("waf", strings.Repeat("b", 64))
	_, err := RenderMarket(Market{SchemaVersion: 2, Commit: "oid", SDKABI: "nre:policy/v1", Packages: []MarketPackage{pkg, pkg}})
	if err == nil {
		t.Fatal("duplicate market projection was accepted")
	}
}

func validMarketPackage(id, packageDigest string) MarketPackage {
	return MarketPackage{
		ID: id, Version: "1.0.0", Description: "Example", Capabilities: []string{"relay.plan"},
		Compatibility: MarketCompatibility{Host: "*", Agent: "*"}, Runtime: "wasm-policy", ABI: "nre:policy/v1", HostScope: "control-plane", PolicyKind: "request",
		Artifacts: []MarketArtifact{{SHA256: strings.Repeat("d", 64), Size: 42}}, PackageSHA256: packageDigest,
		PackageURL: "https://github.com/sakullla/sakullla-plugins/releases/download/official-" + strings.Repeat("a", 40) + "/" + id + "-1.0.0-" + strings.Repeat("e", 64) + ".nrepkg",
		BlobSHA256: strings.Repeat("e", 64), BlobSize: 123, BlobFormat: PackageBlobFormatV1, SignerIdentity: "official://release",
	}
}
