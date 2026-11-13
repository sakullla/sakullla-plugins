package shadowsocksserver

import (
	"bytes"
	"context"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func BenchmarkSealPayloadChunk(b *testing.B) {
	engine, _ := NewProtocolEngine("2022-blake3-aes-128-gcm", []byte("AAAAAAAAAAAAAAAAAAAAAA=="))
	defer engine.Destroy()
	cipher, _ := engine.newSession(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16))
	payload := make([]byte, 32<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		_ = sealPayloadChunk(cipher, payload)
	}
}

type benchmarkRouteDataset struct{ calls int }

func (d *benchmarkRouteDataset) ResolveDataset(context.Context, pluginsdk.DatasetResolveRequest) (pluginsdk.DatasetReference, error) {
	return pluginsdk.DatasetReference{SourceID: "geosite", VersionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}
func (d *benchmarkRouteDataset) QueryDatasets(_ context.Context, r pluginsdk.DatasetQueryRequest) (pluginsdk.DatasetQueryResponse, error) {
	d.calls++
	m := make([]pluginsdk.DatasetMatch, len(r.Classifications))
	for i := range r.Classifications {
		m[i] = pluginsdk.DatasetMatch{Index: i, Matched: false, Coverage: pluginsdk.DatasetCovered}
	}
	return pluginsdk.DatasetQueryResponse{Reference: r.Reference, Status: pluginsdk.DatasetQueryOK, Matches: m}, nil
}

func BenchmarkRouteRepeatedDomain(b *testing.B) {
	d := &benchmarkRouteDataset{}
	cfg := RoutingConfiguration{DefaultAction: RouteDirect}
	for i := 0; i < 16; i++ {
		cfg.Rules = append(cfg.Rules, RouteRule{ID: string(rune('a' + i)), SourceID: "geosite", Classification: pluginsdk.DatasetClassification{Name: string(rune('a' + i)), Kind: pluginsdk.DatasetClassificationDomain}, Action: RouteReject})
	}
	snapshot, err := prepareRouteSnapshot(context.Background(), cfg, d)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := snapshot.decide(context.Background(), "tcp", "www.example.com:443"); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(d.calls)/float64(b.N), "queries/op")
}
