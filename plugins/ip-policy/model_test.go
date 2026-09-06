package ippolicy

import (
	"encoding/json"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func validConfiguration() Configuration {
	return Configuration{
		Schema: ConfigSchema, DefaultAction: DefaultActionAllow,
		Datasets: []DatasetDefinition{{ID: "province-data", SourceID: "dbip-cn-province", Classifications: []ClassificationDefinition{
			{ID: "beijing", Name: "cn-11", Kind: pluginsdk.DatasetClassificationRegion},
			{ID: "jiangsu", Name: "cn-32", Kind: pluginsdk.DatasetClassificationRegion},
			{ID: "guangdong", Name: "cn-44", Kind: pluginsdk.DatasetClassificationRegion},
			{ID: "guangxi", Name: "cn-45", Kind: pluginsdk.DatasetClassificationRegion},
			{ID: "china", Name: "cn", Kind: pluginsdk.DatasetClassificationCountry},
		}}},
		ProvinceWhitelist: []ClassificationRef{{DatasetID: "province-data", ClassificationID: "guangdong"}},
		Rules:             []Rule{{ID: "deny-probe", Action: DefaultActionDeny, Selector: Selector{Type: "cidr", Value: "192.0.2.0/24"}}},
	}
}

func TestConfigurationContractAndProvinceCatalog(t *testing.T) {
	config := validConfiguration()
	encoded, err := EncodeConfiguration(config)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConfiguration(encoded)
	if err != nil || parsed.Datasets[0].Classifications[2].Name != "cn-44" {
		t.Fatalf("round trip = %+v, %v", parsed, err)
	}
	provinces := Provinces()
	if len(provinces) != 31 || provinces[0].Classification != "cn-11" || provinces[9].Classification != "cn-32" || provinces[18].Classification != "cn-44" || provinces[19].Classification != "cn-45" {
		t.Fatalf("province catalog = %+v", provinces)
	}
	provinces[0].Name = "mutated"
	if Provinces()[0].Name != "北京市" {
		t.Fatal("province catalog returned mutable shared state")
	}
}

func TestConfigurationRejectsAttributesUnmaskedCIDRAndCountryWhitelist(t *testing.T) {
	encoded, _ := json.Marshal(validConfiguration())
	withAttributes := strings.Replace(string(encoded), `"kind":"region"`, `"kind":"region","attributes":[{"name":"!cn"}]`, 1)
	if _, err := ParseConfiguration([]byte(withAttributes)); err == nil {
		t.Fatal("policy query attributes were accepted")
	}
	config := validConfiguration()
	config.Rules[0].Selector.Value = "192.0.2.9/24"
	if err := config.Validate(); err == nil {
		t.Fatal("unmasked CIDR was accepted")
	}
	config = validConfiguration()
	config.ProvinceWhitelist[0].ClassificationID = "china"
	if err := config.Validate(); err == nil {
		t.Fatal("country classification expanded province whitelist")
	}
}

func TestConfigurationClassificationIdentityMatchesSDKAndRust(t *testing.T) {
	config := validConfiguration()
	config.Datasets[0].Classifications = append(config.Datasets[0].Classifications, ClassificationDefinition{ID: "guangdong-copy", Name: "cn-44", Kind: pluginsdk.DatasetClassificationRegion})
	if err := config.Validate(); err == nil {
		t.Fatal("different IDs for one canonical classification were accepted")
	}

	config = validConfiguration()
	config.Datasets[0].Classifications = append(config.Datasets[0].Classifications, ClassificationDefinition{ID: "upper-name", Name: "CN-44", Kind: pluginsdk.DatasetClassificationRegion})
	if err := config.Validate(); err != nil {
		t.Fatalf("SDK/Rust case-sensitive classification was rejected: %v", err)
	}
	config.Datasets[0].Classifications[len(config.Datasets[0].Classifications)-1].Name = " cn-44"
	if err := config.Validate(); err == nil {
		t.Fatal("classification name with whitespace was accepted")
	}
}

func TestEntryOverlayUsesBaseDatasetDictionary(t *testing.T) {
	config := validConfiguration()
	valid := []byte(`{"schema":"sakullla.ip-policy-overlay/v1","rules":[{"id":"allow-gd","action":"allow","selector":{"type":"classification","dataset_id":"province-data","classification_id":"guangdong"}}]}`)
	if _, err := ParseEntryOverlay(valid, config); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEntryOverlay([]byte(strings.Replace(string(valid), "guangdong", "missing", 1)), config); err == nil {
		t.Fatal("overlay referenced a foreign classification")
	}
}
