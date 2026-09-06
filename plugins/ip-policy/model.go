package ippolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	PluginID           = "ip-policy"
	PluginVersion      = "0.2.0"
	ConfigSchema       = "sakullla.ip-policy/v1"
	OverlaySchema      = "sakullla.ip-policy-overlay/v1"
	DefaultActionAllow = "allow"
	DefaultActionDeny  = "deny"
	MaxConfigBytes     = pluginsdk.PolicyControlConfigMaxBytes
	MaxDatasets        = 4
	MaxClassifications = 64
	MaxRules           = 256
	MaxOverlayRules    = 64
)

var (
	canonicalID   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	provinceNames = map[string]string{
		"cn-11": "北京市", "cn-12": "天津市", "cn-13": "河北省", "cn-14": "山西省", "cn-15": "内蒙古自治区",
		"cn-21": "辽宁省", "cn-22": "吉林省", "cn-23": "黑龙江省", "cn-31": "上海市", "cn-32": "江苏省",
		"cn-33": "浙江省", "cn-34": "安徽省", "cn-35": "福建省", "cn-36": "江西省", "cn-37": "山东省",
		"cn-41": "河南省", "cn-42": "湖北省", "cn-43": "湖南省", "cn-44": "广东省", "cn-45": "广西壮族自治区",
		"cn-46": "海南省", "cn-50": "重庆市", "cn-51": "四川省", "cn-52": "贵州省", "cn-53": "云南省",
		"cn-54": "西藏自治区", "cn-61": "陕西省", "cn-62": "甘肃省", "cn-63": "青海省", "cn-64": "宁夏回族自治区", "cn-65": "新疆维吾尔自治区",
	}
)

var (
	ErrInvalidConfig = errors.New("IP 策略配置无效")
	ErrUnavailable   = errors.New("IP 策略管理服务暂时不可用")
	ErrUnauthorized  = errors.New("无权管理 IP 策略")
)

type Configuration struct {
	Schema            string              `json:"schema"`
	DefaultAction     string              `json:"default_action"`
	Datasets          []DatasetDefinition `json:"datasets"`
	ProvinceWhitelist []ClassificationRef `json:"province_whitelist"`
	Rules             []Rule              `json:"rules"`
}

type DatasetDefinition struct {
	ID              string                     `json:"id"`
	SourceID        string                     `json:"source_id"`
	Classifications []ClassificationDefinition `json:"classifications"`
}

type ClassificationDefinition struct {
	ID   string                              `json:"id"`
	Name string                              `json:"name"`
	Kind pluginsdk.DatasetClassificationKind `json:"kind"`
}

type ClassificationRef struct {
	DatasetID        string `json:"dataset_id"`
	ClassificationID string `json:"classification_id"`
}

type Rule struct {
	ID       string   `json:"id"`
	Action   string   `json:"action"`
	Selector Selector `json:"selector"`
}

type Selector struct {
	Type             string `json:"type"`
	Value            string `json:"value,omitempty"`
	DatasetID        string `json:"dataset_id,omitempty"`
	ClassificationID string `json:"classification_id,omitempty"`
}

type EntryOverlay struct {
	Schema string `json:"schema"`
	Rules  []Rule `json:"rules"`
}

type ProvinceOption struct {
	Classification string `json:"classification"`
	Name           string `json:"name"`
}

func DefaultConfiguration() Configuration {
	return Configuration{Schema: ConfigSchema, DefaultAction: DefaultActionAllow, Datasets: []DatasetDefinition{}, ProvinceWhitelist: []ClassificationRef{}, Rules: []Rule{}}
}

func ParseConfiguration(raw []byte) (Configuration, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return DefaultConfiguration(), nil
	}
	if len(raw) > MaxConfigBytes {
		return Configuration{}, fmt.Errorf("%w: 超过 %d 字节", ErrInvalidConfig, MaxConfigBytes)
	}
	var config Configuration
	if err := decodeStrictJSON(raw, &config); err != nil {
		return Configuration{}, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if err := config.Validate(); err != nil {
		return Configuration{}, err
	}
	return config, nil
}

func ParseEntryOverlay(raw []byte, config Configuration) (EntryOverlay, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return EntryOverlay{Schema: OverlaySchema, Rules: []Rule{}}, nil
	}
	if len(raw) > pluginsdk.PolicyStageOverlayMaxBytes {
		return EntryOverlay{}, fmt.Errorf("%w: 入口规则超过字节上限", ErrInvalidConfig)
	}
	var overlay EntryOverlay
	if err := decodeStrictJSON(raw, &overlay); err != nil {
		return EntryOverlay{}, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if overlay.Schema != OverlaySchema || overlay.Rules == nil || len(overlay.Rules) > MaxOverlayRules {
		return EntryOverlay{}, fmt.Errorf("%w: 入口规则结构错误", ErrInvalidConfig)
	}
	if err := validateRules(overlay.Rules, config.datasetIndex(), MaxOverlayRules); err != nil {
		return EntryOverlay{}, err
	}
	globalIDs := map[string]bool{}
	for _, rule := range config.Rules {
		globalIDs[rule.ID] = true
	}
	for _, rule := range overlay.Rules {
		if globalIDs[rule.ID] {
			return EntryOverlay{}, fmt.Errorf("%w: 入口规则 ID 与全局规则重复", ErrInvalidConfig)
		}
	}
	return overlay, nil
}

func (config Configuration) Validate() error {
	if config.Schema != ConfigSchema || config.Datasets == nil || config.ProvinceWhitelist == nil || config.Rules == nil {
		return fmt.Errorf("%w: schema 或必需数组缺失", ErrInvalidConfig)
	}
	if config.DefaultAction != DefaultActionAllow && config.DefaultAction != DefaultActionDeny {
		return fmt.Errorf("%w: 默认动作只能是 allow 或 deny", ErrInvalidConfig)
	}
	if len(config.Datasets) > MaxDatasets || len(config.ProvinceWhitelist) > len(provinceNames) || len(config.Rules) > MaxRules {
		return fmt.Errorf("%w: 字典数量超限", ErrInvalidConfig)
	}
	datasets := make(map[string]DatasetDefinition, len(config.Datasets))
	sources := make(map[string]bool, len(config.Datasets))
	for _, dataset := range config.Datasets {
		if !validID(dataset.ID) || !validID(dataset.SourceID) || len(dataset.Classifications) == 0 || len(dataset.Classifications) > MaxClassifications || sources[dataset.SourceID] {
			return fmt.Errorf("%w: 数据集身份或分类数量无效", ErrInvalidConfig)
		}
		if _, duplicate := datasets[dataset.ID]; duplicate {
			return fmt.Errorf("%w: 数据集 ID 重复", ErrInvalidConfig)
		}
		seen := map[string]bool{}
		seenCanonical := map[string]bool{}
		for _, classification := range dataset.Classifications {
			canonical := string(classification.Kind) + "\x00" + classification.Name
			if !validID(classification.ID) || seen[classification.ID] || seenCanonical[canonical] || !validIPClassification(classification) {
				return fmt.Errorf("%w: 数据分类无效或重复", ErrInvalidConfig)
			}
			seen[classification.ID] = true
			seenCanonical[canonical] = true
		}
		datasets[dataset.ID] = dataset
		sources[dataset.SourceID] = true
	}
	seenProvince := map[string]bool{}
	for _, ref := range config.ProvinceWhitelist {
		classification, ok := resolveClassification(datasets, ref)
		if !ok || classification.Kind != pluginsdk.DatasetClassificationRegion {
			return fmt.Errorf("%w: 省份白名单引用无效", ErrInvalidConfig)
		}
		if _, mainland := provinceNames[classification.Name]; !mainland || seenProvince[classification.Name] {
			return fmt.Errorf("%w: 省份必须是唯一的大陆省级分类", ErrInvalidConfig)
		}
		seenProvince[classification.Name] = true
	}
	return validateRules(config.Rules, datasets, MaxRules)
}

func validateRules(rules []Rule, datasets map[string]DatasetDefinition, limit int) error {
	if rules == nil || len(rules) > limit {
		return fmt.Errorf("%w: 规则数量无效", ErrInvalidConfig)
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if !validID(rule.ID) || seen[rule.ID] || (rule.Action != DefaultActionAllow && rule.Action != DefaultActionDeny) {
			return fmt.Errorf("%w: 规则身份或动作无效", ErrInvalidConfig)
		}
		seen[rule.ID] = true
		switch rule.Selector.Type {
		case "ip":
			address, err := netip.ParseAddr(rule.Selector.Value)
			if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != rule.Selector.Value || rule.Selector.DatasetID != "" || rule.Selector.ClassificationID != "" {
				return fmt.Errorf("%w: 单 IP 必须是 canonical IPv4/IPv6", ErrInvalidConfig)
			}
		case "cidr":
			prefix, err := netip.ParsePrefix(rule.Selector.Value)
			if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.String() != rule.Selector.Value || rule.Selector.DatasetID != "" || rule.Selector.ClassificationID != "" {
				return fmt.Errorf("%w: CIDR 必须已规范化", ErrInvalidConfig)
			}
		case "classification":
			if rule.Selector.Value != "" {
				return fmt.Errorf("%w: 分类规则不能携带 value", ErrInvalidConfig)
			}
			if _, ok := resolveClassification(datasets, ClassificationRef{DatasetID: rule.Selector.DatasetID, ClassificationID: rule.Selector.ClassificationID}); !ok {
				return fmt.Errorf("%w: 分类规则引用不存在", ErrInvalidConfig)
			}
		default:
			return fmt.Errorf("%w: 未知规则类型", ErrInvalidConfig)
		}
	}
	return nil
}

func validIPClassification(value ClassificationDefinition) bool {
	if value.Kind != pluginsdk.DatasetClassificationCIDR && value.Kind != pluginsdk.DatasetClassificationCountry && value.Kind != pluginsdk.DatasetClassificationRegion {
		return false
	}
	return (pluginsdk.DatasetClassification{Name: value.Name, Kind: value.Kind}).Validate() == nil
}

func resolveClassification(datasets map[string]DatasetDefinition, ref ClassificationRef) (ClassificationDefinition, bool) {
	dataset, ok := datasets[ref.DatasetID]
	if !ok || !validID(ref.ClassificationID) {
		return ClassificationDefinition{}, false
	}
	for _, classification := range dataset.Classifications {
		if classification.ID == ref.ClassificationID {
			return classification, true
		}
	}
	return ClassificationDefinition{}, false
}

func (config Configuration) datasetIndex() map[string]DatasetDefinition {
	result := make(map[string]DatasetDefinition, len(config.Datasets))
	for _, dataset := range config.Datasets {
		result[dataset.ID] = dataset
	}
	return result
}

func (dataset DatasetDefinition) SDKClassifications() []pluginsdk.DatasetClassification {
	result := make([]pluginsdk.DatasetClassification, len(dataset.Classifications))
	for index, classification := range dataset.Classifications {
		result[index] = pluginsdk.DatasetClassification{Name: classification.Name, Kind: classification.Kind}
	}
	return result
}

func Provinces() []ProvinceOption {
	order := []string{"cn-11", "cn-12", "cn-13", "cn-14", "cn-15", "cn-21", "cn-22", "cn-23", "cn-31", "cn-32", "cn-33", "cn-34", "cn-35", "cn-36", "cn-37", "cn-41", "cn-42", "cn-43", "cn-44", "cn-45", "cn-46", "cn-50", "cn-51", "cn-52", "cn-53", "cn-54", "cn-61", "cn-62", "cn-63", "cn-64", "cn-65"}
	result := make([]ProvinceOption, len(order))
	for index, classification := range order {
		result[index] = ProvinceOption{Classification: classification, Name: provinceNames[classification]}
	}
	return result
}

func EncodeConfiguration(config Configuration) ([]byte, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(config)
	if err != nil || len(encoded) > MaxConfigBytes {
		return nil, fmt.Errorf("%w: 编码后超过边界", ErrInvalidConfig)
	}
	return encoded, nil
}

func cloneConfiguration(config Configuration) Configuration {
	encoded, _ := json.Marshal(config)
	cloned, err := ParseConfiguration(encoded)
	if err != nil {
		return DefaultConfiguration()
	}
	return cloned
}

func validID(value string) bool {
	return canonicalID.MatchString(value) && pluginsdk.ValidatePolicyIdentity(value) == nil
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("JSON 包含多个值")
		}
		return err
	}
	return nil
}

func cleanIdentity(value string) string { return strings.TrimSpace(value) }
