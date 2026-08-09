package sdklock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var fullOID = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Lock struct {
	SchemaVersion            int          `json:"schema_version"`
	Repository               Repository   `json:"repository"`
	SDK                      SDK          `json:"sdk"`
	Artifacts                Artifacts    `json:"artifacts"`
	RequiredCapabilities     []Capability `json:"required_capabilities"`
	CapabilityContractSHA256 string       `json:"capability_contract_sha256"`
}

type Repository struct {
	URL    string `json:"url"`
	Commit string `json:"commit"`
}

type SDK struct {
	ModulePath      string `json:"module_path"`
	ModuleDirectory string `json:"module_directory"`
	ContractTreeOID string `json:"contract_tree_oid"`
}

type Artifacts struct {
	DescriptorSetSHA256  string `json:"descriptor_set_sha256"`
	PolicyProtoSHA256    string `json:"policy_proto_sha256"`
	RPCProtoSHA256       string `json:"rpc_proto_sha256"`
	CanonicalGuestSHA256 string `json:"canonical_guest_sha256"`
	ValidatorTreeOID     string `json:"validator_tree_oid"`
}

type Capability struct {
	ID            string   `json:"id"`
	Available     bool     `json:"available"`
	EvidencePath  string   `json:"evidence_path,omitempty"`
	Symbols       []string `json:"symbols,omitempty"`
	MissingReason string   `json:"missing_reason,omitempty"`
}

func Load(path string) (Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var lock Lock
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("decode SDK lock: %w", err)
	}
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

func (lock Lock) Validate() error {
	if lock.SchemaVersion != 1 || lock.Repository.URL == "" || !fullOID.MatchString(lock.Repository.Commit) {
		return fmt.Errorf("SDK lock requires schema_version 1, repository URL, and full 40-character commit OID")
	}
	if lock.SDK.ModulePath != "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go" || lock.SDK.ModuleDirectory != "plugin-sdk/go" {
		return fmt.Errorf("SDK lock must reference the canonical public Go module")
	}
	if !fullOID.MatchString(lock.SDK.ContractTreeOID) || !fullOID.MatchString(lock.Artifacts.ValidatorTreeOID) {
		return fmt.Errorf("SDK and validator Git tree OIDs must be full SHA-1 object IDs")
	}
	for name, value := range map[string]string{
		"descriptor_set":      lock.Artifacts.DescriptorSetSHA256,
		"policy_proto":        lock.Artifacts.PolicyProtoSHA256,
		"rpc_proto":           lock.Artifacts.RPCProtoSHA256,
		"canonical_guest":     lock.Artifacts.CanonicalGuestSHA256,
		"capability_contract": lock.CapabilityContractSHA256,
	} {
		if !sha256Hex.MatchString(value) {
			return fmt.Errorf("%s digest must be lowercase SHA-256", name)
		}
	}
	if len(lock.RequiredCapabilities) == 0 {
		return fmt.Errorf("SDK lock requires host capability gates")
	}
	seen := make(map[string]bool)
	for _, capability := range lock.RequiredCapabilities {
		if capability.ID == "" || seen[capability.ID] {
			return fmt.Errorf("capability IDs must be non-empty and unique")
		}
		seen[capability.ID] = true
		if capability.Available {
			if capability.EvidencePath == "" || len(capability.Symbols) == 0 || capability.MissingReason != "" {
				return fmt.Errorf("available capability %s requires evidence and no missing reason", capability.ID)
			}
			if !canonicalRepositoryPath(capability.EvidencePath) ||
				(capability.EvidencePath != lock.SDK.ModuleDirectory && !strings.HasPrefix(capability.EvidencePath, lock.SDK.ModuleDirectory+"/")) {
				return fmt.Errorf("capability %s evidence must be a canonical path inside the public SDK module", capability.ID)
			}
		} else if capability.MissingReason == "" || capability.EvidencePath != "" || len(capability.Symbols) != 0 {
			return fmt.Errorf("missing capability %s requires only a missing reason", capability.ID)
		}
	}
	if actual := CapabilityDigest(lock.RequiredCapabilities); actual != lock.CapabilityContractSHA256 {
		return fmt.Errorf("capability contract digest mismatch: got %s, want %s", lock.CapabilityContractSHA256, actual)
	}
	return nil
}

func canonicalRepositoryPath(value string) bool {
	if value == "" || strings.Contains(value, `\`) || pathpkg.IsAbs(value) || filepath.IsAbs(filepath.FromSlash(value)) || strings.Contains(value, ":") {
		return false
	}
	cleaned := pathpkg.Clean(value)
	return cleaned == value && cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

func CapabilityDigest(capabilities []Capability) string {
	canonical := append([]Capability{}, capabilities...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].ID < canonical[j].ID })
	data, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (lock Lock) MissingCapabilities() []string {
	var missing []string
	for _, capability := range lock.RequiredCapabilities {
		if !capability.Available {
			missing = append(missing, capability.ID+": "+capability.MissingReason)
		}
	}
	sort.Strings(missing)
	return missing
}

func normalizeGitOutput(value []byte) string { return strings.TrimSpace(string(value)) }
