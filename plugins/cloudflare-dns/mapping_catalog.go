package cloudflaredns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

type mappingCatalogSnapshot struct {
	Mappings []storedMapping   `json:"mappings"`
	Retired  map[string]uint64 `json:"retired"`
	Revision uint64            `json:"revision"`
}

type mappingCatalog interface {
	Load(context.Context) (mappingCatalogSnapshot, error)
	Save(context.Context, mappingCatalogSnapshot) error
}

type memoryMappingCatalog struct {
	mu       sync.Mutex
	snapshot mappingCatalogSnapshot
}

func newMemoryMappingCatalog() *memoryMappingCatalog {
	return &memoryMappingCatalog{}
}

func (catalog *memoryMappingCatalog) Load(context.Context) (mappingCatalogSnapshot, error) {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	return cloneCatalogSnapshot(catalog.snapshot), nil
}

func (catalog *memoryMappingCatalog) Save(_ context.Context, snapshot mappingCatalogSnapshot) error {
	catalog.mu.Lock()
	catalog.snapshot = cloneCatalogSnapshot(snapshot)
	catalog.mu.Unlock()
	return nil
}

type vaultMappingCatalog struct {
	vault   Vault
	ref     string
	mu      sync.Mutex
	version string
}

func mappingCatalogRef(base string) string {
	return base + "/map/catalog"
}

func newVaultMappingCatalog(vault Vault, secretRef string) *vaultMappingCatalog {
	return &vaultMappingCatalog{vault: vault, ref: mappingCatalogRef(secretRef)}
}

func (catalog *vaultMappingCatalog) Load(ctx context.Context) (mappingCatalogSnapshot, error) {
	attestation, err := catalog.vault.Verify(ctx, catalog.ref)
	if err != nil {
		if errors.Is(err, ErrMappingCatalogNotFound) {
			return mappingCatalogSnapshot{}, nil
		}
		return mappingCatalogSnapshot{}, err
	}
	material, err := catalog.vault.Reveal(ctx, catalog.ref)
	if err != nil {
		return mappingCatalogSnapshot{}, err
	}
	var snapshot mappingCatalogSnapshot
	if err := json.Unmarshal(material, &snapshot); err != nil {
		clear(material)
		return mappingCatalogSnapshot{}, ErrInvalidInput
	}
	clear(material)
	catalog.mu.Lock()
	catalog.version = attestation.Version
	catalog.mu.Unlock()
	return snapshot, nil
}

func (catalog *vaultMappingCatalog) Save(ctx context.Context, snapshot mappingCatalogSnapshot) error {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return ErrInvalidInput
	}
	operation := newCatalogOperationKey()
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	var metadata TokenMetadata
	if catalog.version == "" {
		metadata, err = catalog.vault.Enroll(ctx, catalog.ref, payload, operation)
	} else {
		metadata, err = catalog.vault.Rotate(ctx, catalog.ref, catalog.version, payload, operation)
	}
	if err != nil {
		return err
	}
	catalog.version = metadata.Version
	return nil
}

func newCatalogOperationKey() string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return stableOperationKey("mapping-catalog", hex.EncodeToString(nonce[:]))
	}
	return "operation/catalog/" + hex.EncodeToString(nonce[:])
}

func cloneCatalogSnapshot(snapshot mappingCatalogSnapshot) mappingCatalogSnapshot {
	cloned := mappingCatalogSnapshot{Revision: snapshot.Revision}
	if len(snapshot.Mappings) > 0 {
		cloned.Mappings = append([]storedMapping(nil), snapshot.Mappings...)
	}
	if len(snapshot.Retired) > 0 {
		cloned.Retired = make(map[string]uint64, len(snapshot.Retired))
		for suffix, epoch := range snapshot.Retired {
			cloned.Retired[suffix] = epoch
		}
	}
	return cloned
}

func (service *Service) restoreCatalog(snapshot mappingCatalogSnapshot) {
	for _, mapping := range snapshot.Mappings {
		if mapping.Suffix == "" || !mapping.public().Configured {
			continue
		}
		service.mappings[mapping.Suffix] = mapping
	}
	if snapshot.Retired != nil {
		service.retired = snapshot.Retired
	}
	service.revision = snapshot.Revision
}

func (service *Service) catalogSnapshotLocked() mappingCatalogSnapshot {
	mappings := make([]storedMapping, 0, len(service.mappings))
	for _, mapping := range service.mappings {
		if mapping.public().Configured {
			mappings = append(mappings, mapping)
		}
	}
	retired := make(map[string]uint64, len(service.retired))
	for suffix, epoch := range service.retired {
		retired[suffix] = epoch
	}
	return mappingCatalogSnapshot{Mappings: mappings, Retired: retired, Revision: service.revision}
}

type mappingMemory struct {
	mappings map[string]storedMapping
	retired  map[string]uint64
	revision uint64
}

func (service *Service) cloneMemoryLocked() mappingMemory {
	mappings := make(map[string]storedMapping, len(service.mappings))
	for suffix, mapping := range service.mappings {
		mappings[suffix] = mapping
	}
	retired := make(map[string]uint64, len(service.retired))
	for suffix, epoch := range service.retired {
		retired[suffix] = epoch
	}
	return mappingMemory{mappings: mappings, retired: retired, revision: service.revision}
}

func (service *Service) restoreMemoryLocked(memory mappingMemory) {
	service.mappings = memory.mappings
	service.retired = memory.retired
	service.revision = memory.revision
}

func (service *Service) applyAndPersist(ctx context.Context, action, operation string, request ActionRequest, apply func() error) error {
	if service.catalog == nil {
		service.mu.Lock()
		err := apply()
		service.mu.Unlock()
		return err
	}
	service.catalogMu.Lock()
	defer service.catalogMu.Unlock()
	service.mu.Lock()
	previous := service.cloneMemoryLocked()
	if err := apply(); err != nil {
		service.mu.Unlock()
		return err
	}
	newEpochs := map[string]uint64{}
	for suffix, mapping := range service.mappings {
		if mapping.Epoch == 0 || !mapping.public().Configured {
			continue
		}
		prior, existed := previous.mappings[suffix]
		if !existed || !prior.public().Configured || prior.Epoch != mapping.Epoch || prior.SecretRef != mapping.SecretRef || prior.Version != mapping.Version {
			newEpochs[suffix] = mapping.Epoch
		}
	}
	snapshot := service.catalogSnapshotLocked()
	service.mu.Unlock()
	_, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.catalog.Save(callCtx, snapshot)
	})
	if err != nil {
		service.mu.Lock()
		service.restoreMemoryLocked(previous)
		for suffix, epoch := range newEpochs {
			service.retireSuffixLocked(suffix, epoch)
			if mapping, ok := service.mappings[suffix]; ok && !mapping.public().Configured {
				delete(service.mappings, suffix)
			}
		}
		service.mu.Unlock()
		return service.fail(ctx, action, operation, request, "catalog", safeExternal(err, ErrVaultOperationFailed))
	}
	return nil
}
