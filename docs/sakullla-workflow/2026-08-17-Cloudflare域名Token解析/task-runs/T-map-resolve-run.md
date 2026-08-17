# Task T-map-resolve

## Attempt History

```yaml
format: task_attempt_history
task_id: T-map-resolve
history_ref: evidence/history/sha256-4f5909a5d4fd8ddce79fc91743e92c902957b82f7b4fda37044eadb73488e95f.json
history_count: 3
```

## Execution

```yaml
format: task_run
task_id: T-map-resolve
execution:
  # allowed: blocked|completed|completed_with_concerns|needs_context
  outcome: completed
  summary: Repaired T-map-resolve delivery after catalog Load was wired into Controller.Activate. The integration fakeVault now returns ErrMappingCatalogNotFound for a missing suffix-owned catalog ref, matching the dedicated first-boot not-found contract instead of leaking raw missing token into Activate. Added TestCloudflareRPCActivateLoadsEmptyCatalogAndResolves so first-boot Activate can create a mapping, resolve the longest suffix without using fallback, return the caller fallback on a miss, and fail as that domain having no available Token when neither mapping nor fallback is present.
  verification_refs: [go test ./plugins/cloudflare-dns ./testing/integration/cloudflare-dns ./internal/pluginmanifest]
  concerns: []
```
