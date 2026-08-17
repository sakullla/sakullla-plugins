# Task T-mapping-ui

## Attempt History

```yaml
format: task_attempt_history
task_id: T-mapping-ui
history_ref: evidence/history/sha256-ea8a10e7dc1d9ba18509271eab6ff408086895f6049bb97809e9558e59e25f8e.json
history_count: 4
```

## Execution

```yaml
format: task_run
task_id: T-mapping-ui
execution:
  # allowed: blocked|completed|completed_with_concerns|needs_context
  outcome: completed
  summary: "Rotate now Verifies the live Vault version before CAS, so a persist-failed rotate no longer leaves the next unique-key rotate on a stale expectedVersion. CreateMapping treats an Enroll-already-exists identity with an uncommitted new operation key as a leftover: it retires that epoch and retries the next Vault identity. Tests lock persist-fail then retry rotate, and NewService after a failed create persist can save the suffix again."
  verification_refs: [go test ./plugins/cloudflare-dns]
  concerns: []
```
