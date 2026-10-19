# Service recovery

The current runtime uses request-scoped execution and does not depend on a durable task scheduler. It does not require legacy queued jobs to be replayed after a restart.

## Preserve authorization state

- Do not delete or regenerate the configured OAuth signing key during routine recovery.
- Do not truncate, reset or recreate the `oauth` schema.
- Do not revoke tokens or re-register OAuth clients merely to restart the service.
- Keep a secured copy of the private config, key and database backup; never include them in a public issue or repository.

## Recovery sequence (FreeBSD)

1. Check `service kerno status` and the configured service log.
2. Check the local health endpoint on the configured listener.
3. Verify the configured C executor exists and is executable; run the candidate's `--check-config` before an approved replacement.
4. Restart only the KERNO service unless independent diagnostics show another dependency is failing.
5. Verify protected-resource metadata, `tools/list`, and an authenticated tool call using a test client.

Do not drop or reset a PostgreSQL database as a generic recovery action. Confirm which applications own the database and inspect a verified backup before any destructive database operation.
