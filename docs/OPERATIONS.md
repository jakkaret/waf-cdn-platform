# WAF Project Operations

Status: operational reference
Last reviewed: 2026-08-26
Owner: update this file when deployment or rollback procedures change

## Deployment flow

1. Make and review changes in the local repository.
2. Use the existing sync/deploy script for the target service.
3. Validate configuration with `nginx -t` before reload.
4. Reload only the affected service.
5. Check logs, listener health, and the relevant request path.
6. Backport any emergency server-side change into the repository.

For risky main-node changes, create a timestamped copy of the specific config first.
Do not drop data, recreate volumes, rotate tokens, change firewall rules, or remove
rules without explicit confirmation.

## Testing

The scripts under `scripts/test_*.py` are manual live-stack checks, not an automated
pytest suite. They require the dashboard API, WAF, Redis, and ClickHouse to be
running and may be stale. Run a script once against the current stack before relying
on its result.

The frontend has Playwright E2E tests:

```text
cd dashboard/frontend
npm run test:e2e
```

These also require a meaningful running backend.

## Repository hygiene

Avoid committing generated Python cache files, logs, virtual environments, or other
runtime output. Inspect `git status` before committing because this repository and
its VPS clones may contain unrelated working-tree changes.
