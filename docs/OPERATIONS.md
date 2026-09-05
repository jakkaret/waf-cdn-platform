# WAF Project Operations

Status: operational reference
Last reviewed: 2026-09-05
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

An automated pytest suite exists and is CI-gated (`.github/workflows/ci.yml`, jobs
`test-backend`/`test-ml`):

```text
cd dashboard/backend && .venv/bin/python -m pytest tests/ ../../ml/tests/ -v
```

61 tests under `dashboard/backend/tests/` (auth, RBAC, tenant isolation, rule CRUD,
domain validation, ML attribution explanation, ClickHouse/SecRule injection
regression) plus tests under `ml/tests/` (feature-attribution correctness,
accuracy-target computation). Every change to a shared contract must keep this suite
green.

Two live-system regression scripts (not pytest, but CI-independent and required
before/after any cross-cutting change per `CLAUDE.md`):

```text
bash scripts/smoke_test.sh    # 22 invariants + 6 security gates
bash tunnel/test_tunnel.sh    # 28 tests for the private tunnel protocol
```

The scripts under `scripts/test_*.py` (9 files) are older manual live-stack checks,
separate from the pytest suite above, not CI-gated, and may be stale. Run one once
against the current stack before relying on its result.

The frontend has a Playwright E2E spec, but it is known-stale (selectors don't match
the current DOM — deferred repair, tracked in
`docs/E2E-USER-JOURNEY-MATRIX.md`):

```text
cd dashboard/frontend
npm run test:e2e
```

For a real completion check on a user-facing change, prefer a live-browser run
against the deployed system over this spec — see `docs/E2E-USER-JOURNEY-MATRIX.md`
for the 13 journeys already verified this way.

## Repository hygiene

Avoid committing generated Python cache files, logs, virtual environments, or other
runtime output. Inspect `git status` before committing because this repository and
its VPS clones may contain unrelated working-tree changes.
