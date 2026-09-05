# Agent Ownership Map

Generated: 2026-09-05. Prevents uncontrolled concurrent edits to the same file by two agents — check this before delegating a task.

| Agent | Definition | Owns |
|---|---|---|
| architecture | `.claude/agents/architecture.md` | Cross-cutting structural decisions; no specific files, advisory over the others |
| security | `.claude/agents/security.md` | Injection-safety logic in `clickhouse_service.py`, `rule_manager.py` (escaping helpers only — shared with waf/backend for the rest of each file); `rbac.py`, `auth_service.py`; `tunnel/*` credential model |
| backend | `.claude/agents/backend.md` | `dashboard/backend/api/*.py`, `dashboard/backend/services/*.py` (excluding the shared escaping-logic files above), `dashboard/backend/main.py` |
| frontend | `.claude/agents/frontend.md` | `dashboard/frontend/src/**` |
| waf | `.claude/agents/waf.md` | `nginx/templates/**`, `modsecurity/custom-rules/*.conf`, `scripts/sync_waf_rules.py`; `rule_manager.py` jointly with security |
| logging | `.claude/agents/logging.md` | `log_forward.py`, `cdn_log_forward.py`, `clickhouse_service.py`'s schema + `save_log()` |
| rbac | `.claude/agents/rbac.md` | `rbac.py`, `tenant_service.py`, `auth.py`'s role bootstrap |
| devops | `.claude/agents/devops.md` | `docker-compose.yml`, `cdn/docker-compose-cdn.yml`, systemd units on all three nodes |
| tunnel | `.claude/agents/tunnel.md` | `tunnel/*.py`, `dashboard/backend/api/tunnel.py`, Lab-node agent configs |
| ml | `.claude/agents/ml.md` | `ml/**` |
| e2e-scenario | `.claude/agents/e2e-scenario.md` | Live-browser verification runs; the Lab node as scenario-lab fixture (read-only user of Lab, doesn't own its config — devops does) |
| qa | `.claude/agents/qa.md` | `dashboard/backend/tests/`, `ml/tests/`, `dashboard/frontend/tests/`, `scripts/smoke_test.sh`, `tunnel/test_tunnel.sh` |
| reviewer | `.claude/agents/reviewer.md` | No files — reviews diffs from all other agents, no write ownership |

## Shared-file coordination rule

`dashboard/backend/services/rule_manager.py` and `dashboard/backend/services/clickhouse_service.py` are dual-owned (security + waf, security + logging/backend respectively). When either needs a change: security agent reviews any edit to the escaping/injection-safety portion before it merges, regardless of which agent authored it. Never let two agents edit either file concurrently — sequence the work.

## Documentation ownership

`docs/*.md` — no single agent owns these; whichever agent's phase produces a finding updates the relevant doc, and the reviewer agent checks the update landed before marking a phase complete (per `.claude/commands/release-check.md`).
