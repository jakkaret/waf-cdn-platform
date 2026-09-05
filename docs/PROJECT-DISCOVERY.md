# Project Discovery — WAF+CDN Platform

Generated: 2026-09-05, via the orchestration setup pass.
Supersedes `docs/ARCHITECTURE.md`, `docs/OPERATIONS.md`, `docs/KNOWN_ISSUES.md` (all dated 2026-08-26) where they conflict with the findings below — those files should be updated in Phase 1, not treated as current in the meantime.

Evidence classification used throughout: `[CONFIRMED]` (directly verified against running system/code/test execution), `[LIKELY]` (strongly indicated, not fully verified), `[HYPOTHESIS]` (needs more investigation), `[BLOCKED]` (cannot currently verify).

---

## 1. What this system actually is

A multi-tenant WAF + CDN platform: `[CONFIRMED]` ModSecurity v3 + OWASP CRS 3.3.10 as the signature-based prevention layer, a Random Forest + Isolation Forest anomaly-detection ML layer (advisory only, never auto-blocking), a Gemini-backed AI Copilot for Thai-language analysis, and a FastAPI + React dashboard for multi-tenant management. Ships with an intentionally-vulnerable app testbed (DVWA, Juice Shop, vAmPI, bWAPP) on a separate node for demonstrating WAF effectiveness.

This is a university capstone project (~1 month timeline from 2026-08-29) at the "advanced prototype/demo" stage, not a production deployment — this framing matters for every priority decision below.

## 2. Real infrastructure topology `[CONFIRMED]` (verified live 2026-09-05)

```
Internet
  |
  +-- Edge (45.154.26.91, 1vCPU/2GB): cdn-caddy-ssl, cdn-edge-node (ModSecurity), cdn-log-forwarder
  |
  +-- Main (178.104.53.123, ~3.7GB RAM): caddy-ssl-termination, waf-nginx (ModSecurity, paranoia 1),
  |     waf-redis, waf-clickhouse, waf-control-api (:8070), dvwa,
  |     waf-dashboard.service (:8000), waf-ml.service (:5000), waf-log-analyzer.service,
  |     frps.service (:7000/:7500/:8085), custom tunnel server (:8050 TLS / :8060 vhost)
  |
  +-- Lab (10.198.200.75, behind KKU university VPN, not in this git repo):
        DVWA, Juice Shop, vAmPI, bWAPP behind waf-origin-proxy;
        waf-agent.service (FRP client) + cloudwaf-agent.service (custom tunnel client)
```

Two tunnel mechanisms run in parallel in production, both legitimate: FRP (original three apps) and a custom-built zero-trust tunnel protocol (originally `vampi` only, extended 2026-08-31 to cover all four Lab apps for resilience). This is not redundant-by-accident — do not remove either without checking `/var/lib/cloudwaf-tunnel/state.json` on Main first.

Only one edge region (Thailand) is actually deployed. SG/JP referenced in `scripts/sync_waf_rules.py` are aspirational.

## 3. Known Issues register — status delta since 2026-08-26

`docs/KNOWN_ISSUES.md` lists 6 issues as of 2026-08-26. Current status:

| # | Issue | Status 2026-09-05 |
|---|---|---|
| 1 | Edge config outside git | `[LIKELY]` still true — not re-verified this cycle |
| 2 | Secret committed in `docker-compose.yml` | `[CONFIRMED]` still true — user explicitly declined rotation ("dev stage, not production yet"), a deliberate decision, not an oversight |
| 3 | WAF healthcheck misleading | `[CONFIRMED]` **RESOLVED** 2026-08-31 — healthcheck override now probes the real `:8080/healthz`; container reports `(healthy)` |
| 4 | Working trees contain runtime output | `[LIKELY]` still true — not specifically re-checked |
| 5 | Lab frp path unreachable | `[CONFIRMED]` **RESOLVED** 2026-08-31 — root cause was Lab's KKU network authentication (NAC) session expiring, not a config/repo issue. User re-authenticated; both tunnel agents reconnected automatically |
| 6 | Raw DVWA publicly exposed via Quick Tunnel | `[CONFIRMED]` **RESOLVED** 2026-08-31 — `dvwa-tunnel.service` and `waf-tunnel.service` (the Cloudflare Quick Tunnel paths) disabled and verified closed; all four Lab apps now route exclusively through the WAF via FRP/custom-tunnel |

## 4. Current functionality — verified working `[CONFIRMED]`

- **WAF/prevention**: ModSecurity CRS blocks SQLi/XSS/path-traversal/SSRF reliably — live payload battery against `juice.waf-it-kku.online` (2026-09-04) blocked 15/20 crafted attack payloads; the 5 gaps are documented (§6).
- **Multi-tenancy/RBAC**: real roles (admin/viewer), origin ownership enforcement, tenant isolation — `dashboard/backend/tests/test_rbac.py` and `test_tenant_isolation.py` both pass. Isolation for logs/analytics is pattern-matching-based (not a foreign key), a known architectural limitation, not a defect.
- **ML anomaly detection**: real trained model (Random Forest + Isolation Forest), measured accuracy 80.47% / ROC-AUC 0.8847 / attack precision 98.39% / recall 62.26% (`ml/models/eval_results.json`, 15,027-sample held-out test). Per-request feature attribution is exact (`bias + Σcontribution == predict_proba` to floating-point tolerance). ML is advisory-only — never auto-blocks, by explicit project policy tied to the recall figure.
- **Rule sync**: Dashboard → Edge custom-rule sync works (poll + SHA-256 + graceful nginx reload).
- **Backend test suite**: 61 pytest tests passing (auth, RBAC, tenant isolation, rule CRUD, domain validation, ML explanation degradation, ClickHouse/SecRule injection regression).
- **User journeys**: 13/13 passed against the live deployed system during the T7–T11 verification cycle (see `docs/E2E-USER-JOURNEY-MATRIX.md`).

## 5. Missing / incomplete functionality `[CONFIRMED]` unless noted

- **T12 — self-tuning anomaly-threshold proposal**: not built. This is the project's own stated next-highest priority (after the tunnel-bypass closure, which is done). Real supporting data exists already: ClickHouse shows ~39% block rate driven by the threshold override to 5 (CRS default is 10).
- **`dns_verification_worker.py`**: complete background-loop implementation, never invoked from `main.py` startup — dead code, not a broken feature.
- **Log pipeline data-quality bugs** (full detail in the separate Claude_workspace `Docs/19-Log-Completeness-Analysis`):
  - `edge_node` defaults to `'sg'` when unset — 71.9% of all 175,084 rows carry this fabricated value; no Singapore edge node has ever existed.
  - `request_time_ms` is `0` in 68.4% of rows — nginx logs the real value, the ingestion path just never reads it.
  - `http_referer`, `request_id`, `body_bytes_sent` are captured by nginx but have no column in the ClickHouse schema to land in.
- **ModSecurity audit log retention**: `SecAuditLogRelevantStatus ".*"` logs full body for every request regardless of status; 319MB, growing ~21MB/day, no rotation anywhere in the stack (ClickHouse, DynamoDB, or the file).
- **Playwright E2E spec** (`dashboard/frontend/tests/e2e.spec.ts`): known-stale, selectors don't match current DOM; deferred multiple times across this cycle.
- **CDN multi-region**: code complete, passes tests on dev, never deployed across real multi-region infrastructure — explicitly cuttable per project priority if time runs out.

## 6. Security findings this cycle (all fixed and verified against the real engine, not just unit tests)

- **H4 — ClickHouse LIKE-pattern injection**: 6 call sites used `.replace("'", "\\'")`, unsound against ClickHouse's own backslash-escape rule. Fixed via `escape_like_value()`. Reproduced the break-out against a live ClickHouse instance before and after the fix.
- **SecRule injection** in `rule_manager.py`'s custom-rule writer: identical escaping defect. Fixed via `escape_secrule_string()`. Reproduced against the real ModSecurity engine (`nginx -t` on a crafted rule file) before and after.
- **Live WAF signature gaps** (`Docs/18`, 2026-09-04): bare `;`/backtick command-injection separators, Jinja2 `{{...}}` SSTI syntax, MongoDB `$ne` operator — all pass through unblocked. None confirmed app-exploitable at this endpoint (verified via response body, not just status code) — real signature-coverage gaps nonetheless.
- **Production RAM leak**: `waf-dashboard.service` ran `uvicorn.run(..., reload=True)` in production, holding ~1GB extra resident memory on a RAM-constrained host. Fixed 2026-08-31.
- **Dishonest health reporting**: ML `/health` hardcoded `accuracy_target_passed: true` regardless of actual measured accuracy. Fixed 2026-09-01 with a fail-closed real comparison.
- **Stale deployed bundle serving hardcoded secrets, found 2026-09-05**: not present in current frontend source (which has no "secret" string anywhere), but the bundle actually served by Main was built 2026-09-01 — by someone/something other than this session, since this session did no frontend work that day — from an evidently older, pre-fix version. Caught by re-running `scripts/smoke_test.sh`'s T5 gate during Phase 2's required regression bracket. Fixed by rebuilding from current verified-clean source and redeploying (old bundle backed up first). This is exactly the kind of drift this repo's own `CLAUDE.md` warns is possible ("other people also work on this repo... don't assume your last session's changes are still there untouched") — re-running the full regression bracket periodically, not just after a change you made yourself, is worth keeping up.

## 7. Existing Claude Code configuration `[CONFIRMED]`

- `.claude/skills/` (project-scoped, pre-existing): `management-talk`, `debug-mantra`, `scrutinize`, `post-mortem` — all four preserved untouched by this discovery pass.
- `.claude/agents/`, `.claude/commands/` did not exist before this pass — created fresh this cycle (see `docs/AGENT-OWNERSHIP-MAP.md`).
- No MCP configuration or hooks found scoped to this project specifically.

## 8. CLAUDE.md conflict — resolved 2026-09-05 by explicit user decision

Two `CLAUDE.md`-shaped files gave materially different guidance (see the original framing this section used to carry, still in git history). **Decision**: `/Users/boss/project/waf_project/CLAUDE.md` (this repo's actual, git-tracked file) is the authoritative project CLAUDE.md, because it is the one that lives in the project's own git repository. `/Users/boss/Desktop/Claude_workspace/CLAUDE.md` is a separate, session-local workspace/orchestrator context file — it is not merged wholesale into the project file, and its capstone/deadline framing and priority ordering are explicitly NOT imported as project rules (they are workspace-scoped assumptions, not facts about the repository).

**What was reviewed and brought over, and why each item passed the bar** (project-specific, currently valid, not an unverified assumption):

- **Full-system regression bracket for cross-cutting changes** — added as a new bullet under "Working agreement." This describes an engineering practice tied to the real 3-node topology and the real test scripts that exist (`scripts/smoke_test.sh`, `tunnel/test_tunnel.sh`), not a workspace assumption.
- **ML never auto-blocks** — added as a new section, but reframed from the workspace file's recall-percentage justification to a description of the *verified current implementation*: `ml_rule_service.create_pending_rule()` writes `status: "pending"`, and `POST /api/ml_rules/{rule_id}/approve` requires `require_admin` — no code path bypasses this. Confirmed by reading `ml/auto_rule_generator.py`, `dashboard/backend/services/ml_rule_service.py`, and `dashboard/backend/api/ml_rules.py` directly on 2026-09-05, per instruction to verify implementation rather than trust the workspace file's claim.
- **Reported figures vs. measured ground truth** — added as a new section, grounded in the repo's own documented incident (the 93.40%→80.47% accuracy correction), not a generic workspace bromide.

**What was deliberately NOT brought over**:
- The priority ordering (tunnel > self-tuning > CDN > ML tuning) and the "~1 month capstone deadline" framing — these are workspace-scoped project-management assumptions, not facts about the repository. The repo's own file already states "no fixed priority... follow whatever's explicitly requested," and that stands.
- "Explain before every command, wait for approval" — this would have contradicted the repo file's existing, more specific "Deploy trust" language (already allows unasked action for clearly-scoped requested work, varying by node).
- "Don't agree automatically, challenge with scenarios" — a personal collaboration-style preference, not a project fact.

`CLAUDE.md.bak-orchestrator-20260905` (the pre-edit backup) is retained per instruction and will not be deleted until the new file has been reviewed.

## 9. Backup/restore capability `[LIKELY]` — not fully verified

No automated backup/restore mechanism was found for ClickHouse, DynamoDB, or ModSecurity rule files beyond the manual "copy the file before editing" convention already in the repo's `CLAUDE.md`. This is a `[BLOCKED]` item for any future phase that needs a verified restore path — flagging, not fixing, in this discovery pass.
