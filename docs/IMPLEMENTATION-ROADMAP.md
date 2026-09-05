# Implementation Roadmap

Generated: 2026-09-05. Derived from `docs/PROJECT-DISCOVERY.md`'s actual findings — not the generic phase list a template might suggest. Phases are ordered by dependency and by this project's own stated priority (tunnel-bypass closure, already done, was priority 1; self-tuning threshold is priority 2).

Status legend: `[ ]` not started · `[~]` in progress · `[x]` verified complete · `[!]` failed · `[B]` blocked

---

## Phase 0 — Discovery `[x]` VERIFIED (this cycle)
Repository audit, `.claude/` orchestration scaffolding, `docs/PROJECT-DISCOVERY.md`, this roadmap, agent ownership map, E2E journey matrix. See `docs/PROJECT-DISCOVERY.md` for full findings.

## Phase 1 — Documentation truth reconciliation `[x]` VERIFIED 2026-09-05
Updated `docs/ARCHITECTURE.md` (two-tunnel-mechanism topology, closed bypass path), `docs/KNOWN_ISSUES.md` (issues #3/#6 marked resolved with evidence; #5 kept open — see below), `docs/OPERATIONS.md` (added the real pytest/smoke/tunnel-test suite, noted the stale Playwright spec). `CLAUDE.md` conflict resolved per user decision (see `docs/PROJECT-DISCOVERY.md` §8) before this phase touched it.

**New finding during re-verification** (not a regression from this cycle's own work — an independent recurrence): Lab tunnel connectivity dropped again as of 2026-09-05, different failure signature than the 2026-08-31 incident (`Connection refused` to Main's tunnel ports from Lab specifically, not the NAC captive-portal pattern). Confirmed Main-side is healthy and not blocking (ports open, reachable from an unrelated external host, no ufw/iptables rule targeting Lab). Root cause is on the university network path, outside this repo's control — `[BLOCKED]`, needs the user to check Lab's network/VPN status. Recorded in `docs/KNOWN_ISSUES.md` #5. Does not block Phase 2 or 3, which don't depend on live Lab connectivity.

## Phase 2 — Log pipeline correctness `[x]` VERIFIED 2026-09-05
Fixed via TDD (RED→GREEN, then verified against live ClickHouse data, not just unit tests):
- `resolve_edge_node()` added to `clickhouse_service.py` — replaces the fabricated `'sg'` default with a fail-loud `'unknown'` when the field is genuinely absent. 3 tests.
- `log_forward.py`'s `normalize_access()` now extracts `request_time_ms` from nginx's `request_time` field and sets `edge_node="edge-th"`. 3 tests.
- **Found and fixed a second, previously-undocumented code path with the same bug**: `normalize_modsec()` (feeds `try_merge()`'s merge-timeout fallback in `flush_old_logs()`, confirmed via live traffic to fire under normal load) also never set `edge_node`. Fixed the same way. 1 test.
- ClickHouse schema: added `request_id`, `http_referer`, `body_bytes_sent` columns via `ALTER TABLE ADD COLUMN` — **backed up first** (full table dump to `/root/waf_project/backups/access_logs_backup_20260905_022623.native`, 72MB) **and verified the backup restores correctly** (loaded into a temp table, row-for-row match against the original by key fields, temp table then dropped) before altering. Wired into `save_log()`. 2 tests.
- Total: 88/88 backend+ML tests passing (was 79 at cycle start). Deployed to Main, restarted `waf-dashboard.service`, and **empirically confirmed against fresh live ClickHouse rows** (not just the test suite) that `edge_node` now reads `edge-th` for genuine Main traffic instead of the fabricated `sg`.

**Unrelated finding caught by this phase's required regression bracket, fixed same-day**: `scripts/smoke_test.sh`'s T5 security gate (no secrets in the public JS bundle) failed — the bundle actually being served by Main (`index-DkXXzT28.js`, built 2026-09-01, a date/time this session did no frontend work) contained `WAF_SECURE_TUNNEL_2026_TOKEN` and `cdn-secret-token`, even though current frontend source (last touched by commit `2c9a94d`, "serve agent config from the API instead of the browser bundle") has neither string anywhere. This means someone else's deploy on 2026-09-01 (or an automated process) served a stale/pre-fix build — this repo is explicitly collaborative per its own `CLAUDE.md`, and this is the kind of drift that note warns about. Fixed by rebuilding the frontend from the current, verified-clean source and redeploying (old bundle backed up to `dist.bak-stale-secret-bundle-20260905/` on Main first). Re-verified live: the served bundle now contains zero occurrences of either string. `scripts/smoke_test.sh` now passes 22/22 + 6/6 (was 4/6 security gates just before this fix).

`tunnel/test_tunnel.sh` shows 9 failures, all tracing to the Lab-tunnel-down finding logged in Phase 1 (`agent_count=0`, 502/404 on every tunnel-dependent check) — not a Phase 2 regression; these tests will pass again once Lab's network connectivity is restored.

## Phase 3 — T12 self-tuning anomaly-threshold proposal `[ ]`
**This project's own stated top remaining priority.** Query-driven proposal generation + mandatory human approval + write-through to existing `settings_service.py`. Command: `.claude/commands/phase3.md`. Risk: medium (touches the live anomaly threshold that gates all blocking) — human-approval-in-the-loop is the safety mechanism, not an optional nicety; do not build a variant that skips it. Blocked on: nothing (all reusable pieces — `settings_service.py`, `ml_rule_service.py` approval lifecycle, `MLRules.tsx` queue UI — already exist per prior discovery).

## Phase 4 — WAF signature coverage gaps `[ ]`
Close the 4 confirmed gaps from the 2026-09-04 live payload battery (command-injection separators, Jinja2 SSTI, NoSQL `$ne`). Command: `.claude/commands/phase4.md`. Risk: medium (rule changes can introduce false positives) — must run the Blast Radius Simulator and re-run the full payload battery, not just the fixed case, before deploying. Blocked on: nothing.

## Phase 5 — E2E/regression hardening `[ ]`
Repair the stale Playwright spec; formalize the payload battery as a repeatable regression script rather than a one-off. Command: `.claude/commands/phase5.md`. Risk: low (test-only changes). Blocked on: Phase 4 (needs the fixed rule set to write meaningful regression assertions against).

## Phase 6 — Stretch (only if time remains) `[ ]`
Wire `dns_verification_worker.py`; decide CDN multi-region deploy-vs-defer; do NOT rotate the committed secret or FRP admin password without asking again (both are known, both deliberately deferred, per user's own prior decision — a past "not now" is not a standing "never," but also isn't a green light to act without re-asking). Command: `.claude/commands/phase6.md`. Explicitly lower priority than Phases 1–5; do not start it while any of those remain incomplete.

---

## Deliberately out of scope for this roadmap

Full RBAC/multi-tenancy rebuild, a from-scratch synthetic scenario lab, and an 11-phase production-hardening program (secrets management, mTLS, DB-layer auth) were considered and rejected for this cycle: RBAC/multi-tenancy already exist and are tested (`test_rbac.py`, `test_tenant_isolation.py` passing); the Lab node's DVWA/Juice Shop/vAmPI/bWAPP testbed already serves as the scenario lab; and production hardening is explicitly deferred post-submission per the project's own priority ordering (see the `CLAUDE.md` conflict noted in `docs/PROJECT-DISCOVERY.md` §8 — both versions of the file agree hardening is out of scope for now, whichever one otherwise governs).

## Time constraint

If this is genuinely a ~1-month capstone with the deadline already ~1 week elapsed, Phases 1–3 are the ones that must complete; Phases 4–6 are valuable but explicitly droppable if time runs short, in that order (6 first, then 5, then 4).
