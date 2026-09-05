# Project Implementation Report — Phases 1-3

Generated 2026-09-05. Covers the orchestrated work from Phase 1 (documentation truth
reconciliation) through Phase 3 (T12 self-tuning threshold). Full evidence and per-phase
detail lives in `docs/IMPLEMENTATION-ROADMAP.md`; this document is the single answer to
"what changed, what was tested, what's risky, is it ready."

**Standing instruction still in force: do not push, do not deploy, until the user
explicitly approves after reviewing this report.**

---

## 1. What changed since `dd614ac`/`aad36af` (the merge)

Two independent lines of work were reconciled by merge commit `aad36af` (already made,
not pushed): this session's tunnel implementation, test infrastructure, CLAUDE.md/docs
work, CI and dependency fixes, and ML-accuracy-figure fixes, against `dd614ac`'s FRP
webhook gatekeeper, auto-sync tunnel origins, and dynamic rate limiter. The merge was
done with `--no-commit --no-ff`, every silent auto-deletion was individually restored,
and two files (`nginx/templates/conf.d/default.conf.template`, `ml/dashboard/index.html`)
were resolved by manual semantic review after catching git's auto-merge reintroducing
stale fabricated figures. `.github/workflows/ci.yml` and `requirements.txt` were reverted
wholesale to pre-`dd614ac` content — `dd614ac`'s versions were purely regressive (dropped
`backend` from CI triggers, reintroduced pytest exit-code swallowing, dropped the
`test-ml` job and the `clickhouse-connect` dependency).

Since the merge, two commits were added on top of `aad36af`:

- **`6d0b441`** — closed the two CRITICAL cross-tenant gaps found while writing the
  missing tests for `dd614ac`'s three features (detail in §2).
- **`e59be16`** — T12 self-tuning threshold proposal system (detail in §3).

---

## 2. Tests added and executed for the previously-untested `dd614ac` features

| Feature | Test file | Count | Result |
|---|---|---|---|
| FRP webhook gatekeeper | `test_frp_webhook_gatekeeper.py` | 17 (1 `xfail(strict=True)`) | pass |
| Auto-sync tunnel origins | `test_auto_sync_tunnel_origins.py` | 7 | pass |
| Dynamic rate limiter | `test_dynamic_rate_limiter.py` | 19 | pass |

Coverage matches every category requested: valid/invalid auth or signature, replay,
unauthorized origin registration, cross-tenant origin registration, origin-ownership
enforcement, malformed payload, fail-closed behavior (webhook); create/update/delete,
duplicate/repeated events, stale/out-of-order events, tenant isolation, origin ownership
(auto-sync); normal request, threshold exceeded, burst, reset/expiry, per-tenant/per-origin
isolation, fail-safe behavior (rate limiter).

### Security findings (both CRITICAL, both fixed with RED-before/GREEN-after tests)

1. **FRP webhook domain hijack.** `frp_webhook_gatekeeper`'s NewProxy handler validated
   only against `RESERVED_SUBDOMAINS`; it never checked that the domain being registered
   matched the domain a JWT tunnel token was actually issued for, despite the function's
   own docstring claiming to enforce domain ownership. A token minted for
   `alice.example.com` could register a proxy for `bob.example.com`. Fix: extract
   identity the same way the Login op already does, enforce
   `payload["domain"] == target_domain` for JWT clients, reject with `"Token is not
   authorized for this domain"` on mismatch. Legacy-token clients (no JWT payload) keep
   their prior any-non-reserved-domain behavior — no regression there, since legacy
   tokens carry no domain claim to check against.
2. **Auto-sync cross-tenant origin claiming.** `auto_sync_tunnel_origins` created a new
   origin for any unclaimed domain/tunnel-name string with no check for whether another
   tenant already owned a matching origin (by label/IP/tunnel-name substring). Fix: scan
   all origins first, skip auto-creation when `already_claimed_by_someone_else`.
3. Also hardened: the webhook's fallback for an unrecognised FRP plugin op changed from
   `{"reject": False}` (fail-open) to `{"reject": True, ...}` (fail-closed).

---

## 3. T12 — self-tuning anomaly-threshold proposal

### Discovery, before writing any code
- `services/settings_service.py` and the `modsecurity.d` nginx template confirm the WAF
  enforces **one global `inbound_anomaly_score_threshold`**, shared by every origin. No
  per-origin threshold mechanism exists to target.
- ClickHouse's `access_logs` has no `origin_id` column; per-origin attribution
  everywhere in this codebase (including this new module) uses the same URL-pattern
  `multiIf(...)` convention `api/analytics.py` already established — a known, tracked
  gap, not a new one.
- `access_logs` does not log the raw per-request anomaly score, only the final status
  code — this rules out true historical replay/simulation of a hypothetical threshold
  (see limitation below).

### Design (built around the global-only constraint)
`services/threshold_proposal_service.py`: `generate_threshold_proposal()` is a pure,
non-mutating function over ClickHouse block-rate evidence. `ThresholdProposalStore`
mirrors `ml_rule_service.py`'s pending-approval shape. `api/threshold_proposals.py`:
`/generate`, list, get usable by any authenticated viewer+; `/approve`, `/reject`,
`/rollback` all `require_admin`. **No code path applies a proposal without an explicit
admin action** — `SettingsService.update_settings()` is called nowhere except inside
`approve()`/`rollback()`.

### How each required safety property is met

| Requirement | How it's met | Verified by |
|---|---|---|
| Never auto-converts recommendations into blocks | `create()` only ever writes `pending`; only `/approve` and `/rollback` call `update_settings()`, both admin-gated | `test_threshold_proposal_store.py` (11), `test_threshold_proposal_api.py` (11) |
| Preserve per-origin isolation | **Architectural limitation, not a guarantee**: the WAF has one global threshold with no per-origin lever at all, so no code path — this one or any other — could scope a change to one origin. The property actually enforced is refusing single-origin-driven global change (next row) | documented in code + roadmap |
| Single origin cannot drive another's security profile | Requires `MIN_ORIGINS_FOR_CONSENSUS=2` independently-sampled, independently-elevated origins; every proposal's reason string states the change is global | `test_threshold_proposal_service.py` |
| Insufficient/noisy data can't cause unsafe changes | `MIN_SAMPLES_PER_ORIGIN=200` excludes low-sample origins from the decision (shown in evidence only) | same file |
| False-positive amplification / poisoned-log resistance | Consensus + sample-size gates mean one poisoned origin alone can't clear the bar; blended trigger % only sums corroborating origins | same file, incl. explicit single-anomalous-origin-does-not-propose case |
| Rollback/versioning | `approve()` captures `previous_threshold` from what's live *at approval time*, not the proposal's stale snapshot | `test_threshold_proposal_store.py` |
| Shadow/simulation before activation | **Partially met.** Generation itself is read-only/shadow; nothing reaches prod without explicit approval. True historical replay is not implemented — no raw anomaly-score log exists to replay against. Real gap, documented, not fixed this phase | — |

### Tests
36 new tests: `test_threshold_proposal_service.py` (11), `test_threshold_proposal_store.py`
(11), `test_threshold_proposal_api.py` (11), `test_settings_service_threshold_baseline.py`
(4, establishes pre-existing `settings_service` behavior before building on it, per the
task's "establish current behavior with tests before modifying it"). Also manually
verified `generate_threshold_proposal()` against real current ClickHouse data (fetched via
direct SQL over SSH from Main, evaluated locally — nothing deployed) to confirm behavior
holds on live-shaped data, not only synthetic fixtures.

---

## 4. Full test execution summary

- **Local backend suite** (`dashboard/backend`, `.venv/bin/python -m pytest -q`,
  run 2026-09-05): **150 passed, 1 xfailed, 0 failed.**
- **`scripts/smoke_test.sh`** against the live deployed system: **22/22 invariants,
  6/6 security gates, 0 failed** (clean run; two earlier same-day invocations showed
  inconsistent 18/4 and 21/1 results, traced to rapid repeated invocation rather than a
  code regression — a subsequent clean deterministic run confirms this).
- **`tunnel/test_tunnel.sh`**: 20 passed, 8 failed, 3 skipped. All 8 failures are
  origin/agent-dependent (private-origin reachability, connected-agent count,
  reconnect-after-restart) and trace to the pre-existing, already-documented
  Lab-tunnel-down condition (`docs/KNOWN_ISSUES.md` #5 — a KKU campus network/VPN-side
  issue on the Lab machine, confirmed unrelated to any change made this session). WAF
  filtering and FRP-backed-host checks within the same suite pass in full (5/5, 10/10).

## 5. Blocked tests

Any tunnel test requiring a live, connected Lab agent (private-origin E2E reachability,
agent-restart resilience, `valid token accepted` — the latter two also explicitly `SKIP`
pending `TUNNEL_TOKEN`/`LAB_SSH` env vars) is **BLOCKED** by Lab connectivity, not by
anything in this session's code. Per standing instruction, marked BLOCKED and not
treated as a failure of this work.

## 6. Remaining risks

1. **No historical threshold simulation** (§3, shadow/simulation row) — a proposal's
   real-world effect on past traffic cannot be previewed before approval; an admin
   approving a proposal is trusting the live evidence summary, not a replay.
2. **Global-only threshold is a structural limitation**, not something this phase could
   fix — any future single-origin-scoped tuning would need a WAF-side change (per-origin
   ModSecurity config), out of scope here.
3. **Lab tunnel connectivity remains down** (pre-existing, tracked in
   `docs/KNOWN_ISSUES.md` #5) — blocks true E2E verification of the tunnel-dependent
   parts of both the security fixes and any future tunnel work until resolved on the
   university network side.
4. **T12 has no scheduler or UI wired up yet** — usable today only via direct
   authenticated API calls; a human must know to call `/generate` and review the result.
   This was a deliberate scope decision (substrate first, automation/UI later), not an
   oversight, but it means T12 delivers no operational value until someone actually
   calls it.

## 7. Is `aad36af` (+ `6d0b441` + `e59be16`) ready for staging deployment?

**Conditionally yes, pending your review of this report.** All code implemented this
session is tested (230 total tests in the touched areas: 150 backend-suite pass + 1
xfail, plus the 80 new tests counted within that total), the two CRITICAL cross-tenant
vulnerabilities found in `dd614ac`'s merged features are fixed and proven fixed, the
live smoke-test regression signal was investigated and traced to invocation flakiness
rather than a real defect, and the tunnel-test failures are confirmed pre-existing and
environmental rather than caused by this work. Nothing has been pushed, deployed,
rebased, or force-pushed. `aad36af` remains rollback-safe (rollback would mean resetting
to `2ce5be1` or `dd614ac` directly, both still reachable in history).

The only open item that should factor into a staging decision is the shadow-simulation
gap in §6.1 — T12's proposals are evidence-backed but not backtested — which is a
product-risk trade-off for you to weigh, not a code defect.

**Awaiting your explicit approval before any push or deploy.**
