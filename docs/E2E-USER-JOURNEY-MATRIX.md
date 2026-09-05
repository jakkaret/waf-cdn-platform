# E2E User Journey Matrix

Generated: 2026-09-05, consolidating the T7–T11 real-browser verification cycle (13/13 passed against the live deployed system) plus new rows for work not yet covered.

**Rule enforced across this whole matrix**: a row is marked PASS only after a live run against the deployed system produced the actual observed result below — never inferred from a passing unit test or from reading the code. See `.claude/agents/e2e-scenario.md`.

## Already verified (T7–T11 cycle, live browser + curl against deployed system)

| # | Journey | Steps | Expected | Actual | Result |
|---|---|---|---|---|---|
| J1 | Anonymous visitor | Open `https://waf-it-kku.online/` | Login page renders, no crash | Rendered correctly | PASS |
| J2 | Login as admin | Fill credentials, submit | Lands on dashboard | Landed, no ErrorBoundary | PASS |
| J3 | ML Analyst — benign payload | Enter benign URL, submit | Verdict + Thai explanation + attribution bars | Rendered correctly | PASS |
| J4 | ML Analyst — SQLi payload | Enter `?id=1' UNION SELECT 1,2,3--`, submit | ANOMALY verdict, `keyword_matches` top contributor | ANOMALY_DETECTED 100%, `keyword_matches +0.2289` top, Thai explanation named the correct features | PASS |
| J5 | ML Analyst — no fabricated claims | Inspect page text | No "n-grams", no fake "MODEL v2.1 ONLINE" | Confirmed removed | PASS |
| J6 | ML Rules page loads | Navigate | Renders, no crash from missing `secrule_template` | Rendered | PASS |
| J7 | Origins → Domains tab | Open origin, Domains tab | Tab renders, add-domain wizard reachable | Previously 404, now works after mounting the router | PASS |
| J8 | Domain validation — reject | Submit `x\' OR 1=1 --`, `a%.example.com`, `a_b.example.com` | 422 for each | 422 confirmed for all three | PASS |
| J9 | Domain validation — accept | Submit a valid hostname | 200 | 200 confirmed | PASS |
| J10 | RBAC — viewer restriction | Login as viewer, attempt admin action | Blocked with clear message, not a 500 | Blocked correctly | PASS |
| J11 | WAF still blocks | curl SQLi at a protected host | 403 | 403 confirmed | PASS |
| J12 | WAF still allows | curl normal request at protected host | 200 | 200 confirmed | PASS |
| J13 | Logout | Click logout | Returns to login | Confirmed | PASS |

## Not yet in this matrix — add when the corresponding phase lands

| # | Journey | Phase | Status |
|---|---|---|---|
| J14 | Self-tuning threshold: proposal appears when block rate exceeds threshold | Phase 3 | `[ ]` not startable until Phase 3 exists |
| J15 | Self-tuning threshold: admin approves, `00-modsecurity-override.conf` changes, Edge syncs (check mtime) | Phase 3 | `[ ]` |
| J16 | Self-tuning threshold: admin rejects, no config change occurs | Phase 3 | `[ ]` |
| J17 | WAF signature gap closed: bare `;`/backtick command-injection now blocked | Phase 4 | `[ ]` |
| J18 | WAF signature gap closed: Jinja2 `{{...}}` SSTI now blocked | Phase 4 | `[ ]` |
| J19 | Regression: full 20-payload battery re-run, ≥ the 15/20 baseline block rate, no new false positive on the 5 previously-passing benign-adjacent cases | Phase 4/5 | `[ ]` |
| J20 | Tunnel-origin connectivity: a fresh origin behind NAT connects via the custom tunnel protocol end-to-end (register → auth → route → serve) | Not yet scheduled | `[ ]` — was tested during the tunnel implementation cycle but not as a formal numbered journey; worth promoting into this matrix |
| J21 | Public-IP origin connectivity: an origin with a direct public IP connects without the tunnel | Not yet scheduled | `[B]` blocked — needs a real public-IP test origin, not currently provisioned |

## Known gap

J21 is blocked on infrastructure (no spare public-IP test origin exists) — this is an honest gap in coverage for the "public origin" path the platform is meant to support, not a skipped test. Flag this explicitly rather than assuming the path works because the tunnel path does.
