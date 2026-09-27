# Documentation team brief (read fully before starting)

## Sources of truth
- Repository (read-only for you): `/Users/boss/project/waf_project` at commit `c033758` — identical to the VPS checkout `/root/waf_project`.
- Runtime (read-only): `ssh root@178.104.53.123` (Main), `ssh root@45.154.26.91` (edge-th), `ssh waf-node-azure` (edge-asia, user azure). Allowed: `cat`, `ls`, `grep`, `docker ps/inspect/logs`, `systemctl status/show`, `ss`, `curl` GET to health/status endpoints, read-only `clickhouse-client` SELECT (write the SQL to a file and pipe it; `ssh … 'docker exec -i waf-clickhouse clickhouse-client --multiquery' < q.sql`).
- Forbidden: editing anything outside your own output paths; restarting/reloading services; `docker exec` that changes state; any write to ClickHouse/DynamoDB/Redis; running the backend pytest suite on the VPS (it can write to production DBs); attack payloads or load; reading or copying `.env`, keys, tokens, `.session` files.
- Runtime snapshot already collected: `docs/_evidence/runtime-2026-09-27.md` — reuse it instead of re-collecting.

## Status labels (mandatory, use exactly)
`VERIFIED` (seen in code/config/runtime/test you checked) · `PARTIAL` · `PLANNED` (not implemented) · `UNKNOWN` (no evidence) · `DEPRECATED`.
Never describe a PLANNED/UNKNOWN item as working. Never claim a test passed unless you ran it and saw the result. If something in the repo contradicts runtime, runtime wins and you note the discrepancy.

## Language & style
- Thai as the main language; English technical terms in parentheses on first use, e.g. "ตัวกรองคำขอ (request filter)". Code, paths, identifiers, commands stay in English.
- Audience: basic IT knowledge up to developers/administrators. Explain *why* as well as *what*.
- Be concrete: file paths, function names, table names, ports. Prefer tables for inventories.
- No secrets, tokens, passwords, keys, emails of real users, full IPs of end users. Use `<REDACTED>`, `<YOUR_DOMAIN>`. Server IPs of our own infrastructure (178.104.53.123, 45.154.26.91, 57.158.25.236) may appear.

## File conventions
- One chapter per file: `docs/<area>/<NN>-<slug>.md` where NN is the chapter number from the table below (two digits).
- File starts with YAML front matter:
  ```
  ---
  title: "บทที่ NN — <ชื่อบท>"
  chapter: NN
  part: "<Part name>"
  status: VERIFIED|PARTIAL|...   # overall status of what the chapter describes
  ---
  ```
  then `# บทที่ NN — <ชื่อบท>`; sections `## NN.1 …`, `### NN.1.1 …`.
- Mark status per component/feature inline: `**สถานะ:** VERIFIED` (or in a table column).
- End every chapter with `## แหล่งอ้างอิง (Evidence)` listing the files/commands you used.
- Diagrams: Mermaid. Put the source in `docs/diagrams/<DD>-<slug>.mmd` (DD = diagram number below) AND embed the same code in the chapter as a fenced code block with language `mermaid`, with a caption line right after: `*รูปที่ DD — <caption>*`. Keep node labels short (ASCII or Thai), avoid characters that break Mermaid (`"` inside labels, `()` in unquoted labels → quote labels with `["..."]`). Validate syntax mentally: flowchart/sequenceDiagram/erDiagram only.
- Traceability: write `docs/_traceability/<area>.md` — a table `| Claim | Evidence (file:line or command) | Status |` with 15–40 of your most important claims.
- Facts: write `docs/_facts/<area>.md` — bullet list of component facts (name, type, purpose, status, where it runs, deps, ports, config source, source files, runtime evidence, limitations) for the SYSTEM_FACTS merge.

## Chapter map (numbers are fixed)
Part I Introduction: 01 Overview · 02 Capabilities · 03 Technology stack  (lead)
Part II Infrastructure: 04 Infrastructure overview · 05 Machine & node inventory · 06 Container architecture · 07 Network architecture  (lead)
Part III Backend: 08 Backend overview · 09 Directory structure · 10 API architecture (+ `docs/reference/api-reference.md` generated from the routers) · 11 AuthN/AuthZ · 12 Multi-tenant · 13 Database (+ `docs/reference/database-reference.md`)  (backend)
Part III cont.: 14 Logging · 15 Alerting · 16 ML · 17 Deception layer  (pipeline)
Part IV WAF: 18 Nginx · 19 ModSecurity · 20 OWASP CRS · 21 WAF decision flow  (wafcdn)
Part V CDN: 22 CDN architecture · 23 Edge nodes · 24 Caching · 25 Origin · 26 TLS  (wafcdn)
Part VI Frontend: 27 React architecture · 28 Navigation · 29 Login · 30 Dashboard · 31 Security logs · 32 Rule management · 33 Alerts · 34 Site/tenant management · 35 Users & permissions  (frontend)
Part VII Data flows: `docs/workflows/flow-a-normal.md` … `flow-g-cdn.md` (A normal, B blocked, C challenge, D deception, E logging, F ML, G CDN)  (pipeline)
Part VIII Operations: 36–50 (prereqs, env config, start, stop/restart, health checks, log inspection, DB ops, WAF rule ops, CDN cache ops, cache purge, TLS mgmt, backup/restore, updating, rollback, troubleshooting)  (ops)
Part IX Testing: `docs/testing/51-testing.md` (unit, integration, frontend, WAF, CDN, E2E)  (ops)

## Diagram map (numbers are fixed)
01 system-context · 02 high-level · 03 vps-infrastructure · 04 container-deployment · 05 network-topology (lead)
06 backend-components · 08 database-er (backend) · 07 frontend-components (frontend)
09 seq-normal · 10 seq-blocked · 11 seq-challenge · 12 seq-deception · 13 logging-flow · 14 ml-flow · 15 rule-recommendation · 20 end-to-end (pipeline)
16 cdn-cache-hit · 17 cdn-cache-miss · 18 cache-purge · 19 dns-tls (wafcdn)

## Known facts you can rely on (verified this session)
- Public entry: DNS → edge nodes (edge-th 45.154.26.91, edge-asia 57.158.25.236) running Caddy (TLS, on-demand certs) → cdn-edge-node (nginx + ModSecurity CRS 3.3.10, PL1, inbound threshold 10) → Main waf-nginx :8080 (ModSecurity CRS) → origin via FRP tunnel (`frp_tunnel_router`) / CloudWAF tunnel / direct site routes. Main also has its own Caddy on 80/443.
- Deception: ModSecurity rules 9000000/9000001 (`modsecurity/custom-rules/custom-deceive.conf`, phase 1, deny status 418) → nginx `error_page 418 = @deception` → FastAPI `/api/deception/respond` (internal key) → synthetic body, no-store. Edges forward 418 to Main (`@deception_via_main`). Origin not contacted. Real LFI/SQLi payloads are still blocked by CRS 949110 with 403 (deception only triggers for DECEIVE rules).
- Data: ClickHouse `default.access_logs`, `default.security_audit_logs`; DynamoDB tables `waf_users`, `waf_origins`, `waf_domains`, `waf_alerts_v2` (+ legacy `waf_alerts`), `waf_logs`, `waf_rules`, `waf_pending_rules`, `waf_threat_patterns`, `waf_status_history`, `waf_audit_log`, `waf_postmortems`, `waf_ssl_certs`; Redis; SQLite files in `dashboard/backend/data/`. Confirm details in code.
- Known open issues to mention where relevant (as limitations, not secrets): backend port 8000 reachable from the Internet (bypasses WAF); edge adds `Cache-Control: public` on responses that set cookies; deception SQLi template chosen by argument heuristics; client IP of edge traffic logged as the edge IP on Main.
