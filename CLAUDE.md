# CLAUDE.md — waf_project (WAF + CDN)

Repo: github.com/jakkaret/waf_project, branch `Backend` (local branch name: `backend`).
Local checkout: `/Users/boss/project/waf_project`.

## Document scope

This file is agent context and safety guidance. Detailed topology, operations, and
known issues live in `docs/ARCHITECTURE.md`, `docs/OPERATIONS.md`, and
`docs/KNOWN_ISSUES.md`. The topology and issue register were last verified on
2026-08-26; verify them again before SSH, deployment, or incident work.

## Architecture and operations

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for topology and rule
synchronization. Read [docs/OPERATIONS.md](docs/OPERATIONS.md) before deploying,
reloading services, or relying on a test. Read
[docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) before diagnosing infrastructure.
These documents include verification dates; confirm runtime state before acting.

## Frontend stack

`dashboard/frontend` — React 18 + TypeScript + Vite, Tailwind CSS, Zustand (state), TanStack
Query (data fetching), Axios, Recharts (charts), react-hot-toast, Playwright for e2e
(`npm run test:e2e`). Match this stack/style for any dashboard UI work.

(`docs-ts/` is an unrelated separate docs site — React 19 + Vite + gh-pages — not part of the
dashboard, don't confuse the two.)

## Task priority

No fixed priority across Dashboard / ML pipeline / Infra — follow whatever's explicitly
requested in the moment, don't infer an ordering.

## User background

Comfortable with WAF concepts operationally: understands anomaly-score-based blocking
(unusual traffic vs baseline scores higher) and the false-positive debug loop (find the
offending log → identify which rule fired and why → narrow that rule's scope rather than
disable broadly). **Does not know ModSecurity syntax/internals** — phase 1-4 ordering,
`SecRuleUpdateTargetById`, `ctl:ruleRemoveById`, writing exclusion rules by hand. When writing
or explaining ModSecurity directives, briefly say what the directive does inline (not just cite
it by name) — don't assume familiarity with CRS-specific syntax, but no need to re-explain
paranoia level / anomaly scoring basics each time.

## Collaboration

Other people also work on this repo/VPS — **not solo**. Be careful with anything that rewrites
shared history or state: no force-push, no `git reset --hard` on shared branches, no assuming
your last SSH session's changes are still there untouched. Check `git log`/`git status` for
surprises before big operations rather than assuming a clean baseline.

Before editing anything risky on the main node (large rule changes, nginx config, data
migrations), make a simple copy first (`cp file file.bak.$(date +%s)` or similar) — doesn't need
to be a full system snapshot, just enough to revert the specific file/config fast if it breaks.

## Security findings during unrelated work

If you notice a security issue while working on something else (e.g. more open ports, another
committed secret), report it to the user and record it in the appropriate issue tracker or
`docs/KNOWN_ISSUES.md` after approval. Do not silently modify this file or hide the finding.
Do not re-flag issues already documented unless their status or impact has changed.

## Working agreement

- **Primary work areas:** Dashboard (frontend + backend), ML/anomaly-detection pipeline,
  infra/deploy/config management (nginx, ModSecurity CRS rules, systemd services, docker
  compose).
- **Edit flow:** local repo is source of truth. Make changes in
  `/Users/boss/project/waf_project`, commit, then deploy/sync to the VPS via the existing
  scripts (`scripts/sync_waf_rules.py`, `docker cp`, `scp`, etc.). Reserve direct SSH edits on
  a node for urgent hotfix/debug only (e.g. an active false-positive block, a broken prod
  service) — and when you do that, backport the change into the local repo afterward so a node
  never becomes its own untracked source of truth (this is exactly how Known Issue #1
  happened — don't repeat it).
- **Deploy trust:** allowed to SSH into any of the 3 nodes and run/reload for clearly-scoped,
  requested work (rule sync, service restart, config reload, log inspection) without asking
  permission each time.
  - Edge node (45.154.26.91): freer to act — lower blast radius.
  - Main node (178.104.53.123): origin + control plane + the only copy of ClickHouse analytics
    data. Still fine to act on clear instructions, but be more careful — this is the one that
    matters if something goes wrong.
  - Lab node (10.198.200.75): not part of the git repo, treat as disposable test infra — but
    it's shared, so don't nuke other people's running containers/scripts without asking.
  - Still always confirm before anything destructive/hard-to-reverse regardless of node:
    dropping data, `docker system prune`, force-recreating volumes, deleting rules, rotating
    tokens, touching `waf-redis`/`waf-clickhouse` data, or changing ufw/firewall rules.
- **Commits:** commit as you go, by default — after each logically-complete unit of work, not
  just when asked. This is for revert safety (user wants a clean history to roll back to), so
  keep commits scoped to one logical change each rather than bundling unrelated files together
  (if the working tree has unrelated pre-existing changes sitting around, leave those out and
  flag them separately rather than sweeping them into an unrelated commit — this bit us once,
  see git log around 2026-08-26 for the reset+re-split). Conventional Commits prefix in English
  (`feat:`, `fix:`, `refactor:`, ...), details/body in Thai — matches existing repo convention.
- **Push:** OK to `git push` to `origin/Backend` directly when explicitly asked to ship
  something — no need to stop and ask "should I push" every time once the user has said to do
  it.

## Credentials / access on file (for reference, not to be echoed elsewhere)

- Edge: root@45.154.26.91 — cdn-edge-node, cdn-caddy-ssl, cdn-log-forwarder (key-based SSH)
- Main: root@178.104.53.123 — waf-nginx, waf-control-api (:8070), waf-redis, waf-clickhouse,
  dvwa, waf-dashboard (:8000, systemd), waf-ml (:5000, systemd), waf-log-analyzer (systemd),
  frps (:7000/:7500/:8085) (key-based SSH)
- Lab: project@10.198.200.75, password `project`, password-only SSH (no key configured, no
  passwordless sudo) — see the `expect` snippet in Architecture above
- CONTROL_TOKEN and frps admin creds live in `docker-compose.yml` / `/etc/frp/frps.toml` on the
  main node — see Known Issues #2, do not duplicate them into new files. frpc token on the lab
  node (`/etc/waf-agent/frpc.toml`) is the same shared token.
