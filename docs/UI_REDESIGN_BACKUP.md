# UI Redesign — Backup Record

- Backup branch: `ui-redesign-backup-20260922-1339`
- Baseline commit: `057e1ee` (last commit before this redesign work began — the code-review bug-fix pass)
- Created: 2026-09-22, on `Backend` branch, no checkout performed (pointer branch only)

## Rollback

If anything from this redesign needs to be fully reverted:

```bash
git reset --hard ui-redesign-backup-20260922-1339
```

Confirm with user before running — this discards any commits made after the backup point. Prefer reverting individual milestone commits (`git revert <sha>`) over a hard reset when only one phase needs undoing.

## Milestone commits (filled in as work lands)

- `docs: UI/UX redesign audit, plan, and backup record` — `aa35135`
- `docs: browser-verified audit findings -- mobile sidebar bug, CRS version mismatch` — `982fe08`
- `ui: establish design system fixes + responsive mobile shell` (Drawer a11y/ESC/scroll-lock/focus-trap, mobile off-canvas nav, nav regroup, CRS version fix) — `6c23972`
- `docs: update redesign milestone log` — `f4c8fe0`
- `ui: redesign authentication -- surface security context on mobile` — `fbd264f`
- `ui: dashboard Needs Attention panel` — `a6ff038`
- `fix: prune selectedRuleIds when a rule is no longer pending` — `bc2441d`
- `ui: wire Drawer into Alerts/Logs/Rules detail views` — **blocked**: needs origin-scoped data (viewer test account has none granted yet) or admin role to interactively verify a Modal→Drawer swap on live data; not shipped unverified
- `ui: add Origins quick-glance drawer` — blocked, same reason
- `ui: MLRules action menu (Approve/Reject/Expand/Copy -> primary + overflow)` — not started, lower priority polish item
- `test: frontend regression` — pending final pass once the above unblock
