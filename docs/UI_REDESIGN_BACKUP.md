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

- `ui: fix Drawer component (animation, ESC, scroll-lock, focus trap, a11y)` — pending
- `ui: wire Drawer into Alerts/Logs/Rules detail views` — pending
- `ui: add Origins quick-glance drawer` — pending
- `ui: dashboard Needs Attention panel` — pending
- `ui: MLRules action menu + selection-pruning fix` — pending
