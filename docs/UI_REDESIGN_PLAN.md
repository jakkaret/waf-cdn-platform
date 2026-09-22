# UI/UX Redesign Plan

Scope decided from `docs/UX_AUDIT.md`'s real findings, not the brief's assumed blank-slate state. Backup branch: `ui-redesign-backup-20260922-1339` (pointer at `057e1ee`). Rollback: `git reset --hard ui-redesign-backup-20260922-1339` (only if something breaks mid-work — confirm with user first, per standing git-safety rule).

## Why this plan differs from a from-scratch redesign

The audit found a working design system (17 shared components, token set, CSS-variable theming) and a built-but-unused `Drawer` component that already implements the brief's Section 2 ask. Rebuilding either from zero would be wasted work and real regression risk on a production system serving live student traffic. This plan is **extend + wire up + fix concrete gaps**, phased to match the brief's own 10-phase order.

## Phase 3 — Design System (foundation before any page work)

1. Fix `Drawer.tsx`: add `slide-in-right` keyframe to `tailwind.config.ts` (currently referenced, never defined — dead animation). Add ESC-to-close, body-scroll-lock while open, focus trap + return-focus-on-close, `role="dialog"` + `aria-modal="true"` + `aria-labelledby`.
2. No new color/spacing/shadow tokens needed — existing scale covers redesign needs. Add only if a specific page surfaces a real gap during implementation.
3. Add a `Menu`/`DropdownMenu` primitive if none exists (needed for Table UX "More actions" pattern in Phase 7) — check first, don't duplicate if `FilterSelect` or similar already covers it.

## Phase 4 — Core Layout

No structural change indicated by the audit — `AppLayout`/`Sidebar`/`TopBar` not yet flagged with concrete problems. Inspect during implementation (not yet read this pass); only touch if a real issue surfaces. Navigation reorganization by user mental model (brief Section 4) deferred until Sidebar's current structure is confirmed against actual usage patterns — premature to restructure nav without seeing real current groupings first.

## Phase 5 — Authentication (Login/Register)

Real bug already found and fixed this session in `Register.tsx` (token-reset-on-error race, commit `057e1ee`) — functionally sound. Visual redesign here is pure polish; low priority relative to Phase 6-7's real UX debt. Must not touch auth logic, OAuth flow, or hardcode any credential — reuse existing `authStore`/`api/auth.ts` untouched.

## Phase 6 — Dashboard

Add one new "Needs Attention" panel (real data: unresolved critical alert count, pending ML-rule-review count, any offline node) above the existing KPI grid — answers the brief's Section 5 Q3 ("what needs handling first"), the one real gap found. Do not rebuild the rest of the page — it already uses real data after the `057e1ee` fabricated-metric cleanup.

## Phase 7 — Application Pages (the real work)

Priority order by audit-confirmed impact:
1. **Alerts.tsx**: replace centered `Modal` detail view with `Drawer`.
2. **Logs.tsx**: replace centered modal detail view with `Drawer`.
3. **Rules.tsx**: convert inline edit-form toggle to `Drawer`.
4. **Origins.tsx**: add row-click `Drawer` for quick-glance (status/IP/domain count); keep `/origins/:id` full page for actual management (7 tabs, destructive actions — audit's explicit judgment call, not a page-count violation).
5. **MLRules.tsx**: keep inline expand (multi-row compare is the real workflow); apply "primary action + More menu" only to reduce the 4 visible per-row controls (Approve/Reject/Expand/Copy) to fewer visible + overflow menu. Fix the pre-existing `selectedRuleIds`-not-pruned-on-filter-change bug in the same pass (already documented, not yet fixed).
6. **Users.tsx**: confirm current detail pattern (unchecked in audit), add Drawer if a centered-modal/full-page pattern is found.

## Phase 8 — Interaction Pass

Hover states, tooltips, keyboard nav — applied to whichever components changed in Phase 7, not a separate full-app sweep. Loading/error/empty states: confirmed `LoadingSpinner`/`EmptyState`/`ErrorBoundary` already exist — verify consistent usage during Phase 7, don't rebuild.

## Phase 9 — Responsive + Accessibility

Not yet audited (flagged explicitly in `UX_AUDIT.md` §7-8) — first real task here is browser-driven inspection (brief Section 15's ask), not assumption-based fixes. Add `aria-label` to icon-only buttons found in Phase 7 files as they're touched; full a11y sweep of untouched pages is out of scope for this pass unless time allows.

## Phase 10 — QA

Regression check against the Definition of Done: every existing route still resolves, no API contract change, `tsc -b` clean, vitest suite green, smoke test 24/24, manual click-through of the 5 converted pages before calling anything done.

## Explicit non-goals this pass

- Concept/mockup pages (`/concepts/*`) — not real functionality, redesigning them is wasted effort per audit §1.
- Full nav restructure — no evidence yet it's actually confusing; premature without current-usage data.
- New third-party UI libraries — existing component set covers every need identified.
- Any backend/API change — this is a frontend presentation-layer pass only.
