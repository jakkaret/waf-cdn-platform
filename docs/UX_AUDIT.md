# UX Audit — WAF/CDN Security Dashboard

Date: 2026-09-22. Scope: `dashboard/frontend` (React 18 + TypeScript + Vite + Tailwind, TanStack Query, Zustand, Recharts). Baseline commit: `057e1ee` (backup branch `ui-redesign-backup-20260922-1339`).

## 1. Route inventory (33 real routes, from `App.tsx`)

**Public (4):** `/login`, `/register`, `/oauth-success`, `/status`

**Core protected (16):** `/` (Dashboard), `/logs`, `/rules`, `/ip-rules`, `/rate-limits`, `/ml-rules`, `/alerts`, `/cdn`, `/tunnels`, `/origins`, `/origins/:id`, `/onboarding`, `/ml-analyst`, `/settings`, `/users` (admin-only)

**Concept/mockup (13):** `/concepts` and 12 sub-pages (`ai-rules`, `team`, `postmortem`, `ai-bots`, `cve-patch`, `supply-chain`, `api-guard`, `cost-shield`, `agentic-traffic`, `ai-firewall`, `deception`, `quantum-tls`, `risk-score`) — gated by `ConceptBanner`, frontend-only mockups, not real functionality. **Out of scope for this redesign** unless told otherwise: redesigning mockups that don't back real features would be wasted, confusing effort.

## 2. Existing design system — already substantial, not a blank slate

This is the single most important correction to the task brief: a real component library and token set already exist. The redesign is **audit + consistency + extension**, not "create a design system from nothing."

**Existing shared components** (`components/ui/`): `Badge`, `Button`, `Card`, `CodeBlock`, `ConfirmDialog`, **`Drawer`**, `EmptyState`, `FilterSelect`, `HealthDot`, `LoadingSpinner`, `Modal`, `Pagination`, `SearchInput`, `SeverityBadge`, `StatCard`, `StatusBadge`, `Table`, `ThemeToggle`.

**Existing tokens** (`tailwind.config.ts`): border-radius scale (xs–2xl), brand/cf/forti color palettes, card/glow shadow scale, `fade-in`/`pulse-subtle` keyframes, Inter (sans) + JetBrains Mono (mono) font stack. CSS custom properties (`--bg-surface`, `--text-primary`, `--bg-border`, etc.) are used pervasively across pages for light/dark theming — already a working semantic-color-variable system, not raw hex scattered everywhere.

**Finding — the Drawer component exists but is used nowhere.** `components/ui/Drawer.tsx` (34 lines) implements exactly what Section 2 of the brief asks for: right-side panel, backdrop with click-to-close, scrollable content, close button. `grep` across the entire `src/` tree finds zero imports of it. Every page that shows a detail view today uses either a full page navigation (Origins → `/origins/:id`) or an in-page `Modal`/centered-dialog pattern (Alerts: 16 references to `selectedAlert` state driving a modal; Logs: 10 references to `selectedLog`). **This is the highest-leverage single fix in this audit**: wiring the existing Drawer into Alerts/Logs/Rules/MLRules detail views delivers most of Section 2's ask without inventing new UI.

**Bug found in the unused Drawer:** it applies `className="... animate-slide-in-right"`, but no `slide-in-right` keyframe/animation is defined anywhere in `tailwind.config.ts` or any CSS file. As shipped, opening it would show no slide animation at all (Tailwind's JIT compiler won't generate a rule for an undefined animation name). Needs a keyframe added before first real use.

**Drawer gaps vs. the brief's requirements (Section 2):** no ESC-to-close, no body-scroll lock while open, no focus trap/return-focus-on-close, no `role="dialog"`/`aria-modal`/`aria-labelledby`. All four are real, concrete additions, not redesign — the shell (backdrop, panel, animation-once-fixed) is sound.

## 3. Detail-view pattern inconsistency (Section 2's core complaint, confirmed real)

| Page | Current detail pattern | Should be |
|---|---|---|
| Alerts.tsx | Centered `Modal`, `selectedAlert` state | Drawer |
| Logs.tsx | Centered modal, `selectedLog` state | Drawer |
| Rules.tsx | Inline edit form toggle, no separate detail | Drawer (edit form fits naturally) |
| MLRules.tsx | Inline expand/collapse per row (`expandedRuleIds`) | Keep inline expand for the review queue's compare-many workflow; a per-row drawer would remove the ability to scan multiple pending rules at once, which is the actual task this page supports |
| Origins.tsx → OriginDetail.tsx | Full page navigation, 7-tab page (Overview/Domains/WAF/SSL/Shield/Team/Postmortem) | Origins list row click → Drawer for **quick-glance** (status, IP, domain count, quick actions); "Open full management" stays a real page nav, because OriginDetail genuinely has 7 tabs of content (CAPTCHA config, SSL certs, team roles, postmortem reports) that do not fit a drawer and are not "detail," they're "manage this resource" — a dedicated page is the correct pattern here, not a violation of Section 2 |
| Users.tsx | (needs re-check during implementation; likely inline table, no detail view yet) | Drawer for per-user detail/role change |

**Judgment call, stated explicitly:** Section 2 says "ถ้าข้อมูลไม่จำเป็นต้องมี dedicated page" (if the data doesn't need a dedicated page) — OriginDetail's 7 tabs of real configuration (not read-only detail) is exactly the case that still warrants a page. Converting it to a drawer would cram destructive/multi-step config (delete domain, edit CAPTCHA rules, grant editor access) into a slide-out panel, which fights the brief's own instruction not to reduce friction on risk-bearing actions. Recommendation: **keep OriginDetail as a page**, add a lighter drawer for the Origins list's row-click "quick glance."

## 4. Action-button density (Section 6 concern, confirmed in specific files)

- **MLRules.tsx**: per-row action buttons already reasonably scoped (Approve/Reject + expand), but the bulk-action bar (`selectedRuleIds`) has a known bug (see the code-review commit `057e1ee`) where selection isn't pruned across tab/filter changes — worth fixing in the same pass as any interaction redesign here, not a separate task.
- **Alerts.tsx / Logs.tsx**: primarily read + filter + export; no row-level action sprawl found.
- **Rules.tsx**: Edit/Delete per row, reasonable (2 actions).
- No page found with the "5-10 buttons per row" anti-pattern the brief warns about — this seems to already be handled reasonably. Section 6's "Primary action + More menu" pattern is worth applying preemptively to MLRules' row actions (Approve/Reject/Expand/Copy SecRule = 4 visible controls) to reduce visual noise, but this is a polish item, not a fire.

## 5. Confirmation dialogs — already correctly risk-gated

`ConfirmDialog.tsx` exists and is used for origin delete/restore (confirmed in `OriginDetail.tsx` during tonight's other work: `isDeleteModalOpen`/`isRestoreModalOpen` with a typed confirmation dialog, `isDanger` prop). This already matches Section 1's explicit instruction not to reduce friction on destructive actions. **No changes recommended here** — don't touch working risk-gating to chase a click-count metric.

## 6. Dashboard — current state vs. Section 5's 7 questions

As of the code-review pass in commit `057e1ee` (same session, hours before this audit), Dashboard.tsx already answers most of Section 5's questions with **real** data (after removing several fabricated metrics found in that pass): total requests, blocked count, unique IPs, real average latency, a real per-node online/offline summary badge, a live traffic timeline chart. It does **not** currently have a single "what needs attention right now" surface — the closest is the Alerts KPI strip, but there's no unified "top thing to look at" element answering Section 5's question 3 ("อะไรต้องจัดการก่อน?"). **Recommended addition, not full rebuild:** a single "Needs Attention" panel (unresolved critical alerts count + pending ML rule review count + any offline node) above the KPI grid, Level 1 in the visual hierarchy the brief asks for.

## 7. Responsive — not yet audited

Not checked in this pass (would require the browser-driven QA phase, Section 11/Agent 5/6's job). Flagging as unknown, not "fine": Tailwind is used throughout with some `sm:`/`md:`/`lg:` breakpoints visible in already-reviewed pages (e.g., `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4`), suggesting *some* responsive intent exists, but sidebar-on-mobile, table-on-mobile, and drawer-on-mobile behavior are unverified.

## 8. Accessibility — not yet audited

Same status as responsive: unknown, needs the dedicated pass (Section 12/Agent 5). No `aria-*` attributes were observed in any file read during tonight's code-review pass, which is a signal (not proof) that this needs real attention, particularly: icon-only buttons (several observed, e.g. Rules.tsx's action icons) likely lack `aria-label`; the Drawer and Modal both need `role="dialog"` + `aria-modal="true"` + labelled-by wiring before first real use.

## 9. What this audit deliberately did not do

Per the brief's own Phase 1 instruction ("ห้ามแก้ code ในช่วง audit"), no code was changed in this pass beyond the two already-committed fixes referenced above (those happened in the prior, separate code-review task, not as part of this audit). Browser-driven inspection (Section 15's explicit ask to look at the real rendered app, not just source) was **not** performed in this pass — recommended as the first task for Agent 5 (Interaction/Accessibility) once implementation begins, to validate every judgment call in this document against the real rendered UI before committing to it.
