# Managed ruleset (central rules)

Rules in this directory are the platform's central, managed ruleset — the
equivalent of a provider-managed ruleset. Nobody edits them from the dashboard.
They change only through a reviewed commit to this directory; the backend's
updater (`services/managed_ruleset.py`) notices the change on its next cycle,
publishes a new **version**, and every origin either follows it automatically
(`auto`) or stays on its pinned version until one of its Admins presses
"Update" (`manual`).

Rules for authors:

- IDs must be in **3000000–3099999** and unique.
- A published rule is **immutable**. To change one, add a rule with a new ID
  and delete the old one; the old ID is kept for origins still pinned to a
  version that had it, and is switched off for everyone else.
- Only detection and a disruptive action are allowed. No `ctl:`,
  `SecRuleEngine`, `SecAction`, `exec:`, file/network operators — the updater
  rejects the whole change if it finds one.
- Prefer precise signatures (a specific CVE payload shape) over broad
  patterns; these rules deny immediately, they do not add anomaly score.
