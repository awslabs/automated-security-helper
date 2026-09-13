# Ferret-Scan Plugin v2 Update — Delta (Enhancements & Fixes)

**Date:** 2026-09-13
**Branch:** `feature/ferret-scan-plugin-v2-update`
**Companion docs:** `2026-09-13-ferret-scan-plugin-v2-update-analysis.md` (why),
`2026-09-13-ferret-scan-plugin-v2-update-worklog.md` (audit trail).

This is the running list of concrete changes shipped in this update. Status legend:
☐ planned · ◐ in progress · ☑ delivered (committed + pushed, tests green).

---

## Track A — Realignment + correctness

| ID | Change | Type | Status | Commit |
|----|--------|------|--------|--------|
| A1 | Version window → `>=2.4.5,<2.5.0`; `MIN=2.4.5`, `MAX=2.5.0`, `RECOMMENDED=2.4.5` | fix | ☑ | d1a3130 |
| A2 | Emit `--limit 0` by default (new `finding_limit` option) to stop silent 200-finding truncation | fix | ☑ | e1412f7 |
| A3 | ~~Disable `API_KEY_OR_SECRET` in bundled config~~ → **blocked: config knob doesn't exist** (see analysis §9.5). Recommended: plugin post-filter option, default-on. Awaiting decision. | fix | ⏸ | |
| A4 | Adopt `--fail-on-incomplete` (new `fail_on_incomplete` option) + exit-code-3 handling | feature | ☐ | |
| A5 | Block-list additions: `preprocess_only`, `pre_commit_mode`, `list_profiles` | fix | ☐ | |
| A6 | Doc corrections: `--exclude` glob+substring semantics, empty-result `null`→`[]`, full check list, remove dead GenAI references | docs | ☐ | |

## Track B — Feature surfacing (after Track A)

| ID | Change | Type | Status | Commit |
|----|--------|------|--------|--------|
| B1 | `respect_gitignore` → `--respect-gitignore` (carried from old branch) | feature | ☐ | |
| B2 | `disable_ip_types` → `--disable-ip-types` (carried from old branch) | feature | ☐ | |
| B3 | `explain` → `--explain` (offline per-finding rationale) | feature | ☐ | |
| B4 | `validator_budget` → `--validator-budget` | feature | ☐ | |
| B5 | `max_live_bytes` → `--max-live-bytes` | feature | ☐ | |
| B6 | Document new detectors in README Available Checks (BANK_ACCOUNT, OTP, DOB, DRIVERS_LICENSE, MEDICAL_ID, VIN, CLOUD_RESOURCES, PHYSICAL_ADDRESS) | docs | ☐ | |

## Design decisions recorded

- **DD-1 (API_KEY_OR_SECRET off):** The bundled config disables the generic
  `API_KEY_OR_SECRET` finding type because ferret-scan v2.3.3's unquoted-assignment
  detection flags ordinary typed code (e.g. `session: Optional[Session]`) at ~95% HIGH.
  Named secret patterns (AWS keys, GitHub tokens, etc.) remain active. Rationale and
  revert instructions live in DEVELOPMENT.md and README.md.
