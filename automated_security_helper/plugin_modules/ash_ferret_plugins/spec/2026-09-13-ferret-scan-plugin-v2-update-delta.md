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
| A3 | Keep `API_KEY_OR_SECRET` enabled; suppress the 6 v2.4.5 FPs in the community config + document the policy | fix | ☑ | 35c5dbe |
| A4 | Adopt `--fail-on-incomplete` (new `fail_on_incomplete` option) + exit-code-3 handling | feature | ☑ | 2b0458c |
| A5 | Block-list additions: `preprocess_only`, `pre_commit_mode`, `list_profiles`; always `--quiet` | fix | ☑ | 12f28c0 |
| A5 | Block-list additions: `preprocess_only`, `pre_commit_mode`, `list_profiles`; always `--quiet` | fix | ☑ | 1d34b4f→ |
| A6 | Doc corrections: `--exclude` glob+substring semantics, empty-result `null`→`[]`, full check list, remove dead GenAI references | docs | ☑ | f55ef54 |

## Track B — Feature surfacing (after Track A)

| ID | Change | Type | Status | Commit |
|----|--------|------|--------|--------|
| B1 | `respect_gitignore` → `--respect-gitignore` (carried from old branch) | feature | ☐ | |
| B2 | `disable_ip_types` → `--disable-ip-types` (carried from old branch) | feature | ☐ | |
| B3 | `explain` → `--explain` (offline per-finding rationale) | feature | ☐ | |
| B4 | `validator_budget` → `--validator-budget` | feature | ☐ | |
| B5 | `max_live_bytes` → `--max-live-bytes` | feature | ☐ | |
| B6 | Document new detectors in README Available Checks (BANK_ACCOUNT, OTP, DOB, DRIVERS_LICENSE, MEDICAL_ID, VIN, CLOUD_RESOURCES, PHYSICAL_ADDRESS) | docs | ☐ | |

## Status summary (2026-09-13)

**Track A: COMPLETE (6 of 6).** A1, A2, A3, A4, A5, A6 all delivered, each pushed with the
ferret unit suite green (77 tests) and the pre-push validation script passing (10/10).
**Track B not started.**

## Design decisions recorded

- **DD-1 (API_KEY_OR_SECRET) — REVISED:** the original plan (disable the generic type in
  the bundled config) is **impossible** — ferret-scan honors `disabled_types` only for
  `intellectual_property`, not `secrets` (verified v2.4.5, analysis §9.5). Final policy:
  **keep the detector enabled** (so real secrets are still found) and manage its false
  positives with ASH suppressions (`rule_id: API_KEY_OR_SECRET`) + `exclude_patterns`.
  Six v2.4.5 FPs are suppressed in `.ash/.ash_community_plugins.yaml`; documented in
  DEVELOPMENT.md and README.md. Verified: `ash scan` → ferret PASSED, 0 actionable.
