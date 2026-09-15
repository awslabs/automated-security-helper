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
| A6 | Doc corrections: `--exclude` glob+substring semantics, empty-result `null`→`[]`, full check list, remove dead GenAI references | docs | ☑ | f55ef54 |

## Track B — Feature surfacing (after Track A)

| ID | Change | Type | Status | Commit |
|----|--------|------|--------|--------|
| B1 | `respect_gitignore` → `--respect-gitignore` (carried from old branch) | feature | ☑ | 151661a |
| B2 | `disable_ip_types` → `--disable-ip-types` (carried from old branch) | feature | ☑ | 151661a |
| B3 | `explain` → `--explain` (offline per-finding rationale) | feature | ☑ | 151661a |
| B4 | `validator_budget` → `--validator-budget` | feature | ☑ | 151661a |
| B5 | `max_live_bytes` → `--max-live-bytes` | feature | ☑ | 151661a |
| B6 | Document new detectors in README Available Checks | docs | ☑ | f55ef54 (done in A6) |

## Track C — Review-driven fixes (post Track A/B)

| ID | Change | Type | Status | Commit |
|----|--------|------|--------|--------|
| C1 | Dedupe DEVELOPMENT `### Suppression Strategy`; narrow the `API_KEY_OR_SECRET` test suppression `tests/**`→`tests/unit/cli/mcp/test_sessions.py`; `success_exit_codes` `{0,1,3}`→`{0,3}` (ferret uses exit 1 for errors); fix stale analysis numbers (`20`→`19` checks, drop `KEYWORD_MATCH`, `77`→`79`) + duplicate A5 delta row | fix | ☑ | 5a62dec |
| C2 | Correct DEVELOPMENT §10 — bundled config does NOT override CLI `--exclude`/`--recursive` (verified v2.4.5, CLI wins); fix README + registration `use_default_config` notes; **remove** the false-premise `CONFIG-OVERRIDE-EXCLUDES` validation check (now 9 checks); analysis §9.6 + §5.6 corrections | fix | ☑ | e789825 |
| C3 | Remove duplicated `use_default_config` blockquote heading in DEVELOPMENT.md | docs | ☑ | 4db2163 |
| C4 | Update the public docs page `docs/content/docs/plugins/community/ferret-scan-plugin.md` — versions `2.4.5`, all new options, 19-check list, `API_KEY_OR_SECRET` FP note | docs | ☑ | af5c92e |

## Status summary

**Track A: COMPLETE (6 of 6).** A1–A6 delivered.
**Track B: COMPLETE (6 of 6).** B1–B5 opt-in options; B6 folded into A6.
**Track C: review fixes C1–C4 delivered.**
Current gates: **79 unit tests green**, pre-push validation **9/9** (was 10 before the
false-premise check was removed in C2), `ash config validate` valid, ferret self-scan
**PASSED / 0 actionable**. Each item above was committed and pushed individually; small
audit-sync commits backfill the self-referential SHAs.

## Net files changed vs `main` (full state of the branch)

Every file the branch changes relative to `main`, mapped to the delta items that touched
it. (Diffstat as of `7523ca4`; the three `spec/*.md` docs are the tracking artifacts
themselves. Line counts are approximate and drift with later commits.)

| File | ~Δ | Delta items |
|------|----|-------------|
| `automated_security_helper/plugin_modules/ash_ferret_plugins/ferret_scanner.py` | +159 | A1, A2, A4, A5, B1–B5, C1 |
| `tests/unit/plugin_modules/ash_ferret_plugins/test_ferret_scanner.py` | +142 | A1, A2, A4, A5, B, C1 |
| `automated_security_helper/plugin_modules/ash_ferret_plugins/DEVELOPMENT.md` | +206 | A1, A3, A5, A6, B, C1, C2, C3 |
| `automated_security_helper/plugin_modules/ash_ferret_plugins/README.md` | +80 | A1, A2, A3, A5, A6, B, C2 |
| `.ash/.ash_community_plugins.yaml` | +51 | A3, C1 |
| `scripts/validate_ferret_plugin.py` | −/+50 | C2 (removed `CONFIG-OVERRIDE-EXCLUDES`) |
| `docs/content/docs/plugins/community/ferret-scan-plugin.md` | +61 | C4 |
| `automated_security_helper/plugin_modules/ash_ferret_plugins/spec/…-analysis.md` | +397 | tracking artifact (why) |
| `automated_security_helper/plugin_modules/ash_ferret_plugins/spec/…-worklog.md` | +211 | tracking artifact (audit) |
| `automated_security_helper/plugin_modules/ash_ferret_plugins/spec/…-delta.md` | +62 | tracking artifact (this file) |

Total: **10 files, ~+1313 / −106**. All non-spec files above are shippable changes; the
three `spec/*.md` files are documentation of the change itself. No source/config/doc file
on the branch is unaccounted for by an A/B/C item.

## Design decisions recorded

- **DD-1 (API_KEY_OR_SECRET) — REVISED:** the original plan (disable the generic type in
  the bundled config) is **impossible** — ferret-scan honors `disabled_types` only for
  `intellectual_property`, not `secrets` (verified v2.4.5, analysis §9.5). Final policy:
  **keep the detector enabled** (so real secrets are still found) and manage its false
  positives with ASH suppressions (`rule_id: API_KEY_OR_SECRET`) + `exclude_patterns`.
  Six v2.4.5 FPs are suppressed in `.ash/.ash_community_plugins.yaml`; documented in
  DEVELOPMENT.md and README.md. Verified: `ash scan` → ferret PASSED, 0 actionable.
