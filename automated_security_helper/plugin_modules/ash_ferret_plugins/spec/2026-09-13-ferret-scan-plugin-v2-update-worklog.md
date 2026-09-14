# Ferret-Scan Plugin v2 Update — Work Log / Audit Trail

**Date started:** 2026-09-13
**Branch:** `feature/ferret-scan-plugin-v2-update`
**Purpose:** Chronological audit of every change made while executing the update, so a
future maintainer can reconstruct what happened and why if something breaks.

Format: newest entries at the bottom. Each entry records the work item, what changed,
verification run, result, and the pushed commit SHA.

---

## Environment baseline (2026-09-13)

- `ferret-scan` installed: **v2.4.5** (commit 71b171e, go1.27.1, linux/amd64), via mise shim.
- `uv`, `python3` available.
- Authoritative `--checks` list from `ferret-scan --help checks` (19 checks + `all`):
  `BANK_ACCOUNT, CLOUD_RESOURCES, CREDIT_CARD, DATE_OF_BIRTH, DRIVERS_LICENSE, EMAIL,
  INTELLECTUAL_PROPERTY, IP_ADDRESS, MEDICAL_ID, METADATA, OTP, PASSPORT, PERSON_NAME,
  PHONE, PHYSICAL_ADDRESS, SECRETS, SOCIAL_MEDIA, SSN, VIN`.
- `--limit` default confirmed **200** (`0` = unlimited).
- `--fail-on-incomplete` confirmed: exit **3** on partial coverage.
- Baseline ferret plugin unit tests: **69 passed** (`uv run pytest
  tests/unit/plugin_modules/ash_ferret_plugins/ -q --no-cov -n 0`).
- `scripts/validate_ferret_plugin.py` → `EXPECTED_MIN_TESTS = 67` (below the 69 present).

## Decisions locked (from requester, 2026-09-13)

1. **Version window:** pin conservatively to the tested current line → `>=2.4.5,<2.5.0`.
2. **Scope:** Track A first, then Track B.
3. **Old branch:** start fresh from `main`; mine `origin/feature/ferret-scan-plugin-updates`
   for anything worth carrying (see analysis §9).
4. **API_KEY_OR_SECRET:** disable the generic type globally in the bundled config;
   document as an explicit design decision in DEVELOPMENT.md and README.md.
5. **`--fail-on-incomplete`:** adopt it.

---

## Log entries

### WL-0 — Setup & tracking docs (2026-09-13)
- Created this work log and the delta document.
- Updated analysis doc: recorded locked decisions (§8), added old-branch carry-over
  analysis (§9), refreshed posture notes (baseline 69 tests, ferret-scan 2.4.5 verified,
  `--limit`/exclude semantics confirmed against the installed binary).
- Verification: docs-only change; ferret unit suite still **69 passed**.
- Commit: `921f1cb`

### WL-1 — A1: version window pin (2026-09-13)
- `ferret_scanner.py`: `MIN_SUPPORTED_VERSION 0.1.0→2.4.5`, `MAX 2.0.0→2.5.0`,
  `DEFAULT_VERSION_CONSTRAINT ">=0.1.0,<2.0.0"→">=2.4.5,<2.5.0"`, `RECOMMENDED 1.0.0→2.4.5`.
- Tests: updated `test_check_version_compatibility_compatible` (1.0.0→2.4.5) and
  `test_installation_command_applies_the_declared_constraint` (asserts `2.4.5 in specifier`,
  `2.3.3 not in`; docstring updated to explain the conservative pin).
- Docs: README install line + `tool_version` examples; DEVELOPMENT.md constants block and
  options-table default.
- Verification: **69 passed**; `validate_ferret_plugin.py` **all 10 checks passed**.
- Commit: `d1a3130`

### WL-2 — A2: `--limit 0` (stop silent truncation) (2026-09-13)
- `ferret_scanner.py`: added `finding_limit: int = 0` (ge=0) option; `_process_config_options`
  now always appends `--limit <finding_limit>` (default 0 = unlimited). ferret-scan's own
  default is 200, which silently drops findings on large scans.
- Tests: `test_finding_limit_default_is_unlimited`, `test_finding_limit_custom_value` (71 total).
- Docs: README + DEVELOPMENT option tables.
- Verification: **71 passed**; validation **all 10 checks passed**.
- Commit: `e1412f7`

### WL-3 — A3 investigation: API_KEY_OR_SECRET disable is NOT config-driven (2026-09-13)
- Verified against installed ferret-scan v2.4.5 that `validators.secrets.disabled_types`
  is silently ignored (only `intellectual_property` honors `disabled_types`).
- Reproduced the incident FP in v2.4.5: `session: Optional[Session] = None` →
  `API_KEY_OR_SECRET` @ 93 HIGH (see analysis §9.5 for full evidence).
- **A3 paused** — the requester's chosen mechanism (bundled-config disable) is impossible.
  Recorded the invalidated assumption in analysis §9.5 and surfaced a mechanism decision to
  the requester. No code change to the plugin yet.
- Verification: docs-only; **71 passed**.
- Commit: `1d34b4f`

### WL-4 — A5: block-list additions + always `--quiet` (2026-09-13)
- `ferret_scanner.py`: added `preprocess_only`, `pre_commit_mode`, `list_profiles` to
  `UNSUPPORTED_FERRET_OPTIONS`; `_process_config_options` now always appends `--quiet`
  (carried from old-branch analysis §9.3).
- Tests: 3 new unsupported-option tests (74 total).
- Docs: README unsupported-options table; DEVELOPMENT categories table + hardcoded-flags
  table (`--quiet`).
- Verification: **74 passed**.
- Commit: `12f28c0`

### WL-5 — A4: adopt `--fail-on-incomplete` (2026-09-13)
- Verified against v2.4.5: an incomplete scan (forced via `--validator-budget all=1ns`)
  exits **3** and still writes valid SARIF.
- `ferret_scanner.py`: new `fail_on_incomplete: bool = False` option → emits
  `--fail-on-incomplete`; `success_exit_codes` overridden to `{0, 1, 3}` (added `Set`
  import); `scan()` logs a WARNING when `exit_code == 3`. Invocation records
  `executionSuccessful=False, exitCode=3`; partial SARIF still returned.
- Tests: `test_fail_on_incomplete_default_off`, `test_fail_on_incomplete_when_enabled`,
  `test_incomplete_exit_code_is_accepted` (77 total).
- Docs: README + DEVELOPMENT option tables; new "Exit codes and --fail-on-incomplete"
  subsection in the Scanner Return Contract.
- Verification: **77 passed**.
- Commit: `2b0458c` (amended to use builtin `set[int]` — avoided introducing 2 new ruff
  `UP006/UP035` findings; file stays at its pre-existing 21, same as `origin/main`).

### WL-6 — A6: doc corrections (2026-09-13)
- Corrected `--exclude` semantics in README + DEVELOPMENT (×2) + the EXCLUDE-GLOB-SYNTAX
  check description: it is `filepath.Match` glob (`*`,`?`,`[..]`; no `**`) **plus** a
  substring fallback — not "simple names, not globs". Verified against `cmd/main.go`.
- Corrected the empty-results note: current ferret-scan emits `results: []`, not `null`
  (verified against v2.4.5); `SarifReport.model_validate` accepts both.
- Expanded README "Available Checks" from 11 to the full 19 (v2.4.5) with a
  "use `ferret-scan --help checks`, don't hardcode" note; updated the `checks` field
  description in `ferret_scanner.py` to match.
- No GenAI references exist in the plugin README/DEVELOPMENT (only harmless comments in
  the bundled `ferret-config.yaml`); left those, noted for a later config refresh.
- Verification: **77 passed**; validation **all 10 checks passed**; ruff unchanged (21).
- Commit: `f55ef54` (this doc-sync of SHAs follows in the next commit).

### WL-7 — A3 resolved: keep API_KEY_OR_SECRET + suppress/exclude (2026-09-13)
- Requester decision: keep the detector enabled, manage FPs via suppressions/excludes.
- Enumerated the real hits at v2.4.5 (`SECRETS`, high confidence): 6 API_KEY_OR_SECRET
  FPs — `schemas/ocsf/ocsf_vulnerability_finding.py` (×2, generated), `cli/mcp/sessions.py`,
  `deploy/terraform/modules/fargate/main.tf`, `tests/unit/cli/mcp/test_sessions.py` (×2).
- `.ash/.ash_community_plugins.yaml`: added 4 path-scoped `API_KEY_OR_SECRET` suppressions
  (OCSF file, sessions.py, fargate main.tf, `tests/**`) with paraphrased reasons (so the
  YAML doesn't self-trigger); corrected the stale "ferret-scan contributes nothing" comment.
- Docs: DEVELOPMENT.md design-decision section + README.md user note & suppression recipe;
  clarified that ferret-only rules live in the community config (ferret isn't enabled in
  `.ash.yaml`).
- Verified: `ash scan --scanners ferret-scan` → **PASSED, 0 actionable** (8 suppressed);
  77 unit tests; validation 10/10; `ash config validate` valid; 0 self-findings in new text.
- Commit: `35c5dbe`

### WL-8 — Expand API_KEY_OR_SECRET documentation (2026-09-13)
- DEVELOPMENT.md "Design decision" section expanded into a full decision record:
  an **Alternatives considered** table (option 1 disable-in-config = not viable with
  empirical proof; option 2 plugin post-filter = rejected; option 3 keep+suppress =
  chosen), an explicit **why option 1 isn't viable** proof block (docs + source + a
  reproduced before/after scan), a **suppression behaviour** explanation (ASH suppresses
  at aggregation; findings are recorded-not-hidden), the **FP inventory** table, and a
  **verification** paragraph.
- Paraphrased the proof block so it does not quote the triggering line (which would make
  DEVELOPMENT.md itself a finding — the documented gotcha).
- Verified: 0 self-findings on the edited docs; 77 unit tests; validation 10/10.
- Commit: `2341ce6`

### WL-9 — Track B: surface v2.4.5 flags as opt-in options (2026-09-14)
- Pre-checked each flag against the installed binary: `--explain`, `--validator-budget`,
  `--max-live-bytes`, `--respect-gitignore`, `--disable-ip-types` all accepted and produce
  valid SARIF.
- `ferret_scanner.py`: added 5 opt-in options — `respect_gitignore` (bool),
  `disable_ip_types` (str), `explain` (bool), `validator_budget` (str), `max_live_bytes`
  (str), all default off/None; `_process_config_options` emits the matching flags when set.
- Tests: `test_track_b_options_default_off`, `test_track_b_options_emitted_when_set` (79 total).
- Docs: README + DEVELOPMENT option tables. B6 (new-detector docs) was already delivered in
  A6, so no separate change.
- Verification: **79 passed**; validation **10/10**; ruff unchanged (21).
- Commit: `151661a`

### WL-10 — Review fixes (2026-09-14)
Addressed a code review of the branch:
- **Defect 1 (real):** DEVELOPMENT.md had the entire `### Suppression Strategy` heading +
  paragraph duplicated verbatim (an artifact of the A3/WL-8 edit). Collapsed to one copy.
- **Defect 2 (audit):** delta had a duplicated A5 row mis-attributed to `1d34b4f→` (which
  is actually the "API_KEY_OR_SECRET cannot be disabled via config" docs commit). Removed
  the duplicate; A5 = `12f28c0`.
- **Defect 3 (cosmetic):** analysis prose drift — `20 checks`→`19`, removed `KEYWORD_MATCH`
  (it is an internal validator, not a `--checks` value), `77 green`→`79`. Same 20→19 fix in
  this work log's baseline. Shipped README/tests were already correct.
- **DP1 (hardening):** narrowed the `API_KEY_OR_SECRET` test suppression from `tests/**` to
  the one real FP file `tests/unit/cli/mcp/test_sessions.py`, so a real credential added to
  another test later is not silently suppressed.
- **DP3 (correctness):** `success_exit_codes` narrowed `{0,1,3}`→`{0,3}`. ferret-scan uses
  `os.Exit(1)` for genuine errors (many call sites), so 1 must surface as a failure.
- **DP2 (documented):** left the community-only suppression placement (verified correct —
  ferret isn't enabled in `.ash.yaml`) but strengthened the DEVELOPMENT "Exception" note to
  flag it as load-bearing.
- Verification: **79 passed**; validation **10/10**; ruff unchanged (21); `ash scan
  --scanners ferret-scan` still **PASSED, 0 actionable**; `ash config validate` valid.
- Commit: _(recorded on next push)_
