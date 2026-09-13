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
- Authoritative `--checks` list from `ferret-scan --help checks` (20 checks + `all`):
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
- Commit: _(recorded on next push)_
