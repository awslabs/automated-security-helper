## composer_audit: alpha scanner for known-vulnerable and abandoned PHP dependencies

Adds `composer_audit`, an opt-in (alpha) scanner plugin module, `ash_composer_audit_plugins`. It runs `composer audit --locked --format=json --abandoned=report --no-plugins --no-scripts` once per `composer.lock` in the scan target and turns each Packagist advisory into a finding on the package's line in the lock file. Abandoned packages become LOW findings (rule `COMPOSER-ABANDONED`).

### Tier and posture

- Tier: alpha, community opt-in. It runs only when the module is listed in `ash_plugin_modules`.
- License posture: no license or service gate. Composer is a system tool (with PHP) that ASH does not install or redistribute; the scanner is reported MISSING when `composer` is not on `PATH`. The no-install design is deliberate and pinned by `test_composer_is_not_installed_by_ash`.
- Minimum Composer is 2.8 (`--abandoned` first shipped in 2.8.0; Composer changelog). The earlier "2.4 and later" text in the docstring, README and docs page was wrong and is corrected.
- Network: advisories are fetched when the audit runs, so offline strategy is `SKIP_OFFLINE` and the sandbox declares `network=True`. An unreachable advisory repository is a failed target, never a clean one.

### Facets declared

- `facets` row: rule id, severity, file path (synthesized lock path), message, package name and version, CVE, references, tags and extras mapped. Line range and column, resource id and type, package path, CWE, fingerprints, fix, remediation and snippet are n/a with reasons. `resource_id` is n/a: findings are locked packages, not infrastructure resources.
- `operational_facets` row: content fetch of the advisory feed, tool JSON output, dependency lockfiles target (SCA), user-installed CLI runtime, native severity scale, no tool-side silencing surface surveyed, stable computed identity, exit codes 0 to 3, community opt-in tier, lockfile and manifest prerequisites.
- `nothing_to_scan_reason` is overridden (no `composer.lock` in the scanned files reads SKIPPED, not MISSING).

### Findings from the build review fixed here

- HIGH: documented minimum Composer version corrected from 2.4 to 2.8 (docstring, README, docs page).
- HIGH: no fixture coverage. First landed as `tests/test_data/scanners/composer_audit/modeled/` (modeled on Composer's `Auditor::audit` key list; neither Composer nor PHP was available on the validation desk), now REPLACED by `tests/test_data/scanners/composer_audit/captured/`: a real `composer audit --locked --format=json --abandoned=report` capture (Composer 2.11.3, PHP 8.5.13, Amazon Linux 2023 aarch64) over a committed `composer.json`/`composer.lock` holding guzzlehttp/psr7 1.8.3 (six Packagist advisories, among them CVE-2022-24775 and CVE-2023-29197) and two abandoned packages covering both message shapes (zendframework/zend-stdlib with a suggested replacement, fzaninotto/faker without). The capture also shows two Composer 2.11 document keys the model lacked (`cooldown`, `filter`, tolerated as unknown keys) and that Composer 2.11's default resolution policy must be relaxed (`config.policy.advisories.block = false`) to lock a vulnerable version at all; the captured README documents the run. The fixture test is re-pinned to the capture; `audit.sarif` is regenerated from it.
- HIGH: no sandbox-requirements test. Added `tests/unit/plugin_modules/test_composer_audit_sandbox_requirements.py`.
- Facets register and operational register rows added (the registry totality test is fail-closed).

### Central registration still owed (integration lane)

None of these is made on this branch (shared files). Each is a one-line edit:

1. `automated_security_helper/core/scanner_inventory.py`: add `"automated_security_helper.plugin_modules.ash_composer_audit_plugins",` to `_VENDORED_SCANNER_PLUGIN_PACKAGES`.
2. `automated_security_helper/utils/scanner_names.py`: add `"composer_audit": "SCA",` to `SCANNER_TOOL_TYPES`.
3. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"composer_audit": CorpusSpec("composer_audit", sarif=("captured/*.sarif",)),` to the corpus table.
4. The hard-coded universe count of 22 shipped scanners in `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py` (each +1 per added scanner), and the `["npm-audit", "snyk-code"]` SKIP_OFFLINE list in `test_the_service_upload_scanner_is_the_one_that_skips_offline` (add `composer_audit`).

### Desk validation (dev-dsk-cbc4ff77, Python 3.12.15, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`)

- Module tests (behavior, fixture report, sandbox requirements): all pass.
- Facets and operational-facets registry, totality, corpus, conformance and vocabulary families: 581 passed, 26 failed. The same families on the unmodified main base: 494 passed, 20 failed. The 20 base failures are other scanners' corpus rows and are not touched here. The 6 additional failures are exactly the central registrations above (items 2, 3 and 4); items 1 to 4 close them.
- Extract removed from the desk and its absence read back.

### Final-review rows (round 2)

- CLOSED (was: HIGH, held on a venue): the modeled fixtures are replaced by a real capture under `tests/test_data/scanners/composer_audit/captured/`, taken on a throwaway EC2 validation venue (Amazon Linux 2023 aarch64, PHP 8.5.13, Composer 2.11.3, phar sha256-verified) and torn down after. The fixture test did need re-pinning after all: the real advisory ids, counts (six advisories on one package, eight results) and severities (Packagist rates all six medium) differ from the modeled guesses, which is itself part of what the capture buys.
- Owed: whole-tree collect smoke has not been run on this branch; it belongs to the integration commit together with the central registrations listed above.
