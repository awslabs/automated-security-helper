## Summary

Adds `ggshield` as an alpha, opt-in scanner plugin module (`ash_ggshield_plugins`).
ggshield is GitGuardian's CLI (MIT). `ggshield secret scan path` sends the content of
each file to the GitGuardian API, which returns the secrets it detects; the plugin runs
it and reads the SARIF it writes.

This scanner sends the scanned files to a third-party service. Listing the module in
`ash_plugin_modules` makes it available, and it stays off until
`scanners.ggshield.enabled: true`.

## Tier and behavior

* Tier: alpha, opt-in (`Tier.COMMUNITY_OPTIN` in the operational register today).
* Off by default (`enabled: false`), a deliberate fail-closed deviation from the
  `enabled: true` convention of the other community scanners.
* Fails closed without `GITGUARDIAN_API_KEY`: the dependency check records a reason
  naming the variable, so a scan never reads as clean because nothing was checked.
  Credentials stored by `ggshield auth login` are not read.
* Skipped under `ASH_OFFLINE` (`OfflineStrategy.SKIP_OFFLINE`).
* Refuses a target that holds ASH's own output directory, and a run with
  `global_settings.ignore_paths` set, because ggshield has no exclusion ASH can rely on
  and an ignored file would be uploaded anyway.
* Runs in a new empty directory so a `.gitguardian.yaml` in the scanned tree (which can
  hide findings) is never read.
* Every finding is CRITICAL (ggshield's SARIF writer gives every result level `error`).
* Run through `uv tool` at the pinned release `ggshield==1.56.1`; exit codes 0 and 1 are
  success, 3 (authentication) and 4 (server) fail the scan with a message naming the
  cause and no stderr text.

## Facets declared

Mapped: rule id, severity (constant), file path, line range, column, message,
fingerprints (`partialFingerprints["secret/v1"]`), references (the match locations),
extras. N/A with reasons: resource id and type, package fields, CVE and CWE taxonomy,
fix state, remediation text, snippet, tags. The operational row declares a service
upload (source uploaded, offline not run, sandbox network online), SARIF output,
secrets-contents targets, `uv_python` runtime, constant severity, one repository-written
silencing layer that is not honored (`.gitguardian.yaml`), stable native fingerprints,
exit codes 0 and 1, `AUTH_TOKEN` prerequisite, and `MIT` with a citation of the 1.56.1
distribution's LICENSE (sha256 recorded).

## Findings fixed (RESULTS row for ggshield)

* HIGH, no captured fixtures: `tests/test_data/scanners/ggshield/captured/` now holds
  `positive.sarif` and `negative.sarif`, written by ggshield 1.56.1's own CLI (its file
  walk and its SARIF writer), with only the GitGuardian HTTP calls stubbed. The README
  there says exactly what is real and what is stubbed. The capture also settled the two
  items the module header listed as unmeasured (a report is written when nothing is
  found; the location URI is `file://` plus the absolute path), and a real run observed
  exit 3 for an invalid key.
* Found by that capture: ggshield also writes `relatedLocations` with the same absolute
  `file://` URI, which the flat row reads as references. Only `locations` was made
  source-relative before, so a host path reached the references column. Both are now
  rewritten, with a test.
* SHOULD, no `build_scanner_policy` sandbox test: added (network online and not offline,
  only the `GITGUARDIAN_` variables pass, results directory is the writable place).
* Checklist rows 18 and 24 (captured fixtures and the captured README): met.
* Row 3 (`enabled=True` convention) is a deliberate deviation, kept and documented.
* The license-gated design is deliberate and kept: nothing from ggshield is vendored,
  the tool is installed by the user's environment through `uv tool`.

## Central edits owed (not made here; an integration lane serializes them)

* `automated_security_helper/core/scanner_inventory.py`: add
  `"automated_security_helper.plugin_modules.ash_ggshield_plugins",` to
  `_VENDORED_SCANNER_PLUGIN_PACKAGES`.
* `automated_security_helper/utils/scanner_names.py`: add `"ggshield": "SECRETS",` to
  `SCANNER_TOOL_TYPES`.
* `tests/unit/walked_package.py`: add `"plugin_modules/ash_ggshield_plugins",` to
  `PACKAGE_DIRS` (the whole-tree collect fails "not named in PACKAGE_DIRS" until then).
* `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add
  `"ggshield": CorpusSpec("ggshield", sarif=("captured/*.sarif",)),` to the corpus table,
  and bump the universe count 22 to 23.
* `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py` and
  `test_scanner_facets_registry_totality.py`: bump the universe count 22 to 23; in the
  operational test add `ggshield` to the service-upload list and to the skipped-offline
  list.

## Desk validation

dev-dsk-d14420e2, shipped as a repository, `uv sync --frozen --all-extras --group dev`,
`env -i`, CPython 3.12.15, lane under `/run/user/`, `-n 4`.

* The module's tests: 65 passed, 0 failed.
* With the central edits above applied to the desk copy only (not in this branch): the
  facets registry, resource-id conformance, operational consistency, success-exit-codes
  and scanner-inventory families all pass, and the corpus-consistency row for ggshield
  passes. The corpus-consistency rows of the other 20 scanners fail the same way on a
  clean `origin/main` extract (20 failed there too), so they are not caused by this
  module.
* Whole-tree `pytest --collect-only -q`: 74370/74415 collected (45 deselected), no
  errors, with the `PACKAGE_DIRS` edit applied.
* `ruff format --check` and `ruff check` pass.

On this branch alone the families above fail where they pin the scanner universe
(counts, `SCANNER_TOOL_TYPES`, the corpus table, `PACKAGE_DIRS`); those are the central
edits listed above.

## Not measured

A scan against the live GitGuardian service needs an API key: the detector names,
`extensions[0].version` and service-side error cases are unobserved.
