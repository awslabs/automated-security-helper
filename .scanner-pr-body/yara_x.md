## yara_x: alpha community scanner plugin (YARA-X, bring your own rules)

### What it scans

`yr scan` (YARA-X, VirusTotal's Rust rewrite of YARA) over the scan target with a rule set the operator supplies through `scanners.yara_x.options.rules_path`. YARA-X ships no rules, so with no operator-set path the scanner does not run the tool and reports "nothing scanned" at INFO. Findings are file-level pattern matches; severity comes from the rule's own `severity` metadata (critical, high, medium, low, info; none is INFO; an unrecognized value is MEDIUM).

### Tier and selection

Alpha / opt-in: it loads only when `automated_security_helper.plugin_modules.ash_yara_x_plugins` is listed in `ash_plugin_modules`. Module: `automated_security_helper/plugin_modules/ash_yara_x_plugins/`. Docs page: `docs/content/docs/plugins/community/yara_x-plugin.md`.

### Facets declared

- `facets` (all 20 cells): rule_id, severity, file_path, message, fingerprints, tags and extras MAPPED; references DROPPED (rule meta pairs other than severity and description); line_range, column, snippet N/A (ASH never passes `--print-strings`, so no offsets or matched bytes); resource_id / resource_type N/A (a finding names a file, not a deployable resource); package_*, CVE, CWE, fix, remediation N/A with reasons.
- `operational_facets`: user-installed CLI (`yr`), no network (BUNDLED offline strategy, strict sandbox), TOOL_JSON (ndjson) output, tool type SAST (CUSTOM serves no target kind in the register), success exit codes `{0}`, operator-path rules, ASH-computed `yara_x/v1` fingerprint, tier community opt-in, license "not read" (this scanner is not in the license check, and no pin table row exists yet).

### Findings fixed (RESULTS row: 0 MUST, 2 HIGH)

- HIGH row 24: captured fixtures. Added `tests/test_data/scanners/yara_x/captured/{positive.ndjson,negative.ndjson,README.md}`; the behavior tests now read the captures instead of inline constants.
- HIGH row 25: sandbox policy test. Added `tests/unit/plugin_modules/ash_yara_x_plugins/test_yara_x_sandbox_requirements.py` (strict default, no network, baseline paths, environment filtering, rules path not mounted).
- Found while validating: `_drop_excluded` read `physicalLocation.artifactLocation` without going through `.root`, so every `scan()` that produced a result raised `ScannerError`. Fixed.
- Found while validating: the timeout test's pattern could not match the rendered message (`timed out after '5' s`). Fixed.
- Result-level `tags` property now carries the rule's tags (the facets corpus gate observes that column); `yara_tags` is kept.

### License posture

No license gate recorded for this tool and nothing is vendored or redistributed. `yr` is not installed by ASH: there is no pinned release row, so the operator installs it. The scanner tolerates the missing row (no install command, loads normally). The upstream license was not read for this change (`LICENSE_NOT_READ`).

### Central edits owed (integration lane; NOT made here)

1. `automated_security_helper/utils/scanner_names.py`: add `"yara_x": "SAST",` to `SCANNER_TOOL_TYPES`.
2. `tests/unit/walked_package.py`: add `"plugin_modules/ash_yara_x_plugins",` to `PACKAGE_DIRS` (a whole-tree collect errors without it).
3. Universe counts 22 to 23 in `test_scanner_operational_facets_consistency.py`, `test_scanner_facets_registry_totality.py`, `test_scanner_facets_corpus_consistency.py`.
4. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: a `CORPORA["yara_x"] = CorpusSpec("yara_x", prep="yara_x")` row and a `_prep_yara_x` that reads `captured/positive.ndjson` through `parse_ndjson` and `convert_ndjson`.
5. `utils/tool_downloads.py`: pinned release rows for `yara_x` (then flip the operational row to PINNED_BINARY with `tool_versions_key="yara_x"` and its platforms).
6. SCANNER_TAG_NAMES / registry docs and any generated docs rows follow from item 1.

### Desk validation (dev-dsk-d14420e2, extract at a lane under /run/user, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, `--basetemp` in lane)

- Module tests: 61 passed, 0 failed.
- Facets registry, corpus, resource-id conformance and operational consistency families, with items 1, 3 and 4 above applied to the throwaway desk copy only: 535 passed, 20 failed, 0 failed in any yara_x row. The 20 failures are the `test_declared_facets_agree_with_the_observed_corpus` rows of every other scanner (identical set on a copy without this module), not caused by this change.
- Whole-tree `pytest --collect-only -q`: 74325 collected, 1 error (item 2 above).
- ruff format --check and ruff check (the locked ruff, via the pre-commit hooks): green.

### Known limits

- A file `yr` cannot read goes to its stderr and the scan still exits 0; ASH does not see it.
- An operator rules path outside the scanned tree is not mounted into a sandbox yet.
- The captures record the argv and version written by the original build; they were not re-captured on the desk (no `yr` binary there).
