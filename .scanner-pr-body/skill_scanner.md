## skill_scanner: Cisco skill-scanner as an alpha scanner plugin

Adds `ash_skill_scanner_plugins`, a community (alpha, opt-in) scanner for AI agent skills
(directories holding a `SKILL.md`). Enable it by listing
`automated_security_helper.plugin_modules.ash_skill_scanner_plugins` in `ash_plugin_modules`.

### Tool and pin

- Tool: Cisco AI Defense skill-scanner, installed as the uv tool `cisco-ai-skill-scanner==2.3.2`
  (Python `>=3.11,<3.15`, the package's declared range).
- The bare PyPI name `skill-scanner` is an unrelated project (0.3.3, no home page, no project
  URLs) and is never installed. The tool's executable has the same name as that package, which is
  how the wrong one gets installed, so the scanner sets `uv_tool_package_name` and every uv spec
  names `cisco-ai-skill-scanner`. `TestInstallPin` makes this executable: the install commands
  for every platform name the pinned package, none names the bare one, a planted install through
  the command name is caught by the same check, and a text scan of the plugin and its fixtures
  finds no install text for the bare package. A copy of `skill-scanner` already on PATH is run
  only when its version matches the pin.

### What it scans

`skill-scanner scan-all --recursive --format=sarif --output-sarif=<file> -- .`, run with the
target as the working directory (measured: the tool writes URIs relative to its working
directory, and a bare `SKILL.md` for every skill when run elsewhere). A tree with no `SKILL.md`
is SKIPPED without starting the tool (`scan-all` exits 1 and writes nothing for it). Findings
are prompt-injection wording, risky bundled code and manifest problems.

### Tier and behavior

- Alpha, opt-in, `enabled = True` once the module is listed. `offline_strategy = BUNDLED`,
  `python_only = True`, strict sandbox default.
- `success_exit_codes = {0}`. Cited: the tool exits 0 with CRITICAL findings (measured at
  2.3.2) and exits non-zero on findings only under `--fail-on-findings` /
  `--fail-on-severity` (README, "Options" table), which ASH never passes. Exit 1 is a usage or
  input error and fails the scan even with a report on disk.
- Severity: the tool's five severities are kept in `issue_severity`; SARIF levels follow the
  tool's own table (CRITICAL, HIGH `error`; MEDIUM `warning`; LOW, INFO `note`). No severity is
  MEDIUM, an unknown one is HIGH. Tested row by row and against the levels in the real capture.
- The SARIF driver version is the tool's hard-coded `1.0.0`; it is replaced by the probed
  version.

### Network posture row

Scanning needs no network. The tool's model analyzer (`--use-llm`, `--adjudicate`), service
analyzers (`--use-virustotal`, `--use-aidefense`, `--use-osv`), `scan-repo`, and the flags that
read a policy, rule pack, taxonomy or custom rule file are each behind their own flag; ASH
passes none (20 flags pinned absent by test) and the options model exposes none, so there are
no trust-gated option pointers to deny (PATTERN 6c: no option, no rows). `offline` defaults
False and changes nothing about the argv. A `.skill_scannerrc` and a `pyproject.toml` table of
that name planted in the scanned tree did not change a `scan-all` run (measured, 2.3.2).
Installing the tool needs the network. Sandbox: strict default; the tool's `SKILL_SCANNER_*`
variables are not passed in.

### License posture row (read, not a determination)

PyPI shows `cisco-ai-skill-scanner` 2.3.2 without a `license_expression`; the roster read the
repository LICENSE as Apache-2.0 text. The operational register row therefore records
`not read` for the upstream license, as the register allows, and no determination is made
here. The package is installed by uv at the user's request; nothing is vendored, bundled or
redistributed, and no license, NOTICE or attribution file is touched. Her confirmation of the
Apache-2.0 reading is the roster's gate before the install command ships.

### Fixtures

REAL capture, not schema-derived: `tests/test_data/scanners/skill_scanner/captured/` holds the
SARIF (and the JSON report, with its one absolute path replaced) that
`cisco-ai-skill-scanner==2.3.2` wrote over two skill trees: a benign skill (one INFO manifest
note) and the same skill with one documented prompt-injection marker phrase (CRITICAL, HIGH
and INFO findings). The tests build both trees from constants and compare them with the
committed inputs. The README records the argv, the version and the measured facts the scanner
relies on.

### Facets declared (`facets` and `operational_facets`)

- Mapped: rule_id, severity, file_path, line_range, message, fingerprints (the tool's own
  `fingerprints.primaryLocationLineHash`; the corpus gate observed it populated), remediation_text,
  snippet, extras.
- Mappable but dropped: tags (rule-level only).
- N/A: column, resource_id, resource_type, package_name, package_version, package_path,
  taxonomy_cve, taxonomy_cwe (the tool maps to OWASP LLM, MITRE ATLAS and NIST AML), fix_available,
  references.
- Operational row: no fetch, BUNDLED, SARIF output, SAST tool type over source-code targets,
  uv-python runtime, native severity, stable native fingerprints, exit codes {0}, community
  opt-in tier.

### Central registration still owed (an integration lane serializes these)

These shared edits are outside the module and were not made here. Each is a row:

1. `automated_security_helper/core/scanner_inventory.py`: add
   `"automated_security_helper.plugin_modules.ash_skill_scanner_plugins"` to
   `_VENDORED_SCANNER_PLUGIN_PACKAGES` (alphabetical).
2. `tests/unit/cli/mcp/list_scanners_import_order_probe.py`: leaf `"skill_scanner_scanner"` in
   the leaf tuple, plus the count bumps.
3. `tests/unit/cli/mcp/test_list_scanners.py`: `_expected_entries()` row
   `"skill_scanner": (None, False, True)` (uv-managed, as guarddog).
4. `automated_security_helper/utils/scanner_names.py`: `SCANNER_TOOL_TYPES["skill_scanner"] =
   "SAST"` plus the docstring list.
5. `tests/unit/walked_package.py`: `PACKAGE_DIRS` gains
   `"plugin_modules/ash_skill_scanner_plugins"` (the whole-tree collect smoke stops on it
   otherwise).
6. `automated_security_helper/config/runtime_patch.py`: `_SHIPPED_PLUGIN_KEYS` gains
   `"skill_scanner"`, plus the `test_runtime_patch.py` scanners-dict row.
7. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: `CORPORA` gains
   `"skill_scanner": CorpusSpec("skill_scanner", sarif=("captured/*.sarif",))`.
8. The hard-coded universe count of 22 in `test_scanner_facets_registry_totality.py`,
   `test_scanner_operational_facets_consistency.py` and
   `test_scanner_facets_corpus_consistency.py` goes up by one (more with the other new scanners).
9. `tests/unit/config/test_off_host_plugins_are_operator_only.py`: `LOCAL` row
   `("scanners", "skill_scanner")`: only reads local files and declares no network.
10. Links test: `test_links_leaving_the_tree_reach_no_output.py` gains the module in
    `PLUGIN_MODULES` and a `CONTROLS["skill_scanner"]` row; `test_walking_scanners_skip_links_
    leaving_the_tree.py` gains `LINK_HANDLING` and `SCANNER_CLASSES` rows. How the tool treats a
    symlink out of the tree is UNMEASURED here, so the `LINK_HANDLING` value needs that read.
11. Optional, as for the other alpha scanners: `test_scan_phase_community_modules.py`,
    `test_off_host_plugin_modules_from_repo_config.py`, the docs page and index bullet,
    `reference/coverage.md`, `scanner-sandbox.md`, CHANGELOG, the generated references
    (`scanners.md`, `environment-variables.md`, `plugin-data.html`) and the schemas/snapshots they
    feed.

No trust-gated option rows are owed (the options model exposes no file pointer).

### Desk validation

dev-dsk-d14420e2, shipped as a repository (`git archive` of the branch tip, one commit),
`uv sync --frozen --all-extras --group dev`, `env -i` (HOME, USER, PATH, CI=1, TMPDIR), lane under
`/run/user/23503848/`, `--basetemp` in the lane, `-n 0`.

- Module + sandbox: 92 passed, 0 failed.
- Facets families (module, totality, resource-id conformance, operational consistency, corpus
  consistency, facet cells at the bytes, both vocabulary files): on the unmodified branch 629
  passed / 5 failed, and all 5 are the central rows above (the universe count in three files,
  the `SCANNER_TOOL_TYPES` story, the CORPORA table and the corpus cell, which reads "no corpus"
  without its row). With rows 4, 7 and 8 applied to the throwaway extract only: 634 passed, 1
  skipped, 0 failed, so every declared facet agrees with the committed capture.
- Whole-tree collect smoke: 74785 collected, 1 error: `PACKAGE_DIRS` (row 5).
- `ruff check` and `ruff format --check` (the locked ruff, whole tree) green through the
  pre-commit hooks; conflict-marker scan zero, with a planted control; whole-range identity audit
  one noreply line.
- Extract removed and absence read back.
