## SkillSpector alpha scanner plugin

Adds `ash_skillspector_plugins`, a community (alpha, opt-in) scanner that runs
[SkillSpector](https://github.com/NVIDIA/SkillSpector) (NVIDIA) over the AI agent skills in
the scan target: directories holding `SKILL.md` or `skill.md`.

### Tool and version pin

- `skillspector==2.13.7`, installed by uv from PyPI at run time (`uv tool install`, the
  guarddog shape). Nothing is vendored or redistributed, so no `TOOL_VERSIONS`,
  `_DIGESTS` or `THIRD_PARTY_LICENSES` entry applies.
- `options.tool_version` overrides the pin; the parser is written against 2.13.7.
- Windows is unsupported with a stated reason: SkillSpector's safe file output needs POSIX
  descriptor flags, and ASH reads its report from a file. An enabled scanner is SKIPPED there.

### What it scans

- One `skillspector scan --no-llm --format=sarif --output=<file>` per top-most skill
  directory (a nested skill is covered by its parent's run), the path after `--`.
- SkillSpector's SARIF is rewritten: uris become source-relative, severity is set (below),
  and ASH computes `partialFingerprints["skillspector/v1"]` because the native `findingId`
  is random per run.
- When ASH's output directory is inside the skill (a skill at the repository root), the run
  adds `--exclude=<output dir>/**` and drops any result under it, because SkillSpector
  scans the earlier reports otherwise (measured). That exclusion is the only coverage gap
  the scanner accepts.
- A skill SkillSpector reports as only partly inspected, or a report with no completeness
  record, fails that target; the scan is then not a clean scan.
- Severity: LOW, MEDIUM, HIGH and CRITICAL map one to one (CRITICAL and HIGH are `error`,
  MEDIUM `warning`, LOW `note`); no severity falls back to the SARIF level, then MEDIUM; an
  unknown severity string is HIGH. Pinned row by row in the unit tests.
- Exit status (from `skillspector/cli.py` at 2.13.7): 0 below the risk threshold, 1 above it,
  2 every error. `success_exit_codes = {0, 1}`, and a run counts only when the report parses.

### Tier and posture

- Tier: alpha, opt-in. Enabled by listing `ash_skillspector_plugins` in `ash_plugin_modules`.
- Facets: `ScannerFacets` (mapping) and `ScannerOperationalFacets` (operational) declared on
  the class; the registry totality and operational consistency cells for `skillspector` are
  green once the central rows below exist.
- License posture row: Apache-2.0 per PyPI `License-Expression` and the package's shipped
  LICENSE, as the roster read it. Read and flagged only: no license file is written, the
  operational register records the license as "not read" rather than a determination, and
  confirmation of the reading is hers. No no-install gate is needed on this read.
- Network posture row: no network at scan time. `--no-llm` is always passed with no option
  to remove it, so the skill's text is never sent to a model provider; the same scan inside
  an empty network namespace produced the same findings (measured, `captured/README.md`).
  `offline_strategy` is `BUNDLED`; `offline` stays an option defaulting False and the sandbox
  declaration is the strict default (no network, baseline environment only, so no
  `SKILLSPECTOR_*` or provider credential reaches the tool). Only installing the tool needs
  the network.
- Trust-gated options: none exist. The plugin has no option that points at a file and never
  passes `--baseline`, `--use-shipped-baseline`, `--yara-rules-dir`,
  `--inspect-dependencies`, `--transitive`, `--mcp-registry` or a URL input (each asserted
  absent in a unit test), so a skill cannot suppress its own findings or trigger a download.
  A baseline file inside a skill is reported by the tool and not applied.

### Fixtures

- Kind: captured. `tests/test_data/scanners/skillspector/captured/` holds the unedited SARIF
  of `skillspector==2.13.7` over a benign skill (no results, the negative control) and a
  seeded skill (five results), with a README giving argv and facts, plus `positive.sarif`
  (the converter's output, read by the facets corpus gate).
- The seeded skill is a documented detection marker (the instruction-override phrase
  behind an `ASH-TEST-MARKER` label in an HTML comment) and a fetch line aimed at a host
  under `.invalid`; no attack content. The unit tests build both skills from constants and
  assert the committed `fixture_repo/` files equal them.

### Central registration rows owed (not made here)

Universal set from the roster's section 4, with this scanner's values:

1. `automated_security_helper/core/scanner_inventory.py`: add
   `"automated_security_helper.plugin_modules.ash_skillspector_plugins"` to
   `_VENDORED_SCANNER_PLUGIN_PACKAGES` (alphabetical).
2. `tests/unit/cli/mcp/list_scanners_import_order_probe.py`: leaf `"skillspector_scanner"`
   in the leaf tuple at the same position, plus the count bumps.
3. `tests/unit/cli/mcp/test_list_scanners.py` `_expected_entries()`:
   `"skillspector": (None, False, True)` (uv-managed, as guarddog).
4. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`:
   `"skillspector": "SAST",` and the docstring list. Required by
   `test_tool_type_is_one_story_across_four_declarations[SkillSpectorScanner]`.
5. `tests/unit/walked_package.py` `PACKAGE_DIRS`: `"plugin_modules/ash_skillspector_plugins"`.
   Whole-tree collection errors without it (the one collection error on this branch).
6. `automated_security_helper/config/runtime_patch.py` `_SHIPPED_PLUGIN_KEYS`: `"skillspector"`,
   and the `tests/unit/config/test_runtime_patch.py` scanners-dict row.
7. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`:
   `"skillspector": CorpusSpec("skillspector", sarif=("captured/positive.sarif",)),`
   (the exact file name, not `captured/*.sarif`: the two raw captures are tool-format SARIF).
8. Universe pins: `test_scanner_facets_registry_totality.py` and
   `test_scanner_operational_facets_consistency.py` count 22 shipped scanners and read 23
   with this one (the corpus-table agreement test fails on the same count). The NOT_RUN offline
   set is unchanged: this scanner's offline outcome is `unchanged`.
9. `tests/unit/config/test_off_host_plugins_are_operator_only.py` `LOCAL`:
   `("scanners","skillspector")`, runs only local files and declares no network.
10. Links tests: `tests/integration/scanners/test_links_leaving_the_tree_reach_no_output.py`
    `PLUGIN_MODULES` and a `CONTROLS` row (uv tool; `in_tree` the seeded skill's `SKILL.md`);
    `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`
    `LINK_HANDLING` and `SCANNER_CLASSES`. This plugin drops a symlinked manifest or a skill
    under a symlinked directory itself and passes only directories; what SkillSpector does
    with a symlink inside a skill is unmeasured.
11. Trust-gated options (`ash_config.py` and `client_config_policy.py` denied paths,
    `PLUGIN_OPTION_DEFAULTS`, the two `tests/unit/cli/mcp/` enumerations): none, no pointer
    options exist. `("skillspector","offline"): False` joins `PLUGIN_OPTION_DEFAULTS` only if
    the alpha wave does that for every scanner.
12. The two hand-kept tables (`test_scan_phase_community_modules.py`,
    `test_off_host_plugin_modules_from_repo_config.py`): accept the gap or add a row, as for
    the rest of the wave.
13. Docs page `docs/content/docs/plugins/community/skillspector-plugin.md`, the community
    index bullet and count, `scanner-sandbox.md`, `coverage.md`, CHANGELOG, and the
    regenerated references (`scanners.md`, `environment-variables.md`, `plugin-data.html`).

### Desk validation

dev-dsk-d14420e2, shipped as a repository (`git archive` plus one `git init` commit),
`uv sync --frozen --all-extras --group dev`, `env -i` (HOME, USER, PATH, CI=1, TMPDIR),
`--basetemp` in the lane, `-n 4`:

- Module tests plus sandbox test: 123 passed, 0 failed. ruff format --check and ruff check
  clean on the module and tests.
- Facets and operational-facets families (`test_scanner_facets_*`,
  `test_scanner_operational_facets_*`): 485 passed, 1 skipped, 5 failed on the branch alone.
  All five are central rows: three universe-count pins (23 against 22), the tool-type story
  for `SkillSpectorScanner` (row 4) and the corpus observation for `skillspector` (row 7).
  With rows 4 and 7 applied in the desk copy only: 487 passed, 1 skipped, 3 failed, the
  three universe-count pins. The carried baseline `test_declared_facets_agree_with_the_observed_corpus`
  reds for existing scanners are not this branch's.
- Whole-tree `--collect-only` (`tests/unit`): 73311 tests collected, 1 error
  (`test_walked_package.py`, row 5).
- Extract removed by literal path, absence read back.
- Marker scan over the 13 files of this change: zero hits, with a planted conflict-marker
  file read as 3.
