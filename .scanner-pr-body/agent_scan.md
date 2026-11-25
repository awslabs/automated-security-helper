## agent-scan alpha scanner plugin (Snyk Agent Scan)

Adds `ash_agent_scan_plugins`, a community (alpha, opt-in) scanner that runs
[Snyk Agent Scan](https://github.com/snyk/agent-scan) (PyPI `snyk-agent-scan`, formerly
invariantlabs' `mcp-scan`; this one plugin covers both names and no separate `mcp-scan`
plugin exists) over the AI agent skills in the scan target and reports the risks it scores.

Tool and pin: `snyk-agent-scan==0.7.1`, run through `uv tool run --from snyk-agent-scan==0.7.1`.
The `--json` schema is experimental and changes between releases, so the parser is locked
to the 0.7.1 document and fails closed on anything it does not recognize (see Parser).
Branch `scanner/agent_scan`, cut from `origin/main` at `84771d0aa4f`.

### What it scans

- A skill root is a directory holding a file named exactly `SKILL.md` (the tool's own test).
  One `snyk-agent-scan scan --json --skills --storage-file=<file> -- <staged skill dir>` run
  per root, so a result lands on the skill that raised it and one failure costs one skill.
- Each root is staged as a copy outside the scanned tree: the scan set less ignore paths,
  with every symlink and every file reached through a symlinked directory left out. The tool
  follows links and sends what it reads to a remote service, so a link in the scanned tree
  cannot make it read or send a file outside the tree. A nested skill is scanned on its own.
- With a skill directory as its path the tool discovers that skill and no MCP configuration,
  so no MCP server named in a scanned tree is started or contacted. ASH never passes
  `--dangerously-run-mcp-servers`, `--ci`, `--analysis-url`, `--control-server`, `--push-key`,
  `--machine-id`, `--config-file`, `--verification-H`, `--skip-ssl-verify`, `--scan-all-users`
  or `--mcp-oauth-tokens-path` (a parametrized test pins each).
- The tool has no `--version` flag (`snyk-agent-scan --version` exits 2), and ASH's generic uv
  resolution decides that a uv-run tool exists by running `<tool> --version`. So
  `validate_plugin_dependencies` checks offline, the token and uv, and the run command is built
  in the module from the exact requirement.

### Parser (version-locked, fail closed)

`parse_agent_scan_document` validates the document against closed models of the 0.7.1
`v2026-07-10` contract: an unknown key, an unknown risk name, an unknown error category, a
non-integer or out-of-range score, a location path that is absolute or contains `..`, a URL
list on the wrong risk, or any server entry is `AgentScanSchemaError` and fails that skill's
target. The message names the failing locations and error kinds, never an input value. A
document that does not answer for exactly one skill, or in which the tool marks an error as a
failure, is a failed target (named by the tool's `X00n` code, never its message), so the run
is not reported clean. A 0.5-style document (issue codes) is covered by a test.

### Severity

The tool gives each risk a score from 0 to 1000 and no severity name. ASH uses the four score
bands of the tool's own printer (`printer.py` `RISK_SCORE_BANDS`: 299, 599, 999, 1000):
0-299 LOW (`note`), 300-599 MEDIUM (`warning`), 600-999 HIGH (`error`), 1000 CRITICAL
(`error`). Issue severity and SARIF level are set together. Every boundary (0, 299, 300, 599,
600, 999, 1000, and 1001 refused) is a test row, and every score band is exercised by the
captured fixture.

### Exit status

`success_exit_codes = {0}`. `scan` exits 0 when it completed, with or without risks
(`cli.py` `main`: `sys.exit(0)` after `print_scan_inspect`); `--ci`, which ASH does not pass,
is what makes risks exit 1. An uncaught error (no token, the service unreachable) exits 1 with
nothing on stdout, and a usage error exits 2. A 0 counts only when stdout holds the document.
The tool's stderr can quote paths and file text, so failure messages name the log and never
copy it.

### Fixture row

| field | value |
|---|---|
| fixture kind | captured: the pinned tool's real `scan --json` envelope over a local stub analysis service. The risk values inside it (names, scores, evidence, locations) are the stub's, not an analysis result. |
| why not a real analysis | `scan` needs a Snyk token and posts the skill files to Snyk. Nothing was sent. |
| files | `tests/test_data/scanners/agent-scan/captured/`: `scan-skill-marked-0.7.1.json`, `scan-skill-clean-0.7.1.json` (negative control), `positive.sarif`, `stub_analysis_server.py`, `README.md` with the exact argv and inputs |
| reproducible | a test loads the committed stub and checks it answers the capture it produced, flagging the documented marker and nothing else |
| must-flag / must-not-flag | the scanner tests build a seeded skill from the documented marker string `ASH-FIXTURE-MARKER-agent-scan-mild` and a benign skill, and drive the real `scan()` with only `_run_subprocess` replaced |
| not captured | the real service's answer; observed failure exits (no token: exit 1, nothing on stdout; service unreachable: exit 1 with a traceback on stderr) are described in the fixture README |

### Tier and facets

- Alpha, opt-in: enabled by listing `ash_agent_scan_plugins` in `ash_plugin_modules`, and
  unusable until `SNYK_TOKEN` is exported, so opt-in twice.
- Facets (`ScannerFacets`, declared on the class, totality green): rule id (risk index name),
  severity (score, banded), file path, line range, message, fingerprints (computed
  `agent-scan/v1`, which leaves out the service's evidence text because it can vary between
  runs), tags and extras are MAPPED; column (`offset`) and references (rule `helpUri`) are
  DROPPED with reasons; resource id and type, package name, version and path, CVE and CWE
  taxonomy, fix state, remediation text and snippet are N/A with reasons.
  Operational facets (`ScannerOperationalFacets`): service upload of the skill files,
  not-run offline, `uv_python` runtime with one run per skill, derived severity,
  stable computed fingerprints, success exit codes `(0,)`, community opt-in, auth-token
  prerequisite. `tool_type` is SAST; the register has no agent-skill target kind, so the
  nearest `source_code` is declared and the gap is recorded in the row's `tool_type_note`.

### License posture row

- Read 2026-11-25: PyPI metadata of `snyk-agent-scan` 0.7.1, `license` field `Apache-2.0`
  (`license_expression` unset); the `snyk/agent-scan` repository was read as Apache-2.0 when
  the roster for this wave was written the same day. Not re-read at the repository here.
- Nothing is vendored or redistributed: a uv-managed pin installed from PyPI at run time. No
  license file, notice, third-party entry or SPDX header was written, and the operational
  register's `upstream_license` is left `not read` on purpose.
- For her: Snyk's README says use of Agent Scan is subject to Snyk's terms of use for Agent
  Scan (a `TERMS.md` in the repository). That is a service term that applies to posting skill
  files to the service. It was not read or judged here and gates nothing in the code.

### Network posture row

- Needs the network at scan time. `scan` posts the collected skill files (after the tool's own
  secret redaction, which ASH does not rely on) to Snyk's analysis API (`https://api.snyk.io`,
  the tool's default `--analysis-url`). The 0.7.1 package carries no local analyzer, and the
  scores come back from the service.
- Needs `SNYK_TOKEN` (the tool raises without it). Snyk's free tier has a daily usage limit.
- Whether the service's analysis uses a language model is not stated by the package or its
  README, so that part is recorded as unconfirmed in the operational facets (`NetworkFacet.unconfirmed`).
- `offline_strategy = SKIP_OFFLINE`: offline the scanner does not run and is reported
  `MISSING` with the reason, never as a clean scan. The `offline` option is the base default,
  False.
- Sandbox: `SandboxRequirements(network=True, env_names=("SNYK_TOKEN",))`, as snyk-code
  declares. No option or tree-writable setting changes either, so no grant gate applies.
  A sandbox test builds the policy with `build_scanner_policy`.
- Trust-gated pointers: none exist. There is no analysis URL, config file, push key or control
  server option (a test pins that the options model adds only `tool_version`), so no
  option-level denied-path rows are owed. The whole `scanners/agent-scan` section is off-host
  and is owed an always-denied row (central row 9 below).

### Owed central registration rows (not made here; one combined lander applies them)

Each row was applied to a throwaway validation copy and the result measured. "cleared" means
the named test went from red to green with that row applied.

1. `automated_security_helper/core/scanner_inventory.py` `_VENDORED_SCANNER_PLUGIN_PACKAGES`: add
   `"automated_security_helper.plugin_modules.ash_agent_scan_plugins"` (first). Clears
   `test_the_vendored_list_is_every_in_tree_community_module`.
2. `tests/unit/cli/mcp/list_scanners_import_order_probe.py`: add `"agent_scan_scanner"` as the
   first leaf and bump the vendored count by one. Cleared with item 1.
3. `tests/unit/cli/mcp/test_list_scanners.py` `_expected_entries()`: `"agent_scan": (None, False, True)`
   (uv-managed, as guarddog). The value passes.
4. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: `"agent-scan": "SAST"` and
   the docstring list. Clears `test_tool_type_is_one_story_across_four_declarations[AgentScanScanner]`.
5. `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `plugin_modules/ash_agent_scan_plugins`.
   Without it whole-tree collection has 1 error and every package-walking test (print, console,
   thread and shown-text families, 15 tests in the sweep) fails naming it.
6. `automated_security_helper/config/runtime_patch.py` `_SHIPPED_PLUGIN_KEYS` += `"agent-scan"`, with the
   `test_runtime_patch.py` scanners-dict row. Not applied or measured: no test failed without it.
7. Facets corpus: `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`:
   `"agent-scan": CorpusSpec("agent-scan", sarif=("captured/*.sarif",))`. Clears
   `test_declared_facets_agree_with_the_observed_corpus[agent-scan]`.
8. Universe pins: the totality and operational-consistency tests pin 22 shipped scanners, and the
   offline test pins the not-run set to `["snyk-code"]`; agent-scan joins it. Four tests, red
   until the pins move: `test_the_enumeration_holds_all_twenty_two_shipped_scanners`,
   `test_the_universe_is_the_twenty_two_shipped_scanners`,
   `test_the_service_upload_scanner_is_the_one_that_skips_offline`,
   `test_the_registry_and_the_corpus_table_agree`.
9. Off-host classification and denial (the scanner uploads skill content):
   `tests/unit/config/test_off_host_plugins_are_operator_only.py` `OFF_HOST[("scanners", "agent-scan")]`
   (clears `test_every_shipped_plugin_is_classified`), and `"/scanners/agent-scan/**"` in
   `ALWAYS_DENIED_PATHS` (`config/ash_config.py`, beside snyk-code's) and in
   `SHIPPED_DEFAULT_DENIED_PATHS` (`config/client_config_policy.py`), plus
   `PLUGIN_OPTION_DEFAULTS[("agent-scan", "offline")] = False`. The denial rows are what make
   `test_every_off_host_plugin_is_always_denied` and
   `test_no_profile_lets_a_client_configure_an_off_host_plugin[scanners/agent-scan]` pass. Measured
   caution: the `ash_config.py` row alone, with nothing regenerated, turned about 80 more tests red
   (the denied-path list is embedded in `schemas/AshConfig.json`, `schemas/AshAggregatedResults.json`,
   the configuration reference, snapshot files and the per-path case rows in
   `test_select_profile_override_gate.py` and `test_delivered_scanner_exclusions.py`), so it must be
   applied with the generators, once for the whole combined PR.
10. Link handling: `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`
    `LINK_HANDLING["agent-scan"] = READS_THE_SCAN_SET` and a `SCANNER_CLASSES` row
    (`ash_agent_scan_plugins.agent_scan_scanner`, `AgentScanScanner`, `AgentScan`). Clears
    `test_every_registered_scanner_has_a_link_handling`.
11. `tests/integration/scanners/test_links_leaving_the_tree_reach_no_output.py`: `PLUGIN_MODULES` entry
    and a `CONTROLS["agent-scan"]` row. Not applied or run: a control needs a working tool run,
    and this one needs a token and the network. The lander decides whether to exempt it.
12. Image build: `test_every_ash_dependencies_install_takes_the_pins` requires every in-tree community
    module outside ferret, snyk and trivy to be in the Dockerfile's `ASH_COMMUNITY_PLUGIN_MODULES`.
    Recommended: add agent-scan to that test's exclusion set, as snyk is (it needs an account
    token and uploads content, so baking it into the image gains nothing). Measured: the exclusion
    clears the test. Baking it in is the alternative and is the maintainer's call.
13. Docs and generated references (module and tests only here): the community plugin page, the
    community index bullet and count, `scanner-sandbox.md`, `coverage.md` rows, the `CHANGELOG.md`
    bullet, and the regenerated `scanners.md`, `environment-variables.md` and
    `plugin-data.html`.
14. Optional hand-kept tables (`test_scan_phase_community_modules.py`,
    `test_off_host_plugin_modules_from_repo_config.py`): accept the gap or add a row, as for the
    other community scanners.

### Desk validation

Linux x86_64 validation host, repository shipped as a git repository from `git archive`,
`uv sync --frozen --all-extras --group dev`, Python 3.12.15, `env -i` with an empty `HOME`,
`-n 4` to `-n 12`, `--basetemp` in the lane, lane on a RAM filesystem. Code tip
`25dcca4f326`; the later commit adds only this file.

| run | result |
|---|---|
| module tests (`tests/unit/plugin_modules/ash_agent_scan_plugins`, `test_agent_scan_sandbox_requirements.py`) | 137 passed, 0 failed |
| facets families, 7 files (vocabulary x2, cells-at-the-bytes, corpus, totality, resource-id, operational consistency) | 536 passed, 6 failed, 1 skipped. Two are agent-scan's (items 4 and 7) and four are the universe pins (item 8) |
| the same 7 files plus the module tests, with items 4 and 7 applied in the validation copy only | 675 passed, 4 failed (the item 8 pins), 1 skipped |
| unit sweep (`config`, `plugin_modules`, `plugins`, `utils`, `cli`, `core`, `base`), unmodified `origin/main` | 47053 passed, 45 failed |
| the same sweep on this branch, no central row applied | 47195 passed, 67 failed (42 identical to main; the rest are items 1, 4, 5, 7, 8, 9, 10 and 12) |
| the same sweep with items 1-5, 7-10 and 12 applied in the validation copy only (not the `ash_config.py` denial row) | 47216 passed, 48 failed: the same 42, plus 6 that are all owed rows (item 8's four, and the two item 9 denial tests that need the `ash_config.py` row) |
| `ruff format --check` and `ruff check` (ruff 0.16.10), module and tests | clean. The repository's own pre-commit hooks (ruff on the whole tree, schema generation, JSON format, commitizen) passed on each commit |
| whole-tree `--collect-only` | 74830 of 74875 collected, 45 deselected, 1 error: item 5 (`tests/unit/test_walked_package.py`) |
| conflict-marker scan over the 13 changed files (this one included) | 0 hits; planted control 3 of 3 |

The 42 reds shared with `origin/main` belong to the validation host (sandbox backend, firejail
and home-link cells and similar). Three reds appear only in the `origin/main` run
(`test_cdk_nag_container_deps` x2, `test_ash_install_failures_are_logged_redacted`) and are
environment-dependent. The validation extract was removed and its absence read back.

### Limits and open points

- The real analysis service was not run (no token, and skill content would leave the host). The
  fixture's risk values are stubbed; the scanner's handling of the service's real answers
  rests on the pinned 0.7.1 models, and a real run is the one thing that would settle them.
- `ash dependencies install` runs `uv tool install snyk-agent-scan==0.7.1`; a verification
  step that runs `<tool> --version` would read exit 2. Not measured here.
- Snyk's daily usage limit surfaces as the tool's own error; ASH reports the skill as a failed
  target (exit 1 or an `X007` analysis error), never as clean.
- The roster named the slug `agent_scan`; the scanner's configured name is `agent-scan`, as
  pip-audit's is for `pip_audit`. Item 4 and the config key use the hyphenated name.
