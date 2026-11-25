## feat(plugins): kyverno alpha scanner plugin

### What it scans

[Kyverno](https://kyverno.io) policy checks over Kubernetes manifests, offline. ASH runs
`kyverno apply --policy-report` once per chunk of `--resource=<manifest>` arguments
(no `--cluster`, no `--registry`) against the operator's policies in
`scanners.kyverno.options.policy_paths`, and reports each failed or warned rule at the
file and line that declares the object. Kyverno ships no policies, so with none
configured the scanner is skipped (`targets_attempted = 0`), not passed.

### Tier

Alpha, opt-in: a community plugin module, `ash_kyverno_plugins`, loaded only when listed
in `ash_plugin_modules`. Exit codes `{0, 1}`; strict default sandbox requirements (no
network, no env, no extra paths); `offline_strategy` BUNDLED.

### Facets declared

Both register rows are declared on the class (`facets`, `operational_facets`), read from
the committed capture in `tests/test_data/scanners/kyverno/captured/`:

- Mapped: rule_id (`<policy>/<rule>`), severity (native `severity`), file_path and
  line_range (the object is located in the scanned manifest; Kyverno reports no path),
  message, fingerprints (computed `kyverno/v1`), tags, extras.
- N/A with reasons: column, package_*, taxonomy_*, fix_available, remediation_text,
  snippet, references, and resource_id / resource_type. The report does name the object
  (kind, namespace, name), but the adapter keeps it only in `kyverno_resource` and writes
  no `ash_resource_id`; a wrong value would bind resource-scoped suppressions, so
  attaching it is its own later unit. Declared N/A, not DROPPED, because a DROPPED cell
  needs a row in the shared rot-guard table (see the central edits below).
- Operational: no network; output is the tool's YAML report converted to SARIF; target
  kind IaC/Kubernetes (tool type IaC); runtime is a user-installed CLI today (no pin row
  yet); severity native; no tool-side silencing layer; identity stable-computed;
  operator-path rules; community opt-in tier; license "not read" (no pinned upstream
  LICENSE read in the register's form).

### Findings fixed (RESULTS row for kyverno)

- MUST, per-chunk exit-code judgment (`kyverno_scanner.py`): the loop read `self.exit_code`,
  which the base folds to the worst code over every run, so a clean chunk after a chunk
  that exited 1 was judged "exited 1 without a report" and failed the scan. It now reads
  the response's own `returncode` (falling back to `self.exit_code` only when the response
  carries none). Red-first tests with a folding stand-in for `_run_subprocess`:
  `TestEachChunkIsJudgedOnItsOwnExitCode`.
- HIGH, shipped red test `test_a_multi_document_file_gives_each_object_its_start_line`:
  the expectation was wrong, not the parser. The second object's first line is 11 (nine
  lines, the `---` separator on 10); the test now says so.
- HIGH, row 24 (captured fixtures): `tests/test_data/scanners/kyverno/captured/` holds a real
  run of the pinned kyverno 1.19.2 (native report, input manifest, the SARIF the adapter
  makes of it, README with the command and archive sha256). Tests rebuild the SARIF from
  the report and compare, and check the high-to-HIGH/error mapping over it.
- HIGH, row 25 (sandbox requirements): `TestSandboxRequirements` pins the strict default
  and the BUNDLED offline strategy.
- HIGH, "existing unit test red": the central registrations listed below.
- Docs: the plugin page and README no longer claim a container image bundle, a pinned
  download or a shipped license file, none of which exist until the pin rows land.

### License posture

Kyverno is Apache-2.0. No binary is vendored or redistributed by this module; ASH runs a
`kyverno` the operator installed, so no license file ships. Not a license-gated tool.

### Central registration edits owed (an integration lane serializes these)

None of these is made in this branch; each makes an existing test red until it lands:

1. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add
   `"kyverno": "IAC",` (fails `test_tool_type_is_one_story_across_four_declarations[KyvernoScanner]`
   and the corpus join).
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`: add
   `"kyverno": CorpusSpec("kyverno", sarif=("captured/*.sarif",)),`.
3. `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `"plugin_modules/ash_kyverno_plugins",`.
3b. Three more central tables, each keyed by scanner or plugin module (measured on the
   desk by running `tests/unit/{plugin_modules,core,interactions,config,cli/mcp}`; a
   `kyverno` row or module name is what each needs):
   `tests/unit/cli/mcp/test_list_scanners_import_order.py` (the vendored community-module
   list, add `automated_security_helper.plugin_modules.ash_kyverno_plugins`),
   `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`
   (link handling: kyverno reads the scan set, so `READS_THE_SCAN_SET`, and its module
   row), and `tests/unit/config/test_off_host_plugins_are_operator_only.py`
   (`("scanners", "kyverno")` classified LOCAL: it never leaves the host).
4. Scanner-count pins (22 to 23, or the combined count): `test_scanner_facets_registry_totality.py`,
   `test_scanner_operational_facets_consistency.py`, `test_scanner_facets_corpus_consistency.py`.
5. The tool pin rows in `utils/tool_downloads.py` (v1.19.2, archive and executable digests;
   `ash dependencies install --tool kyverno` then works, and the plugin already uses
   `pinned_tool_install_commands("kyverno")` when the table exists). With them the
   operational row's runtime flips from `USER_INSTALLED_CLI` / `USER_INSTALLED` to
   `PINNED_BINARY` / `PINNED_RELEASE_BINARY` with `tool_versions_key="kyverno"` and the
   platform set `tool_downloads` publishes.

### Desk validation

dev-dsk-d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`,
`-n 4`, basetemp in the lane. See the report for counts.
