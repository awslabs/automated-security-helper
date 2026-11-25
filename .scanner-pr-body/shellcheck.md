feat(shellcheck): add ShellCheck as an alpha, opt-in scanner plugin

## What it scans

ShellCheck lints shell scripts. The scanner finds `.sh`, `.bash`, `.ksh`, `.dash` and `.ash`
files in the scan set, plus extensionless files whose shebang names sh, bash, dash, ksh, ash
or busybox. It passes them to `shellcheck --norc --format=json1 --severity=style -- <files>`
(chunked under the command-line cap), reads the json1 report from stdout and converts it to
SARIF. Files with a zsh or other non-shell shebang, and symlinks that leave the tree, are
skipped. A tree with no shell scripts reports no findings and zero targets.

## Tier

Alpha, opt-in: the module `automated_security_helper.plugin_modules.ash_shellcheck_plugins`
is loaded only when listed in `ash_plugin_modules`. The built-in config does not declare it.

## Facets

Declared in the scanner's own `facets` and `operational_facets` class attributes (module-local).

- Mapped: rule_id (`SC<code>`), severity (four levels to HIGH/MEDIUM/LOW/INFO), file_path,
  line_range, column, message, references (wiki link per rule), extras.
- Dropped: fix_available (the json1 `fix` object is not read).
- N/A with reasons: resource_id and resource_type (in-file locators, not resources), package
  facets, CVE/CWE taxonomy, fingerprints, remediation_text, snippet, tags.
- Operational: no network, offline strategy BUNDLED, tool JSON output, SAST over source code,
  user-installed CLI (no pin), native severity, inline `# shellcheck disable=` honored and
  rc files refused (`--norc`), positional-only identity, exit codes 0 and 1.

## Findings fixed

- MUST: the scanner could not be constructed on main because
  `pinned_tool_install_commands("shellcheck")` needs a `utils/tool_downloads.py` entry that does
  not exist, and the tool-downloads edit is outside this module. The scanner now declares no
  install commands; a missing binary is reported with how to install it. Tests cover
  construction, the empty install table and the message.
- HIGH (row 25): added `tests/unit/plugin_modules/test_shellcheck_sandbox_requirements.py`
  (strict default policy; `SHELLCHECK_OPTS` is not passed through).
- HIGH (rows 5b/24): added `tests/test_data/scanners/shellcheck/captured/` with the
  ShellCheck 0.11.0 positive and negative json1 captures and a README with the argv; tests read
  the capture as the oracle for the severity mapping and conversion.

## License posture

ShellCheck is GPL-3.0-or-later. ASH does not download, bundle or redistribute it, and the
module vendors none of its material. Users install it themselves (package manager or upstream
release). This no-install design is deliberate. The register records the upstream license as
"not read" because no pinned upstream LICENSE read exists.

## Central registration owed (not made here)

The integration lane serializes these shared-file edits:

1. `automated_security_helper/core/scanner_inventory.py`: add
   `"automated_security_helper.plugin_modules.ash_shellcheck_plugins",` beside the
   betterleaks entry (line 73).
2. `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `"plugin_modules/ash_shellcheck_plugins",`.
3. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add
   `"shellcheck": "SAST",`.
4. The scanner-universe counts (22 to 23 on adding this scanner) in
   `test_scanner_facets_registry_totality.py`, `test_scanner_facets_corpus_consistency.py` and
   `test_scanner_operational_facets_consistency.py`, and the corpus-table row
   `"shellcheck": ("shellcheck/captured/positive.json1", opsf.OutputFormat.TOOL_JSON)`.
5. Docs: the community plugin index and the docs page `docs/content/docs/plugins/community/
   shellcheck-plugin.md` (written at the build tip; not included here because it is outside the
   module), and the scanners reference table.

## Desk validation

dev-dsk-d14420e2, shipped as a repository, `uv sync --frozen --all-extras --group dev`, `env -i`,
`-n 4`, lane under `/run/user/23503848/`:

- shellcheck module tests plus the sandbox test: 78 passed, 0 failed.
- Facets registry, resource-id conformance, corpus and operational consistency families: every
  ShellCheck-specific row passes except the four rows that depend on the central edits above
  (tool-type table, three universe counts). The families carry 20 failures on the unmodified
  base in this environment (corpus rows for the other scanners); none are in this module.
- Whole-tree collect-only: 74,341 of 74,386 collected; the one collection error is the
  `PACKAGE_DIRS` central edit (item 2).
- The extract was removed and its absence read back.
