## binskim: alpha scanner plugin (binary hardening)

Opt-in community scanner module `ash_binskim_plugins`, listed in `ash_plugin_modules`.

### What it scans

Microsoft BinSkim (`BinSkim analyze --recurse`) over compiled PE, ELF and Mach-O files in the scan target: missing ASLR, DEP, stack protector, control-flow guard, RELRO and similar. Rules are `BA####` ids. SARIF level maps error to HIGH, warning to MEDIUM, note to LOW; non-failure results are dropped. A tree with no binary is SKIPPED (`nothing_to_scan_reason` probes magic bytes). BinSkim exits 0 on a completed run, so any other code fails the scan.

### Tier and design

- Alpha, opt-in (community tier). No network (rules compiled in, `--disable-telemetry`, no `--sympath`, no `--config`), so the strict default sandbox applies and `offline_strategy` is BUNDLED.
- `success_exit_codes = {0}`.
- Install: the module calls `pinned_tool_install_commands("binskim")` and now tolerates the missing pin (empty install table, tool reported MISSING) instead of raising at construction.
- License: MIT (not read from a pinned upstream LICENSE, so the register says "not read"). No license gate applies, and nothing is vendored or redistributed.

### Facets declared

`facets` (resource identity: resource_id and resource_type n/a, since findings name a binary file) and `operational_facets` (network none, SARIF output, SAST, user-installed CLI until pinned, native severity, exit codes (0,), community opt-in). Every `facets` cell is n/a with "output not read; a sample run would settle it", because the facets consistency gate refuses MAPPED cells with no captured corpus and BinSkim was unavailable to capture one.

### Findings fixed (RESULTS row)

- MUST (integration-dependent): install commands raised `ToolNotProvisionableError` when no pin exists. Fixed module-locally with a guard; pin is a central edit (below).
- HIGH: timeout test could not pass. Rewritten to match the base's actual message.
- HIGH: `dependency_unavailable_reason` test patched the class, not the instance. Rewritten to set the field on the instance and to assert True first.
- HIGH: no sandbox-requirements test. Added.
- HIGH: no captured fixture. Not fixable here (no BinSkim available). Added `tests/test_data/scanners/binskim/reference.sarif` clearly labelled hand-written, a severity-mapping test over it, and a README stating what a real capture would replace.
- Also added: facets register tests.

### Central registration owed (integration lane, not made here)

1. `automated_security_helper/utils/tool_downloads.py`: `binskim` in `TOOL_VERSIONS` and `_ASSET_TABLES` (pinned `Microsoft.CodeAnalysis.BinSkim` NuGet package + digest); then runtime becomes PINNED_BINARY.
2. `automated_security_helper/utils/scanner_names.py`: `"binskim": "sast"` in `SCANNER_TOOL_TYPES`.
3. `tests/unit/walked_package.py`: `"plugin_modules/ash_binskim_plugins"` in `PACKAGE_DIRS`.
4. The universe counts (22) in `test_scanner_operational_facets_consistency.py` and `test_scanner_facets_registry_totality.py`, and the corpus table in `test_scanner_facets_corpus_consistency.py` (once a captured log exists).

### Desk validation

See the report: module tests plus the facets families on a repository extract; the only failures involving binskim are the central items above.
