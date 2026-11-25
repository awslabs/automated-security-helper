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
- HIGH: no captured fixture. Fixed by running BinSkim 4.4.9.14 (the self-contained `linux-x64` build from the NuGet package, no .NET install) on a desk with the scanner's exact argv. The hand-written reference log is deleted; `tests/test_data/scanners/binskim/captured/` holds a positive and a negative log with a README (argv, version, trees). Rows in `TestCapturedLog` read them.
- HIGH (found by the capture): the real log writes artifact URIs percent-encoded (`sp%20ace/app%202`), and `_relative_uri` never decoded them, so a path with a space or other escaped character named no file. It now decodes (`binskim_scanner.py`, `_relative_uri`).
- HIGH (found by the capture): the hand-written log gave `message.text`; the real one gives `{"id": "Error", "arguments": [...]}` and no text. The base resolves it through the rule's `messageStrings`; a row pins that the resolved text reads "The stack protector was not found in 'app'".
- Java class files share the fat Mach-O magic number, so a tree of class files was run instead of SKIPPED. `_looks_like_binary` now reads the next four bytes (architecture count versus class version).
- The missing-tool warning, the plugin README and the docs page named `ash dependencies install --tool binskim`, which does nothing while no pin is registered. They now say how to install BinSkim by hand.
- Also added: facets register tests. The register cells stay n/a (the consistency gate wants a corpus-table row, a central file); their reasons now say the capture is committed and the row is owed.

### Measured with the real tool (BinSkim 4.4.9.14, linux-x64, Amazon Linux 2023)

- Exit 0 on a tree with findings, on a clean tree, and on a tree holding only a Java class file (each writes a log; the last has an empty `results`).
- Results carry `level` (`error` for BA3001, BA3003, BA3010, BA3011 on an unhardened ELF), no `kind`, and `ruleIndex`; rules that cannot run on Linux appear as `toolConfigurationNotifications`.
- NuGet package `Microsoft.CodeAnalysis.BinSkim` 4.4.9.14: sha256 `ea2f48ed02e6d7ff569614d0895b80c2669fbc261c8b386639de551af049bcf4`, 153,894,969 bytes, with `tools/{linux-x64,linux-arm64,osx-x64,win-x64}`. Input for the owed pin, not a pin.

### Central registration owed (integration lane, not made here)

1. `automated_security_helper/utils/tool_downloads.py`: `binskim` in `TOOL_VERSIONS` and `_ASSET_TABLES` (pinned `Microsoft.CodeAnalysis.BinSkim` NuGet package + digest); then runtime becomes PINNED_BINARY.
2. `automated_security_helper/utils/scanner_names.py`: `"binskim": "sast"` in `SCANNER_TOOL_TYPES`.
3. `tests/unit/walked_package.py`: `"plugin_modules/ash_binskim_plugins"` in `PACKAGE_DIRS`.
4. The universe counts (22) in `test_scanner_operational_facets_consistency.py` and `test_scanner_facets_registry_totality.py`, and the corpus table in `test_scanner_facets_corpus_consistency.py` (once a captured log exists).

### Desk validation (fix round)

Desk d14420e2, repository extract of this branch, `uv sync --frozen --all-extras --group dev`, env -i, -n 4:
- binskim module tests: 57 passed, 1 skipped, 0 failed.
- Facets families plus the link-handling table (5 files): 25 failed, 517 passed. The 20 `test_declared_facets_agree_with_the_observed_corpus[...]` failures name other scanners (pre-existing on main); the other 5 are the central items: universe counts (2), corpus-table agreement, `SCANNER_TOOL_TYPES` KeyError, and `test_every_registered_scanner_has_a_link_handling` (owed row; the probe and BinSkim's `--recurse` link handling are not measured here).
- ruff format --check and ruff check (whole tree, the repo hook): green. Conflict-marker scan with a planted control: zero. Identity audit over origin/main..HEAD: one noreply line.

### Desk validation (earlier round)

Desk cbc4ff77, repository extract at main e0aac6c3aff plus this branch, `uv sync --frozen --all-extras --group dev`, env -i, -n 4:
- binskim module tests: 44 passed, 1 skipped, 0 failed.
- ruff format --check and ruff check: green on the module and its tests.
- Facets families (6 files): 509 passed, 24 failed. The binskim-specific failures are the central items above (universe counts x2, corpus-table agreement, `SCANNER_TOOL_TYPES` KeyError). The other 20 corpus-consistency failures name other scanners; the same file reads 20 failed on an origin/main extract in the same lane (that baseline run may have imported the branch's editable install, so treat it as indicative).
- Whole-tree collect: 72806 tests, one collection error, the `PACKAGE_DIRS` central item (3 above).
- Extract removed and absence read back.
