## Add the cppcheck alpha scanner plugin

### What it scans

[Cppcheck](https://cppcheck.sourceforge.io/) is a static analyzer for C and C++: undefined behavior, memory and resource leaks, out-of-bounds access, and with the style groups ASH enables, unused code and portability and performance problems. It needs no build. ASH runs it once per scan target (the source tree as `.`, a converted copy as an absolute path) and reads its SARIF report:

```text
cppcheck --output-format=sarif --output-file=<results>/<target>/cppcheck.sarif \
  --error-exitcode=2 --enable=warning,style,performance,portability --quiet <path>
```

Exit 0 (clean) and 2 (findings) succeed; any other exit fails the scan.

### Tier

Alpha, opt-in: the scanner runs only when `automated_security_helper.plugin_modules.ash_cppcheck_plugins` is listed in `ash_plugin_modules`. The default configuration does not mention it.

### Facets declared

`facets` (what the SARIF maps) and `operational_facets` (how it runs), both in `cppcheck_scanner.py`:

- Mapped: rule id, severity, file path, line range, column, message, extras (`issue_severity`).
- Dropped: tags (the `security` tag sits on the rule entry, which ASH does not read).
- N/A with reasons: resource id and type, package fields, CVE and CWE taxonomy, fingerprints, fix state, remediation text, snippet, references.
- Operational: no network, `OfflineStrategy.BUNDLED`, user-installed CLI, `SAST` over source code, positional identity, exit codes (0, 2), community opt-in, upstream license read from the 2.17.1 source tarball.

### Fixed in this port

- No captured fixture from a real run (checklist rows 18 and 24, HIGH): `tests/test_data/scanners/cppcheck/captured/` now holds `positive.sarif`, `negative.sarif` and a README with the argv, version and source tarball sha256. They come from a Cppcheck 2.17.1 built from the upstream tag on a desk.
- Wrong severity assumption the capture exposed: 2.17.1 writes level `warning` for its error and warning severities (never `error`), so every real finding rated MEDIUM and the documented "error is HIGH" never happened. The scanner now rates a result HIGH when its rule carries `properties.security-severity` of 7.0 or more (9.9 for `memleak` and `arrayIndexOutOfBounds` in the capture) and otherwise rates by level. The docstring, plugin README and docs page were corrected to the measured behavior.
- No sandbox-requirements test (row 25, HIGH): `tests/unit/plugin_modules/test_cppcheck_sandbox_requirements.py` builds the policy with `build_scanner_policy`.
- Severity rows now run over the real captured report as well as the synthetic one (row 18).
- The tests the port needs from the facets register (totality, conformance, corpus consistency, operational consistency, vocabulary) pass for cppcheck on a desk.

There were no MUST findings against this scanner.

### License posture

Cppcheck is GPL-3.0-or-later. ASH only runs it as a separate program; nothing of it is linked, vendored or redistributed, and no download is pinned. The project publishes no Linux or macOS binary, so `ash dependencies install` uses apt (Linux) and Homebrew (macOS). A Cppcheck old enough to lack `--output-format=sarif` exits 1 and fails the scan closed.

### Central registration still owed

This PR touches only the module, its tests, its fixtures and its docs page. Four one-line edits in shared files belong to the integration change:

1. `automated_security_helper/utils/scanner_names.py`: add `"cppcheck": "SAST",` to `SCANNER_TOOL_TYPES` (without it `test_tool_type_is_one_story_across_four_declarations[CppcheckScanner]` fails).
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"cppcheck": CorpusSpec("cppcheck", sarif=("captured/*.sarif",)),` beside the betterleaks row.
3. `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py`: add `"cppcheck": ("cppcheck/captured/positive.sarif", opsf.OutputFormat.SARIF),` to `_NATIVE_FIXTURES`.
4. The scanner-universe counts (22 becomes 23 for this scanner alone) in `test_scanner_operational_facets_consistency.py`, `test_scanner_facets_registry_totality.py` and the count in `test_scanner_facets_corpus_consistency.py`.

Until those land, adding the module turns the universe-count tests and the tool-type and corpus rows for cppcheck red.

### Desk validation

dev-dsk-cbc4ff77, shipped as a repository, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, lane under `/run/user/23503848/`. With the four registration edits above applied to the desk copy only: all cppcheck tests and all cppcheck rows of the facets families pass (546 passed in the run of 568 selected); the 22 failures that remained are 20 that fail identically on a pristine main extract (the corpus-consistency rows of the other scanners and one table row) plus two universe-count assertions whose edit is item 4. The extract was removed and its absence read back.
