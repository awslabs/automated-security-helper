## CodeQL scanner plugin (alpha, opt-in, off by default)

### What it scans
Multi-language SAST with the CodeQL CLI. Per configured language it runs `codeql database create --build-mode=none` then `codeql database analyze --format=sarifv2.1.0 --no-download --sarif-add-snippets` against the language's code scanning suite, and reports the SARIF as ASH findings. Languages: python, javascript-typescript, java (Java sources only), csharp, c-cpp, ruby, rust. Go, Swift and Kotlin need a build and are refused.

### Tier
Alpha community scanner module `ash_codeql_plugins`, `enabled: false` by default.

### License posture
The CodeQL CLI terms bar generating a database for automated analysis except for open-source code on GitHub.com (or under a paid GitHub Advanced Security license). The no-install, no-redistribution design is deliberate: ASH never installs CodeQL, and the scan fails before CodeQL starts unless `options.license_terms_acknowledged: true`. No CodeQL material is vendored.

### Facets
Declares the `facets` register row (rule_id, severity, file_path, line_range, column, message, taxonomy_cwe, fingerprints, snippet, extras mapped; tags dropped because CodeQL's tags sit on the rule; resource and package facets n/a) and the `operational_facets` row (user-installed CLI, no network, SARIF, exit codes 0 and 32, native severity).

### Review findings fixed
- MUST: the `kotlin` alias silently produced a Java-only database under `--build-mode=none` (clean result for unanalyzed Kotlin). `kotlin` is now refused like Go and Swift; tests cover it.
- HIGH (checklist rows 18/24): added a committed sample SARIF (`tests/test_data/scanners/codeql/sample`) and tests grading the severity mapping over it. It is hand-built to the documented shape, not captured: running CodeQL here would breach its terms. A real capture can be added by a licensed maintainer.

### Central registration owed (integration lane)
Outside this module, one edit each:
- `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add `"codeql": "SAST",`
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`: add `"codeql": CorpusSpec("codeql", sarif=("sample/*.sarif",)),`
- Scanner-count assertions 22 -> N in `test_scanner_facets_corpus_consistency.py`, `test_scanner_facets_registry_totality.py`, `test_scanner_operational_facets_consistency.py` and `tests/unit/docs/test_page_claims.py` (builtin + community).

### Desk counts (dev-dsk-d14420e2, repository extract, uv sync --frozen, env -i, -n 4)
With the central edits above applied locally (not committed): module tests + facets families + tests/unit/base: 2200 passed, 110 skipped, 0 failures attributable to codeql (20 failures are other scanners' corpus rows, the same on those scanners without this change). Whole-tree collect: 72666 collected; 28 collection errors from the extract omitting `.github` (lane artifact).
