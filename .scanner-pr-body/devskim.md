## devskim: alpha scanner plugin

Adds `ash_devskim_plugins`, an alpha (opt-in, community tier) scanner module that runs Microsoft DevSkim (`devskim analyze`) over the scan target and reads the SARIF it writes. DevSkim is a .NET tool whose compiled-in rules flag insecure API use and risky patterns across many languages. The scanner loads only when `ash_devskim_plugins` is listed in `ash_plugin_modules`; a scan that does not list it is unchanged.

### What it scans

- Target: the whole scan target (`--source-code=.`), SAST. DevSkim picks files by its own language rules.
- Invocation: `devskim analyze --source-code=<path> --output-file=<results>/<type>/devskim.sarif --file-format=sarif --disable-supression` (DevSkim spells the flag with one `p`).
- `--disable-supression` turns off DevSkim's inline `DevSkim: ignore` comments, so the scanned tree cannot hide findings before ASH sees them; ASH suppressions apply as for every scanner.
- No rules path, options file or `-E` is passed. Success exit code is `{0}`; any other exit fails the scan.
- Install: `dotnet tool install Microsoft.CST.DevSkim.CLI --version 1.0.103 --tool-path <bin>`, declared only where `dotnet` is present.

### Facets declared

- `facets` register row: resource_id and resource_type are n/a (findings name a file and region, not a deployable resource). Every other cell is n/a with the reason "DevSkim's SARIF was never read from a real run": no .NET runtime exists on the validation hosts, so there is no captured report to cite a native field from, and the register's rule for unread output is n/a with a reason (a MAPPED cell with no fixture fails the corpus gate). Re-declare each cell MAPPED, naming its native field, when a real capture is committed.
- `operational_facets` row: network none, offline unchanged (bundled rules), SARIF output, SOURCE_CODE/SAST, user-installed CLI needing `dotnet`, native severity scale, one tool-side silencing layer (inline `DevSkim: ignore`, repository-writable, not honored), identity unconfirmed, no custom rules, exit codes `(0,)`, community opt-in, upstream license "not read".

### MUSTs and HIGHs fixed

- RESULTS HIGH, severity/level mismatch: `ManualReview` was `("INFO", Level.note)`, but the repo's severity ladder rates `note` LOW and `none` INFO. It is now `("INFO", Level.none)`; docstring, README and docs page tables updated; the expectation row and a new ladder-agreement test pin it.
- Committed `scan()` test failing on current main: `test_a_timeout_fails_the_scan_and_says_so` matched `timed out after 5`, but main's message reads `timed out after '5' s`; the pattern now matches both.

### Checklist rows left unmet (not fixable inside the module)

- Rows 18 and 24 (severity mapping over a REAL captured report; `captured/` fixtures with a README): DevSkim has not been run. The desks carry no .NET runtime (frozen toolchain), so no real report exists. The behavior tests build the SARIF from DevSkim's documented writer shape and say so in their docstring; nothing synthetic is placed under `captured/`. Owed: one real `devskim analyze` capture, then MAPPED re-declaration and a CORPORA row.
- Row 20 (stderr text quoting the scanned tree kept out of `self.errors`): no measure added.

### License posture

DevSkim is installed by the user's own `dotnet tool install` from NuGet; nothing is vendored or redistributed. devskim has no row in the license check, so the register records the upstream license as "not read" rather than a recalled name.

### Central registration owed (outside this module; an integration lane serializes these)

- `automated_security_helper/utils/scanner_names.py`: add `"devskim": "SAST",` to `SCANNER_TOOL_TYPES`.
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add a `CORPORA` row `"devskim": CorpusSpec("devskim", missing="no real devskim capture yet; commit a captured devskim analyze SARIF")` and create `tests/test_data/scanners/devskim/` with that capture; bump the pinned scanner counts (`len(SCANNER_CLASSES) == 22`) and the three other "twenty-two scanners" universe tests (`test_scanner_operational_facets_consistency.py`, `test_scanner_facets_registry_totality.py`, `test_scanner_names_registry_agreement.py` / `test_scanner_tool_types.py`).
- `tests/unit/walked_package.py`: add `"plugin_modules/ash_devskim_plugins",` to `PACKAGE_DIRS`. Without it, collecting `tests/unit/test_walked_package.py` fails ("not named in PACKAGE_DIRS"), which is the one whole-tree collection error.
- `automated_security_helper/core/scanner_inventory.py` (community module list, next to `ash_betterleaks_plugins`) and the Dockerfile `ASH_COMMUNITY_PLUGIN_MODULES` args: add `automated_security_helper.plugin_modules.ash_devskim_plugins` if the scanner is to ship in the image; the .NET SDK is not in the image, so that is the integration lane's decision.

### Desk validation

dev-dsk-cbc4ff77 (index parity 17), lane under `/run/user/23503848/`, repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, `--basetemp` in the lane.

- Devskim tests: 45 passed, 0 failed.
- Facets families (registry totality, corpus consistency, resource-id conformance, operational consistency, scanner-names agreement, tool-types): every devskim row passes. Of 24 failures, 20 also fail on the same extract with devskim removed (corpus-consistency rows for other scanners, in this environment), and 4 are the pinned "twenty-two scanners" universe counts that the central registration above resolves.
- Whole-tree `pytest --collect-only -q`: 74308 of 74353 collected, 1 collection error (the PACKAGE_DIRS entry above).
- Extract removed; absence read back.
