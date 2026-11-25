## dotnet_vulnerable: alpha community scanner for vulnerable NuGet packages

Adds `ash_dotnet_vulnerable_plugins`, an opt-in community scanner that runs
`dotnet list <project> package --vulnerable --include-transitive --format json
--output-version 1` once per `.csproj`, `.fsproj` and `.vbproj` in the scan set and
converts the JSON to SARIF. One result per (project, package, version, advisory); a
package under several target frameworks is one result naming them all. The GHSA id in
the advisory URL is the rule id.

### Tier and posture

- Tier: alpha, opt-in community plugin (`ash_plugin_modules`), not in the default set.
- The tool is the .NET SDK (7.0.200 or later). ASH installs nothing: a missing `dotnet`
  is reported MISSING. This no-install design is deliberate (the SDK is not a pinned
  download and has no redistribution path through ASH).
- Network: the advisory lookup reads the NuGet sources' data, so the scanner is
  `SKIP_OFFLINE` and its sandbox declares `network=True` with the `DOTNET_` and `NUGET_`
  environment prefixes only. Feed credentials are not passed.
- Upstream license: recorded as "not read" in the operational register; no pinned
  upstream LICENSE read was available, and nothing is vendored.

### Facets declared

Mapping register (`facets`): rule_id, severity, file_path, line_range (a constant line 1,
as grype's), message, package_name, package_version, fingerprints, tags and extras are
MAPPED; references is DROPPED (the advisory URL stays in the message and the
`advisory_url` property; the pipeline reads `relatedLocations`, which this adapter does
not write); column, resource_id, resource_type, package_path, taxonomy_cve,
taxonomy_cwe, fix_available, remediation_text and snippet are N/A with reasons. Resource
identity is N/A: a finding names a NuGet package, not a deployable resource.

Operational register (`operational_facets`): content fetch of the advisory feed,
offline outcome not_run, tool JSON output, SCA over project files, user-installed CLI,
native severity (Critical/High/Moderate/Low; unrated is MEDIUM, unknown is HIGH),
computed sha256 fingerprint, success exit code {0}, community opt-in tier.

### Fixes against the build review

- MUST: `--no-restore` was always passed, but `dotnet list package` has no such option
  before SDK 10 while the plugin documents and gates on SDK 7.0.200, so every project
  would have failed on SDK 7 to 9. The flag is removed; a test pins that it is never
  passed. The docs and README now say that SDK 10 restores on its own (writing `obj/`
  and fetching packages) and that SDK 7 to 9 never restore.
- Found while validating: a failed project's error was recorded twice (an explicit
  append plus the ERROR-level `_plugin_log`, which already records it), so the committed
  not-restored scan() test failed on current main. The explicit append is removed.
- Found against the facets register: package identity was written as `package_id`, a key
  the shared pipeline does not read; it now goes through `identity_properties`
  (`package_name`, `package_version`).
- HIGH, captured fixtures: no SDK was available on the build or desk hosts, so real
  captures are NOT possible yet. `tests/test_data/scanners/dotnet_vulnerable/reports/`
  holds hand-built reports in the renderer's documented shape (and a SARIF rendered from
  them for the facets corpus gate), named `reports`, not `captured`, with a README saying
  so. The severity mapping is now asserted row by row over that fixture. Checklist rows
  18, 21 and 24 stay unmet until a real capture replaces the files.
- HIGH, sandbox policy test: `tests/unit/plugin_modules/test_dotnet_vulnerable_sandbox_requirements.py`
  builds the policy with `build_scanner_policy` and pins network online-only, the two
  env prefixes, and that credential-bearing names are not passed.

### Central registration owed (not made here; one line each, for the integration lane)

- `automated_security_helper/utils/scanner_names.py`, `SCANNER_TOOL_TYPES`: `"dotnet_vulnerable": "SCA",`
- `automated_security_helper/core/scanner_inventory.py`: add
  `"automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins"` to the community module list.
- `tests/unit/walked_package.py`, `PACKAGE_DIRS`: add `"plugin_modules/ash_dotnet_vulnerable_plugins",`
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`, `CORPORA`:
  `"dotnet_vulnerable": CorpusSpec("dotnet_vulnerable", sarif=("reports/*.sarif",)),`
- Hard-coded universe counts (22 becomes 23 with this scanner) in
  `test_scanner_facets_registry_totality.py`, `test_scanner_facets_corpus_consistency.py`
  and `test_scanner_operational_facets_consistency.py`, and the offline-skip expectation
  there (`["dotnet_vulnerable", "npm-audit", "snyk-code"]`).

### Desk validation

dev-dsk-cbc4ff77, a repository extract of this branch plus the temporary central edits
above (uncommitted, on the extract only), `uv sync --frozen --all-extras --group dev`,
`env -i`, `-n 4`. Selected families (dotnet tests, registry totality, corpus
consistency, operational consistency, resource-id conformance, both vocabulary
meta-tests): 585 selected, 582 passed, 3 failed, all three the hard-coded universe
counts and the offline-skip list named above. The dotnet scanner's own tests, its
sandbox test and its row in every facets gate pass. Whole-tree collect of tests/unit:
72850 collected, 1 collection error (`test_walked_package.py`, the PACKAGE_DIRS line).
The corpus-consistency gate also reads red for other scanners' rows on the
extract; those rows are not touched by this change.
