## Add the skillcheck agent-skill scanner as an alpha plugin module

### What it scans

`skillcheck --json --no-color --project=<scan target>` (Mondoo's
[skillcheck](https://github.com/mondoohq/skillcheck), a Go binary, Apache-2.0, built and measured
against release `v0.4.0`). It reads the target's agent skills (`SKILL.md` files and `.skill`
packages). For each skill the tool SHA-256-hashes the content and looks the hash up in the Mondoo AI
Agent Security database, and runs the Agent Skills specification checks. The report on stdout is
converted to SARIF by `convert_report`.

It is not the PyPI package `skillcheck` (a SKILL.md lint gate by another author, 1.5.0) and not
`sx4im/skillcheck`. Neither is installed, read or wrapped; a test pins that the module names no
install command at all.

### Tier

Alpha, opt-in. The scanner loads only when `ash_skillcheck_plugins` is listed in
`ash_plugin_modules` (or passed with `--ash-plugin-modules`). A scan that does not list the module
is unchanged.

### What the tool does and does not detect

The tool matches no content pattern. A skill is flagged because the database holds a report for its
hash, so a skill carrying a marker string, or any new malicious skill, reads as `unknown` (clean)
until the database has seen it. The seeded-marker unit test therefore has two halves: the marker
skill the test writes is NOT flagged when the database answers `unknown`, and IS flagged (CRITICAL)
when the answer is a database verdict. The verdict record is SCHEMA-DERIVED (see Fixtures).

### Severity

- Database verdict (`status` affected, or top severity critical or high, the tool's own exit
  gate): critical CRITICAL, high HIGH, medium MEDIUM, low LOW; a missing or unknown severity on an
  affected skill is HIGH (errs severe).
- Specification finding: conformance lint ("a malformed skill is not a malicious one", the tool's
  words), so capped: critical and high MEDIUM, medium LOW, low INFO; unknown severity HIGH.

### Facets

Both register rows are declared on the class (`facets`, `operational_facets`).

- Mapped: rule id, severity, file path, message, fingerprints (adapter-computed from rule, path and
  skill name; the content hash is left out), tags, extras.
- Dropped: references (the report URL stays in the result properties).
- N/A: line range and column (the report names a file only), resource id and type, package fields,
  CVE and CWE taxonomy, fix state, remediation text, snippet (the tool sends hashes, not content).
- Operational: runtime `user_installed_cli`, provenance `user_installed`, exit codes (0, 1), severity
  class derived, network `content_fetch` (hash lookup), offline outcome `not_run`
  (`SKIP_OFFLINE`), sandbox network online.

### License posture row

The tool is Apache-2.0 (the repository LICENSE at `v0.4.0` is the Apache License 2.0 text; GitHub and
npm agree). Nothing read forbids an install-time download, so no no-install gate is needed. Even so,
this module does not provision the binary: a pinned-asset install needs `tool_downloads.py`
entries and a `THIRD_PARTY_LICENSES` entry, the second of which is licensing material under the
2026-11-25 standing rule and waits for an explicit per-change approval. `custom_install_commands`
stays empty on purpose; a missing binary logs the release page and the version tested. No license
file, notice or tool material is committed. The release archive was fetched on the desk to take the
captures, checked against the release's `checksums.txt`
(`3f3fa982898a438078dafe4d13a7c47adfc6acbab89a58b6f71f08a39fe05528`, linux/amd64) and left there.

### Network posture row

The tool makes one network call per skill: `GET https://mondoo.com/ai-agent-security/api/v1/search/hash?q=<sha256>`
(10 s timeout), which sends the content hash and never the content. It makes no LLM call. It fails
open: when the lookup cannot be made the skill reads `unknown`, so an unreachable database looks the
same as a clean run, and ASH cannot tell them apart from the output. Because a run without the lookup
says nothing about malice:

- `offline_strategy` is `SKIP_OFFLINE` and the `offline` option defaults to False (an offline scan
  skips the scanner; the specification checks alone are not run in its place);
- the sandbox declares `SandboxRequirements(network=True)` and nothing else (no read paths, env names
  or prefixes);
- the tool runs with `HOME` and `USERPROFILE` set to a new empty directory. Without `--project` it
  reads 25 agents' directories under the home directory, and the capture `home_leak.json` shows the
  tool reporting a home's `.claude/skills` as a second agent beside the project. Any non-`Project`
  agent in the output is dropped with a warning;
- the spawn passes the operator's delivery variables through to the tool — the proxy family
  (`PROXY_ENV_NAMES`; Go's default transport honors them) and the CA-bundle names
  (`CA_BUNDLE_ENV_NAMES`) read from `snapshot_environ` — so the lookup works behind a proxy or a
  private CA instead of failing open there. Nothing else of the parent environment reaches the
  tool: no token, and not the real `HOME`;
- there are no options that point at a file or switch off a check, so no trust-gated pointers
  (PATTERN 6c) and no denied-path rows are owed.

### Exit status

Exit 1 means "a critical or high verdict" OR "the tool failed" (`--project` at a path that is not a
directory exits 1 with nothing on stdout). Both 0 and 1 are success codes, told apart by the output:
exit 1 without a printed report that holds a critical or high verdict fails the scan, and any other
code fails it. Output that is not the v0.4.0 report shape fails closed, with the tool's text never
quoted.

### Fixtures

- Captured (real `v0.4.0` output, desk `dev-dsk-d14420e2`, `env -i`, empty `HOME`, network on):
  `benign.json`, `spec_violation.json`, `home_leak.json`, over the committed inputs in
  `tests/test_data/scanners/skillcheck/fixture_repo`. The failure run is recorded in the capture
  README. The repository's `pretty-format-json` hook sorted the keys.
- SCHEMA-DERIVED: `affected_schema_derived.json`, written from the `SkillResult` struct at `v0.4.0`
  with synthetic names, hashes and URLs. A real database verdict cannot be produced from any input
  built here.

### Open points

- No run with the network blocked was captured; the fail-open reading is from `client.go` at
  `v0.4.0`, not from a blocked run.
- The tool's schema is not versioned; the parser is written to v0.4.0 and fails closed on a shape it
  does not recognize. A pin move needs a new capture.
- No pinned download (see the license row).

### Central registration owed (outside this module, for the integration lane)

One line each:

1. `automated_security_helper/core/scanner_inventory.py`
   `_VENDORED_SCANNER_PLUGIN_PACKAGES`: add
   `"automated_security_helper.plugin_modules.ash_skillcheck_plugins",` (alphabetical).
2. `tests/unit/cli/mcp/list_scanners_import_order_probe.py`: add `"skillcheck_scanner"` to the leaf
   tuple at the same position and bump the counts.
3. `tests/unit/cli/mcp/test_list_scanners.py` `_expected_entries()`: add
   `"skillcheck": (None, False, False),` (a user-installed binary found on PATH, as for snyk-code).
4. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add
   `"skillcheck": "SAST",` and the docstring list.
5. `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `"plugin_modules/ash_skillcheck_plugins",`.
6. `automated_security_helper/config/runtime_patch.py` `_SHIPPED_PLUGIN_KEYS`: add `"skillcheck"`,
   and the `tests/unit/config/test_runtime_patch.py` scanners-dict row
   (`SkillcheckScannerConfig().model_dump(by_alias=True)`).
7. `automated_security_helper/config/client_config_policy.py` `PLUGIN_OPTION_DEFAULTS`: add
   `("skillcheck", "offline"): False,`.
8. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: a `CORPORA` row
   `"skillcheck": CorpusSpec("skillcheck", prep="skillcheck")`, a `_prep_skillcheck` that feeds the
   three `captured/*.json` documents through `convert_report`, and the `_PREPS` entry.
9. The "22 shipped scanners" counts become 23 in `test_scanner_facets_corpus_consistency.py`,
   `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`;
   in the last, `test_the_service_upload_scanner_is_the_one_that_skips_offline` lists
   `["npm-audit", "skillcheck", "snyk-code"]`, and `_NATIVE_FIXTURES` gains
   `"skillcheck": ("skillcheck/captured/spec_violation.json", opsf.OutputFormat.TOOL_JSON)`.
10. `tests/unit/config/test_off_host_plugins_are_operator_only.py`: classify
    `("scanners", "skillcheck")`. Recommended OFF_HOST ("the SHA-256 of each skill, sent to the
    Mondoo database"), which also puts the section in `ALWAYS_DENIED_PATHS`
    (`automated_security_helper/config/ash_config.py`) so a client's overrides cannot enable it or
    change it. A decision for the maintainer, because it changes what a client may configure.
11. `.ash/.ash_community_plugins.yaml`, the optional hand-kept tables
    (`test_scan_phase_community_modules.py`, `test_off_host_plugin_modules_from_repo_config.py`),
    the community docs page, `index.md`, `scanner-sandbox.md`, `coverage.md`, `CHANGELOG.md` and the
    regenerated references: the same accept-the-gap-or-add-a-row status as the alpha wave.

Applied in the desk extract only (not committed), rows 1, 4, 5, 8 and 9 turn every skillcheck-related
failure in the families below green.

### Desk validation (dev-dsk-d14420e2, repository extract, uv sync --frozen --all-extras --group dev, env -i, lane under /run/user/23503848)

- Module tests (`ash_skillcheck_plugins`, `test_skillcheck_sandbox_requirements.py`): 70 passed, 0 failed.
- Module plus the facets families (registry totality, operational consistency, corpus consistency,
  resource-id conformance, facet cells settled at the bytes) plus `test_list_scanners_import_order.py`
  and `test_scanner_names_registry_agreement.py`, tip as committed, no central edit: 574 passed,
  7 failed, 2 skipped. The 7 are all central rows: the three 22-to-23 counts and the service-upload
  skip list (row 9), the `SCANNER_TOOL_TYPES` KeyError (row 4), the corpus-table row (row 8) and the
  vendored-list test (row 1).
- The same set with central rows 1, 4, 5, 8 and 9 applied in the desk extract only: 582 passed,
  0 failed, 2 skipped.
- `test_declared_facets_agree_with_the_observed_corpus[skillcheck]` passes with row 8 applied (the
  corpus prep feeds the three captures through `convert_report`). The 20 pre-existing reds of that
  test did not appear in this extract's run; none was investigated.
- Whole-tree collect smoke (git-initialized extract): 74802/74847 collected, 0 errors with the
  central rows applied. Without row 5 the walked-package guard raises one collection error naming
  `plugin_modules/ash_skillcheck_plugins`.
- `ruff format --check` and `ruff check` over the module and tests: clean (also run by the commit
  hooks). The conflict-marker scan over the module, tests, fixtures and this file read 0, with a
  planted file read as 3 in the same batch.
- The desk extract, lane and downloaded release were removed by literal path and the absence read
  back.

### Fix-forward round (post-build review)

The review of the branch tip `f4cd8165b1e` read FIX-NEEDED with one HIGH, fixed here as a
fix-forward commit on this branch:

- HIGH (fixed): the spawn env was the bare dict `{"HOME": ..., "USERPROFILE": ..., "NO_COLOR": "1"}`
  on both spawn paths, so `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` and the CA-bundle variables never
  reached the tool. Behind proxy-only egress every hash lookup then failed open, and a
  database-known malicious skill read `unknown` — a clean-looking run indistinguishable from a real
  one. The env now allowlists `PROXY_ENV_NAMES` + `CA_BUNDLE_ENV_NAMES` from `snapshot_environ`,
  with `HOME`/`USERPROFILE` still overridden and everything else still dropped. Two new tests pin
  the pass-through and the allowlist bound.

Carried LOW rows from the same review (recorded, not fixed in this round):

1. `test_a_missing_binary_is_reported_with_the_release_page` requests `caplog` and never reads it,
   so the "reported with the release page" half of its name (the `ASH_LOGGER.warning` naming the
   releases page and the tested version) cannot fail; the only assertion is
   `validate_plugin_dependencies()` is False.
2. On Windows (the tool publishes darwin, linux and windows builds) the tool's backslash paths make
   `_relative_uri`'s `PurePosixPath(...).relative_to(...)` raise for every skill, so every finding's
   uri degrades to `.` — findings survive, locations are lost. By the bytes only; no Windows
   capture exists.
3. The module docstring's parenthetical "(the tool's own exit gate)" attaches to the whole
   "affected or critical/high" disjunction, but upstream `reporter.go` `HasCriticalOrHigh` at
   v0.4.0 reads `topSeverity` only and never `status`; `_is_blocking` correctly mirrors the real
   gate, so a maintainer "aligning" `_is_blocking` with that sentence would wrongly widen the
   exit-1 acceptance. Doc imprecision only; the code is correct.
4. The outbound half of the lookup (each skill's SHA-256 leaves the host as the query) has no
   `Fetched` member to declare it — `SOURCE_UPLOAD` is validator-paired with `SERVICE_UPLOAD` and a
   hash is not the source — so that direction lives in prose only (the offline reason, this file's
   row 10 OFF_HOST recommendation). A facet-vocabulary gap, not a misdeclaration; npm-audit
   (`CONTENT_FETCH` + `NOT_RUN`) is the precedent.
5. The namesake install guard (`pip install`/`uvx`/... not in source) scans the module source only;
   README.md and this file (the install texts an operator reads) are outside it, so a later README
   edit could introduce `pip install skillcheck` (the PyPI namesake) unguarded. Today both texts are
   clean and the guard can fail on the module.

### Desk validation of the fix-forward round (dev-dsk-d14420e2)

Same discipline as the build run: repository extract (shallow clone of this branch), `uv sync
--frozen --all-extras --group dev` (Python 3.12.15), `env -i` with HOME/USER/PATH/CI=1/TMPDIR, lane
under `/run/user/23503848`, `--basetemp` in the lane.

- Red proof: with the pre-fix module checked out at `f4cd8165b1e` under the new tests, the proxy
  pass-through test fails (`KeyError: 'HTTPS_PROXY'`); the allowlist-bound test passes there too, as
  expected (the bare dict is a subset of the allowlist).
- Green: module family (`ash_skillcheck_plugins` plus `test_skillcheck_sandbox_requirements.py`,
  the two new tests included) at the fixed tip: 72 passed, 0 failed.
- `ruff format --check` and `ruff check` over the changed module and test file: clean (also run by
  the commit hooks).
- Conflict-marker scan over the changed module, tests and this file: 0, with a planted control file
  read as 3 in the same batch.
- The desk lane and extract were removed by literal path and the absence read back.
