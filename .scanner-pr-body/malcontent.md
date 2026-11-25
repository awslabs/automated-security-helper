## Malcontent alpha scanner plugin

Adds `ash_malcontent_plugins`, a community (alpha, opt-in) scanner that runs Chainguard's
[Malcontent](https://github.com/chainguard-dev/malcontent) (`mal analyze`) over the scan
target. Malcontent lists the capabilities of programs, scripts and archives with YARA-X
rules and gives each behavior a risk level, looking for supply-chain compromise (droppers,
obfuscation, exfiltration, persistence). Its `CRITICAL` findings "should be considered
malicious" and `analyze` is "paranoid", so low-risk behaviors map to INFO.

Enable it by listing `automated_security_helper.plugin_modules.ash_malcontent_plugins` in
`ash_plugin_modules`. A scan that does not list the module is unchanged.

### Tier and facets

- Tier: alpha, opt-in (`Tier.COMMUNITY_OPTIN`), user-installed CLI (Malcontent publishes no
  release binaries, so ASH pins and downloads nothing).
- Facets register row declared (`facets`): rule id, severity, file path, message, fingerprint,
  references and extras mapped; line, column, resource, package, CVE/CWE, fix and remediation
  facets n/a with reasons; the matched text (`MatchStrings`) is DROPPED by policy because it
  can quote a secret from the scanned tree. Resource identity: n/a (a finding names a file,
  not a deployable resource).
- Operational register row declared (`operational_facets`): bundled rules, no network,
  strict sandbox default, tool JSON converted to SARIF, severity native, exit code 0 only,
  computed fingerprint, no custom rules surface.

### MUST and HIGH rows fixed

- MUST, license gate fails open: the plugin claimed third-party rules "with licensing
  restrictions" were excluded because `--third-party` was never passed, but Malcontent's
  `--third-party` defaults to on. The argv now carries `--third-party=false`, the docstring,
  README and docs page say so, and the invocation test pins the token and the absence of the
  bare flag.
- MUST, committed failing test: `TestCommunityPlugin::test_declarations` compared the enum's
  value to `"BUNDLED"` (the value is `bundled`) and failed. It now compares the enum member.
- HIGH, sandbox-requirements test missing (PATTERN row 25): added
  `tests/unit/plugin_modules/test_malcontent_sandbox_requirements.py` (strict default, no
  network, baseline environment only), after the Betterleaks test.
- HIGH, no captured fixtures (rows 18, 21, 24): the test oracle is now Malcontent's own
  recorded `--format=json` output, not a hand-written report. There is no `mal` binary or
  release asset to capture from (GitHub releases v1.28.2 and earlier carry no assets;
  building needs Go, Rust and YARA-X; running the container image needs a separate
  approval), so two reports that upstream's test suite records
  (`tests/macOS/clean/ls.json`, six LOW behaviors; `tests/linux/2024.kubo_injector/injector.json`,
  sixteen behaviors from LOW to CRITICAL, no third-party rule) are committed under
  `tests/test_data/scanners/malcontent/recorded/`, with a README naming their source. The
  repository's JSON formatter re-sorted their keys; the parsed documents equal upstream's.
  `TestRecordedReports` converts them (one result per behavior, the severity tally, no
  matched text kept), and `TestUpstreamShape` pins the full member set seen across the
  eleven report files under upstream's `tests/` (440 behaviors; LOW 267, MEDIUM 144,
  HIGH 15, CRITICAL 14, upper-case, which `severity_for` lower-cases). The invocation was
  re-read against the v1.28.2 source (`cmd/mal/mal.go` flags, defaults and exit codes;
  `pkg/malcontent` structs; `pkg/render/json.go`). Still owed: a capture ASH makes itself,
  and a recorded negative, once someone can build or run `mal`; the README of the fixture
  directory says so.

- Two register defects the recorded reports exposed through the facets corpus check, both
  fixed in the module: the adapter wrote `region.startLine 1` for every behavior while the
  register declares `line_range` n/a, so the invented line is gone (a behavior is file-level);
  and `references` was declared mapped although the flat references column reads
  `relatedLocations` only, so it is now declared mappable-dropped with the reason (the rule
  `helpUri` still carries `RuleURL`).

### License posture

Malcontent is Apache-2.0 (per its README; the facet states `not read` because no pinned
upstream LICENSE was read). Nothing is downloaded and no Malcontent code or rule is
vendored; the two recorded reports are test data that name their source. The no-install design is
deliberate: ASH does not redistribute Malcontent or its rules, and it never enables the
third-party rule set (`--third-party=false`).

### Central registration owed (not made in this branch)

These edits sit outside the module, its tests and its facets, so an integration lane makes
them:

1. `automated_security_helper/utils/scanner_names.py`: add `"malcontent": "SAST",` to
   `SCANNER_TOOL_TYPES` (after `"betterleaks"`).
2. `tests/unit/walked_package.py`: add `"plugin_modules/ash_malcontent_plugins",` to the
   package list (PACKAGE_DIRS; its collection check fails without it).
3. Scanner-count tests: `== 22` becomes `== 23` in
   `test_scanner_facets_registry_totality.py`, `test_scanner_facets_corpus_consistency.py` and
   `test_scanner_operational_facets_consistency.py`.
4. `test_scanner_facets_corpus_consistency.py`: a `CORPORA` row
   `"malcontent": CorpusSpec("malcontent", prep="malcontent"),` and a registered prep (a
   `None` row would add a 21st red to the 20 existing ones, the same "mapped but no corpus"
   failure that detect-secrets and snyk-code show):

   ```python
   def _prep_malcontent(spec):
       from automated_security_helper.plugin_modules.ash_malcontent_plugins.malcontent_scanner import (
           convert_malcontent_report,
       )

       for path in sorted((_FIXTURES / spec.directory / "recorded").glob("*.json")):
           document = json.loads(path.read_text(encoding="utf-8"))
           report = SarifReport.model_validate(
               convert_malcontent_report(document, Path("."))
           )
           yield report, [r for run in report.runs or [] for r in run.results or []]
   ```

   plus `"malcontent": _prep_malcontent` in `_PREPS`.
5. `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`: a
   `LINK_HANDLING` row `"malcontent": FOLLOWS_NO_LINK` and a `SCANNER_CLASSES` row
   `"malcontent": ("ash_malcontent_plugins.malcontent_scanner", "MalcontentScanner", "Malcontent")`
   (use the module path form the other community rows use). The value is read from
   Malcontent v1.28.2 source, not measured on a binary (none exists to run):
   `pkg/action/path.go` `scanWalk.walk` skips every walked entry whose type is a symlink
   (`d.Type()&fs.ModeSymlink != 0` then `continue`, comment "Ignore symlinked directories
   like regular directories"), and `pkg/file/walk.go` documents a walker that does not follow
   symlinks below its start. ASH hands it a directory, so a link leaving the target is never
   read, and the command passes no exclusion. The module tests pin the argv half
   (`TestLinks`).

### Desk validation

dev-dsk-cbc4ff77, a repository extract of the branch tip with edits 1 to 5 applied in the
extract only, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`:

- Malcontent behavior tests, sandbox test, facets registry totality and resource-id
  conformance, operational facets consistency, facets corpus consistency, link-handling
  registry test: 578 passed, 2 skipped, 20 failed. The 20 are
  `test_declared_facets_agree_with_the_observed_corpus` for the existing scanners, none
  for malcontent (the same 20 fail on `origin/main` content; a `None` corpus row for
  malcontent made it a 21st before the recorded reports and edit 4's prep).
- The converter run over all eleven report files in upstream's `tests/` (kept outside the
  repository): 440 behaviors in, 440 results out, no region on any, severities INFO 267,
  MEDIUM 144, HIGH 15, CRITICAL 14.
- Whole-tree collect smoke (`pytest --collect-only -q tests/unit`): 72,856 tests collected
  with edit 2 applied; without it the collection stops on the PACKAGE_DIRS check.
- The extract was removed and its absence read back.
