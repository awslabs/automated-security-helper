# M0 sample-run findings: the survey cells the captured fixtures settle

Unit M0 of the facets program. Each answer below
quotes the captured fixture committed beside it. Runs were performed on
2026-11-24 with these tool versions: trivy 0.76.2 and
opengrep 2.0.0 (binaries verified against the sha256 digests in
`automated_security_helper/utils/tool_downloads.py`), cfn-lint 1.61.0,
bandit 1.9.4, cfn-nag 0.8.10 (gem version pinned by `CFN_NAG_GEM_VERSION`).
Input fixtures are the small, clearly-labeled test files committed under each
scanner's directory; none describes real infrastructure.

## (a) trivy misconfig: JSON carries the terraform resource address; SARIF drops it — SETTLED

Fixtures: `trivy/captured/trivy-0.76.2-misconfig-terraform.{json,sarif}`, from
`trivy fs --scanners misconfig` over `trivy/fixture_repo_misconfig/main.tf`
(8 misconfigurations on one plain `aws_s3_bucket`).

- JSON: every misconfiguration carries the resource address as a structured
  field. First record, verbatim fields:
  `"Target": "main.tf"`, `"Class": "config"`, `"ID": "AWS-0086"`, and
  `"CauseMetadata": {"Resource": "aws_s3_bucket.m0_fixture_bucket",
  "Provider": "AWS", "Service": "s3", "StartLine": 6, "EndLine": 8, ...}`.
- SARIF: result keys are exactly `[level, locations, message, ruleId,
  ruleIndex]` — no property bag on results. The message text is
  `"Artifact: main.tf\nType: terraform\nVulnerability AWS-0086\nSeverity:
  HIGH\n..."`. The string `m0_fixture_bucket` occurs 0 times in the whole
  SARIF file.

Consequence for M3c: the resource exists natively and dies at the SARIF format
choice, so a trivy/trivy-repo misconfig attach is a side-`--format json` read,
the same two-report pattern as checkov's #1024. This applies to trivy-repo's
default run (misconfig is in its default scanner set).

## (b) cfn-nag: the logical id is a structured SARIF field, one result per id — SETTLED (recapture)

### On Homebrew portable-ruby, every scan FATALs

cfn-nag 0.8.10 is a Ruby gem. It installed cleanly on a Homebrew portable-ruby
3.4.5, but every scan of the valid template `cfn_nag/m0_fixture_bucket.yaml`
failed before producing findings. The JSON output, verbatim:

```text
"violations": [
  {
    "id": "FATAL",
    "name": "system",
    "type": "FAIL",
    "message": "#<NoMethodError: undefined method 'parse' for an instance of Psych::Parser>",
    "logical_resource_ids": [],
    "line_numbers": [],
    "element_types": []
  }
]
```

The SARIF output for the same run parses but carries 0 results, exits 1 and
writes nothing to stderr (`captured/cfn_nag-0.8.10-fatal-psych-portable-ruby-*`).
This is not a cfn-nag incompatibility with Ruby 3.4's Psych: the recapture below
shows that the Ruby build decides whether the scan FATALs, not the Ruby version.

### Recapture (2026-11-24, Linux x86_64)

A Ruby version constraint was considered as the fix. Measured, the Ruby version
is not the variable; the build is:

| Ruby | Build | cfn-nag 0.8.10 on `m0_fixture_bucket.yaml` |
|---|---|---|
| 3.4.5 | Homebrew portable-ruby bottle (sha256 `5ea0e3a3...705f5`) | FATAL, exit 1 |
| 3.3.8 | Homebrew portable-ruby bottle (sha256 `2449f1f4...35fd9a`) | FATAL, exit 1, same message in Ruby 3.3's quoting (`` `parse' ``) |
| 3.3.8 | built from the ruby-lang.org source tarball | 3 warnings, exit 0 |
| 3.4.5 | built from the ruby-lang.org source tarball | 3 warnings, exit 0 |
| 3.1.7 | built from the ruby-lang.org source tarball (the Ruby 3.1 line the container image installs) | 3 warnings, exit 0 |

The source-built SARIF and JSON outputs are byte-identical across the three
Rubies (sha256 `f805db7e...596b` and `11220284...ad6b`). What differs is the
build: cfn-nag pins `psych ~> 3`, so the gem-installed psych 3.3.4 loads next
to the Ruby's own Psych. On a portable-ruby bottle the interpreter's Psych is
linked into the `ruby` binary, its `Psych::Parser` (which defines
`_native_parse`) is already loaded, and psych 3.3.4's `parser.rb` expects the C
extension to define a public `parse`. On a portable-ruby bottle the loaded
`Psych::Parser` had public methods `[:external_encoding=, :handler, :handler=,
:mark]` and private `[:_native_parse, :initialize]`, and a `strings`-level grep
of the gem's `psych.so` found 0 occurrences of `_native_parse`. That mechanism
is a reading of this evidence; the measured fact is the table above.

Install details: gems were fetched from rubygems.org by exact version (the 18
versions `gem install cfn-nag -v 0.8.10` resolved) and installed with
`gem install --local` in dependency order, `GEM_HOME` per Ruby, `env -i`. Ruby
3.1.7 took `multi_json` 1.15.0 because 1.21.2 requires Ruby 3.2 or later. Ruby
3.4.5 needed its own gem directory on `GEM_PATH` for `bigdecimal` (a bundled gem
there). The source builds used libyaml 0.2.5 and OpenSSL 3.0.15, each built for
them.

Answer to question (b), quoted from `captured/cfn_nag-0.8.10-m0.sarif`
(`cfn_nag_scan --output-format sarif`), first of three results:

```text
"ruleId": "CFN_NAG_W51",
"level": "warning",
"message": {"text": "S3 bucket should likely have a bucket policy"},
"locations": [{
  "physicalLocation": {
    "artifactLocation": {"uri": "in/m0_fixture_bucket.yaml", "uriBaseId": "%SRCROOT%"},
    "region": {"startLine": 5}},
  "logicalLocations": [{"name": "M0FixtureBucket"}]}]
```

- The logical resource id is a structured SARIF field:
  `locations[0].logicalLocations[0].name` (`M0FixtureBucket`).
- It is one result per id, not a plural field. The two-resource fixture
  (`m0_fixture_two_buckets.yaml`, `captured/cfn_nag-0.8.10-two-buckets.*`) gives
  6 SARIF results for 3 rules over 2 buckets, each with a one-element
  `logicalLocations` (`M0FixtureBucketA` at line 8, `M0FixtureBucketB` at line
  12). The JSON format keeps one violation per rule with the plural
  `"logical_resource_ids": ["M0FixtureBucketA", "M0FixtureBucketB"]`,
  `"line_numbers": [8, 12]`, `"element_types": ["resource", "resource"]`.
- So SARIF is the route for resource identity (no second JSON read is needed):
  the id rides in the SARIF result the adapter already parses.
- Other cells the SARIF settles for this fixture: `region` carries `startLine`
  only (no column, no snippet); results carry no `fingerprints` and no
  `properties` bag; the driver is `{name, informationUri, semanticVersion}` and
  each rule is `{id, name, fullDescription}` (no `helpUri`, no tags). The
  `id` is `CFN_NAG_<rule>` in SARIF and `<rule>` in JSON.
- The exit status is the failing-violation count (`failure_count`); the three
  warnings exit 0.

A FATAL output is committed only as a named failure fixture
(`cfn_nag-0.8.10-fatal-psych-portable-ruby-*`), never as a golden the
conformance rows read. M3a can pick the SARIF route now.

## (c) cfn-lint: JSON `Location.Path` names the resource — SETTLED

Fixture: `cfn_lint_guard/captured/cfn-lint-1.61.0-m0-bad-property.json`, from
`cfn-lint --format json` over `cfn_lint_guard/m0_sources/m0_bad_property.yaml` (kept outside `repo/`, which the
cfn-lint and cfn-guard scanner tests copy whole and count templates in)
(one E3002). Verbatim:

```text
"Location": {
  "Path": ["Resources", "M0FixtureBucket", "Properties", "NotARealProperty"],
  ...
}
```

So cfn-lint's JSON format does name the logical resource id (second element of
`Path`), where its SARIF format carries only file/line. The survey's
`– (chosen format)` cell for cfn-lint resource identity is correct for SARIF,
and a D (mappable-but-dropped) state exists behind the `--format json` choice.

## (d) bandit `issue_severity` and opengrep `matchBasedId` — both SETTLED, both present

- Fixture: `bandit/captured/bandit-1.9.4-m0.sarif` (plus the plain-JSON run
  beside it), from `bandit --format sarif` over `bandit/m0_flagged.py`
  (3 results: B404, B602-family, B307-family). Every result carries a property
  bag, verbatim on the first result:
  `"properties": {"issue_confidence": "HIGH", "issue_severity": "LOW"}`.
  The snippet is also structured: `region.snippet.text` is
  `"import subprocess\n"` and a `contextRegion` is present. So
  `issue_severity` is a structured SARIF field, and the survey's `?` snippet
  cell for bandit resolves to present-in-SARIF.
- Fixture: `opengrep/captured/opengrep-2.0.0-m0.sarif`, from
  `opengrep scan --config m0_rule.yaml --sarif` over
  `opengrep/fixture_repo/m0_flagged.py` (1 result). Verbatim:
  `"fingerprints": {"matchBasedId/v1": "98cd472cc44dca3b970db0a43e1d4a90ad66611dfef5527ed8362e08b8eea1ca71444911398c2059ab5bb549b948963f59983a38be37ebd4acc914c6248396fa_0"}`.
  The fork emits a real match-based fingerprint — not the "requires login"
  placeholder semgrep OSS ships — so the opengrep `fngr ?` cell resolves to
  MAPPED-shaped (the value is usable the way semgrep's is, and
  `finding_identity`'s placeholder discard does not fire on it).

## (e) snyk-code characterization fixture — UNCONFIRMED (run not performed)

The `pytest -k snyk tests/unit/characterization` run did not happen. What the
tree showed, statically, on 2026-11-24:

- `tests/unit/characterization/` contains `_snyk_code_double.py` (a tool
  double) and only one test module (`test_harness_confinement.py`); no snyk
  test file exists there, so a `-k snyk` selection over that directory has no
  obvious test to match.
- The harness resolves committed fixtures at
  `FIXTURES_DIR = Path(__file__).with_name("fixtures")` (`_harness.py:403`),
  and that directory does not exist in the tree.
- `_snyk_code_double.py:72` calls `call.write_fixture(f"snyk/{self.sarif}",
  output)`, and `write_fixture` raises `ValueError(f"{name!r} is not a file
  under {FIXTURES_DIR}")` for a missing fixture file (`_harness.py:961-963`).

So any test that exercises the snyk double today would fail at fixture
resolution until `tests/unit/characterization/fixtures/snyk/results.sarif` is
committed; whether such a test is collected at all, and the committed tool
fixture itself, both remain to be produced by a rerun of this item.

## (f) Further cells read from tool output (2026-11-25)

Run on Linux x86_64. Tool versions as named; every tool ran offline over the
one-file inputs described.

- **trivy 0.76.2, `fs --scanners misconfig` in JSON and SARIF over four inputs**
  (sha256 of the release asset checked against the pin in `tool_downloads.py`).
  `Results[].Type` and `CauseMetadata.Resource`:

  | input | Type | Resource |
  |---|---|---|
  | `main.tf` (one `aws_s3_bucket`) | `terraform` | `aws_s3_bucket.m0_fixture_bucket` |
  | `t.yaml` (CloudFormation, one bucket) | `cloudformation` | `t.yaml:3-4` (a file and line range) |
  | `deploy.yaml` (a Deployment) | `kubernetes` | absent |
  | `Dockerfile` | `dockerfile` | absent |

  The failed records match the SARIF results one for one on (check id, file,
  start line, end line) for Terraform, CloudFormation and Kubernetes (8, 8 and
  17 keys, no orphan either way); the Dockerfile's JSON has a null line range
  on two records where its SARIF writes line 1. So only a `terraform` result is
  given a resource id: the CloudFormation value is a position, not the logical
  id.
- **semgrep 1.187.0 and opengrep 2.0.0 (the pinned release, sha256 checked), a
  rule with `fix: $X is None` over `if x == None:`**: the SARIF result keys are
  exactly `fingerprints, locations, message, properties, ruleId` in both. Neither
  writes `fixes`, so there is nothing for `fix_available` to map.
- **checkov 3.4.5 over the same four inputs, JSON**: `fixed_definition` is null
  on 34 of 34 records (terraform 7, cloudformation 6, kubernetes 19, dockerfile
  2). `code_block` spans the whole `file_line_range` (20 lines for the
  Deployment), and `guideline` is a policy-page URL on every record.
- **cfn-lint 1.57.2, `--format sarif` and `--format json` over
  `m0_sources/m0_two_bad_properties.yaml`**: the two reports are spelled alike
  (same file string, spans and message), so a finding is matched on rule, file,
  span and message. The JSON `Location.Path` is `["Resources", "<id>", ...]` for
  the two bucket findings and `["Parameters", "Unused", ...]` for the two
  parameter findings, which are in no resource.
- **guarddog scan output** (every committed `scan_*.json`): top-level keys are
  `errors, issues, package, results, risk_score, risks`, and `package` is the
  scanned directory path, so scan mode names no package or version.
