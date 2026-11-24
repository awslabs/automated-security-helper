# M0 sample-run findings: the survey cells the captured fixtures settle

Unit M0 of the facets program. Each answer below
quotes the captured fixture committed beside it. Runs were performed on
2026-11-24 on a disposable lane with these tool versions: trivy 0.76.2 and
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

## (b) cfn-nag: UNCONFIRMED — the tool could not be run to a real result

cfn-nag 0.8.10 is a Ruby gem. The run host has no system
Ruby; the gem installed cleanly on a portable Ruby 3.4.5 in the lane, but every
scan of the valid template `cfn_nag/m0_fixture_bucket.yaml` failed before
producing findings. The JSON output, verbatim:

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

The SARIF output for the same run parses but carries 0 results. The failure is
a cfn-nag 0.8.10 incompatibility with Ruby 3.4's Psych, not a template problem
(the same template lints clean apart from the deliberate cfn-lint error cases).
So the question — is the logical id a structured SARIF field or only
one-result-per-id multiplicity? — remains open, and no cfn-nag golden is
committed: a FATAL-error output must not become the fixture later conformance
rows read. Settling it needs a Ruby at or below the versions cfn-nag 0.8.10
supports (the project's container image installs it with Bundler against
`assets/Gemfile.lock`; a rerun inside that image, or on a host with an older
Ruby, is the route). M3a's route choice stays open until then.

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
checkout itself shows, statically, at this branch's base:

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
