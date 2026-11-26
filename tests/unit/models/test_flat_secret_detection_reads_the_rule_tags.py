"""A trivy secret is a secret detection in the flat finding model as well.

trivy's secret scanner, and the alpha scanner ``trivy-repo`` that runs the same
engine, mark a finding as a secret only on the rule's descriptor: the rule
``github-pat`` carries the tags ``secret``, ``security`` and ``CRITICAL``, while
the result itself carries no secret tag and no fingerprint. When a scanner's
SARIF is merged into ``AshAggregatedResults`` its driver, rules included, lands
in the aggregate run's ``tool.extensions``, and two consumers already read the
tags there: the secret masking (``utils/secret_masking``, through
``report_secret_rule_ids``) and the Bedrock summary reporter
(``is_secret_detection`` with ``secret_detection_rule_ids``). Both call that
result a secret.

``FlatVulnerability.from_sarif_result`` classifies one result at a time, and a
trivy result carries no mark of its own, so the secret-detection flag reads the
tags of the rule the result names in its own run and tool component
(``is_secret_detection_of_rule``). What it sets from that answer is read
elsewhere:

* the baseline gate (``utils/scan_baseline``) matches a secret detection only by
  exact identity, and only when both sides carry a fingerprint, never line-free,
  so a trivy secret classified as an ordinary finding was matched to a baseline
  after it moved lines, or at the same line without a fingerprint;
* the ``secret/`` correlation id belongs to a secret detection, so a trivy
  secret classified as an ordinary finding got no correlation id where gitleaks
  reports the same file and line (a finding with no advisory, package or
  version has no ``dep/`` id either);
* a secret finding's fallback snippet (``properties.snippet``) is masked whole
  by the flat findings on their own, whether or not the masking pass has run;
  which findings those are follows the masking's reading of the report's rule
  ids (``report_secret_rule_ids``).

The flag reads each result's own rule, not every rule of the report that shares
its id. It agrees with the Bedrock summary reporter on trivy's secret findings.
Unlike the reporter, it does not make a finding a secret detection because a
rule of another scanner under the same id is tagged (grype, trivy and npm-audit
can name one advisory by one id), nor a dependency advisory one because of a CWE
its rule names (npm-audit writes an advisory's CWE ids as tags of its rule). A
code scanner's finding whose own rule is tagged CWE-798 or CWE-321 is one.

The controls beside these must not move: a dependency advisory is not a secret
detection whatever CWE its rule names, its excerpt is masked only when the
masking takes it for a secret, and the baseline gate still matches an ordinary
finding that moved.
"""

from __future__ import annotations

import copy
import functools
import json
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.finding_identity import SECRET_CORRELATION_PREFIX
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.scan_baseline import ScanBaseline, apply_baseline
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    is_secret_detection,
    mask_secrets_in_results,
    secret_detection_rule_ids,
)

pytestmark = pytest.mark.unit

TEST_DATA = Path(__file__).resolve().parents[2] / "test_data"
TRIVY_SECRET_FIXTURE = (
    TEST_DATA / "images" / "captured" / "trivy-0.76.2-secret-image.sarif"
)
TRIVY_VULNERABILITY_FIXTURE = (
    TEST_DATA / "scanners" / "trivy" / "trivy-0.69.3.vuln.sarif"
)

#: The two scanners whose SARIF marks a secret on the rule's descriptor alone.
SECRET_SCANNERS = ("trivy", "trivy-repo")

#: Text for a snippet slot. Neither has the shape of a token.
PLANTED = "planted-not-a-real-token"
ADVISORY_SNIPPET = "lodash 4.17.20"


@functools.cache
def _parsed(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _load(path: Path) -> dict:
    return copy.deepcopy(_parsed(path))


def _first_result(document: dict) -> dict:
    return document["runs"][0]["results"][0]


def _place(result: dict, start_line: int, end_line: int) -> None:
    region = result["locations"][0]["physicalLocation"]["region"]
    region["startLine"] = start_line
    region["endLine"] = end_line


def trivy_secret(
    start_line: int = 1,
    partial_fingerprint: str | None = None,
    snippet: str | None = None,
) -> dict:
    """The captured trivy secret run: one rule (``github-pat``), one result."""
    document = _load(TRIVY_SECRET_FIXTURE)
    result = _first_result(document)
    _place(result, start_line, start_line)
    if partial_fingerprint is not None:
        result["partialFingerprints"] = {"key": partial_fingerprint}
    if snippet is not None:
        result.setdefault("properties", {})["snippet"] = snippet
    return document


def trivy_vulnerability(
    start_line: int = 13,
    end_line: int = 17,
    snippet: str | None = None,
    first_rule_description: str | None = None,
) -> dict:
    """The first result of the captured trivy vulnerability run (CVE-2021-23337,
    lodash 4.17.20, package-lock.json lines 13-17), with the run's rules as
    captured. ``first_rule_description`` replaces that rule's short description.
    """
    document = _load(TRIVY_VULNERABILITY_FIXTURE)
    run = document["runs"][0]
    run["results"] = run["results"][:1]
    result = _first_result(document)
    _place(result, start_line, end_line)
    if snippet is not None:
        result.setdefault("properties", {})["snippet"] = snippet
    if first_rule_description is not None:
        rule = run["tool"]["driver"]["rules"][0]
        rule["shortDescription"]["text"] = first_rule_description
    return document


def gitleaks_secret() -> dict:
    """A dedicated secrets scanner's finding at the place the trivy fixture
    reports one. The rule has no tags and the result no fingerprint."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitleaks",
                        "rules": [{"id": "github-fine-grained-pat"}],
                    }
                },
                "results": [
                    {
                        "ruleId": "github-fine-grained-pat",
                        "level": "error",
                        "message": {"text": "A GitHub access token was found."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "/app/creds.txt",
                                        "uriBaseId": "ROOTPATH",
                                    },
                                    "region": {
                                        "startLine": 1,
                                        "endLine": 1,
                                        "startColumn": 1,
                                        "endColumn": 1,
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


#: An advisory id for the tests below. It is invented and names no CVE, so the
#: ``dep/`` correlation key (advisory, package and version: ``dep_correlation_key``)
#: is empty and a finding of it has no correlation id, unless it is read as a
#: secret detection.
GHSA = "GHSA-aaaa-bbbb-cccc"

#: A semgrep rule for a hard-coded JWT secret and the tags semgrep writes on it.
#: Its id has no ``secrets`` segment, so only the CWE tag marks it as a detection.
JWT_RULE = "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret"
JWT_TAGS = [
    "CWE-798: Use of Hard-coded Credentials",
    "OWASP-A07:2021 - Identification and Authentication Failures",
    "security",
]

#: A semgrep rule for a hard-coded password, as a linter raises it on a name such
#: as ``password`` whatever the value is. Its id has no ``secrets`` segment either.
DEFAULT_ARGUMENT_RULE = "python.lang.security.audit.hardcoded-password-default-argument"


def npm_audit_advisory(
    rule_id: str,
    cwe_tags: list[str],
    start: int = 13,
    end: int = 17,
    fingerprint: str = "f1",
) -> dict:
    """An npm-audit advisory in the shape the scanner writes it: the advisory's CWE
    ids are tags of the rule (``npm_audit_scanner._cwe_tags``) and the result
    carries none, the package is lodash 4.17.20 at ``package-lock.json``, and the
    partial fingerprint is the one ASH composes. Nothing in the rule describes a
    credential."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "npm-audit",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": f"npm-audit-{rule_id}",
                                "shortDescription": {
                                    "text": "Weak default configuration in lodash"
                                },
                                "fullDescription": {
                                    "text": "Vulnerability in lodash: Weak default "
                                    "configuration in lodash"
                                },
                                "properties": {
                                    "tags": [
                                        "security",
                                        "npm-audit",
                                        "high",
                                        *cwe_tags,
                                        "tool_name::npm-audit",
                                        "tool_type::SCA",
                                    ]
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {
                            "text": "Weak default configuration in lodash <4.17.21. "
                            f"https://github.com/advisories/{rule_id}"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "package-lock.json"},
                                    "region": {"startLine": start, "endLine": end},
                                }
                            }
                        ],
                        "partialFingerprints": {"ashNpmAuditFinding/v1": fingerprint},
                        "properties": {
                            "package_name": "lodash",
                            "package_version": "4.17.20",
                            "severity": "high",
                        },
                    }
                ],
            }
        ],
    }


def trivy_advisory(rule_id: str, start: int = 13, end: int = 17) -> dict:
    """The first result of the captured trivy vulnerability run, with its rule id
    replaced (trivy names an advisory with no CVE by its GHSA id) on the rule and
    on the result, and the package properties trivy's adapter writes. The rule
    keeps its tags (``vulnerability``, ``security``, ``HIGH``) and the result has
    no fingerprint."""
    document = trivy_vulnerability(start_line=start, end_line=end)
    document["runs"][0]["tool"]["driver"]["rules"][0]["id"] = rule_id
    result = _first_result(document)
    result["ruleId"] = rule_id
    result["properties"] = {"package_name": "lodash", "package_version": "4.17.20"}
    return document


def semgrep_finding(
    rule_id: str,
    tags: list[str],
    start: int = 10,
    *,
    short_description: str | None = None,
) -> dict:
    """A semgrep OSS result: the rule carries ``tags``, the result carries none,
    and the fingerprint is the ``requires login`` placeholder semgrep writes
    without a login, which the identity ignores
    (``finding_identity.PLACEHOLDER_FINGERPRINT_VALUES``). The message is semgrep's
    text for a hard-coded credential rule. ``short_description`` replaces the
    rule's short description."""
    description = short_description or f"Semgrep Finding: {rule_id}"
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": rule_id,
                                "shortDescription": {"text": description},
                                "properties": {"tags": list(tags)},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {
                            "text": "A hard-coded credential was detected. It is "
                            "not recommended to store credentials in source-code."
                        },
                        "fingerprints": {"matchBasedId/v1": "requires login"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/auth.js"},
                                    "region": {
                                        "startLine": start,
                                        "endLine": start,
                                        "startColumn": 5,
                                        "endColumn": 30,
                                        "snippet": {"text": "jwt.sign(p, cfg.key)"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def sast_finding(rule_id: str, scanner_driver_name: str, start: int = 7) -> dict:
    """One result of a static analysis scanner at ``src/app.py``. The scanner's own
    driver declares the rule, with no tags."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": scanner_driver_name,
                        "rules": [{"id": rule_id}],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {"text": "A static analysis rule matched."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": start, "endLine": start},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def aggregate(*parts: tuple[dict, str]) -> AshAggregatedResults:
    """The scanners' SARIF merged as a scan merges it: each driver, rules
    included, joins the aggregate run's ``tool.extensions``."""
    model = AshAggregatedResults()
    for document, scanner in parts:
        report = attach_scanner_details(
            SarifReport.model_validate(copy.deepcopy(document)),
            scanner_name=scanner,
            scanner_version="0.76.2",
        )
        model.sarif.merge_sarif_report(report)
    # The baseline gate counts only the baseline findings of scanners that
    # completed.
    model.scanner_results = {
        scanner: ScannerTargetStatusInfo(status="PASSED") for _, scanner in parts
    }
    return model


def results_left(model: AshAggregatedResults) -> list:
    return [result for run in model.sarif.runs for result in (run.results or [])]


def gate_scans(
    baseline_parts: list[tuple[dict, str]], current_parts: list[tuple[dict, str]]
):
    """``apply_baseline`` of a current scan against a baseline, each a list of
    ``(document, scanner)`` parts merged as :func:`aggregate` merges them.

    Returns the outcome and the results left in the current scan. A baseline is
    read from a file, and ``AshAggregatedResults.model_post_init`` masks every
    model it builds, so the baseline is masked before it is flattened here;
    ``apply_baseline`` masks the current results itself.
    """
    old = aggregate(*baseline_parts)
    mask_secrets_in_results(old)
    current = aggregate(*current_parts)
    baseline = ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))
    outcome = apply_baseline(current, baseline)
    return outcome, results_left(current)


def gate(baseline_document: dict, current_document: dict, scanner: str):
    """``gate_scans`` of one scanner's current scan against its baseline."""
    return gate_scans([(baseline_document, scanner)], [(current_document, scanner)])


def left_names(left: list) -> list[str]:
    """The results the gate left, as ``scanner:rule`` text, so that an assertion
    over them names what stayed in the report."""
    return sorted(
        f"{result.properties.scanner_name}:{result.ruleId}" for result in left
    )


def flat_snippet(document: dict, scanner: str) -> str | None:
    """The flat finding's ``code_snippet`` for the scanner's only result, from a
    report the masking pass has not run on."""
    (finding,) = aggregate((document, scanner)).to_flat_vulnerabilities()
    return finding.code_snippet


# ---------------------------------------------------------------------------
# the classification


@pytest.mark.parametrize("scanner", SECRET_SCANNERS)
def test_a_trivy_secret_is_a_secret_detection_in_the_flat_model(scanner):
    """trivy tags the rule and nothing else. The masker and the Bedrock reporter
    read that tag, and the flat finding reads it too."""
    (finding,) = aggregate((trivy_secret(), scanner)).to_flat_vulnerabilities()

    assert finding.is_secret_detection is True
    assert finding.requires_exact_identity_match is True


def test_the_flat_model_classifies_a_mixed_report_as_the_bedrock_reporter_does():
    model = aggregate((trivy_secret(), "trivy"), (trivy_vulnerability(), "trivy"))
    rule_ids = secret_detection_rule_ids(model.sarif)
    reporter = [
        is_secret_detection(result, rule_ids)
        for result in model.sarif.get_all_results()
    ]
    flat = model.to_flat_vulnerabilities()

    # The reporter already reads the rule tags, so the comparison below is not
    # between two lists of False.
    assert reporter == [True, False]
    # The flat rows are the SARIF results in get_all_results order.
    assert [finding.rule_id for finding in flat] == ["github-pat", "CVE-2021-23337"]
    assert [finding.is_secret_detection for finding in flat] == reporter


@pytest.mark.parametrize("scanner", SECRET_SCANNERS)
def test_a_trivy_secret_has_the_correlation_id_a_secrets_scanner_gives_it(scanner):
    """Two scanners that report a secret at one file and line share one
    ``secret/`` correlation id, whichever scanner and rule found it."""
    model = aggregate((trivy_secret(), scanner), (gitleaks_secret(), "gitleaks"))
    by_scanner = {
        finding.scanner: finding for finding in model.to_flat_vulnerabilities()
    }
    gitleaks = by_scanner["gitleaks"]
    trivy = by_scanner[scanner]

    assert (gitleaks.correlation_id or "").startswith(SECRET_CORRELATION_PREFIX)
    assert trivy.correlation_id == gitleaks.correlation_id


def test_a_trivy_vulnerability_is_no_secret_detection_and_has_no_secret_id():
    (finding,) = aggregate((trivy_vulnerability(), "trivy")).to_flat_vulnerabilities()

    assert finding.is_secret_detection is False
    assert finding.requires_exact_identity_match is False
    assert not (finding.correlation_id or "").startswith(SECRET_CORRELATION_PREFIX)


# ---------------------------------------------------------------------------
# the baseline gate


@pytest.mark.parametrize("scanner", SECRET_SCANNERS)
def test_the_baseline_keeps_a_trivy_secret_that_moved(scanner):
    """A secret detection is matched by exact identity only, never line-free."""
    outcome, left = gate(
        trivy_secret(start_line=1), trivy_secret(start_line=5), scanner
    )

    assert (outcome.matched, outcome.matched_without_lines) == (0, 0)
    assert len(left) == 1


@pytest.mark.parametrize("scanner", SECRET_SCANNERS)
def test_the_baseline_keeps_a_trivy_secret_with_no_fingerprint_at_the_same_line(
    scanner,
):
    """An exact match is not enough for a secret detection: both sides must also
    carry a fingerprint identity, and the line alone is not one."""
    outcome, left = gate(trivy_secret(), trivy_secret(), scanner)

    assert outcome.matched == 0
    assert len(left) == 1


@pytest.mark.parametrize("scanner", SECRET_SCANNERS)
def test_the_baseline_drops_a_fingerprinted_trivy_secret_at_the_same_line(scanner):
    """The exact-identity path still covers a secret both scans fingerprint."""
    outcome, left = gate(
        trivy_secret(partial_fingerprint="p"),
        trivy_secret(partial_fingerprint="p"),
        scanner,
    )

    assert outcome.matched == 1
    assert left == []


def test_the_baseline_still_drops_a_trivy_vulnerability_that_moved():
    """The control: an ordinary finding that only moved is matched line-free."""
    outcome, left = gate(
        trivy_vulnerability(start_line=13, end_line=17),
        trivy_vulnerability(start_line=40, end_line=44),
        "trivy",
    )

    assert (outcome.matched, outcome.matched_without_lines) == (1, 1)
    assert left == []


# ---------------------------------------------------------------------------
# the fallback snippet
#
# These flatten the merged report without the masking pass, so they pin what the
# flat findings do on their own, as
# ``test_flat_secret_findings_fallback_snippet_is_masked`` does with a bare
# result: the excerpt agrees with the masking's classification whether or not
# that pass has run.


@pytest.mark.parametrize("scanner", SECRET_SCANNERS)
def test_the_fallback_snippet_of_a_trivy_secret_is_masked_whole(scanner):
    """A secret finding's fallback snippet is masked whole by the flat finding,
    and trivy's result is a secret finding only by its rule's tags, so the flat
    finding agrees with the masking's classification only if it reads the
    report's rule ids."""
    document = trivy_secret(snippet=f'token = "{PLANTED}"')

    assert flat_snippet(document, scanner) == MASKED_LINE


def test_the_fallback_snippet_of_a_trivy_vulnerability_is_kept():
    """The control: an advisory's excerpt is not a secret finding's."""
    document = trivy_vulnerability(snippet=ADVISORY_SNIPPET)

    assert flat_snippet(document, "trivy") == ADVISORY_SNIPPET


def test_the_fallback_snippet_of_an_advisory_that_describes_a_credential_is_kept():
    """The flat excerpt agrees with the masking's classification. An advisory
    whose rule describes a credential ("Hard-coded credentials in
    configuration") is among the masking's secret rule ids by that description
    only, and the masking does not take a dependency advisory for a secret in
    the scanned files (``_DEPENDENCY_TOOL_TYPES``, ``is_secret_finding``), so the
    flat finding does not mask the advisory's excerpt either."""
    document = trivy_vulnerability(
        snippet=ADVISORY_SNIPPET,
        first_rule_description="Hard-coded credentials in configuration",
    )

    assert flat_snippet(document, "trivy") == ADVISORY_SNIPPET


# ---------------------------------------------------------------------------
# the flag reads each result's own rule
#
# A report-wide set of rule ids is keyed by the bare id of a rule, across every
# scanner's rules. The flag is read from the rule the result names in its own run
# and tool component, which two scanners that name one advisory by one id do not
# share, and a dependency advisory is not a secret detection by a CWE its rule
# names.


@pytest.mark.parametrize("cwe", ("CWE-798", "CWE-321"))
def test_an_advisory_whose_rule_names_a_credential_cwe_is_no_secret_detection(cwe):
    """npm-audit writes an advisory's CWE ids as tags of its rule
    (``npm_audit_scanner._cwe_tags``). The CWE names a weakness of the dependency,
    not a value in the scanned files, so a dependency advisory is no secret
    detection whatever CWE its rule names, as the secret masking already says of
    an advisory's description (``_DEPENDENCY_TOOL_TYPES``). Read as one, the
    advisory got a ``secret/`` correlation id keyed by its file and line, and the
    baseline gate matched it only by an exact identity."""
    model = aggregate((npm_audit_advisory(GHSA, [cwe]), "npm-audit"))
    (finding,) = model.to_flat_vulnerabilities()

    assert finding.is_secret_detection is False
    assert finding.requires_exact_identity_match is False
    assert not (finding.correlation_id or "").startswith(SECRET_CORRELATION_PREFIX)


def test_a_same_id_rule_of_another_scanner_does_not_make_an_advisory_a_secret():
    """grype, trivy and npm-audit can name one advisory by one id. npm-audit's rule
    for it names CWE-798 and trivy's does not, and one scanner's rule says nothing
    about another scanner's finding, so neither finding is a secret detection:
    npm-audit's because it is a dependency advisory, trivy's because its own rule
    is untagged. A set of rule ids keyed by the bare id read the tag of one as the
    other's."""
    model = aggregate(
        (npm_audit_advisory(GHSA, ["CWE-798"]), "npm-audit"),
        (trivy_advisory(GHSA), "trivy"),
    )
    flat = model.to_flat_vulnerabilities()

    assert [finding.scanner for finding in flat] == ["npm-audit", "trivy"]
    assert [finding.is_secret_detection for finding in flat] == [False, False]
    assert [
        (finding.correlation_id or "").startswith(SECRET_CORRELATION_PREFIX)
        for finding in flat
    ] == [False, False]


def test_each_results_own_rule_decides_when_two_scanners_share_a_rule_id():
    """trivy's rule ``github-pat`` is tagged ``secret``. A static analysis
    scanner's rule of the same id, in the same report, is not. The flag reads the
    rule each result names in its own run and tool component, so trivy's finding
    is a secret detection and the other scanner's is not."""
    model = aggregate(
        (trivy_secret(), "trivy"),
        (sast_finding("github-pat", "bandit"), "bandit"),
    )
    flat = model.to_flat_vulnerabilities()
    by_scanner = {finding.scanner: finding for finding in flat}

    assert sorted(by_scanner) == ["bandit", "trivy"]
    assert len(flat) == 2
    assert by_scanner["trivy"].is_secret_detection is True
    assert by_scanner["bandit"].is_secret_detection is False


@pytest.mark.parametrize(
    ("tags", "short_description", "detection"),
    [
        pytest.param(
            ["CWE-259: Use of Hard-coded Password"], None, False, id="cwe-259"
        ),
        pytest.param(
            ["CWE-798: Use of Hard-coded Credentials"], None, True, id="cwe-798"
        ),
        pytest.param(
            [],
            "Hard-coded password in a default argument",
            False,
            id="described-only",
        ),
    ],
)
def test_only_the_detection_cwes_make_a_semgrep_finding_a_secret_detection(
    tags, short_description, detection
):
    """The flag's tags are ``secret``, ``secrets``, CWE-798 and CWE-321
    (``_SECRET_TAGS``, ``_DETECTION_CWE``). The secret masking reads a wider set:
    it masks a finding of a hard-coded password check (CWE-259), or of a rule
    described as one, as it masks a credential. Neither is a detection of a
    credential."""
    document = semgrep_finding(
        DEFAULT_ARGUMENT_RULE, tags, short_description=short_description
    )
    (finding,) = aggregate((document, "semgrep")).to_flat_vulnerabilities()

    assert finding.is_secret_detection is detection


# ---------------------------------------------------------------------------
# the baseline gate with that reading


def test_the_baseline_matches_both_findings_of_an_advisory_two_scanners_name_alike():
    """The advisory both scanners report, at the same lines in the baseline and in
    the current scan: neither finding is a secret detection, so both are matched.
    A secret detection is matched only by an exact identity with a fingerprint on
    both sides, and trivy writes none, so trivy's finding stayed in the report when
    npm-audit's tag was read as its own."""
    pair = [
        (npm_audit_advisory(GHSA, ["CWE-798"]), "npm-audit"),
        (trivy_advisory(GHSA), "trivy"),
    ]
    outcome, left = gate_scans(pair, pair)

    assert outcome.matched == 2
    assert left_names(left) == []


def test_the_baseline_matches_a_moved_advisory_beside_its_same_id_namesake():
    """trivy's finding moved from lines 13-17 to 40-44. It is an ordinary finding,
    so it is matched without its lines, and npm-audit's, at its lines, is matched
    exactly."""
    before = [
        (npm_audit_advisory(GHSA, ["CWE-798"]), "npm-audit"),
        (trivy_advisory(GHSA), "trivy"),
    ]
    after = [
        (npm_audit_advisory(GHSA, ["CWE-798"]), "npm-audit"),
        (trivy_advisory(GHSA, start=40, end=44), "trivy"),
    ]
    outcome, left = gate_scans(before, after)

    assert (outcome.matched, outcome.matched_without_lines) == (2, 1)
    assert left_names(left) == []


def test_the_pair_is_matched_when_npm_audits_rule_names_no_cwe():
    """The control for the pair above: the same two scanners, the same id and the
    same lines, with no CWE on npm-audit's rule."""
    pair = [
        (npm_audit_advisory(GHSA, []), "npm-audit"),
        (trivy_advisory(GHSA), "trivy"),
    ]
    outcome, left = gate_scans(pair, pair)

    assert outcome.matched == 2
    assert left_names(left) == []


def test_a_trivy_advisory_alone_is_matched_by_the_baseline():
    """The control: trivy's advisory under the same id with no other scanner's rule
    in the report is an ordinary finding, matched at the same lines."""
    scan = [(trivy_advisory(GHSA), "trivy")]
    outcome, left = gate_scans(scan, scan)

    assert outcome.matched == 1
    assert left_names(left) == []


@pytest.mark.parametrize("current_line", (10, 20), ids=("same-line", "moved"))
def test_the_baseline_keeps_a_semgrep_secret_detection_it_cannot_fingerprint(
    current_line,
):
    """The rule is tagged CWE-798 and its id has no ``secrets`` segment, so the
    finding is a secret detection by its rule's tag alone. semgrep without a login
    writes the ``requires login`` placeholder as its fingerprint, which the
    identity ignores (``finding_identity.PLACEHOLDER_FINGERPRINT_VALUES``), and a
    baseline matches a secret detection only by an exact identity with a
    fingerprint on both sides: neither the same line nor a moved one is covered."""
    current = semgrep_finding(JWT_RULE, JWT_TAGS, start=current_line)
    (finding,) = aggregate((current, "semgrep")).to_flat_vulnerabilities()
    outcome, left = gate(semgrep_finding(JWT_RULE, JWT_TAGS), current, "semgrep")

    assert finding.is_secret_detection is True
    assert finding.has_fingerprint_identity is False
    assert (outcome.matched, outcome.matched_without_lines) == (0, 0)
    assert left_names(left) == [f"semgrep:{JWT_RULE}"]
