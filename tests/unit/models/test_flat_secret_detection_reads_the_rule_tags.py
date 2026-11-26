"""A trivy secret is a secret detection in the flat finding model as well.

trivy's secret scanner, and the alpha scanner ``trivy-repo`` that runs the same
engine, mark a finding as a secret only on the rule's descriptor: the rule
``github-pat`` carries the tags ``secret``, ``security`` and ``CRITICAL``, while
the result itself carries no secret tag and no fingerprint. When a scanner's
SARIF is merged into ``AshAggregatedResults`` its driver, rules included, lands
in the aggregate run's ``tool.extensions``, and two consumers already read the
tags there: the secret masking (``utils/secret_masking``, through
``secret_rule_ids``) and the Bedrock summary reporter (``is_secret_detection``
with ``secret_detection_rule_ids``). Both call that result a secret.

``FlatVulnerability.from_sarif_result`` classifies one result at a time, and a
trivy result carries no mark of its own, so without the report's rule ids it
takes the result for an ordinary finding. What it sets from that answer is read
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
  by the flat findings on their own, whether or not the masking pass has run,
  and with the report's rule ids they decide which findings those are as the
  masking does.

These tests pin the flat findings to the masker's and the reporter's reading of
one report. The controls beside them must not move: a dependency advisory is no
secret (not even one whose rule describes a credential), and the baseline gate
still matches an ordinary finding that moved.
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


def gate(baseline_document: dict, current_document: dict, scanner: str):
    """``apply_baseline`` of one scanner's current scan against its baseline.

    Returns the outcome and the results left in the current scan. A baseline is
    read from a file, and ``AshAggregatedResults.model_post_init`` masks every
    model it builds, so the baseline is masked before it is flattened here;
    ``apply_baseline`` masks the current results itself.
    """
    old = aggregate((baseline_document, scanner))
    mask_secrets_in_results(old)
    current = aggregate((current_document, scanner))
    baseline = ScanBaseline("abc", old, tuple(old.to_flat_vulnerabilities()))
    outcome = apply_baseline(current, baseline)
    return outcome, results_left(current)


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
