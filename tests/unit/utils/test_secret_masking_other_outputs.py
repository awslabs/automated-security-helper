# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Masking reaches every part of the results that is saved or reported.

``mask_secrets_in_results`` masked the SARIF runs and, by propagating value
only, ``additional_reports``. The CycloneDX SBOM, written to the results file
and to the CycloneDX, SPDX and GitLab SBOM reports, was never walked; an
additional-report entry (which the reports flatten into a finding with its own
snippet) was never masked by location, nor at the values of a secret finding it
overlapped unless they propagated, nor as a secret finding itself; and results a
SARIF log carries in ``inlineExternalProperties`` were neither indexed nor
masked.

The values here are derived at import time or plain words; none is a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    _mask_secret_value,
    mask_secrets_in_results,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("u27-other-value", 12)
WORD = "pass" + "word"
HARDCODED = "Possible hardcoded " + WORD + ": "
ASSIGN_LINE = f'{WORD} = "{VALUE}"\n'


def _result(rule_id, uri, line, message, scanner, snippet=None):
    region = {"startLine": line, "endLine": line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
        ],
        "properties": {"scanner_name": scanner, "tags": [scanner]},
    }


def _secret(uri="app.py", line=2):
    return _result(
        "SECRET-KEYWORD",
        uri,
        line,
        "Secret of type 'Keyword' detected",
        "detect-secrets",
    )


def _results(results, external=None, additional=None):
    log = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "test"}}, "results": list(results)}],
    }
    if external is not None:
        log["inlineExternalProperties"] = [{"results": list(external)}]
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(log)
    if additional is not None:
        model.additional_reports = additional
    return model


def _entry(**fields):
    entry = {
        "id": "entry-1",
        "title": "A finding",
        "description": "Found something",
        "severity": "LOW",
    }
    entry.update(fields)
    return entry


class TestTheCycloneDxSbom:
    def test_a_value_a_finding_exposed_is_masked_in_the_sbom(self):
        model = _results(
            [_result("B105", "app.py", 2, HARDCODED + f"'{VALUE}'", "bandit")]
        )
        model.cyclonedx = CycloneDXReport.model_validate(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": VALUE},
                    {"type": "library", "name": "requests"},
                ],
            }
        )

        mask_secrets_in_results(model)

        names = [component.name for component in model.cyclonedx.components]
        assert names == [_mask_secret_value(VALUE), "requests"]


class TestAdditionalReportEntries:
    def test_an_entrys_snippet_at_a_reported_line_is_masked(self):
        model = _results(
            [_secret()],
            additional={
                "semgrep": [
                    _entry(
                        file_path="app.py",
                        line_start=2,
                        line_end=2,
                        snippet=ASSIGN_LINE,
                    )
                ]
            },
        )

        mask_secrets_in_results(model)

        assert model.additional_reports["semgrep"][0]["snippet"] == MASKED_LINE + "\n"

    def test_a_secrets_scanners_entry_is_masked_whole(self):
        model = _results(
            [],
            additional={
                "detect-secrets": [
                    _entry(
                        description="Secret of type 'Keyword' detected",
                        file_path="app.py",
                        line_start=5,
                        snippet=ASSIGN_LINE,
                    )
                ]
            },
        )

        mask_secrets_in_results(model)

        assert model.additional_reports["detect-secrets"][0]["snippet"] == (
            MASKED_LINE + "\n"
        )

    def test_an_entry_that_quotes_a_value_is_a_secret_finding(self):
        model = _results(
            [],
            additional={
                "bandit": [
                    _entry(
                        description=HARDCODED + "'" + WORD + "'",
                        file_path="app.py",
                        line_start=5,
                        snippet=f'{WORD} = "{WORD}"\n',
                    )
                ]
            },
        )

        mask_secrets_in_results(model)

        entry = model.additional_reports["bandit"][0]
        assert entry["description"] == HARDCODED + "'" + _mask_secret_value(WORD) + "'"
        assert entry["snippet"] == MASKED_LINE + "\n"

    def test_a_secret_findings_value_is_masked_in_an_overlapping_entry(self):
        """A value that does not propagate is masked in what reports the same line."""
        model = _results(
            [_result("B105", "app.py", 2, HARDCODED + "'" + WORD + "'", "bandit")],
            additional={
                "semgrep": [
                    _entry(
                        description=f"the call uses {WORD} here",
                        file_path="app.py",
                        line_start=2,
                        line_end=2,
                    )
                ]
            },
        )

        mask_secrets_in_results(model)

        description = model.additional_reports["semgrep"][0]["description"]
        assert description == f"the call uses {_mask_secret_value(WORD)} here"

    def test_an_overlapping_entrys_placing_fields_are_left_as_written(self):
        """The file is named by the value a finding on its line exposed: the
        entry's ``file_path`` and ``rule_id`` place it, they are not text it
        reports, so they keep the value while its text fields are masked."""
        file_name = WORD + ".py"
        model = _results(
            [_result("B105", file_name, 2, HARDCODED + "'" + WORD + "'", "bandit")],
            additional={
                "semgrep": [
                    _entry(
                        rule_id="rules." + WORD,
                        description=f"the call uses {WORD} here",
                        file_path=file_name,
                        line_start=2,
                        line_end=2,
                    )
                ]
            },
        )

        mask_secrets_in_results(model)

        entry = model.additional_reports["semgrep"][0]
        assert entry["file_path"] == file_name
        assert entry["rule_id"] == "rules." + WORD
        assert entry["line_start"] == 2
        assert entry["description"] == f"the call uses {_mask_secret_value(WORD)} here"

    def test_an_overlapping_entrys_id_is_still_masked(self):
        """An ``id`` is hash-shaped text that can hold the matched value, so it is
        masked like any other field, while ``file_path`` places the entry and is
        kept."""
        file_name = WORD + ".py"
        model = _results(
            [_result("B105", file_name, 2, HARDCODED + "'" + WORD + "'", "bandit")],
            additional={
                "semgrep": [
                    _entry(
                        id=WORD,
                        file_path=file_name,
                        line_start=2,
                        line_end=2,
                    )
                ]
            },
        )

        mask_secrets_in_results(model)

        entry = model.additional_reports["semgrep"][0]
        assert entry["id"] == _mask_secret_value(WORD)
        assert entry["file_path"] == file_name

    def test_an_entry_in_another_file_is_left_alone(self):
        """Control."""
        model = _results(
            [_secret()],
            additional={
                "semgrep": [
                    _entry(
                        file_path="other.py",
                        line_start=2,
                        line_end=2,
                        snippet="x = 1\n",
                    )
                ]
            },
        )

        mask_secrets_in_results(model)

        assert model.additional_reports["semgrep"][0]["snippet"] == "x = 1\n"


class TestInlineExternalProperties:
    def test_results_carried_outside_the_runs_are_masked(self):
        model = _results(
            [],
            external=[
                _secret(),
                _result("B404", "app.py", 2, "import", "bandit", snippet=ASSIGN_LINE),
            ],
        )

        mask_secrets_in_results(model)

        neighbor = model.sarif.inlineExternalProperties[0].results[1]
        physical = neighbor.locations[0].physicalLocation.root
        assert physical.region.snippet.text == MASKED_LINE + "\n"
