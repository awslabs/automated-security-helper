# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Snippets are placed on their file's lines before they are read or masked.

The value a semgrep or opengrep finding matched is read by slicing its region
snippet's first line at the region's columns, which are the file line's; a
snippet that starts after the line's first column was sliced at the wrong
offset, so the value was not recovered (and a fragment was propagated instead).
An artifact's base64 contents, which cannot be masked line by line, were dropped
only when the secret finding reported line 1.

The values here are derived at import time; none is a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
    mask_secrets_in_results,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("u27-plain-value", 12)
MATCH = 'token = "' + VALUE + '"'
LEAD = 'a = "zz"; '
TAIL = "; b = 2; c = 3; d = 4; e = 5"
FULL_LINE = LEAD + MATCH + TAIL
REUSE_LINE = f'run("login --token {VALUE}")\n'


def _matched_finding(snippet, context_text):
    """A rule that matches by columns on line 7 of app.py, quoting no value."""
    return {
        "ruleId": "generic.secrets.gitleaks.generic-api-key",
        "level": "warning",
        "message": {"text": "Generic API key detected"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {
                        "startLine": 7,
                        "endLine": 7,
                        "startColumn": len(LEAD) + 1,
                        "endColumn": len(LEAD) + 1 + len(MATCH),
                        "snippet": {"text": snippet},
                    },
                    "contextRegion": {
                        "startLine": 7,
                        "snippet": {"text": context_text},
                    },
                }
            }
        ],
        "properties": {"scanner_name": "semgrep", "tags": ["semgrep"]},
    }


def _reuse_finding():
    return {
        "ruleId": "B404",
        "level": "warning",
        "message": {"text": "import"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "other.py"},
                    "region": {
                        "startLine": 3,
                        "endLine": 3,
                        "snippet": {"text": REUSE_LINE},
                    },
                }
            }
        ],
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
    }


def _secret_at_line(uri, line):
    return {
        "ruleId": "SECRET-KEYWORD",
        "level": "warning",
        "message": {"text": "Secret of type 'Keyword' detected"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
        "properties": {"scanner_name": "detect-secrets", "tags": ["detect-secrets"]},
    }


def _results(results, artifacts=None):
    run = {"tool": {"driver": {"name": "test"}}, "results": list(results)}
    if artifacts is not None:
        run["artifacts"] = artifacts
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
    return model


def _region_text(model, position):
    physical = model.sarif.runs[0].results[position].locations[0].physicalLocation.root
    return physical.region.snippet.text


class TestAMatchedValueReadAtTheRegionsColumns:
    def test_a_snippet_that_starts_mid_line_is_read_at_its_offset(self):
        """The contextRegion shows the full line; the snippet is its tail."""
        model = _results(
            [
                _matched_finding(FULL_LINE[len(LEAD) :], FULL_LINE + "\n"),
                _reuse_finding(),
            ]
        )

        mask_secrets_in_results(model)

        reuse = _region_text(model, 1)
        assert VALUE not in reuse
        assert _mask_secret_value(VALUE) in reuse

    def test_a_snippet_that_starts_at_column_one_is_read_as_before(self):
        """Control."""
        model = _results(
            [_matched_finding(FULL_LINE, FULL_LINE + "\n"), _reuse_finding()]
        )

        mask_secrets_in_results(model)

        assert VALUE not in _region_text(model, 1)


class TestEmbeddedArtifactContents:
    def test_base64_contents_are_dropped_when_any_line_of_the_file_is_reported(
        self,
    ):
        model = _results(
            [_secret_at_line("app.py", 2)],
            artifacts=[
                {"location": {"uri": "app.py"}, "contents": {"binary": "QUJD"}},
                {"location": {"uri": "other.py"}, "contents": {"binary": "QUJD"}},
            ],
        )

        mask_secrets_in_results(model)

        artifacts = model.sarif.runs[0].artifacts
        assert artifacts[0].contents.binary is None
        assert artifacts[1].contents.binary == "QUJD"
