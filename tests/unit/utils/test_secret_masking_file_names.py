# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Two names of one file meet: URI forms, and an artifact named by index.

``file:/path`` and ``file://localhost/path`` were not read as the absolute path;
``a/./b`` and ``a//b`` were not read as ``a/b``; a name one tool wrote raw with a
literal ``%2B`` and another wrote encoded as ``%252B`` decoded to two names; and a
location whose ``artifactLocation`` names its file by ``index`` into the run's
artifacts, with no ``uri``, was neither indexed as a secret location nor placed.

Every value here is derived at import time; none is a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    _normalized_uri,
    mask_secrets_in_results,
)

pytestmark = pytest.mark.unit

NAME = "pass" + "word"
HARDCODED = "Possible hardcoded " + NAME + ": "


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("file-names", 11) + "9"
SECRET_LINE = NAME + f' = "{VALUE}"\n'


def _result(rule_id, line, message, uri="app.py", snippet=None, artifact=None):
    region = {"startLine": line, "endLine": line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": artifact or {"uri": uri},
                    "region": region,
                }
            }
        ],
        "properties": {"scanner_name": "bandit", "tags": ["bandit"]},
    }


def _results(*results, artifacts=None):
    run = {"tool": {"driver": {"name": "test"}}, "results": list(results)}
    if artifacts is not None:
        run["artifacts"] = artifacts
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
    return model


def _snippet(model, position):
    physical = model.sarif.runs[0].results[position].locations[0].physicalLocation
    return physical.root.region.snippet.text


class TestNormalizedUriForms:
    @pytest.mark.parametrize(
        ("uri", "expected"),
        [
            ("file:/abs/x.py", "/abs/x.py"),
            ("file://localhost/abs/x.py", "/abs/x.py"),
            ("file:///abs/x.py", "/abs/x.py"),
            ("src/./a//b.py", "src/a/b.py"),
            ("./a/./b.py", "a/b.py"),
            ("a%252Bb.py", "a+b.py"),
            ("a%2Bb.py", "a+b.py"),
            ("my%20app/x.py", "my app/x.py"),
        ],
    )
    def test_each_form_names_the_plain_path(self, uri, expected):
        assert _normalized_uri(uri) == expected

    def test_a_relative_path_is_kept(self):
        """Control."""
        assert _normalized_uri("src/app.py") == "src/app.py"


class TestAFileSchemeWithOneSlash:
    def test_names_the_same_file_as_the_plain_absolute_path(self):
        model = _results(
            _result("B105", 5, HARDCODED + f"'{VALUE}'", uri="file:/abs/app.py"),
            _result("B404", 5, "import", uri="/abs/app.py", snippet=SECRET_LINE),
        )

        mask_secrets_in_results(model)

        assert _snippet(model, 1) == MASKED_LINE + "\n"


class TestAnArtifactNamedByIndex:
    def test_its_line_is_masked_in_another_findings_snippet(self):
        model = _results(
            _result(
                "B105",
                5,
                HARDCODED + f"'{VALUE}'",
                artifact={"index": 0},
            ),
            _result("B404", 5, "import", snippet=SECRET_LINE),
            artifacts=[{"location": {"uri": "app.py"}}],
        )

        mask_secrets_in_results(model)

        assert _snippet(model, 1) == MASKED_LINE + "\n"

    def test_the_location_is_left_as_written(self):
        """The artifact's uri is read for the location, not written onto it: the
        results are read, never changed, beyond the masking itself."""
        model = _results(
            _result("B105", 5, HARDCODED + f"'{VALUE}'", artifact={"index": 0}),
            _result("B404", 5, "import", snippet=SECRET_LINE),
            artifacts=[{"location": {"uri": "app.py", "uriBaseId": "SRCROOT"}}],
        )
        location = (
            model.sarif.runs[0]
            .results[0]
            .locations[0]
            .physicalLocation.root.artifactLocation
        )
        before = location.model_dump_json()

        mask_secrets_in_results(model)

        assert location.model_dump_json() == before
        assert location.uri is None
        assert location.uriBaseId is None
        assert location.index == 0
        assert _snippet(model, 1) == MASKED_LINE + "\n"

    def test_an_index_past_the_artifacts_is_left_alone(self):
        """Control: nothing is invented for an index the run does not have."""
        model = _results(
            _result("B105", 5, HARDCODED + f"'{VALUE}'", artifact={"index": 3}),
            _result("B404", 5, "import", snippet="other = 1\n"),
            artifacts=[{"location": {"uri": "app.py"}}],
        )

        mask_secrets_in_results(model)

        assert _snippet(model, 1) == "other = 1\n"
