# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitLab SAST and OCSF reports give each finding the id every other report gives.

Both reporters read the id by position from ``to_flat_vulnerabilities`` through
one helper, ``shared_finding_ids.shared_ids_by_position``. The helper is pinned
here on its own, and the two reporters are pinned against it together: for one
model, the GitLab vulnerability ``id`` and the OCSF ``finding_info.uid`` of every
finding derive from the same flattened id. A test of that contract for the
GitLab report alone was removed when the helper was introduced; this is its
replacement, for both reporters.
"""

import json
import uuid
from types import SimpleNamespace

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    _FINDING_UID_NAMESPACE,
    OcsfReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.shared_finding_ids import (
    flat_describes_result,
    shared_ids_by_position,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
)

pytestmark = pytest.mark.unit


def _result(rule_id: str, text: str, uri: str = "app/main.py") -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.error,
        message=Message(text=text),
        properties=PropertyBag(scanner_name="bandit"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=7),
                )
            )
        ],
    )


def _flat(identifier: str, rule_id: str, file_path: str) -> SimpleNamespace:
    return SimpleNamespace(id=identifier, rule_id=rule_id, file_path=file_path)


class TestSharedIdsByPosition:
    def test_each_position_takes_the_row_that_describes_it(self):
        results = [_result("R1", "a"), _result("R2", "b")]
        flat = [_flat("id-1", "R1", "app/main.py"), _flat("id-2", "R2", "app/main.py")]

        assert shared_ids_by_position(flat, results) == ["id-1", "id-2"]

    def test_lists_of_different_length_vouch_for_no_position(self):
        results = [_result("R1", "a"), _result("R2", "b")]
        flat = [_flat("id-1", "R1", "app/main.py")]

        assert shared_ids_by_position(flat, results) == [None, None]
        assert shared_ids_by_position(flat + flat + flat, results) == [None, None]

    @pytest.mark.parametrize(
        "row",
        [
            _flat("drifted", "R9", "app/main.py"),
            _flat("drifted", "R2", "elsewhere/other.py"),
            _flat("", "R2", "app/main.py"),
            _flat(None, "R2", "app/main.py"),
        ],
        ids=["another-rule", "another-file", "empty-id", "no-id"],
    )
    def test_a_row_that_does_not_describe_its_result_gives_none_there_alone(self, row):
        results = [_result("R1", "a"), _result("R2", "b"), _result("R3", "c")]
        flat = [
            _flat("id-1", "R1", "app/main.py"),
            row,
            _flat("id-3", "R3", "app/main.py"),
        ]

        assert shared_ids_by_position(flat, results) == ["id-1", None, "id-3"]

    def test_a_file_uri_is_compared_with_its_scheme_stripped(self):
        """The flattening records ``file:///repo/a.py`` as ``/repo/a.py``."""
        result = _result("R1", "a", uri="file:///repo/a.py")

        assert flat_describes_result(_flat("id", "R1", "/repo/a.py"), result)
        assert not flat_describes_result(_flat("id", "R1", "file:///repo/a.py"), result)

    def test_a_result_with_no_location_pairs_with_a_row_with_no_file(self):
        result = Result(ruleId="R1", level=Level.error, message=Message(text="a"))

        assert flat_describes_result(_flat("id", "R1", None), result)
        assert not flat_describes_result(_flat("id", "R1", "app/main.py"), result)


class TestBothReportersGiveTheFlattenedId:
    @pytest.fixture
    def model(self):
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            _result("B105", "hardcoded password string"),
            _result("B105", "hardcoded password string"),
            _result("B602", "subprocess with shell", uri="app/run.py"),
        ]
        return model

    def test_the_gitlab_and_ocsf_ids_derive_from_the_same_flattened_ids(
        self, test_plugin_context, model
    ):
        gitlab = json.loads(
            GitLabSASTReporter(context=test_plugin_context).report(model)
        )
        ocsf = json.loads(OcsfReporter(context=test_plugin_context).report(model))

        flat_ids = [item.id for item in model.to_flat_vulnerabilities()]
        assert len(set(flat_ids)) == 3
        assert [v["id"] for v in gitlab["vulnerabilities"]] == flat_ids
        assert [
            {i["value"] for i in v["identifiers"] if i["type"] == "ash-finding-id"}
            for v in gitlab["vulnerabilities"]
        ] == [{flat_id} for flat_id in flat_ids]
        assert [r["finding_info"]["uid"] for r in ocsf] == [
            str(uuid.uuid5(_FINDING_UID_NAMESPACE, flat_id)) for flat_id in flat_ids
        ]
