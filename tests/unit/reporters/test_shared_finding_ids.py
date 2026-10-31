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
from automated_security_helper.utils.shared_finding_ids import (
    flat_describes_result,
    shared_ids_by_position,
)

pytestmark = pytest.mark.unit


def _result(rule_id: str, text: str, uri: str = "app/main.py", line: int = 7) -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.error,
        message=Message(text=text),
        properties=PropertyBag(scanner_name="bandit"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=line),
                )
            )
        ],
    )


def _flat(
    identifier: str,
    rule_id: str,
    file_path: str,
    line_start: int | None = 7,
    source_report: str | None = None,
) -> SimpleNamespace:
    """A flattened row as the pairing reads it: id, rule, file, first line, and
    where it came from (None = a SARIF row; a key = a row of that additional
    report)."""
    return SimpleNamespace(
        id=identifier,
        rule_id=rule_id,
        file_path=file_path,
        line_start=line_start,
        source_report=source_report,
    )


class TestSharedIdsByPosition:
    def test_each_position_takes_the_row_that_describes_it(self):
        results = [_result("R1", "a"), _result("R2", "b")]
        flat = [_flat("id-1", "R1", "app/main.py"), _flat("id-2", "R2", "app/main.py")]

        assert shared_ids_by_position(flat, results) == ["id-1", "id-2"]

    def test_a_missing_row_costs_its_own_position_alone(self):
        """One stray row used to switch every id of the report to its legacy
        key, which changed every id between two pipelines of the same tree."""
        results = [_result("R1", "a"), _result("R2", "b"), _result("R3", "c")]
        flat = [_flat("id-1", "R1", "app/main.py"), _flat("id-3", "R3", "app/main.py")]

        assert shared_ids_by_position(flat, results) == ["id-1", None, "id-3"]

    def test_an_extra_row_costs_no_position(self):
        results = [_result("R1", "a"), _result("R2", "b")]
        flat = [
            _flat("id-1", "R1", "app/main.py"),
            _flat("stray", "R9", "elsewhere/other.py"),
            _flat("id-2", "R2", "app/main.py"),
        ]

        assert shared_ids_by_position(flat, results) == ["id-1", "id-2"]

    def test_repeated_rows_pair_once_each_in_order(self):
        results = [_result("R1", "a"), _result("R2", "b")]
        flat = [_flat("id-1", "R1", "app/main.py")]

        assert shared_ids_by_position(flat, results) == ["id-1", None]
        assert shared_ids_by_position(flat + flat + flat, results) == ["id-1", None]

    def test_rows_of_an_additional_report_are_not_paired_with_sarif_results(self):
        """``to_flat_vulnerabilities`` appends a scanner's list-form additional
        report after the SARIF rows. Read as one list those rows made the
        lengths differ and every id of the report fell back; they describe no
        SARIF result and are left out of the pairing."""
        results = [_result("R1", "a"), _result("R2", "b")]
        flat = [
            _flat("id-1", "R1", "app/main.py"),
            _flat("id-2", "R2", "app/main.py"),
            _flat("npm-1", "R1", "app/main.py", source_report="npm-audit"),
            _flat("npm-2", "R2", "app/main.py", source_report="npm-audit"),
        ]

        assert shared_ids_by_position(flat, results) == ["id-1", "id-2"]

    def test_two_hits_of_one_rule_in_one_file_do_not_swap_ids(self):
        """Rule and file are the same for two hits of one rule in one file; the
        line is what tells them apart, and a flattening that ordered them the
        other way round swapped their ids with no sign."""
        results = [_result("R1", "a"), _result("R1", "b", line=20)]
        flat = [
            _flat("id-at-20", "R1", "app/main.py", line_start=20),
            _flat("id-at-7", "R1", "app/main.py", line_start=7),
        ]

        assert shared_ids_by_position(flat, results) == [None, None]
        assert shared_ids_by_position(list(reversed(flat)), results) == [
            "id-at-7",
            "id-at-20",
        ]

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

    @pytest.mark.parametrize(
        ("uri", "path"),
        [
            ("file:///my%20app/a.py", "/my app/a.py"),
            ("file:///C:/src/a.py", "C:/src/a.py"),
            ("file://host/src/a.py", "/src/a.py"),
        ],
        ids=["percent-encoded", "drive-letter", "host-segment"],
    )
    def test_a_file_uri_is_reduced_as_the_flattening_reduces_it(self, uri, path):
        """The flattening drops a host segment and the slash before a drive
        letter and decodes percent escapes; a pairing that only cut the scheme
        found no row for such a result, and its report printed a legacy id."""
        result = _result("R1", "a", uri=uri)

        assert flat_describes_result(_flat("id", "R1", path), result)
        assert not flat_describes_result(_flat("id", "R1", uri), result)

    def test_results_at_reduced_file_uris_keep_their_shared_ids_end_to_end(
        self, test_plugin_context
    ):
        """Through the model: each row carries the path the flattening wrote
        for its URI, and the pairing gives every result that row's id."""
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            _result("R1", "a", uri="file:///my%20app/a.py"),
            _result("R2", "b", uri="file:///C:/src/b.py"),
            _result("R3", "c", uri="file://host/src/c.py"),
        ]

        flat = model.to_flat_vulnerabilities()
        results = model.sarif.get_all_results()

        assert [row.file_path for row in flat] == [
            "/my app/a.py",
            "C:/src/b.py",
            "/src/c.py",
        ]
        assert shared_ids_by_position(flat, results) == [row.id for row in flat]

    def test_a_result_with_no_location_pairs_with_a_row_with_no_file(self):
        result = Result(ruleId="R1", level=Level.error, message=Message(text="a"))

        assert flat_describes_result(_flat("id", "R1", None, line_start=None), result)
        assert not flat_describes_result(
            _flat("id", "R1", "app/main.py", line_start=None), result
        )

    def test_a_row_at_another_line_describes_another_hit(self):
        result = _result("R1", "a")

        assert flat_describes_result(_flat("id", "R1", "app/main.py", 7), result)
        assert not flat_describes_result(_flat("id", "R1", "app/main.py", 8), result)
        assert not flat_describes_result(_flat("id", "R1", "app/main.py", None), result)

    def test_a_start_line_given_only_by_the_context_region_is_read(self):
        """The flattening takes ``contextRegion.startLine`` when ``region`` names
        no line, so its row carries the context line; a read of ``region`` alone
        answered None and the result never paired with its own row."""
        result = Result(
            ruleId="R1",
            level=Level.error,
            message=Message(text="a"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri="app/main.py"),
                        contextRegion=Region(startLine=12),
                    )
                )
            ],
        )

        assert flat_describes_result(_flat("id", "R1", "app/main.py", 12), result)
        assert not flat_describes_result(_flat("id", "R1", "app/main.py", None), result)

    def test_the_region_line_wins_over_the_context_region_line(self):
        result = Result(
            ruleId="R1",
            level=Level.error,
            message=Message(text="a"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri="app/main.py"),
                        region=Region(startLine=7),
                        contextRegion=Region(startLine=5),
                    )
                )
            ],
        )

        assert flat_describes_result(_flat("id", "R1", "app/main.py", 7), result)
        assert not flat_describes_result(_flat("id", "R1", "app/main.py", 5), result)

    def test_a_context_region_only_result_keeps_its_shared_id_end_to_end(
        self, test_plugin_context
    ):
        """Through the model: the flattened row's ``line_start`` is the context
        line, and the pairing gives the result that row's id."""
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(
                ruleId="R1",
                level=Level.error,
                message=Message(text="a"),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(uri="app/main.py"),
                            contextRegion=Region(startLine=12),
                        )
                    )
                ],
            ),
            _result("R2", "b"),
        ]

        flat = model.to_flat_vulnerabilities()
        results = model.sarif.get_all_results()

        assert [row.line_start for row in flat] == [12, 7]
        assert shared_ids_by_position(flat, results) == [flat[0].id, flat[1].id]


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

    def test_an_additional_report_leaves_every_shared_id_in_place(
        self, test_plugin_context, model
    ):
        """A scanner's list-form additional report adds flattened rows after the
        SARIF rows. Read as one list, those rows made every OCSF uid and GitLab
        id of the run fall back to the legacy key, and flip back in a run whose
        report was empty: the SIEM saw every finding as new each time."""
        model.additional_reports["npm-audit"] = [
            {
                "id": "GHSA-1",
                "title": "lodash",
                "severity": "HIGH",
                "file_path": "package.json",
            }
        ]
        flat = model.to_flat_vulnerabilities()
        assert [row.source_report for row in flat] == [None, None, None, "npm-audit"]
        sarif_ids = [row.id for row in flat if row.source_report is None]

        gitlab = json.loads(
            GitLabSASTReporter(context=test_plugin_context).report(model)
        )
        ocsf = json.loads(OcsfReporter(context=test_plugin_context).report(model))

        # Exact equality, not a list filtered to the expected ids: neither report
        # exports the additional report's own findings, so an entry beyond the
        # SARIF results is that report leaking into the export, which a
        # filtered comparison would let through. A later export of those
        # findings would add entries of its own and is the change that updates
        # this assertion on purpose.
        expected_uids = [
            str(uuid.uuid5(_FINDING_UID_NAMESPACE, flat_id)) for flat_id in sarif_ids
        ]
        assert [v["id"] for v in gitlab["vulnerabilities"]] == sarif_ids
        assert [r["finding_info"]["uid"] for r in ocsf] == expected_uids
