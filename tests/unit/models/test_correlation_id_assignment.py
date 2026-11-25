# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Correlation ids are assigned at flatten time, one value per observation.

Two scanners reporting one secret location, or one advisory against one
installed package, get equal ``correlation_id`` with distinct scanner-inclusive
``id``s; SAST rows and rows missing their family's key fields get an explicit
None. The flat frame carries the id as a nullable String column.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_frame import flat_frame
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def _result(
    rule_id: str,
    uri: str = "src/creds.py",
    line: int = 3,
    **properties,
) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text=f"{rule_id} fired"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=line, endLine=line),
                )
            )
        ],
        properties=PropertyBag(**properties) if properties else None,
    )


def _run(tool_name: str, tool_type: str, results) -> Run:
    return Run(
        tool=Tool(
            driver=ToolComponent(
                name=tool_name, properties=PropertyBag(tags=[tool_type])
            )
        ),
        results=list(results),
    )


def _model(*runs: Run) -> AshAggregatedResults:
    return AshAggregatedResults(sarif=SarifReport(version="2.1.0", runs=list(runs)))


class TestSecretFamily:
    def test_two_scanners_at_one_location_share_one_id(self):
        model = _model(
            _run("scanner-a", "SECRETS", [_result("SECRET-1")]),
            _run("scanner-b", "SECRETS", [_result("generic.secrets.9")]),
        )
        first, second = model.to_flat_vulnerabilities()
        assert first.correlation_id is not None
        assert first.correlation_id.startswith("secret/")
        assert first.correlation_id == second.correlation_id
        assert first.id != second.id

    def test_two_secrets_on_one_line_share_one_id(self):
        # Intended: the family's meaning is "same secret location"; the
        # scanner-inclusive id still tells the two findings apart.
        model = _model(
            _run("scanner-a", "SECRETS", [_result("SECRET-1"), _result("SECRET-1")])
        )
        first, second = model.to_flat_vulnerabilities()
        assert first.correlation_id == second.correlation_id is not None
        assert first.id != second.id

    def test_a_secret_with_no_line_carries_none(self):
        no_line = Result(
            ruleId="SECRET-1",
            message=Message(text="SECRET-1 fired"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri="src/creds.py")
                    )
                )
            ],
        )
        model = _model(_run("scanner-a", "SECRETS", [no_line]))
        (finding,) = model.to_flat_vulnerabilities()
        assert finding.correlation_id is None

    def test_different_lines_are_different_ids(self):
        model = _model(
            _run(
                "scanner-a",
                "SECRETS",
                [_result("SECRET-1", line=3), _result("SECRET-1", line=4)],
            )
        )
        first, second = model.to_flat_vulnerabilities()
        assert first.correlation_id != second.correlation_id


class TestDepFamily:
    def test_two_sca_scanners_sharing_the_observation_share_one_id(self):
        grype_shaped = _result(
            "CVE-2024-12345",
            uri="package-lock.json",
            line=1,
            package_name="lodash",
            package_version="4.17.20",
        )
        npm_shaped = _result(
            "CVE-2024-12345",
            uri="deploy/package-lock.json",
            line=1,
            package_name="lodash",
            package_version="4.17.20",
        )
        model = _model(
            _run("grype", "SCA", [grype_shaped]),
            _run("npm-audit", "SCA", [npm_shaped]),
        )
        first, second = model.to_flat_vulnerabilities()
        assert first.correlation_id is not None
        assert first.correlation_id.startswith("dep/")
        # The key has no file in it, so the two lockfile copies agree.
        assert first.correlation_id == second.correlation_id
        assert first.id != second.id

    def test_a_dep_row_missing_its_version_carries_none(self):
        incomplete = _result(
            "CVE-2024-12345",
            uri="package-lock.json",
            line=1,
            package_name="lodash",
        )
        model = _model(_run("grype", "SCA", [incomplete]))
        (finding,) = model.to_flat_vulnerabilities()
        assert finding.cve_id == "CVE-2024-12345"
        assert finding.correlation_id is None


class TestNonCarryingClasses:
    def test_a_sast_row_carries_none_by_design(self):
        model = _model(_run("bandit", "SAST", [_result("B105", uri="src/app.py")]))
        (finding,) = model.to_flat_vulnerabilities()
        assert finding.correlation_id is None

    def test_an_iac_row_carries_none_by_design(self):
        iac = _result(
            "CKV_AWS_18",
            uri="main.tf",
            line=7,
            ash_resource_id="aws_s3_bucket.logs",
            ash_resource_type="AWS::S3::Bucket",
        )
        model = _model(_run("checkov", "IAC", [iac]))
        (finding,) = model.to_flat_vulnerabilities()
        assert finding.correlation_id is None


class TestFrameAndTarget:
    def test_the_flat_frame_carries_the_id_as_a_nullable_column(self):
        model = _model(
            _run("scanner-a", "SECRETS", [_result("SECRET-1")]),
            _run("bandit", "SAST", [_result("B105", uri="src/app.py")]),
        )
        findings = model.to_flat_vulnerabilities()
        frame = flat_frame(findings)
        assert "correlation_id" in frame.columns
        cells = frame["correlation_id"].to_list()
        assert cells[0] == findings[0].correlation_id
        assert cells[1] is None

    def test_the_target_is_the_metadata_project_name(self):
        one = _model(_run("scanner-a", "SECRETS", [_result("SECRET-1")]))
        other = _model(_run("scanner-a", "SECRETS", [_result("SECRET-1")]))
        other.metadata.project_name = "another-repo"
        (ours,) = one.to_flat_vulnerabilities()
        (theirs,) = other.to_flat_vulnerabilities()
        # Same location, different scope: no cross-repo correlation.
        assert ours.correlation_id != theirs.correlation_id

    def test_an_additional_report_row_carries_none(self):
        model = _model()
        model.additional_reports = {
            "plugin-x": [
                {
                    "id": "plugin-x-1",
                    "title": "A finding",
                    "description": "From a list-form report",
                    "severity": "LOW",
                    "type": "SAST",
                }
            ]
        }
        (finding,) = model.to_flat_vulnerabilities()
        assert finding.correlation_id is None
