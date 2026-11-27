# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every carrying surface exports the one correlation id; none invents its own.

One model, two secrets scanners at one location plus one SCA and one SAST
finding: the ASFF ProductFields pair, the SARIF and GHAS result properties, the
OCSF ``metadata.correlation_uid`` and ``unmapped`` bag, the GitLab SAST
``details`` entry, the flat-JSON key and the CSV column all carry the value the
flatten assigned, and every surface omits it for the SAST finding rather than
writing an empty one.
"""

import csv
import io
import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_formatter import (
    AsffFormatter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
    GHASReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    OcsfReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SarifReporter,
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
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.finding_identity import CORRELATION_ID_PROPERTY

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def _result(rule_id: str, uri: str, line: int = 3, **properties) -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.error,
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


@pytest.fixture
def model() -> AshAggregatedResults:
    """Two secrets scanners at one location, one SCA finding, one SAST finding."""
    # The secret runs are classified SECRETS only by their run driver's tags:
    # neither scanner name is in SCANNER_TOOL_TYPES and the results carry no
    # tag of their own (the third-party-scanner shape scanner_tool_types names
    # as its limit). Every surface, the ASFF ProductFields pair included, must
    # still carry the flatten's id: a reporter that re-derived the
    # classification without the run in hand would silently drop the pair.
    return AshAggregatedResults(
        sarif=SarifReport(
            version="2.1.0",
            runs=[
                _run(
                    "scanner-a",
                    "SECRETS",
                    [_result("SECRET-1", "src/creds.py")],
                ),
                _run(
                    "scanner-b",
                    "SECRETS",
                    [_result("generic.secrets.9", "src/creds.py")],
                ),
                _run(
                    "grype",
                    "SCA",
                    [
                        _result(
                            "CVE-2024-12345",
                            "package-lock.json",
                            line=1,
                            package_name="lodash",
                            package_version="4.17.20",
                        )
                    ],
                ),
                _run("bandit", "SAST", [_result("B602", "src/app.py", line=12)]),
            ],
        )
    )


@pytest.fixture
def flat(model):
    return model.to_flat_vulnerabilities()


@pytest.fixture
def secret_id(flat):
    value = flat[0].correlation_id
    assert value is not None and value.startswith("secret/")
    return value


@pytest.fixture
def dep_id(flat):
    value = flat[2].correlation_id
    assert value is not None and value.startswith("dep/")
    return value


class TestAsff:
    def test_the_product_fields_pair_is_present_only_on_carrying_findings(
        self, model, secret_id, dep_id
    ):
        formatter = AsffFormatter("example", None, None, offline=True)
        findings = formatter.build_asff_findings(
            model, account_id="123456789012", region="us-east-1"
        )
        fields = [finding["ProductFields"] for finding in findings]
        assert fields[0][CORRELATION_ID_PROPERTY] == secret_id
        assert fields[1][CORRELATION_ID_PROPERTY] == secret_id
        assert fields[2][CORRELATION_ID_PROPERTY] == dep_id
        assert CORRELATION_ID_PROPERTY not in fields[3]
        for bag in fields:
            assert len(bag) <= 50
            for value in bag.values():
                assert len(value) < 2048

    def test_the_finding_id_is_untouched_by_the_correlation_id(self, model):
        formatter = AsffFormatter("example", None, None, offline=True)
        findings = formatter.build_asff_findings(
            model, account_id="123456789012", region="us-east-1"
        )
        for finding in findings:
            assert finding["Id"].startswith("ash/")
            assert len(finding["Id"]) == 68

    def test_the_pair_is_the_flatten_value_for_a_path_stored_absolute_under_the_root(
        self,
    ):
        """The pair is read off the flatten, never recomputed over the rebased file.

        A stored result whose path stayed absolute under the scan root is the
        case ``relative_to_scan_root`` exists for: the finding ``Id`` is still
        derived over the rebased identity, but the correlation key is the
        flatten's, over the path as the run spelled it, so a consumer joining
        the ASFF report to the SARIF, OCSF or CSV report of the same run on
        ``ash/correlationId`` matches.
        """
        model = AshAggregatedResults(
            sarif=SarifReport(
                version="2.1.0",
                runs=[
                    _run(
                        "scanner-a",
                        "SECRETS",
                        [_result("SECRET-1", "/scan/src/creds.py", tags=["secret"])],
                    )
                ],
            )
        )
        expected = model.to_flat_vulnerabilities()[0].correlation_id
        assert expected is not None and expected.startswith("secret/")
        formatter = AsffFormatter("example", None, "/scan", offline=True)
        (finding,) = formatter.build_asff_findings(
            model, account_id="123456789012", region="us-east-1"
        )
        assert finding["ProductFields"][CORRELATION_ID_PROPERTY] == expected
        # The rebase still happened where it belongs: the resource and file
        # fields carry the path relative to the scan root.
        assert finding["ProductFields"]["ash/file"] == "src/creds.py"


class TestSarif:
    def test_the_dumped_results_carry_the_property_and_the_model_does_not(
        self, test_plugin_context, model, secret_id, dep_id
    ):
        document = json.loads(SarifReporter(context=test_plugin_context).report(model))
        results = [
            result for run in document["runs"] for result in run.get("results", [])
        ]
        carried = [
            result.get("properties", {}).get(CORRELATION_ID_PROPERTY)
            for result in results
        ]
        assert carried == [secret_id, secret_id, dep_id, None]
        # The stored model is left as it is: a reload must flatten the same
        # bytes the scan flattened.
        for result in model.sarif.get_all_results():
            extra = getattr(result.properties, "__pydantic_extra__", None) or {}
            assert CORRELATION_ID_PROPERTY not in extra


class TestGhas:
    def test_the_slim_copy_keeps_the_id_while_stripping_the_rest(
        self, test_plugin_context, model, secret_id, dep_id
    ):
        document = json.loads(GHASReporter(context=test_plugin_context).report(model))
        results = [
            result for run in document["runs"] for result in run.get("results", [])
        ]
        carried = [
            result.get("properties", {}).get(CORRELATION_ID_PROPERTY)
            for result in results
        ]
        assert carried == [secret_id, secret_id, dep_id, None]
        # The strip proof: the source results carried other properties
        # (package_name, tags); only the correlation id survives the slim copy.
        for result in results:
            properties = result.get("properties")
            if properties is not None:
                assert set(properties) == {CORRELATION_ID_PROPERTY}


class TestOcsf:
    def test_correlation_uid_and_unmapped_on_carrying_findings_only(
        self, test_plugin_context, model, secret_id, dep_id
    ):
        findings = json.loads(OcsfReporter(context=test_plugin_context).report(model))
        uids = [finding["metadata"].get("correlation_uid") for finding in findings]
        assert uids == [secret_id, secret_id, dep_id, None]
        bags = [finding.get("unmapped") for finding in findings]
        assert [bag.get(CORRELATION_ID_PROPERTY) if bag else None for bag in bags] == [
            secret_id,
            secret_id,
            dep_id,
            None,
        ]


class TestGitlab:
    def test_the_details_entry_is_present_only_on_carrying_findings(
        self, test_plugin_context, model, secret_id, dep_id
    ):
        document = json.loads(
            GitLabSASTReporter(context=test_plugin_context).report(model)
        )
        entries = [
            vulnerability.get("details", {}).get("ash_correlation_id")
            for vulnerability in document["vulnerabilities"]
        ]
        assert [entry["value"] if entry else None for entry in entries] == [
            secret_id,
            secret_id,
            dep_id,
            None,
        ]
        # Not an identifier: identifiers drive GitLab's own dedup semantics.
        for vulnerability in document["vulnerabilities"]:
            for identifier in vulnerability["identifiers"]:
                assert identifier["value"] not in {secret_id, dep_id}


class TestFlatJsonAndCsv:
    def test_flat_json_carries_the_key_only_where_a_value_exists(
        self, test_plugin_context, model, secret_id, dep_id
    ):
        document = json.loads(
            FlatJSONReporter(context=test_plugin_context).report(model)
        )
        values = [finding.get("correlation_id") for finding in document["findings"]]
        assert values == [secret_id, secret_id, dep_id, None]
        # Omitted, never null: consistent with the other Optional fields under
        # the reporter's exclude_none dump.
        assert "correlation_id" not in document["findings"][3]

    def test_the_csv_column_follows_every_older_column_and_is_empty_for_non_carrying_rows(
        self, test_plugin_context, model, secret_id, dep_id
    ):
        text = CsvReporter(context=test_plugin_context).report(model)
        rows = list(csv.reader(io.StringIO(text)))
        header, data = rows[0], rows[1:]
        # result_kind, the kind of each row's result, is the one column after it.
        assert header[-2:] == ["correlation_id", "result_kind"]
        column = [row[header.index("correlation_id")] for row in data]
        assert column == [secret_id, secret_id, dep_id, ""]
