# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stable finding IDs distinguish occurrences without hashing raw evidence."""

import copy
import json
import os
import re
import subprocess
import sys

import pytest
from pydantic import ValidationError

from automated_security_helper.models import flat_vulnerability
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Result


def _payload():
    return {
        "ruleId": "RULE001",
        "message": {"text": "same finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/first.py"},
                    "region": {"startLine": 10, "startColumn": 2},
                },
            }
        ],
    }


def _id(payload):
    return FlatVulnerability.from_sarif_result(
        Result.model_validate(payload), "scanner", "SAST"
    ).id


@pytest.mark.parametrize(
    "change",
    [
        {"artifactLocation": {"uri": "src/second.py"}},
        {"artifactLocation": {"uri": "src/first.py", "uriBaseId": "OTHER"}},
        {"artifactLocation": {"uri": "src/first.py", "index": 0}},
        {"region": {"startLine": 10, "startColumn": 3}},
        {"region": {"startLine": 10, "startColumn": 2, "endColumn": 5}},
        {
            "region": {
                "startLine": 10,
                "startColumn": 2,
                "charOffset": 0,
                "charLength": 4,
            }
        },
        {
            "region": {
                "startLine": 10,
                "startColumn": 2,
                "byteOffset": 0,
                "byteLength": 4,
            }
        },
    ],
)
def test_distinct_physical_occurrences_have_distinct_ids(change):
    first = _payload()
    second = copy.deepcopy(first)
    second["locations"][0]["physicalLocation"].update(change)
    assert _id(first) != _id(second)


@pytest.mark.parametrize(
    "property_name, first_value, second_value",
    [
        ("package_name", "one", "two"),
        ("package_version", "1.0.0", "2.0.0"),
        ("package_path", "node_modules/pkg", "node_modules/parent/node_modules/pkg"),
        ("workspace_project", "backend", "frontend"),
    ],
)
def test_package_and_workspace_identity_distinguish_occurrences(
    property_name, first_value, second_value
):
    first, second = _payload(), _payload()
    first["properties"] = {property_name: first_value}
    second["properties"] = {property_name: second_value}
    assert _id(first) != _id(second)


@pytest.mark.parametrize(
    "logical",
    [
        {"name": "other"},
        {"fullyQualifiedName": "module.other"},
        {"decoratedName": "_other"},
        {"kind": "function"},
        {"index": 0},
        {"parentIndex": 0},
    ],
)
@pytest.mark.parametrize("physical", [True, False])
def test_logical_identity_distinguishes_shared_physical_locations(logical, physical):
    first, second = _payload(), _payload()
    if not physical:
        first["locations"] = [{}]
        second["locations"] = [{}]
    first["locations"][0]["logicalLocations"] = [{"name": "first"}]
    second["locations"][0]["logicalLocations"] = [{"name": "first", **logical}]
    assert _id(first) != _id(second)


def test_location_and_dictionary_order_are_irrelevant_but_association_matters():
    first = _payload()
    first["locations"][0]["logicalLocations"] = [{"name": "a"}, {"name": "b"}]
    other = copy.deepcopy(first["locations"][0])
    other["physicalLocation"]["artifactLocation"]["uri"] = "src/second.py"
    other["logicalLocations"] = [{"name": "c"}]
    first["locations"].append(other)
    second = copy.deepcopy(first)
    second["locations"].reverse()
    second["locations"][1]["logicalLocations"].reverse()
    assert _id(first) == _id(second)
    third = copy.deepcopy(first)
    (
        third["locations"][0]["logicalLocations"],
        third["locations"][1]["logicalLocations"],
    ) = (
        third["locations"][1]["logicalLocations"],
        third["locations"][0]["logicalLocations"],
    )
    assert _id(first) != _id(third)


def test_presentation_and_runtime_metadata_do_not_change_identity_or_source():
    first, second = _payload(), _payload()
    second.update(
        {
            "level": "note",
            "suppressions": [{"kind": "external", "justification": "test"}],
            "provenance": {"lastDetectionTimeUtc": "2025-01-01T00:00:00Z"},
            "fingerprints": {"native": "retain-me"},
            "partialFingerprints": {"native": "retain-partial"},
            "properties": {
                "issue_severity": "LOW",
                "unrelated": "synthetic-only",
                "scanner_details": {
                    "tool_invocation": {"end_time": "2025-01-02T00:00:00Z"}
                },
            },
        }
    )
    physical = second["locations"][0]["physicalLocation"]
    physical["region"]["snippet"] = {"text": "synthetic snippet"}
    physical["contextRegion"] = {
        "startLine": 1,
        "snippet": {"text": "synthetic context"},
    }
    result = Result.model_validate(second)
    before = result.model_dump(mode="json")
    flat = FlatVulnerability.from_sarif_result(result, "scanner", "SAST")
    assert _id(first) == flat.id
    assert result.model_dump(mode="json") == before
    assert json.loads(flat.raw_data)["fingerprints"] == second["fingerprints"]
    assert (
        json.loads(flat.raw_data)["partialFingerprints"]
        == second["partialFingerprints"]
    )


def test_id_seed_uses_masked_description_and_excludes_raw_secrets(monkeypatch):
    payload = _payload()
    payload["ruleId"] = "B105"
    payload["message"]["text"] = "Possible hardcoded password: 'synthetic-secret-only'"
    payload["properties"] = {"unrelated": "synthetic-private-property"}
    payload["locations"][0]["physicalLocation"]["region"]["snippet"] = {
        "text": "synthetic-private-snippet"
    }
    captured = []
    real_hash = flat_vulnerability.hashlib.sha256

    def capture(value):
        captured.append(value.decode())
        return real_hash(value)

    monkeypatch.setattr(flat_vulnerability.hashlib, "sha256", capture)
    flat = FlatVulnerability.from_sarif_result(
        Result.model_validate(payload), "bandit", "SAST"
    )
    assert len(captured) == 1
    assert flat.description in captured[0]
    for raw in (
        "synthetic-secret-only",
        "synthetic-private-property",
        "synthetic-private-snippet",
    ):
        assert raw not in captured[0]
    assert re.fullmatch(r"bandit-B105-v2-[0-9a-f]{32}", flat.id)


def test_message_changes_at_the_same_occurrence_change_identity():
    first, second = _payload(), _payload()
    second["message"]["text"] = "different evidence"
    assert _id(first) != _id(second)


@pytest.mark.parametrize("source_id", ["native-id", "native-id ", 0, False])
def test_explicit_additional_report_ids_keep_the_existing_prefix(source_id):
    assert (
        FlatVulnerability.from_additional_report({"id": source_id}, "scanner").id
        == f"scanner-{source_id}".strip()
    )


@pytest.mark.parametrize("source_id", [None, ""])
def test_missing_additional_report_ids_use_occurrence_evidence(source_id):
    first = {
        "id": source_id,
        "description": "same",
        "file_path": "src/one.py",
        "line_start": 1,
    }
    second = {**first, "file_path": "src/two.py"}
    flat = FlatVulnerability.from_additional_report(first, "scanner")
    assert re.fullmatch(r"scanner-v2-[0-9a-f]{32}", flat.id)
    assert flat.id != FlatVulnerability.from_additional_report(second, "scanner").id
    assert (
        flat.id
        == FlatVulnerability.from_additional_report(
            {k: v for k, v in first.items() if k != "id"}, "scanner"
        ).id
    )
    changed = {
        **first,
        "severity": "LOW",
        "detected_at": "2025-01-01T00:00:00Z",
        "unrelated": "private",
    }
    assert flat.id == FlatVulnerability.from_additional_report(changed, "scanner").id
    assert json.loads(flat.raw_data) == first


def test_ids_are_stable_across_hash_seed_processes_and_dictionary_order():
    code = """
import json, sys
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Result
data = json.load(sys.stdin)
print(json.dumps([
    FlatVulnerability.from_sarif_result(Result.model_validate(data['sarif']), 'scanner', 'SAST').id,
    FlatVulnerability.from_additional_report(data['additional'], 'scanner').id,
]))
"""
    payload = {
        "sarif": _payload(),
        "additional": {"description": "same", "file_path": "src/one.py"},
    }
    payload["sarif"]["locations"][0]["logicalLocations"] = [
        {"name": "one"},
        {"name": "two"},
    ]
    second_location = copy.deepcopy(payload["sarif"]["locations"][0])
    second_location["physicalLocation"]["artifactLocation"]["uri"] = "src/second.py"
    payload["sarif"]["locations"].append(second_location)
    outputs = []
    for seed, sort_keys in [("1", False), ("2", True)]:
        reordered = copy.deepcopy(payload)
        if sort_keys:
            reordered["sarif"]["locations"].reverse()
            for location in reordered["sarif"]["locations"]:
                location["logicalLocations"].reverse()
        proc = subprocess.run(
            [sys.executable, "-c", code],
            input=json.dumps(reordered, sort_keys=sort_keys),
            text=True,
            capture_output=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(json.loads(proc.stdout))
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize(
    "field, first_advisory, second_advisory",
    [("cve_id", "CVE-2025-10001", "CVE-2025-10002"), ("cwe_id", "CWE-79", "CWE-89")],
)
def test_missing_additional_ids_distinguish_advisories(
    field, first_advisory, second_advisory
):
    first = {
        "description": "shared advisory description",
        "file_path": "requirements.txt",
        "line_start": 1,
        field: first_advisory,
    }
    second = {**first, field: second_advisory}
    flat_first = FlatVulnerability.from_additional_report(first, "scanner")
    flat_second = FlatVulnerability.from_additional_report(second, "scanner")
    assert flat_first.id != flat_second.id
    assert getattr(flat_first, field) == first_advisory
    assert getattr(flat_second, field) == second_advisory
    assert json.loads(flat_first.raw_data) == first
    assert json.loads(flat_second.raw_data) == second
    assert FlatVulnerability.from_additional_report(
        {**first, "id": "native"}, "scanner"
    ).id == (
        FlatVulnerability.from_additional_report(
            {**second, "id": "native"}, "scanner"
        ).id
    )


@pytest.mark.parametrize(
    "region",
    [
        None,
        {},
        {"startLine": None, "endLine": None},
        {"startLine": 10},
        {"endLine": 10},
        {"startLine": None, "endLine": 10},
        {"startLine": 10, "endLine": None},
    ],
)
def test_context_line_fallback_distinguishes_occurrences(region):
    payloads = []
    for line in (10, 20):
        payload = _payload()
        physical = payload["locations"][0]["physicalLocation"]
        physical["region"] = region
        physical["contextRegion"] = {"startLine": line, "endLine": line}
        payloads.append(payload)
    assert _id(payloads[0]) != _id(payloads[1])


def test_complete_region_lines_ignore_context_coordinates_and_presentation():
    payloads = []
    for line in (10, 20):
        payload = _payload()
        physical = payload["locations"][0]["physicalLocation"]
        physical["region"] = {"startLine": 30, "endLine": 31}
        physical["contextRegion"] = {
            "startLine": line,
            "endLine": line,
            "snippet": {"text": f"synthetic context {line}"},
            "message": {"text": f"synthetic presentation {line}"},
        }
        payloads.append(payload)
    assert _id(payloads[0]) == _id(payloads[1])


def test_context_fallback_has_the_identity_of_the_same_reported_region_lines():
    first, second = _payload(), _payload()
    first["locations"][0]["physicalLocation"]["region"] = {
        "startLine": 20,
        "endLine": 21,
    }
    second["locations"][0]["physicalLocation"]["region"] = None
    second["locations"][0]["physicalLocation"]["contextRegion"] = {
        "startLine": 20,
        "endLine": 21,
    }
    assert _id(first) == _id(second)


@pytest.mark.parametrize("field", ["line_start", "line_end"])
@pytest.mark.parametrize("line", [10, "10", 10.0])
def test_additional_line_representations_normalize_before_identity(field, line):
    entry = {"description": "same", "line_start": 5, "line_end": 5, field: line}
    flat = FlatVulnerability.from_additional_report(entry, "scanner")
    control = FlatVulnerability.from_additional_report({**entry, field: 10}, "scanner")
    distinct = FlatVulnerability.from_additional_report({**entry, field: 20}, "scanner")
    assert getattr(flat, field) == 10
    assert flat.id == control.id
    assert flat.id != distinct.id
    assert json.loads(flat.raw_data) == entry


@pytest.mark.parametrize(
    "normalized, aliases",
    [
        (0, [0, "0", 0.0, False]),
        (-1, [-1, "-1", -1.0]),
        (1, [1, "1", 1.0, True]),
    ],
)
def test_all_accepted_additional_line_aliases_contribute_to_identity(
    normalized, aliases
):
    ids = set()
    unknown = FlatVulnerability.from_additional_report(
        {"description": "same"}, "scanner"
    )
    for value in aliases:
        entry = {"description": "same", "line_start": value, "line_end": value}
        flat = FlatVulnerability.from_additional_report(entry, "scanner")
        assert flat.line_start == flat.line_end == normalized
        assert flat.id != unknown.id
        assert json.loads(flat.raw_data) == entry
        ids.add(flat.id)
    assert len(ids) == 1


@pytest.mark.parametrize("value", [1.5, "1.5", "not-a-line", {}, []])
@pytest.mark.parametrize("source_id", [None, "explicit"])
def test_invalid_additional_line_values_still_fail_validation(value, source_id):
    with pytest.raises(ValidationError):
        FlatVulnerability.from_additional_report(
            {"id": source_id, "line_start": value}, "scanner"
        )
