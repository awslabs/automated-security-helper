# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stable finding IDs follow the repository's finding identity.

A flattened finding's id is ``<scanner>-<rule>-<12 hex digits>`` of the key in
``utils/finding_identity``: scanner, rule, file, lines, package and project. A
result that is alone with its key is not re-keyed by anything else it carries. Results
of one run that share a key are told apart by an occurrence digest of their column
and message, and exact duplicates also by an ordinal.
"""

import copy
import json
import os
import re
import subprocess
import sys

import pytest
from pydantic import ValidationError

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    assign_identity_ids,
)
from automated_security_helper.schemas.sarif_schema_model import Result, SarifReport
from automated_security_helper.utils import finding_identity


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


def _run_ids(*payloads):
    """The ids the results get when they are flattened together, as one run."""
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner"}},
                    "results": list(payloads),
                }
            ],
        }
    )
    flats = AshAggregatedResults(sarif=report).to_flat_vulnerabilities()
    return [flat.id for flat in flats]


@pytest.mark.parametrize(
    "change",
    [
        {"artifactLocation": {"uri": "src/second.py"}},
        {"region": {"startLine": 11, "startColumn": 2}},
        {"region": {"startLine": 10, "endLine": 12, "startColumn": 2}},
    ],
)
def test_distinct_physical_occurrences_have_distinct_ids(change):
    first = _payload()
    second = copy.deepcopy(first)
    second["locations"][0]["physicalLocation"].update(change)
    assert _id(first) != _id(second)


@pytest.mark.parametrize(
    "change",
    [
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
def test_coordinates_outside_the_key_tell_results_apart_only_within_a_run(change):
    first = _payload()
    second = copy.deepcopy(first)
    second["locations"][0]["physicalLocation"].update(change)
    assert _id(first) == _id(second)
    ids = _run_ids(first, second)
    assert len(set(ids)) == 2
    for flat_id in ids:
        assert re.fullmatch(r"scanner-RULE001-[0-9a-f]{12}", flat_id)


@pytest.mark.parametrize(
    "property_name, first_value, second_value",
    [
        ("package_name", "one", "two"),
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


def test_package_version_is_not_part_of_the_identity():
    first, second = _payload(), _payload()
    first["properties"] = {"package_name": "pkg", "package_version": "1.0.0"}
    second["properties"] = {"package_name": "pkg", "package_version": "2.0.0"}
    assert _id(first) == _id(second)


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
def test_logical_locations_are_outside_the_key(logical, physical):
    first, second = _payload(), _payload()
    if not physical:
        first["locations"] = [{}]
        second["locations"] = [{}]
    first["locations"][0]["logicalLocations"] = [{"name": "first"}]
    second["locations"][0]["logicalLocations"] = [{"name": "first", **logical}]
    assert _id(first) == _id(second)
    assert len(set(_run_ids(first, second))) == 2


def test_only_the_first_location_is_part_of_the_key():
    single = _payload()
    first = _payload()
    first["locations"][0]["logicalLocations"] = [{"name": "a"}, {"name": "b"}]
    other = copy.deepcopy(first["locations"][0])
    other["physicalLocation"]["artifactLocation"]["uri"] = "src/second.py"
    other["logicalLocations"] = [{"name": "c"}]
    first["locations"].append(other)
    assert _id(first) == _id(single)
    reversed_locations = copy.deepcopy(first)
    reversed_locations["locations"].reverse()
    second_file = _payload()
    second_file["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
        "src/second.py"
    )
    assert _id(reversed_locations) == _id(second_file)
    assert _id(reversed_locations) != _id(first)


def test_presentation_and_runtime_metadata_do_not_change_identity_or_source():
    # Fingerprints are part of the key (they replace the lines), so both results
    # carry them; everything else the second one adds is outside it.
    fingerprints = {
        "fingerprints": {"native": "retain-me"},
        "partialFingerprints": {"native": "retain-partial"},
    }
    first, second = {**_payload(), **fingerprints}, _payload()
    second.update(
        {
            **fingerprints,
            "level": "note",
            "suppressions": [{"kind": "external", "justification": "test"}],
            "provenance": {"lastDetectionTimeUtc": "2025-01-01T00:00:00Z"},
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
    real_hash = finding_identity.hashlib.sha256

    def capture(value):
        captured.append(value.decode())
        return real_hash(value)

    monkeypatch.setattr(finding_identity.hashlib, "sha256", capture)
    flat = FlatVulnerability.from_sarif_result(
        Result.model_validate(payload), "bandit", "SAST"
    )
    # Two digests: the occurrence digest of the column and the masked message,
    # then the digest of the key.
    assert len(captured) == 2
    assert json.loads(captured[0]) == [2, flat.description]
    for raw in (
        "synthetic-secret-only",
        "synthetic-private-property",
        "synthetic-private-snippet",
    ):
        assert all(raw not in seed for seed in captured)
    assert re.fullmatch(r"bandit-B105-[0-9a-f]{12}", flat.id)


def test_a_lone_finding_is_not_re_keyed_by_its_message():
    first, second = _payload(), _payload()
    second["message"]["text"] = "different evidence"
    assert _id(first) == _id(second)


def test_message_changes_at_a_shared_key_tell_the_results_apart():
    first, second = _payload(), _payload()
    second["message"]["text"] = "different evidence"
    reworded = _payload()
    reworded["message"]["text"] = "reworded evidence"
    pair = _run_ids(first, second)
    assert pair[0] != pair[1]
    # Only the second result's own message differs, so the first keeps its id.
    assert _run_ids(first, reworded)[0] == pair[0]
    assert _run_ids(first, reworded)[1] != pair[1]


def test_exact_duplicates_at_a_shared_key_get_an_id_each():
    ids = _run_ids(_payload(), _payload(), _payload())
    assert len(set(ids)) == 3
    assert _run_ids(_payload(), _payload()) == ids[:2]


@pytest.mark.parametrize("source_id", ["native-id", "native-id ", 0, False, ""])
def test_explicit_additional_report_ids_keep_the_existing_prefix(source_id):
    assert (
        FlatVulnerability.from_additional_report({"id": source_id}, "scanner").id
        == f"scanner-{source_id}".strip()
    )


def test_missing_additional_report_ids_use_the_finding_identity():
    first = {
        "id": None,
        "description": "same",
        "file_path": "src/one.py",
        "line_start": 1,
    }
    second = {**first, "file_path": "src/two.py"}
    flat = FlatVulnerability.from_additional_report(first, "scanner")
    assert re.fullmatch(r"scanner-unknown-[0-9a-f]{12}", flat.id)
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
def test_missing_additional_ids_tell_advisories_apart_only_within_a_run(
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
    # The advisory is not part of the key, so alone the two share an id; flattened
    # as one run they are exact duplicates and the second gets an ordinal.
    assert flat_first.id == flat_second.id
    run = [flat_first, flat_second]
    assign_identity_ids(run)
    assert run[0].id != run[1].id
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
def test_additional_line_representations_normalize_and_a_new_line_changes_the_id(
    field, line
):
    entry = {"description": "same", "line_start": 5, "line_end": 5, field: line}
    flat = FlatVulnerability.from_additional_report(entry, "scanner")
    distinct = FlatVulnerability.from_additional_report({**entry, field: 20}, "scanner")
    assert getattr(flat, field) == 10
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
    unknown = FlatVulnerability.from_additional_report(
        {"description": "same"}, "scanner"
    )
    for value in aliases:
        entry = {"description": "same", "line_start": value, "line_end": value}
        flat = FlatVulnerability.from_additional_report(entry, "scanner")
        assert flat.line_start == flat.line_end == normalized
        assert flat.id != unknown.id
        assert json.loads(flat.raw_data) == entry


@pytest.mark.parametrize("value", [1.5, "1.5", "not-a-line", {}, []])
@pytest.mark.parametrize("source_id", [None, "explicit"])
def test_invalid_additional_line_values_still_fail_validation(value, source_id):
    with pytest.raises(ValidationError):
        FlatVulnerability.from_additional_report(
            {"id": source_id, "line_start": value}, "scanner"
        )


@pytest.mark.parametrize(
    "field, values",
    [
        ("absoluteAddress", [0, 4096]),
        ("relativeAddress", [-1, 0]),
        ("offsetFromParent", [-1, 0]),
        ("length", [0, 4]),
        ("index", [0, 1]),
        ("parentIndex", [0, 1]),
        ("kind", ["data", "function"]),
        ("name", ["one", "two"]),
        ("fullyQualifiedName", ["module.one", "module.two"]),
    ],
)
def test_address_is_outside_the_key_but_kept_in_the_source(field, values):
    payloads = [
        {
            "ruleId": "RULE",
            "message": {"text": "same"},
            "locations": [{"physicalLocation": {"address": {field: value}}}],
        }
        for value in values
    ]
    assert _id(payloads[0]) == _id(payloads[1])
    assert len(set(_run_ids(*payloads))) == 2
    for payload in payloads:
        result = Result.model_validate(payload)
        before = result.model_dump(mode="json")
        flat = FlatVulnerability.from_sarif_result(result, "scanner", "SAST")
        assert result.model_dump(mode="json") == before
        assert (
            json.loads(flat.raw_data)["locations"][0]["physicalLocation"]["address"][
                field
            ]
            == payload["locations"][0]["physicalLocation"]["address"][field]
        )


def test_additional_default_and_validated_string_aliases_have_equal_identity():
    flat = FlatVulnerability.from_additional_report({}, "scanner")
    explicit = FlatVulnerability.from_additional_report(
        {"title": "Unknown Issue", "description": "No description available"}, "scanner"
    )
    assert flat.id == explicit.id
    padded = {
        "title": " Title ",
        "description": " same ",
        "rule_id": " RULE ",
        "cve_id": " CVE-2025-10001 ",
        "cwe_id": " CWE-79 ",
        "file_path": " file.py ",
        "line_start": "10",
    }
    normalized = {
        key: value.strip() if isinstance(value, str) else value
        for key, value in padded.items()
    }
    first = FlatVulnerability.from_additional_report(padded, " scanner ")
    second = FlatVulnerability.from_additional_report(normalized, "scanner")
    for field in ("scanner", "title", "rule_id", "file_path", "cve_id", "cwe_id"):
        assert getattr(first, field) == getattr(second, field)
    assert first.line_start == second.line_start == 10
    assert json.loads(first.raw_data) == padded


@pytest.mark.parametrize(
    "change",
    [
        {"ruleIndex": 0},
        {"rule": {"id": "other"}},
        {"rule": {"index": 0}},
        {"rule": {"guid": "11111111-1111-4111-8111-111111111111"}},
        {"rule": {"id": "RULE001", "toolComponent": {"name": "extension"}}},
        {"rule": {"id": "RULE001", "toolComponent": {"index": 0}}},
        {
            "rule": {
                "id": "RULE001",
                "toolComponent": {"guid": "11111111-1111-4111-8111-111111111111"},
            }
        },
    ],
)
def test_rule_references_are_outside_the_key(change):
    first = _payload()
    second = {**first, **change}
    assert _id(first) == _id(second)
    assert _id(first) == _id({**first, "ruleIndex": -1})
    assert len(set(_run_ids(first, second))) == 2


@pytest.mark.parametrize(
    "locations",
    [
        [],
        [{"physicalLocation": {"address": {"absoluteAddress": 4096}}}],
        [{"logicalLocations": [{"name": "function"}]}],
    ],
)
def test_analysis_target_is_outside_the_key_without_a_physical_artifact(locations):
    first = {
        "ruleId": "RULE",
        "message": {"text": "same"},
        "locations": locations,
        "analysisTarget": {"uri": "one.bin"},
    }
    second = {**first, "analysisTarget": {"uri": "two.bin"}}
    assert _id(first) == _id(second)
    assert len(set(_run_ids(first, second))) == 2


def test_ordinary_file_identity_is_stable_and_ignores_analysis_target():
    payload = {
        "ruleId": "RULE",
        "message": {"text": "same"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/file.py"},
                    "region": {"startLine": 10, "endLine": 10},
                }
            }
        ],
    }
    assert _id(payload) == "scanner-RULE-d93563740af5"
    assert _id(payload) == _id(
        {
            **payload,
            "analysisTarget": {
                "uri": "different.bin",
                "properties": {"raw": "synthetic"},
            },
        }
    )


@pytest.mark.parametrize("artifact", [{"uriBaseId": "BASE"}, {"index": 0}])
def test_analysis_target_is_outside_the_key_whatever_the_artifact_names(artifact):
    payload = {
        "ruleId": "RULE",
        "message": {"text": "same"},
        "locations": [{"physicalLocation": {"artifactLocation": artifact}}],
        "analysisTarget": {"uri": "one"},
    }
    assert _id(payload) == _id({**payload, "analysisTarget": {"uri": "two"}})


@pytest.mark.parametrize(
    "field, in_key",
    [
        ("rule_id", True),
        ("file_path", True),
        ("title", False),
        ("description", False),
        ("cve_id", False),
        ("cwe_id", False),
    ],
)
def test_only_the_rule_and_file_of_an_additional_entry_key_its_identity(field, in_key):
    one = FlatVulnerability.from_additional_report({field: "one"}, "scanner")
    two = FlatVulnerability.from_additional_report({field: "two"}, "scanner")
    assert (one.id != two.id) is in_key


def test_explicit_additional_id_keeps_raw_scanner_prefix_and_trimming():
    assert (
        FlatVulnerability.from_additional_report({"id": " native "}, " scanner ").id
        == "scanner - native"
    )
