# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The line-pinned .ash/.ash.yaml entries on deploy/cdk/templates hit one resource each.

Why this exists
---------------
cdk-nag findings on a committed template are suppressed through .ash/.ash.yaml, which
matches on rule id, path and optionally a line range, and takes the FIRST entry that
matches. The file-level entries for AshCodeCommitGate name the resources they were
written for. When the gate gained its optional VPC placement, two new records appeared
under rules those entries cover (F3031 on ScanFunction's conditional KmsKeyArn, and the
four packs' IAMNoInlinePolicy on the conditional ENI policy). Rather than widen the
file-level reasons, each new record has its own entry pinned to the line ASH reports for
that resource, placed ahead of the file-level entry so it wins the first-match race.

A line pin rots silently: regenerate the template and the line can move onto another
resource, or onto nothing, and the suppression then covers the wrong record or none.
These tests compute ASH's reported line for every resource from the committed template,
the same way ``utils/cdk_nag_wrapper.py`` does (the first line naming the logical id),
and fail if a pinned line belongs to any resource other than the intended one.
"""

import json
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[3]
ASH_YAML = REPO / ".ash" / ".ash.yaml"
TEMPLATES = REPO / "deploy" / "cdk" / "templates"
GATE = "deploy/cdk/templates/AshCodeCommitGate.template.json"

PACKS = ["HIPAA.Security", "NIST.800.53.R4", "NIST.800.53.R5", "PCI.DSS.321"]

#: (rule id, path) -> the one logical id the pinned entry is for.
EXPECTED = {
    ("F3031", GATE): "ScanFunction322CD7EE",
    **{
        (f"{p}-IAMNoInlinePolicy", GATE): "ScanFunctionRoleEc2Access99A7E33E"
        for p in PACKS
    },
}


def _suppressions():
    return yaml.safe_load(ASH_YAML.read_text(encoding="utf-8"))["global_settings"][
        "suppressions"
    ]


def _reported_lines(path: str) -> dict:
    """Logical id -> the line ASH's cdk-nag wrapper reports a finding on it at."""
    text = (REPO / path).read_text(encoding="utf-8")
    lines = text.splitlines()
    out = {}
    for logical_id in json.loads(text)["Resources"]:
        pattern = re.compile(
            r"(?<![a-zA-Z0-9_])" + re.escape(logical_id) + r"(?![a-zA-Z0-9_])"
        )
        out[logical_id] = next(
            i for i, line in enumerate(lines, start=1) if pattern.search(line)
        )
    return out


def _pinned():
    return [
        (i, s)
        for i, s in enumerate(_suppressions())
        if str(s.get("path", "")).startswith("deploy/cdk/templates/")
        and s.get("line_start") is not None
    ]


def test_the_pinned_entries_are_exactly_the_expected_set():
    keys = sorted((s["rule_id"], s["path"]) for _, s in _pinned())
    assert keys == sorted(EXPECTED)


@pytest.mark.parametrize("key", sorted(EXPECTED), ids=lambda k: k[0])
def test_each_pin_lands_on_its_resource_and_no_other(key):
    rule_id, path = key
    [(index, entry)] = [
        (i, s) for i, s in _pinned() if (s["rule_id"], s["path"]) == key
    ]
    assert entry["line_start"] == entry["line_end"]
    owners = sorted(
        lid
        for lid, line in _reported_lines(path).items()
        if line == entry["line_start"]
    )
    assert owners == [EXPECTED[key]]
    assert len(entry["reason"]) > 80


@pytest.mark.parametrize("key", sorted(EXPECTED), ids=lambda k: k[0])
def test_each_pin_precedes_the_file_level_entry_it_must_beat(key):
    # ASH takes the first matching entry, so a pin listed after the file-level entry
    # for the same rule and path would never be the one applied.
    entries = _suppressions()
    pinned = [
        i
        for i, s in enumerate(entries)
        if (s["rule_id"], s.get("path")) == key and s.get("line_start") is not None
    ]
    file_level = [
        i
        for i, s in enumerate(entries)
        if (s["rule_id"], s.get("path")) == key and s.get("line_start") is None
    ]
    assert pinned and file_level
    assert max(pinned) < min(file_level)


def test_the_pinned_resources_are_the_conditional_vpc_ones():
    resources = json.loads((REPO / GATE).read_text(encoding="utf-8"))["Resources"]
    assert (
        resources["ScanFunctionRoleEc2Access99A7E33E"]["Condition"]
        == "ScanFunctionInVpc"
    )
    assert resources["ScanFunctionRoleEc2Access99A7E33E"]["Type"] == "AWS::IAM::Policy"
    kms = resources["ScanFunction322CD7EE"]["Properties"]["KmsKeyArn"]
    assert kms == {
        "Fn::If": ["HasKmsKey", {"Ref": "KmsKeyArn"}, {"Ref": "AWS::NoValue"}]
    }


def test_the_line_helper_sees_a_moved_pin():
    # Positive control: shifting a pin by one line must leave it owned by nobody or by
    # a different resource, or the ownership assertion above could not fail.
    lines = _reported_lines(GATE)
    target = lines["ScanFunction322CD7EE"]
    assert [lid for lid, line in lines.items() if line == target + 1] != [
        "ScanFunction322CD7EE"
    ]
