# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The resource-scoped .ash.yaml entries on deploy/cdk/templates hit one resource each.

Why this exists
---------------
cdk-nag findings on a committed template are suppressed through .ash.yaml, which
takes the FIRST entry that matches. The file-level entries for AshCodeCommitGate name
the resources they were written for. When the gate gained its optional VPC placement,
two new records appeared under rules those entries cover (F3031 on ScanFunction's
conditional KmsKeyArn, and the four packs' IAMNoInlinePolicy on the conditional ENI
policy). Each has its own entry scoped to that one resource, placed ahead of the
file-level entry so it wins the first-match race.

These entries used to be LINE pins on the line ASH reports for the resource, which
rotted silently: regenerate the template and the line moves. They are now
``resource_id`` scopes. The matcher compares the scope against the resource identity
the finding carries -- for cdk-nag, the construct path, whose last segment under
CfnInclude is the template's own logical id (utils/cdk_nag_wrapper.py) -- literal
first, then glob (models/core.py scope_value_matches). So each entry's glob is
``*/<LogicalId>``, and these tests hold that shape to one existing resource each,
with the real matcher as the oracle.
"""

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.models.core import scope_value_matches

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
ASH_YAML = REPO / ".ash.yaml"
GATE = "deploy/cdk/templates/AshCodeCommitGate.template.json"

PACKS = ["HIPAA.Security", "NIST.800.53.R4", "NIST.800.53.R5", "PCI.DSS.321"]

#: (rule id, path) -> the one logical id the scoped entry is for.
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


def _resources() -> dict:
    return json.loads((REPO / GATE).read_text(encoding="utf-8"))["Resources"]


def _scoped():
    return [
        (i, s)
        for i, s in enumerate(_suppressions())
        if str(s.get("path", "")).startswith("deploy/cdk/templates/")
        and (s.get("resource_id") or (s.get("scope") or {}).get("resource_id"))
    ]


def _resource_glob(entry: dict) -> str:
    return entry.get("resource_id") or entry["scope"]["resource_id"]


def test_the_scoped_entries_are_exactly_the_expected_set():
    keys = sorted((s["rule_id"], s["path"]) for _, s in _scoped())
    assert keys == sorted(EXPECTED)


@pytest.mark.parametrize("key", sorted(EXPECTED), ids=lambda k: k[0])
def test_each_scope_names_its_resource_and_matches_only_that_one(key):
    """The glob is ``*/<LogicalId>``, the logical id is a resource of the template,
    and through the REAL matcher the glob covers that resource's construct path and
    no other resource's. The construct path shape is CfnInclude's,
    ``<stack>/<template>/<LogicalId>`` (cdk_nag_wrapper.py)."""
    rule_id, path = key
    [(index, entry)] = [
        (i, s) for i, s in _scoped() if (s["rule_id"], s["path"]) == key
    ]
    glob = _resource_glob(entry)
    logical_id = EXPECTED[key]
    assert glob == f"*/{logical_id}"
    resources = _resources()
    assert logical_id in resources
    for candidate in resources:
        construct_path = f"Stack/Template/{candidate}"
        assert scope_value_matches(construct_path, glob, case_sensitive=True) == (
            candidate == logical_id
        ), candidate
    assert len(entry["reason"]) > 80


def test_the_glob_does_not_match_a_suffixed_logical_id():
    # Positive control for the one-resource claim: a logical id that merely ENDS
    # with the target's name is a different path segment and must not match.
    glob = "*/ScanFunction322CD7EE"
    assert scope_value_matches(
        "Stack/T/ScanFunction322CD7EE", glob, case_sensitive=True
    )
    assert not scope_value_matches(
        "Stack/T/OtherScanFunction322CD7EE/ScanFunction322CD7EEX",
        glob,
        case_sensitive=True,
    )
    # The real ends-with case, and the reason the glob needs its leading `*/`: a
    # logical id that ends with the target's name, as the last segment, is a
    # different resource.
    assert not scope_value_matches(
        "Stack/T/OtherScanFunction322CD7EE", glob, case_sensitive=True
    )
    # fnmatch's `*` crosses `/`, so a BARE suffix glob would match the suffixed id
    # above; the leading `*/` anchors the id to its own segment... which still
    # requires the segment to be the LAST one, as the wrapper's paths have it.
    assert scope_value_matches(
        "Stack/T/OtherScanFunction322CD7EEX/ScanFunction322CD7EE",
        glob,
        case_sensitive=True,
    )


@pytest.mark.parametrize("key", sorted(EXPECTED), ids=lambda k: k[0])
def test_each_scoped_entry_precedes_the_file_level_entry_it_must_beat(key):
    # ASH takes the first matching entry, so a scoped entry listed after the
    # file-level entry for the same rule and path would never be the one applied.
    entries = _suppressions()
    scoped = [
        i
        for i, s in enumerate(entries)
        if (s["rule_id"], s.get("path")) == key
        and (s.get("resource_id") or (s.get("scope") or {}).get("resource_id"))
    ]
    file_level = [
        i
        for i, s in enumerate(entries)
        if (s["rule_id"], s.get("path")) == key
        and not (s.get("resource_id") or (s.get("scope") or {}).get("resource_id"))
    ]
    assert scoped and file_level
    assert max(scoped) < min(file_level)


def test_the_scoped_resources_are_the_conditional_vpc_ones():
    resources = _resources()
    assert (
        resources["ScanFunctionRoleEc2Access99A7E33E"]["Condition"]
        == "ScanFunctionInVpc"
    )
    assert resources["ScanFunctionRoleEc2Access99A7E33E"]["Type"] == "AWS::IAM::Policy"
    kms = resources["ScanFunction322CD7EE"]["Properties"]["KmsKeyArn"]
    assert kms == {
        "Fn::If": ["HasKmsKey", {"Ref": "KmsKeyArn"}, {"Ref": "AWS::NoValue"}]
    }


def test_no_template_entry_is_line_pinned_any_more():
    # The line pins this file used to hold rotted when `cdk synth` regenerated a
    # template; the migration replaced every one with a resource scope. A new
    # line pin on a template is the old failure mode returning.
    pinned = [
        (s["rule_id"], s["path"])
        for s in _suppressions()
        if str(s.get("path", "")).startswith("deploy/cdk/templates/")
        and s.get("line_start") is not None
    ]
    assert pinned == []
