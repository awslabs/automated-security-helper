# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A result that states no finding joins no duplicate cluster.

A result of kind ``pass``, ``notApplicable`` or ``informational`` that reports no
problem by its level or severity states no finding. It is listed as information
and counted in no total, so it cannot be a duplicate of a finding, and it cannot be
the row that links two findings that do not overlap each other. Rows here are built
by hand, as in the other cluster tests; a row of such a kind is graded INFO, which is
how a row with no result behind it says it states no finding.
"""

import pytest

from automated_security_helper.utils.finding_clusters import (
    assign_clusters,
    cluster_findings,
    clusters_by_project,
)
from tests.unit.models._flat_vulnerability_helpers import flat_with_severity

pytestmark = pytest.mark.unit

KINDS = ["informational", "notApplicable", "pass"]


def _row(fid, scanner, severity="HIGH", **fields):
    return flat_with_severity(
        severity,
        id=fid,
        title="t",
        description="d",
        scanner=scanner,
        scanner_type="SAST",
        **fields,
    )


def _iac(fid, scanner, **over):
    fields = {
        "resource_id": "MyStack/Bucket/Resource",
        "resource_type": "AWS::S3::Bucket",
        "file_path": "cdk.out/stack.template.json",
        "cwe_id": "CWE-732",
    }
    fields.update(over)
    return _row(fid, scanner, **fields)


def _code(fid, scanner, line, end, **over):
    fields = {"file_path": "src/a.py", "line_start": line, "line_end": end}
    fields.update(over)
    return _row(fid, scanner, cwe_id="CWE-89", **fields)


@pytest.mark.parametrize("kind", KINDS)
def test_an_iac_check_that_states_no_finding_is_no_duplicate_of_a_violation(kind):
    rows = [
        _iac("fail", "checkov"),
        _iac("note", "cdk-nag", severity="INFO", result_kind=kind),
    ]

    assert cluster_findings(rows) == []
    assert [a.cluster_id for a in assign_clusters(rows)] == [None, None]


@pytest.mark.parametrize("kind", KINDS)
def test_a_result_that_states_no_finding_chains_no_two_findings(kind):
    """The two failing rows overlap only through the middle row."""
    rows = [
        _code("first", "bandit", 10, 12),
        _code("middle", "semgrep", 11, 20, severity="INFO", result_kind=kind),
        _code("second", "opengrep", 19, 22),
    ]

    clusters = cluster_findings(rows)

    assert not any({0, 2} <= set(cluster.members) for cluster in clusters)
    assert not any(1 in cluster.members for cluster in clusters)


def test_two_findings_that_overlap_still_cluster():
    """Guard: the two failing rows overlap directly."""
    rows = [_code("first", "bandit", 10, 14), _code("second", "semgrep", 12, 20)]

    (cluster,) = cluster_findings(rows)

    assert set(cluster.members) == {0, 1}


@pytest.mark.parametrize("kind", KINDS)
def test_the_fold_leaves_such_a_row_out_too(kind):
    rows = [
        _iac("fail", "checkov"),
        _iac("note", "cdk-nag", severity="INFO", result_kind=kind),
    ]

    assert clusters_by_project(rows) == []
