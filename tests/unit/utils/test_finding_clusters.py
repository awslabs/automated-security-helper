# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Duplicate clusters over hand-built flat rows.

Each class has rows that must fold and rows that must not. The cells also pin
what clustering never does: it changes no row and no id, it is independent of
input order, and a suppressed row never stands for a live one.
"""

import random

import pytest

from automated_security_helper.utils.finding_clusters import (
    CLASS_IAC,
    CLASS_LOCATION,
    CLASS_PACKAGE,
    assign_clusters,
    cluster_findings,
)
from tests.unit.models._flat_vulnerability_helpers import flat_with_severity

pytestmark = pytest.mark.unit


def row(fid, scanner="grype", severity="HIGH", fingerprinted=False, **fields):
    flat = flat_with_severity(
        severity,
        id=fid,
        title="t",
        description="d",
        scanner=scanner,
        scanner_type="SCA",
        **fields,
    )
    if fingerprinted:
        flat._assigned_identity_key = {"fingerprints": {"x": "y"}}
    return flat


def pkg(fid, scanner, **over):
    fields = {
        "cve_id": "CVE-2024-0001",
        "package_name": "left-pad",
        "package_version": "1.0.0",
        "package_path": "node_modules/left-pad",
        "rule_id": "CVE-2024-0001",
    }
    fields.update(over)
    return row(fid, scanner=scanner, **fields)


def code(fid, scanner, line=10, end=None, cwe="CWE-89", path="src/a.py", **over):
    return row(
        fid,
        scanner=scanner,
        file_path=path,
        line_start=line,
        line_end=end,
        cwe_id=cwe,
        **over,
    )


def shape(rows):
    """The clusters as ids: {member ids: (cluster id, primary id, source ids)}."""
    return {
        frozenset(rows[i].id for i in c.members): (
            c.cluster_id,
            rows[c.primary].id,
            tuple(s["id"] for s in c.sources),
        )
        for c in cluster_findings(rows)
    }


# --- package / CVE ---------------------------------------------------------


def test_two_scanners_on_one_cve_and_package_fold_across_versions():
    rows = [
        pkg("g", "grype", package_version="1.0.0"),
        pkg("t", "trivy", package_version="1.0.1"),
    ]
    (cluster,) = cluster_findings(rows)
    assert cluster.finding_class == CLASS_PACKAGE and cluster.foldable
    assert set(cluster.members) == {0, 1}


def test_cve_case_does_not_split_a_cluster():
    rows = [pkg("g", "grype"), pkg("t", "trivy", cve_id="cve-2024-0001")]
    assert len(cluster_findings(rows)) == 1


def test_same_cve_in_another_package_path_does_not_fold():
    rows = [
        pkg("g", "grype"),
        pkg("t", "trivy", package_path="deploy/node_modules/left-pad"),
    ]
    assert cluster_findings(rows) == []


def test_same_cve_in_another_package_does_not_fold():
    rows = [pkg("g", "grype"), pkg("t", "trivy", package_name="right-pad")]
    assert cluster_findings(rows) == []


def test_a_package_row_without_a_path_falls_back_to_its_file():
    rows = [
        pkg("g", "grype", package_path=None, file_path="package-lock.json"),
        pkg("t", "trivy", package_path=None, file_path="./package-lock.json"),
        pkg("n", "npm-audit", package_path=None, file_path="other-lock.json"),
    ]
    assert list(shape(rows)) == [frozenset({"g", "t"})]


def test_a_cve_without_a_package_is_not_the_package_class():
    rows = [pkg("g", "grype", package_name=None), pkg("t", "trivy", package_name=None)]
    assert cluster_findings(rows) == []


# --- IaC resource ----------------------------------------------------------


def iac(fid, scanner, **over):
    fields = {
        "resource_id": "MyStack/Bucket/Resource",
        "resource_type": "AWS::S3::Bucket",
        "file_path": "cdk.out/stack.template.json",
        "cwe_id": "CWE-732",
    }
    fields.update(over)
    return row(fid, scanner=scanner, **fields)


def test_equal_resource_identity_clusters_but_never_folds():
    (cluster,) = cluster_findings([iac("a", "cdk-nag"), iac("b", "checkov")])
    assert cluster.finding_class == CLASS_IAC
    assert cluster.foldable is False
    assignments = assign_clusters([iac("a", "cdk-nag"), iac("b", "checkov")])
    assert not any(a.foldable for a in assignments)


@pytest.mark.parametrize(
    "other",
    [
        {"resource_id": "MyStack/Bucket2/Resource"},
        {"resource_type": "AWS::S3::BucketPolicy"},
        {"resource_type": None},
        {"file_path": "cdk.out/other.template.json"},
        {"cwe_id": "CWE-200"},
        {"cwe_id": "CWE-732, CWE-200"},
        {"cwe_id": None},
    ],
)
def test_any_difference_in_the_iac_key_keeps_two_rows_apart(other):
    assert cluster_findings([iac("a", "cdk-nag"), iac("b", "checkov", **other)]) == []


# --- code location ---------------------------------------------------------


def test_two_scanners_on_one_line_with_one_cwe_fold():
    rows = [code("s", "semgrep"), code("b", "bandit")]
    (cluster,) = cluster_findings(rows)
    assert cluster.finding_class == CLASS_LOCATION and cluster.foldable


def test_same_line_different_cwe_does_not_fold():
    rows = [code("s", "semgrep", cwe="CWE-89"), code("b", "bandit", cwe="CWE-78")]
    assert cluster_findings(rows) == []


def test_a_shared_cwe_in_a_list_is_enough():
    rows = [
        code("s", "semgrep", cwe="CWE-78, CWE-88"),
        code("b", "bandit", cwe="cwe-88"),
    ]
    assert len(cluster_findings(rows)) == 1


@pytest.mark.parametrize("missing", ["both", "one"])
def test_no_cwe_on_either_side_fails_closed(missing):
    rows = [
        code("s", "semgrep", cwe=None),
        code("b", "bandit", cwe=None if missing == "both" else "CWE-89"),
    ]
    assert cluster_findings(rows) == []


def test_a_cwe_column_naming_no_cwe_is_no_cwe():
    rows = [code("s", "semgrep", cwe="n/a"), code("b", "bandit", cwe="n/a")]
    assert cluster_findings(rows) == []


@pytest.mark.parametrize(
    "a, b, folds",
    [
        ((10, None), (10, None), True),
        ((10, 12), (12, 15), True),
        ((10, 12), (13, 15), False),
        ((20, 30), (25, 25), True),
        ((10, None), (11, None), False),
        ((10, 5), (10, None), True),
    ],
)
def test_line_ranges_must_overlap_inclusively(a, b, folds):
    rows = [
        code("s", "semgrep", line=a[0], end=a[1]),
        code("b", "bandit", line=b[0], end=b[1]),
    ]
    assert bool(cluster_findings(rows)) is folds


def test_another_file_does_not_fold_and_spelling_does_not_split():
    other = [code("s", "semgrep"), code("b", "bandit", path="src/b.py")]
    assert cluster_findings(other) == []
    spelled = [code("s", "semgrep"), code("b", "bandit", path="./src/./a.py")]
    assert len(cluster_findings(spelled)) == 1


def test_no_line_or_no_file_is_not_the_location_class():
    rows = [
        code("s", "semgrep", line=None),
        code("b", "bandit", line=None),
        code("c", "x", path=None),
        code("d", "y", path=None),
    ]
    assert cluster_findings(rows) == []


def test_overlap_chains_join_into_one_component():
    # Chaining is bounded by the split guard: it joins rows of three different
    # scanners here, and never two findings of one scanner and rule id that are
    # connected only through a bridge row (the tests below pin the bound).
    rows = [
        code("a", "semgrep", line=1, end=5),
        code("b", "bandit", line=5, end=9),
        code("c", "opengrep", line=9, end=12),
    ]
    (cluster,) = cluster_findings(rows)
    assert cluster.members == (0, 1, 2)


def test_a_bridge_row_never_folds_two_findings_of_one_scanner_and_rule():
    # Two separate semgrep findings of one rule, 40 lines apart, and a wide
    # multi-CWE bandit row spanning both: without the guard the chain
    # x1-w-x2 folded all three into one cluster. The guard splits it, the
    # bridge clusters with nothing, and nothing is left to fold.
    rows = [
        code("x1", "semgrep", line=10, end=12, cwe="CWE-79", rule_id="xss"),
        code("x2", "semgrep", line=50, end=52, cwe="CWE-89", rule_id="xss"),
        code("w", "bandit", line=1, end=100, cwe="CWE-79, CWE-89"),
    ]
    assert cluster_findings(rows) == []


def test_the_split_guard_keeps_the_directly_connected_remainder():
    # Removing the bridge re-clusters the rest: x1 and o overlap directly and
    # stay one cluster; x2 and the bridge w each stand alone.
    rows = [
        code("x1", "semgrep", line=10, end=12, cwe="CWE-79", rule_id="xss"),
        code("o", "opengrep", line=11, end=13, cwe="CWE-79"),
        code("x2", "semgrep", line=50, end=52, cwe="CWE-89", rule_id="xss"),
        code("w", "bandit", line=1, end=100, cwe="CWE-79, CWE-89"),
    ]
    (cluster,) = cluster_findings(rows)
    assert cluster.members == (0, 1)
    assert cluster.finding_class == CLASS_LOCATION and cluster.foldable


def test_two_rows_of_one_scanner_that_overlap_directly_still_fold():
    # The guard severs transitive-only connections, never a direct overlap:
    # one scanner double-reporting one span is still one finding.
    rows = [
        code("a", "semgrep", line=10, end=12, rule_id="xss"),
        code("b", "semgrep", line=11, end=14, rule_id="xss"),
    ]
    (cluster,) = cluster_findings(rows)
    assert set(cluster.members) == {0, 1}


def test_two_findings_legitimately_sharing_a_cwe_stay_clustered():
    # The negative control: two scanners, one line, one CWE. The guard does
    # not touch a component with no same-scanner-and-rule pair.
    rows = [
        code("s", "semgrep", line=10, end=12, cwe="CWE-89"),
        code("b", "bandit", line=11, end=13, cwe="CWE-89"),
    ]
    (cluster,) = cluster_findings(rows)
    assert set(cluster.members) == {0, 1} and cluster.foldable


def test_a_chain_with_no_single_bridge_leaves_the_two_findings_alone():
    # x1 and x2 are connected only through b1-b2, and no single row touches
    # both. Fail closed: the two semgrep findings stand alone, and the chain
    # rows re-cluster without them (b1 and b2 overlap directly).
    rows = [
        code("x1", "semgrep", line=10, end=12, cwe="CWE-79", rule_id="xss"),
        code("b1", "bandit", line=12, end=30, cwe="CWE-79, CWE-89"),
        code("b2", "opengrep", line=30, end=52, cwe="CWE-89"),
        code("x2", "semgrep", line=50, end=52, cwe="CWE-89", rule_id="xss"),
    ]
    (cluster,) = cluster_findings(rows)
    assert cluster.members == (1, 2)


def test_the_split_guard_keys_on_scanner_and_rule_id_together():
    # Two semgrep findings under different rules bridged by a wide row are
    # not the guard's pair, so the documented chaining still joins them.
    rows = [
        code("x1", "semgrep", line=10, end=12, cwe="CWE-79", rule_id="xss"),
        code("x2", "semgrep", line=50, end=52, cwe="CWE-89", rule_id="sqli"),
        code("w", "bandit", line=1, end=100, cwe="CWE-79, CWE-89"),
    ]
    (cluster,) = cluster_findings(rows)
    assert cluster.members == (0, 1, 2)


def test_secrets_without_a_cwe_never_cluster():
    rows = [
        row("g", "gitleaks", file_path="a.env", line_start=3),
        row("d", "detect-secrets", file_path="a.env", line_start=3),
    ]
    assert cluster_findings(rows) == []


def test_a_row_joins_one_class_only():
    both = {"file_path": "src/a.py", "line_start": 10, "cwe_id": "CWE-89"}
    rows = [
        pkg("g", "grype", **both),
        pkg("t", "trivy", package_path="elsewhere", **both),
        code("s", "semgrep"),
    ]
    # g and t are in different package clusters (singletons, so none); the
    # package key shadows the location key, so neither joins s.
    assert cluster_findings(rows) == []


def test_a_singleton_is_in_no_cluster():
    (only,) = assign_clusters([pkg("g", "grype")])
    assert only.cluster_id is None and not only.is_primary
    assert only.duplicate_of is None and only.duplicate_sources == ()


# --- primary selection -----------------------------------------------------


def test_the_primary_is_the_most_severe_member():
    rows = [
        pkg("g", "grype", severity="MEDIUM"),
        pkg("t", "trivy", severity="CRITICAL"),
        pkg("n", "npm-audit", severity="HIGH"),
    ]
    assert shape(rows)[frozenset("gtn")][1] == "t"


def test_an_unrecognized_severity_ranks_as_most_severe():
    rows = [pkg("g", "grype", severity="CRITICAL"), pkg("t", "trivy", severity="odd")]
    assert shape(rows)[frozenset("gt")][1] == "t"


def test_severity_ties_prefer_a_fingerprinted_identity_then_scanner_then_id():
    rows = [pkg("g", "grype"), pkg("t", "trivy", fingerprinted=True)]
    assert shape(rows)[frozenset("gt")][1] == "t"
    rows = [pkg("t", "trivy"), pkg("g", "grype")]
    assert shape(rows)[frozenset("gt")][1] == "g"
    # Two rows of one scanner never share a package cluster (they are two
    # copies), so the id tie-break is pinned in the location class.
    rows = [code("b", "semgrep"), code("a", "semgrep")]
    assert shape(rows)[frozenset("ab")][1] == "a"


def test_a_suppressed_member_never_stands_for_a_live_one():
    rows = [
        pkg("g", "grype", severity="CRITICAL", is_suppressed=True),
        pkg("t", "trivy", severity="LOW"),
    ]
    (cluster,) = cluster_findings(rows)
    assert rows[cluster.primary].id == "t"
    by_id = {rows[i].id: a for i, a in enumerate(assign_clusters(rows))}
    assert by_id["g"].duplicate_of == "t"
    assert rows[0].is_suppressed and not rows[1].is_suppressed


def test_all_suppressed_members_choose_among_themselves():
    rows = [
        pkg("g", "grype", severity="LOW", is_suppressed=True),
        pkg("t", "trivy", severity="HIGH", is_suppressed=True),
    ]
    assert shape(rows)[frozenset("gt")][1] == "t"


# --- assignments -----------------------------------------------------------


def test_assignments_carry_provenance_on_the_primary_and_a_pointer_on_the_rest():
    rows = [
        pkg("g", "grype", severity="MEDIUM", rule_id="CVE-2024-0001-left-pad"),
        pkg("t", "trivy", severity="HIGH"),
        pkg("n", "npm-audit", severity="LOW"),
    ]
    g, t, n = assign_clusters(rows)
    assert t.is_primary and t.duplicate_of is None
    assert t.duplicate_sources == (
        {
            "scanner": "grype",
            "rule_id": "CVE-2024-0001-left-pad",
            "id": "g",
            "severity": "MEDIUM",
        },
        {
            "scanner": "npm-audit",
            "rule_id": "CVE-2024-0001",
            "id": "n",
            "severity": "LOW",
        },
    )
    for other in (g, n):
        assert not other.is_primary and other.duplicate_of == "t"
        assert other.duplicate_sources == ()
        assert other.cluster_id == t.cluster_id and other.finding_class == CLASS_PACKAGE


# --- purity ----------------------------------------------------------------


def test_clustering_changes_no_row_and_no_id():
    rows = [pkg("g", "grype"), pkg("t", "trivy"), code("s", "semgrep")]
    before = [(r.id, r.model_dump()) for r in rows]
    assign_clusters(rows)
    assert [(r.id, r.model_dump()) for r in rows] == before


def test_input_order_changes_no_cluster_id_primary_or_source_order():
    rows = [
        pkg("g", "grype", severity="MEDIUM"),
        pkg("t", "trivy", severity="HIGH"),
        pkg("n", "npm-audit", severity="HIGH"),
        code("s", "semgrep"),
        code("b", "bandit"),
        code("o", "opengrep", line=9, end=10),
        iac("a", "cdk-nag"),
        iac("c", "checkov"),
        pkg("lone", "grype", cve_id="CVE-2000-0002"),
    ]
    expected = shape(rows)
    assert len(expected) == 3
    rng = random.Random(7)
    for _ in range(20):
        shuffled = rows[:]
        rng.shuffle(shuffled)
        assert shape(shuffled) == expected


def test_an_empty_list_has_no_clusters():
    assert cluster_findings([]) == [] and assign_clusters([]) == []


# --- distinct copies, unknown locations, rules, advisories ------------------


def lock(fid, scanner, version, **over):
    return pkg(
        fid,
        scanner,
        package_version=version,
        package_path=None,
        file_path="yarn.lock",
        **over,
    )


def test_two_copies_from_one_scanner_in_one_lockfile_are_two_findings():
    rows = [lock("a", "trivy", "1.2.3"), lock("b", "trivy", "2.0.1")]
    assert cluster_findings(rows) == []


def test_copies_pair_by_version_across_scanners_when_a_scanner_has_two():
    rows = [
        lock("t1", "trivy", "1.2.3"),
        lock("t2", "trivy", "2.0.1"),
        lock("g2", "grype", "2.0.1"),
    ]
    assert list(shape(rows)) == [frozenset({"t2", "g2"})]


def test_two_same_version_rows_of_one_scanner_cluster_with_nothing():
    rows = [
        lock("t1", "trivy", "1.0.0"),
        lock("t2", "trivy", "1.0.0"),
        lock("g", "grype", "1.0.0"),
    ]
    assert cluster_findings(rows) == []


def test_a_versionless_row_in_a_multi_copy_group_clusters_with_nothing():
    rows = [
        lock("t1", "trivy", "1.0.0"),
        lock("t2", "trivy", None),
        lock("g", "grype", None),
    ]
    assert cluster_findings(rows) == []


def test_rows_with_no_location_at_all_do_not_match_each_other():
    rows = [
        pkg("g", "grype", package_path=None, file_path=None),
        pkg("t", "trivy", package_path=None, file_path=" "),
    ]
    assert cluster_findings(rows) == []


def test_rows_pinned_only_to_an_sbom_do_not_match_each_other():
    rows = [
        pkg("a", "grype", package_path=None, file_path="out/sbom.cdx.json"),
        pkg("b", "trivy", package_path=None, file_path="out/sbom.cdx.json"),
    ]
    assert cluster_findings(rows) == []


def test_cross_ecosystem_same_name_rows_in_one_scanner_stay_apart():
    sbom = {"package_path": None, "file_path": "out/sbom.spdx.json"}
    rows = [
        pkg("apk", "trivy", package_version="3.21", **sbom),
        pkg("pip", "trivy", package_version="4.21", **sbom),
    ]
    assert cluster_findings(rows) == []


def test_different_cdk_nag_rules_on_one_construct_are_not_one_finding():
    rows = [
        iac("a", "cdk-nag", cwe_id=None, rule_id="AwsSolutions-IAM4"),
        iac("b", "cdk-nag", cwe_id=None, rule_id="AwsSolutions-IAM5"),
    ]
    assert cluster_findings(rows) == []


def test_one_rule_on_one_construct_without_a_cwe_still_clusters():
    rows = [
        iac("a", "cdk-nag", cwe_id=None, rule_id="AwsSolutions-IAM4"),
        iac("b", "cdk-nag2", cwe_id=None, rule_id="AwsSolutions-IAM4"),
    ]
    (cluster,) = cluster_findings(rows)
    assert cluster.finding_class == CLASS_IAC and not cluster.foldable


def test_an_iac_row_with_neither_cwe_nor_rule_has_no_key():
    rows = [
        iac("a", "x", cwe_id=None, rule_id=None),
        iac("b", "y", cwe_id=None, rule_id=None),
    ]
    assert cluster_findings(rows) == []


def test_a_non_cve_advisory_package_row_never_location_clusters():
    spot = {"file_path": "package-lock.json", "line_start": 1, "cwe_id": "CWE-1321"}
    rows = [
        pkg("a", "npm-audit", cve_id=None, rule_id="GHSA-aaaa-bbbb-cccc", **spot),
        pkg("b", "npm-audit", cve_id=None, rule_id="GHSA-dddd-eeee-ffff", **spot),
    ]
    assert cluster_findings(rows) == []
