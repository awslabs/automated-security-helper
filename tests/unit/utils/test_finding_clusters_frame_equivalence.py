# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The cluster engine decides exactly what the all-pairs engine decided.

``finding_clusters_reference.py`` beside this file is the engine as it was
written before it moved onto frames, kept verbatim as an oracle. A wrong
cluster folds a finding under another and hides it, or shows one finding twice,
so this module pins the engine two ways:

* golden outputs recorded from the engine before the move, for a set of named
  scenarios (``golden/finding_clusters_characterization.json``): every cluster's
  id, class, foldable flag, members, primary and sources, for
  ``cluster_findings``, ``clusters_by_project`` and ``assign_clusters_by_project``;
* a differential over generated finding lists, shuffled, against the oracle.
  The generators cover two or three files, one to three CWEs drawn from four, a
  narrow line range (ties and chains), an end before the start, a missing end,
  negative lines and lines above ``2**63``, paths holding a lone surrogate,
  package groups with repeated scanners, missing versions, version collisions
  and two projects.

Regenerate the golden file, only after reading why the engine's answer changed,
with ``python -B -s -c "from tests.unit.utils.test_finding_clusters_frame_equivalence
import record_golden; record_golden()"`` from the repository root.
"""

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from automated_security_helper.utils import finding_clusters as module
from tests.unit.models._flat_vulnerability_helpers import flat_with_severity
from tests.unit.utils import finding_clusters_reference as reference

pytestmark = pytest.mark.unit

GOLDEN_PATH = (
    Path(__file__).parent / "golden" / "finding_clusters_characterization.json"
)

SURROGATE_PATH = "dir/s\udcff.py"
BIG = 2**70
PAST_INT64 = 2**63


# ---------------------------------------------------------------------------
# building findings
# ---------------------------------------------------------------------------


def make(spec: Dict[str, Any]):
    """One finding from a spec dict; ``raw_path`` is set after validation."""
    spec = dict(spec)
    fid = spec.pop("id")
    scanner = spec.pop("scanner", "bandit")
    severity = spec.pop("severity", "HIGH")
    suppressed = spec.pop("suppressed", False)
    fingerprinted = spec.pop("fingerprinted", False)
    raw_path = spec.pop("raw_path", None)
    flat = flat_with_severity(
        severity,
        id=fid,
        title="t",
        description="d",
        scanner=scanner,
        scanner_type="SAST",
        is_suppressed=suppressed,
        **spec,
    )
    if fingerprinted:
        flat._assigned_identity_key = {"fingerprints": {"x": "y"}}
    if raw_path is not None:
        flat.__dict__["file_path"] = raw_path
    return flat


def pkg(fid, scanner, **over):
    fields = {
        "id": fid,
        "scanner": scanner,
        "cve_id": "CVE-2024-0001",
        "package_name": "left-pad",
        "package_version": "1.0.0",
        "package_path": "node_modules/left-pad",
        "rule_id": "CVE-2024-0001",
    }
    fields.update(over)
    return fields


def iac(fid, scanner, **over):
    fields = {
        "id": fid,
        "scanner": scanner,
        "resource_id": "aws_s3_bucket.b",
        "resource_type": "aws_s3_bucket",
        "file_path": "main.tf",
        "cwe_id": "CWE-732",
        "rule_id": "R1",
    }
    fields.update(over)
    return fields


def loc(fid, scanner, line=10, end=None, cwe="CWE-89", path="src/a.py", **over):
    fields = {
        "id": fid,
        "scanner": scanner,
        "file_path": path,
        "line_start": line,
        "line_end": end,
        "cwe_id": cwe,
        "rule_id": over.pop("rule_id", "R1"),
    }
    fields.update(over)
    return fields


def scenarios() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "empty": [],
        "single_row": [loc("a", "semgrep")],
        "package_two_scanners": [pkg("g", "grype"), pkg("t", "trivy")],
        "package_case_and_blanks": [
            pkg("g", "grype"),
            pkg("t", "trivy", cve_id=" cve-2024-0001 ", package_version=None),
            pkg("o", "osv", package_path="./node_modules/left-pad"),
        ],
        "package_other_path_stays_apart": [
            pkg("g", "grype"),
            pkg("t", "trivy", package_path="other/left-pad"),
        ],
        "package_location_free_or_sbom_has_no_key": [
            pkg("g", "grype", package_path=None, file_path=None),
            pkg("t", "trivy", package_path=None, file_path=None),
            pkg("a", "grype", package_path=None, file_path="bom.cdx.json"),
            pkg("b", "trivy", package_path=None, file_path="bom.cdx.json"),
            pkg("c", "grype", package_path="sbom.json", file_path="bom.cdx.json"),
            pkg("d", "trivy", package_path="sbom.json", file_path="bom.cdx.json"),
        ],
        "package_copies_split_by_version": [
            pkg("g1", "grype", package_version="1.0.0"),
            pkg("g2", "grype", package_version="2.0.0"),
            pkg("t1", "trivy", package_version="1.0.0"),
            pkg("t2", "trivy", package_version="2.0.0"),
        ],
        "package_version_collision_clusters_nothing": [
            pkg("g1", "grype", package_version="1.0.0"),
            pkg("g2", "grype", package_version="1.0.0"),
            pkg("t1", "trivy", package_version="1.0.0"),
        ],
        "package_missing_versions_in_a_split_group": [
            pkg("g1", "grype", package_version="1.0.0"),
            pkg("g2", "grype", package_version=None),
            pkg("t1", "trivy", package_version="1.0.0"),
            pkg("t2", "trivy", package_version=None),
        ],
        "package_a_lone_version_lane_is_no_cluster": [
            pkg("g1", "grype", package_version="1.0.0"),
            pkg("g2", "grype", package_version="2.0.0"),
        ],
        "package_missing_versions_without_a_repeat_stay_whole": [
            pkg("g", "grype", package_version=None),
            pkg("t", "trivy", package_version=None),
            pkg("o", "osv", package_version="3"),
        ],
        "package_scanner_repeat_is_counted_per_key": [
            pkg("g1", "grype", cve_id="CVE-1", package_version=None),
            pkg("t1", "trivy", cve_id="CVE-1", package_version=None),
            pkg("g2", "grype", cve_id="CVE-2", package_version=None),
            pkg("t2", "trivy", cve_id="CVE-2", package_version=None),
            pkg("g3", "grype", cve_id="CVE-3", package_version="1"),
            pkg("t3", "trivy", cve_id="CVE-3", package_version="1"),
        ],
        "package_blank_scanners_are_one_scanner": [
            pkg("a", "", package_version="1.0.0"),
            pkg("b", "", package_version="1.0.0"),
            pkg("t", "trivy", package_version="1.0.0"),
        ],
        "iac_exact_keys": [
            iac("a", "checkov"),
            iac("b", "cfn-nag"),
            iac("c", "checkov", cwe_id="CWE-732, CWE-16"),
            iac("d", "cfn-nag", cwe_id="cwe-16 cwe-732"),
            iac("e", "checkov", resource_type=None),
            iac("f", "cfn-nag", resource_type=None),
        ],
        "iac_rule_keys_a_row_with_no_cwe": [
            iac("a", "checkov", cwe_id=None, rule_id="R1"),
            iac("b", "cfn-nag", cwe_id=None, rule_id="R1"),
            iac("c", "checkov", cwe_id=None, rule_id="R2"),
            iac("d", "cfn-nag", cwe_id=None, rule_id=None),
            iac("e", "checkov", cwe_id=None, rule_id=None),
        ],
        "location_inclusive_overlap": [
            loc("a1", "semgrep", line=10, end=12, path="a.py"),
            loc("a2", "bandit", line=12, end=15, path="a.py"),
            loc("b1", "semgrep", line=10, end=12, path="b.py"),
            loc("b2", "bandit", line=13, end=15, path="b.py"),
            loc("c1", "semgrep", line=10, path="c.py"),
            loc("c2", "bandit", line=11, path="c.py"),
            loc("d1", "semgrep", line=20, end=30, path="d.py"),
            loc("d2", "bandit", line=25, end=25, path="d.py"),
        ],
        "location_chain_across_distinct_scanners": [
            loc("a", "semgrep", line=1, end=3),
            loc("b", "bandit", line=3, end=5),
            loc("c", "gosec", line=5, end=7),
            loc("d", "njsscan", line=9, end=9),
        ],
        "location_chain_of_one_scanner_and_rule_is_cut": [
            loc("a", "semgrep", line=1, end=3),
            loc("b", "bandit", line=3, end=5),
            loc("c", "semgrep", line=5, end=7),
        ],
        "location_bridge_row_clusters_with_nothing": [
            loc("a", "semgrep", line=1, end=1, cwe="CWE-89"),
            loc("b", "semgrep", line=50, end=50, cwe="CWE-79"),
            loc("w", "bandit", line=1, end=50, cwe="CWE-89, CWE-79"),
        ],
        "location_bridge_row_leaves_a_pair": [
            loc("a", "semgrep", line=1, end=1, cwe="CWE-89"),
            loc("b", "semgrep", line=50, end=50, cwe="CWE-79"),
            loc("w", "bandit", line=1, end=50, cwe="CWE-89, CWE-79"),
            loc("x", "gosec", line=1, end=1, cwe="CWE-89"),
            loc("y", "gosec", line=50, end=50, cwe="CWE-79"),
        ],
        "location_chain_with_no_single_bridge": [
            loc("a", "semgrep", line=1, end=2),
            loc("x", "bandit", line=2, end=3),
            loc("y", "gosec", line=3, end=4),
            loc("b", "semgrep", line=4, end=5),
        ],
        "location_end_before_start_and_missing_end": [
            loc("a", "semgrep", line=10, end=5),
            loc("b", "bandit", line=10, end=None),
            loc("c", "gosec", line=10, end=9),
            loc("d", "njsscan", line=11, end=2),
            loc("e", "semgrep", line=12, end=None, rule_id="R2"),
        ],
        "location_equal_starts_and_ties": [
            loc("a", "semgrep", line=4, end=9),
            loc("b", "bandit", line=4, end=4),
            loc("c", "gosec", line=4, end=6),
            loc("d", "njsscan", line=9, end=9),
            loc("e", "pyre", line=10, end=10),
        ],
        "location_negative_and_huge_lines": [
            loc("a", "semgrep", line=-5, end=-3),
            loc("b", "bandit", line=-3, end=-1),
            loc("c", "gosec", line=BIG, end=BIG + 5),
            loc("d", "njsscan", line=BIG + 5, end=BIG + 6),
            loc("e", "pyre", line=PAST_INT64, end=PAST_INT64),
            loc("f", "semgrep", line=PAST_INT64 - 1, end=PAST_INT64),
            loc("g", "bandit", line=-BIG, end=-BIG + 1),
            loc("h", "gosec", line=-BIG + 1, end=-BIG + 1),
            loc("i", "njsscan", line=BIG, end=BIG - 3),
        ],
        "location_cwes_join_separate_islands": [
            loc("a", "semgrep", line=1, end=2, cwe="CWE-89"),
            loc("b", "bandit", line=1, end=2, cwe="CWE-89, CWE-79"),
            loc("c", "gosec", line=10, end=12, cwe="CWE-79"),
            loc("d", "njsscan", line=11, end=11, cwe="CWE-22"),
        ],
        "location_cwe_must_be_shared": [
            loc("a", "semgrep", line=1, end=5, cwe="CWE-89"),
            loc("b", "bandit", line=1, end=5, cwe="CWE-79"),
            loc("c", "gosec", line=1, end=5, cwe="n/a"),
            loc("d", "njsscan", line=1, end=5, cwe=None),
        ],
        "location_files_are_independent": [
            loc("a", "semgrep", line=1, end=5, path="a.py"),
            loc("b", "bandit", line=1, end=5, path="b.py"),
            loc("c", "gosec", line=1, end=5, path="./a.py"),
            loc("d", "njsscan", line=1, end=5, path="x/../b.py"),
        ],
        "location_surrogate_paths": [
            loc("a", "semgrep", line=1, end=5, path="x.py", raw_path=SURROGATE_PATH),
            loc("b", "bandit", line=3, end=7, path="x.py", raw_path=SURROGATE_PATH),
            loc("c", "gosec", line=3, end=7, path="x.py", raw_path="dir/s\udcfe.py"),
            loc("d", "njsscan", line=3, end=7, path="dir/s\xffy.py"),
        ],
        "location_a_package_row_never_joins": [
            loc("a", "semgrep", line=1, end=5),
            loc("b", "bandit", line=1, end=5, package_name="left-pad"),
            pkg(
                "c",
                "grype",
                cve_id=None,
                file_path="src/a.py",
                line_start=1,
                line_end=5,
                cwe_id="CWE-89",
            ),
        ],
        "classes_in_order": [
            pkg("p1", "grype", file_path="src/a.py", line_start=1, cwe_id="CWE-89"),
            pkg("p2", "trivy", file_path="src/a.py", line_start=1, cwe_id="CWE-89"),
            iac("i1", "checkov", line_start=1, line_end=3),
            iac("i2", "cfn-nag", line_start=1, line_end=3),
            loc("l1", "semgrep", line=1, end=3, path="main.tf"),
            loc("l2", "bandit", line=2, end=4, path="main.tf"),
        ],
        "primary_prefers_live_and_severity": [
            loc("a", "semgrep", line=1, end=3, severity="LOW"),
            loc("b", "bandit", line=1, end=3, severity="CRITICAL", suppressed=True),
            loc("c", "gosec", line=1, end=3, severity="MEDIUM", fingerprinted=True),
            loc("d", "njsscan", line=1, end=3, severity="MEDIUM"),
            loc("e", "pyre", line=1, end=3, severity="MEDIUM", suppressed=True),
        ],
        "two_projects_hold_one_finding_each": [
            pkg("a1", "grype", workspace_project="p1"),
            pkg("a2", "grype", workspace_project="p2"),
            pkg("b1", "trivy", workspace_project="p1"),
            pkg("b2", "trivy", workspace_project="p2"),
            loc("c1", "semgrep", line=1, end=3, workspace_project="p1"),
            loc("c2", "bandit", line=2, end=4, workspace_project="p2"),
            loc("c3", "gosec", line=2, end=4, workspace_project="p1"),
            loc("c4", "njsscan", line=2, end=4, workspace_project=None),
            loc("c5", "pyre", line=3, end=3, workspace_project=None),
            iac("i1", "checkov", workspace_project="p1"),
            iac("i2", "cfn-nag", workspace_project="p2"),
            iac("i3", "cfn-nag", workspace_project=None),
            iac("i4", "checkov", workspace_project=None),
        ],
        "two_projects_with_one_repeated_id": [
            loc("same", "semgrep", line=1, end=3, workspace_project="p1"),
            loc("same", "bandit", line=1, end=3, workspace_project="p1"),
            loc("same", "semgrep", line=1, end=3, workspace_project="p2"),
            loc("same", "bandit", line=1, end=3, workspace_project="p2"),
        ],
    }


# ---------------------------------------------------------------------------
# comparable views
# ---------------------------------------------------------------------------


def _severity(value):
    return getattr(value, "value", value)


def _source(source):
    return [
        source["scanner"],
        source["rule_id"],
        source["id"],
        _severity(source["severity"]),
    ]


def cluster_view(cluster):
    return [
        cluster.cluster_id,
        cluster.finding_class,
        cluster.foldable,
        list(cluster.members),
        cluster.primary,
        [_source(source) for source in cluster.sources],
    ]


def assignment_view(assignment):
    return [
        assignment.cluster_id,
        assignment.finding_class,
        assignment.foldable,
        assignment.is_primary,
        assignment.duplicate_of,
        [_source(source) for source in assignment.duplicate_sources],
    ]


def outputs(engine, rows):
    return {
        "cluster_findings": [cluster_view(c) for c in engine.cluster_findings(rows)],
        "clusters_by_project": [
            cluster_view(c) for c in engine.clusters_by_project(rows)
        ],
        "assign_clusters_by_project": [
            assignment_view(a) for a in engine.assign_clusters_by_project(rows)
        ],
    }


def record_golden() -> None:
    """Write the golden file from the engine as it is now; see the module docs."""
    golden = {
        name: outputs(module, [make(spec) for spec in specs])
        for name, specs in sorted(scenarios().items())
    }
    GOLDEN_PATH.write_text(
        json.dumps(golden, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


@pytest.fixture(scope="module")
def golden():
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# goldens
# ---------------------------------------------------------------------------


def test_the_golden_file_holds_exactly_the_scenarios(golden):
    assert sorted(golden) == sorted(scenarios())


@pytest.mark.parametrize("name", sorted(scenarios()))
def test_the_engine_reproduces_the_recorded_clusters(golden, name):
    rows = [make(spec) for spec in scenarios()[name]]
    assert outputs(module, rows) == golden[name]


@pytest.mark.parametrize("name", sorted(scenarios()))
def test_the_oracle_reproduces_the_recorded_clusters(golden, name):
    rows = [make(spec) for spec in scenarios()[name]]
    assert outputs(reference, rows) == golden[name]


def test_the_scenarios_hold_clusters_of_every_class():
    classes = set()
    for specs in scenarios().values():
        rows = [make(spec) for spec in specs]
        classes |= {c.finding_class for c in reference.cluster_findings(rows)}
    assert classes == {"package", "iac", "location"}


@pytest.mark.parametrize(
    "a, b, folds",
    [
        ((10, 12), (12, 15), True),
        ((10, 12), (13, 15), False),
        ((10, None), (10, None), True),
        ((10, None), (11, None), False),
        ((10, 5), (10, None), True),
        ((1, 3), (3, 5), True),
        ((BIG, BIG + 1), (BIG + 1, BIG + 2), True),
        ((BIG, BIG + 1), (BIG + 2, BIG + 3), False),
    ],
)
def test_line_ranges_overlap_with_inclusive_ends(a, b, folds):
    rows = [
        make(loc("s", "semgrep", line=a[0], end=a[1])),
        make(loc("b", "bandit", line=b[0], end=b[1])),
    ]
    assert bool(module.cluster_findings(rows)) is folds
    assert bool(reference.cluster_findings(rows)) is folds


# ---------------------------------------------------------------------------
# empty input and imports
# ---------------------------------------------------------------------------


def test_empty_input_builds_no_frame(monkeypatch):
    import polars as pl

    def refuse(*args, **kwargs):
        raise AssertionError("a frame was built for empty input")

    monkeypatch.setattr(pl, "DataFrame", refuse)
    assert module.cluster_findings([]) == []
    assert module.clusters_by_project([]) == []
    assert module.assign_clusters([]) == []
    assert module.assign_clusters_by_project([]) == []


def test_importing_the_module_does_not_load_polars():
    probe = (
        "import sys; "
        "import automated_security_helper.utils.finding_clusters; "
        "print('polars' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", probe],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False"


# ---------------------------------------------------------------------------
# the differential
# ---------------------------------------------------------------------------

CWES = ["CWE-79", "CWE-89", "CWE-22", "CWE-20"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LINE_CHOICES = st.one_of(
    st.integers(-2, 10),
    st.integers(3, 6),
    st.sampled_from([PAST_INT64 - 1, PAST_INT64, PAST_INT64 + 1, BIG, -BIG]),
)


@st.composite
def cwe_text(draw):
    count = draw(st.integers(0, 3))
    if count == 0:
        return draw(st.sampled_from([None, "", "n/a", "no cwe here"]))
    picked = draw(st.permutations(CWES))[:count]
    parts = []
    for cwe in picked:
        style = draw(st.sampled_from(["plain", "lower", "zeros"]))
        if style == "lower":
            parts.append(cwe.lower())
        elif style == "zeros":
            parts.append("CWE-0" + cwe.split("-")[1])
        else:
            parts.append(cwe)
    return draw(st.sampled_from([", ", ";", " "])).join(parts)


@st.composite
def line_pair(draw):
    start = draw(LINE_CHOICES)
    end = draw(
        st.one_of(
            st.none(),
            st.integers(-3, 5).map(lambda delta: start + delta),
            LINE_CHOICES,
        )
    )
    return start, end


@st.composite
def finding_specs(draw, with_projects):
    count = draw(st.integers(0, 14))
    specs = []
    for position in range(count):
        kind = draw(
            st.sampled_from(["loc", "loc", "loc", "pkg", "pkg", "iac", "plain"])
        )
        spec: Dict[str, Any] = {
            "id": draw(st.sampled_from([f"id{position}", f"id{position}", "dup"])),
            "scanner": draw(st.sampled_from(["s1", "s2", "s3", "grype", "trivy", ""])),
            "rule_id": draw(st.sampled_from([None, "", "R1", "R2"])),
            "severity": draw(st.sampled_from(SEVERITIES)),
            "suppressed": draw(st.booleans()),
            "fingerprinted": draw(st.booleans()),
        }
        if with_projects:
            spec["workspace_project"] = draw(st.sampled_from([None, "p1", "p2"]))
        if kind in ("loc", "plain") or draw(st.booleans()):
            start, end = draw(line_pair())
            path = draw(
                st.sampled_from(["a.py", "b.py", "./a.py", "d/../a.py", "c.py", None])
            )
            spec.update(
                file_path=path,
                line_start=draw(st.sampled_from([start, start, None])),
                line_end=end,
                cwe_id=draw(cwe_text()),
            )
            if path is not None and draw(st.integers(0, 6)) == 0:
                spec["raw_path"] = SURROGATE_PATH
        if kind == "pkg":
            spec.update(
                cve_id=draw(st.sampled_from([None, "CVE-1", "cve-1", " CVE-2 "])),
                package_name=draw(st.sampled_from(["a", "b", " "])),
                package_version=draw(st.sampled_from([None, "1", "2", " 1 ", ""])),
                package_path=draw(st.sampled_from([None, "p/a", "p/b", "./p/a", ""])),
            )
            if "file_path" not in spec:
                spec["file_path"] = draw(
                    st.sampled_from([None, "x.py", "sbom.json", "bom.cdx.json"])
                )
        if kind == "iac":
            spec.update(
                resource_id=draw(st.sampled_from([None, "r1", "r2", " r1 "])),
                resource_type=draw(st.sampled_from([None, "t1", ""])),
            )
            if "file_path" not in spec:
                spec["file_path"] = draw(st.sampled_from([None, "main.tf", "other.tf"]))
            if "cwe_id" not in spec:
                spec["cwe_id"] = draw(cwe_text())
        specs.append(spec)
    order = draw(st.permutations(range(count)))
    return [specs[i] for i in order]


DIFFERENTIAL = settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


@DIFFERENTIAL
@given(finding_specs(with_projects=False))
def test_cluster_findings_matches_the_oracle(specs):
    rows = [make(spec) for spec in specs]
    assert [cluster_view(c) for c in module.cluster_findings(rows)] == [
        cluster_view(c) for c in reference.cluster_findings(rows)
    ]


@DIFFERENTIAL
@given(finding_specs(with_projects=True))
def test_clusters_by_project_matches_the_oracle(specs):
    rows = [make(spec) for spec in specs]
    assert [cluster_view(c) for c in module.clusters_by_project(rows)] == [
        cluster_view(c) for c in reference.clusters_by_project(rows)
    ]


@DIFFERENTIAL
@given(finding_specs(with_projects=True))
def test_assign_clusters_by_project_matches_the_oracle(specs):
    rows = [make(spec) for spec in specs]
    assert [assignment_view(a) for a in module.assign_clusters_by_project(rows)] == [
        assignment_view(a) for a in reference.assign_clusters_by_project(rows)
    ]


@DIFFERENTIAL
@given(finding_specs(with_projects=False))
def test_assign_clusters_matches_the_oracle(specs):
    rows = [make(spec) for spec in specs]
    assert [assignment_view(a) for a in module.assign_clusters(rows)] == [
        assignment_view(a) for a in reference.assign_clusters(rows)
    ]


@DIFFERENTIAL
@given(finding_specs(with_projects=False))
def test_the_components_match_the_oracle(specs):
    rows = [make(spec) for spec in specs]
    spans = {
        index: span
        for index, row in enumerate(rows)
        if (span := reference._span(row)) is not None
    }
    expected = sorted(reference._location_groups(spans))
    assert sorted(module._location_groups(spans)) == expected
    for group in expected:
        assert sorted(module._location_split_guard(rows, spans, group)) == sorted(
            reference._location_split_guard(rows, spans, group)
        )


@DIFFERENTIAL
@given(finding_specs(with_projects=False), st.randoms(use_true_random=False))
def test_the_clusters_do_not_depend_on_input_order(specs, rng):
    rows = [make(spec) for spec in specs]
    order = list(range(len(rows)))
    rng.shuffle(order)
    shuffled = [rows[i] for i in order]
    before = {
        (c.cluster_id, c.finding_class, tuple(sorted(order[m] for m in c.members)))
        for c in module.cluster_findings(shuffled)
    }
    after = {
        (c.cluster_id, c.finding_class, tuple(c.members))
        for c in module.cluster_findings(rows)
    }
    assert before == after


# ---------------------------------------------------------------------------
# cost
# ---------------------------------------------------------------------------


def many_cluster_rows(files):
    specs = []
    for k in range(files):
        path = f"m{k}.py"
        specs += [
            loc(f"a{k}", "semgrep", line=1, end=1, cwe="CWE-89", path=path),
            loc(f"b{k}", "semgrep", line=50, end=50, cwe="CWE-79", path=path),
            loc(f"w{k}", "bandit", line=1, end=50, cwe="CWE-89, CWE-79", path=path),
            loc(f"p{k}", "semgrep", line=100, cwe="CWE-22", path=path, rule_id="R2"),
            loc(f"q{k}", "gosec", line=100, cwe="CWE-22", path=path, rule_id="R3"),
            pkg(f"g{k}", "grype", cve_id=f"CVE-{k}"),
            pkg(f"t{k}", "trivy", cve_id=f"CVE-{k}"),
        ]
    return [make(spec) for spec in specs]


def test_the_cost_of_a_many_cluster_fixture_is_reported():
    """Prints the median of five runs of each engine; asserts only equal output."""
    rows = many_cluster_rows(300)
    new_runs = []
    old_runs = []
    for _ in range(5):
        started = time.perf_counter()
        got = module.cluster_findings(rows)
        new_runs.append(time.perf_counter() - started)
        started = time.perf_counter()
        expected = reference.cluster_findings(rows)
        old_runs.append(time.perf_counter() - started)
    assert [cluster_view(c) for c in got] == [cluster_view(c) for c in expected]
    print(
        f"CLUSTER COST rows={len(rows)} clusters={len(got)} "
        f"median_new_s={statistics.median(new_runs):.4f} "
        f"median_oracle_s={statistics.median(old_runs):.4f}"
    )
