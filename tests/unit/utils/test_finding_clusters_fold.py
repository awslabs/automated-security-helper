# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The fold layer over duplicate clusters: which rows a view shows once.

The switch is ``global_settings.deduplication.fold``, off unless a literal
``True`` is recorded. A view folds only the members it shows, never folds a
suppressed row under a live one, and never folds the IaC class or a location
pair that carries no CWE. The fold changes no row and no id.
"""

import random
from types import SimpleNamespace

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.finding_clusters import (
    clusters_by_project,
    cluster_findings,
    fold_enabled,
    fold_positions,
    provenance_entries,
    provenance_note,
)

pytestmark = pytest.mark.unit


def row(fid, scanner, severity="HIGH", **over):
    fields = {
        "cve_id": "CVE-2024-0001",
        "package_name": "left-pad",
        "package_version": "1.0.0",
        "package_path": "node_modules/left-pad",
        "rule_id": "CVE-2024-0001",
    }
    fields.update(over)
    return FlatVulnerability(
        id=fid,
        title="t",
        description="d",
        severity=severity,
        scanner=scanner,
        scanner_type="SCA",
        **fields,
    )


def sast(fid, scanner, cwe="CWE-89", line=10, **over):
    fields = {
        "cve_id": None,
        "package_name": None,
        "package_path": None,
        "package_version": None,
        "rule_id": f"{scanner}-rule",
        "file_path": "src/app.py",
        "line_start": line,
        "line_end": line,
        "cwe_id": cwe,
    }
    fields.update(over)
    return row(fid, scanner, **fields)


def folded(rows, shown=None):
    clusters = clusters_by_project(rows)
    view = list(range(len(rows))) if shown is None else shown
    return fold_positions(rows, clusters, view)


def model_with(fold):
    return SimpleNamespace(
        ash_config=SimpleNamespace(
            global_settings=SimpleNamespace(deduplication=SimpleNamespace(fold=fold))
        )
    )


class TestTheSwitch:
    def test_the_default_config_leaves_it_off(self):
        config = AshConfig()
        assert config.global_settings.deduplication.fold is False
        assert fold_enabled(SimpleNamespace(ash_config=config)) is False

    def test_the_config_file_key_turns_it_on(self):
        config = AshConfig.model_validate(
            {"global_settings": {"deduplication": {"fold": True}}}
        )
        assert fold_enabled(SimpleNamespace(ash_config=config)) is True

    def test_annotate_and_fold_are_independent(self):
        config = AshConfig.model_validate(
            {"global_settings": {"deduplication": {"annotate": True}}}
        )
        assert config.global_settings.deduplication.fold is False

    @pytest.mark.parametrize("value", [1, "true", None, "yes"])
    def test_only_a_literal_true_counts(self, value):
        assert fold_enabled(model_with(value)) is False

    def test_a_model_with_no_config_is_off(self):
        assert fold_enabled(SimpleNamespace()) is False
        assert fold_enabled(SimpleNamespace(ash_config=None)) is False


class TestMustFold:
    def test_a_cve_in_one_package_folds_to_its_primary(self):
        rows = [
            row("a", "trivy", "MEDIUM"),
            row("b", "grype", "HIGH"),
            row("c", "other", package_name="other", package_path="x/other"),
        ]
        kept = dict(folded(rows))
        assert set(kept) == {1, 2}, "the HIGH grype row stands for the cluster"
        assert kept[1] == (0,)
        assert kept[2] == ()

    def test_a_package_version_difference_still_folds(self):
        rows = [
            row("a", "grype", package_version="1.0.0"),
            row("b", "trivy", package_version="1.0.1"),
        ]
        assert [position for position, _ in folded(rows)] == [0]

    def test_a_location_with_a_shared_cwe_folds(self):
        rows = [sast("a", "bandit"), sast("b", "semgrep", cwe="CWE-89, CWE-20")]
        assert dict(folded(rows)) == {0: (1,)}

    def test_the_order_of_the_view_is_kept(self):
        rows = [
            row("a", "x", package_name="p1", package_path="p1"),
            row("b", "grype"),
            row("c", "y", package_name="p2", package_path="p2"),
            row("d", "trivy"),
        ]
        assert [position for position, _ in folded(rows)] == [0, 1, 2]


class TestMustNotFold:
    def test_the_same_cve_in_another_package_path_stays_two_rows(self):
        rows = [
            row("a", "grype", package_path="node_modules/left-pad"),
            row("b", "trivy", package_path="vendor/left-pad"),
        ]
        assert [position for position, _ in folded(rows)] == [0, 1]

    def test_the_same_line_with_another_cwe_stays_two_rows(self):
        rows = [sast("a", "bandit", cwe="CWE-89"), sast("b", "semgrep", cwe="CWE-79")]
        assert [position for position, _ in folded(rows)] == [0, 1]

    def test_a_location_without_a_cwe_fails_closed(self):
        rows = [sast("a", "bandit", cwe=None), sast("b", "semgrep", cwe=None)]
        assert [position for position, _ in folded(rows)] == [0, 1]

    def test_an_iac_resource_pair_is_annotated_but_never_folded(self):
        rows = [
            row(
                "a",
                "checkov",
                cve_id=None,
                package_name=None,
                resource_id="aws_s3_bucket.b",
                resource_type="aws_s3_bucket",
                file_path="main.tf",
            ),
            row(
                "b",
                "cfn-nag",
                cve_id=None,
                package_name=None,
                resource_id="aws_s3_bucket.b",
                resource_type="aws_s3_bucket",
                file_path="main.tf",
            ),
        ]
        clusters = cluster_findings(rows)
        assert len(clusters) == 1 and clusters[0].foldable is False
        assert [position for position, _ in folded(rows)] == [0, 1]
        assert dict(folded(rows)) == {0: (), 1: ()}

    def test_a_suppressed_duplicate_is_not_hidden_under_a_live_row(self):
        rows = [
            row("a", "grype"),
            row("b", "trivy", is_suppressed=True),
        ]
        assert dict(folded(rows)) == {0: (), 1: ()}

    def test_a_live_row_is_not_hidden_under_a_suppressed_one(self):
        rows = [
            row("a", "grype", severity="CRITICAL", is_suppressed=True),
            row("b", "trivy", severity="LOW"),
        ]
        assert dict(folded(rows)) == {0: (), 1: ()}

    def test_two_suppressed_duplicates_fold_together(self):
        rows = [
            row("a", "grype", is_suppressed=True),
            row("b", "trivy", is_suppressed=True),
        ]
        assert len(folded(rows)) == 1

    def test_secrets_with_no_cwe_never_fold(self):
        rows = [
            sast("a", "gitleaks", cwe=None, rule_id="aws-key"),
            sast("b", "detect-secrets", cwe=None, rule_id="aws-key"),
        ]
        assert [position for position, _ in folded(rows)] == [0, 1]


class TestAViewFoldsWhatItShows:
    def test_a_primary_outside_the_view_hands_over_to_the_best_that_is_in_it(self):
        rows = [
            row("a", "grype", "HIGH"),
            row("b", "trivy", "MEDIUM"),
            row("c", "osv", "LOW"),
        ]
        # The HIGH primary is filtered out of the view: the MEDIUM row stands.
        assert dict(folded(rows, shown=[1, 2])) == {1: (2,)}

    def test_a_cluster_with_one_member_in_the_view_stands_alone(self):
        rows = [row("a", "grype"), row("b", "trivy")]
        assert dict(folded(rows, shown=[1])) == {1: ()}

    def test_a_view_with_no_cluster_changes_nothing(self):
        rows = [
            row("a", "grype", package_path="a"),
            row("b", "trivy", package_path="b"),
        ]
        assert folded(rows) == [(0, ()), (1, ())]

    def test_an_empty_view_is_empty(self):
        assert folded([row("a", "grype"), row("b", "trivy")], shown=[]) == []

    def test_a_preferred_member_stands_for_the_cluster_over_a_severer_one(self):
        rows = [
            row("a", "grype", "HIGH"),
            row("b", "trivy", "MEDIUM"),
            row("c", "osv", "MEDIUM"),
        ]
        shown = list(range(len(rows)))
        clusters = cluster_findings(rows)
        # Without a preference the severity-ranked primary stands.
        assert dict(fold_positions(rows, clusters, shown)) == {0: (1, 2)}
        # The preference (the emitter's actionable rows) wins while any of its
        # positions is present; the primary ranking orders the preferred, so of
        # the two equally severe preferred rows the scanner name decides.
        assert dict(fold_positions(rows, clusters, shown, prefer={1, 2})) == {2: (0, 1)}
        assert dict(fold_positions(rows, clusters, shown, prefer={1})) == {1: (0, 2)}
        # A preference none of whose positions is present changes nothing.
        assert dict(fold_positions(rows, clusters, shown, prefer={99})) == {0: (1, 2)}
        # A preferred primary is still the representative.
        assert dict(fold_positions(rows, clusters, shown, prefer={0, 1})) == {0: (1, 2)}

    def test_a_suppressed_preferred_row_never_stands_for_live_ones(self):
        rows = [
            row("a", "grype", "HIGH"),
            row("b", "trivy", "MEDIUM"),
            row("c", "osv", "MEDIUM", is_suppressed=True),
        ]
        shown = [0, 1, 2]
        clusters = cluster_findings(rows)
        # The suppressed row is alone on its side of the split whatever the
        # preference says, so it stays in the view.
        assert dict(fold_positions(rows, clusters, shown, prefer={2})) == {
            0: (1,),
            2: (),
        }


class TestTheFoldIsDeterministic:
    def test_a_shuffled_input_keeps_the_same_representatives(self):
        base = [
            row("a", "grype", "HIGH"),
            row("b", "trivy", "MEDIUM"),
            row("c", "osv", "HIGH"),
            sast("d", "bandit"),
            sast("e", "semgrep"),
            row("f", "x", package_name="solo", package_path="solo"),
        ]
        expected = None
        for seed in range(8):
            rows = list(base)
            random.Random(seed).shuffle(rows)
            result = {
                rows[position].id: sorted(rows[o].id for o in others)
                for position, others in folded(rows)
            }
            if expected is None:
                expected = result
            assert result == expected
        # Equal severity: the scanner name breaks the tie, so grype stands.
        assert expected["a"] == ["b", "c"]
        assert expected["d"] == ["e"]


class TestProjects:
    def test_clusters_by_project_read_against_the_full_list(self):
        rows = [
            row("a", "grype", workspace_project="p1"),
            row("x", "grype", workspace_project="p2"),
            row("b", "trivy", workspace_project="p1"),
            row("y", "trivy", workspace_project="p2"),
        ]
        clusters = clusters_by_project(rows)
        assert sorted(c.members for c in clusters) == [(0, 2), (1, 3)]
        assert dict(fold_positions(rows, clusters, [0, 1, 2, 3])) == {
            0: (2,),
            1: (3,),
        }

    def test_two_projects_never_share_a_cluster(self):
        rows = [
            row("a", "grype", workspace_project="p1"),
            row("b", "trivy", workspace_project="p2"),
        ]
        assert clusters_by_project(rows) == []

    def test_identical_ids_in_two_projects_never_share_a_cluster_id(self):
        # Identity-derived ids embed their project; a plugin-supplied id on an
        # identity-less finding can repeat across projects, and two different
        # clusters must never share an id.
        def pair(project):
            return [
                row("same-id", "grype", workspace_project=project),
                row("other-id", "trivy", workspace_project=project),
            ]

        clusters = clusters_by_project([*pair("api"), *pair("web")])
        assert len(clusters) == 2
        assert len({c.cluster_id for c in clusters}) == 2


class TestProvenance:
    def test_a_note_names_each_other_scanner_rule_and_severity(self):
        rows = [row("a", "grype"), row("b", "trivy", "MEDIUM"), row("c", "osv", "LOW")]
        note = provenance_note(provenance_entries(rows, [2, 1]))
        assert note == (
            "Also reported by osv CVE-2024-0001 (LOW); trivy CVE-2024-0001 (MEDIUM)"
        )

    def test_the_note_does_not_depend_on_the_order_of_the_others(self):
        rows = [row("a", "grype"), row("b", "trivy"), row("c", "osv")]
        assert provenance_entries(rows, [1, 2]) == provenance_entries(rows, [2, 1])

    def test_a_row_standing_for_none_has_no_note(self):
        assert provenance_note([]) is None

    def test_a_missing_scanner_or_rule_is_left_out(self):
        assert provenance_note([{"severity": "HIGH"}]) == "Also reported by (HIGH)"
        assert provenance_note([{}]) == "Also reported by unknown"

    def test_the_fold_changes_no_row(self):
        rows = [row("a", "grype"), row("b", "trivy")]
        before = [r.model_dump() for r in rows]
        folded(rows)
        assert [r.model_dump() for r in rows] == before
