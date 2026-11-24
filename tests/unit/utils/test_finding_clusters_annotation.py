# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The annotation layer over duplicate clusters: switch, columns, projects.

The switch is ``global_settings.deduplication.annotate`` and is off unless a
literal ``True`` is recorded. The columns are a view of a row's assignment and
change no row. Workspace projects never share a cluster.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.finding_clusters import (
    ANNOTATION_COLUMNS,
    ClusterAssignment,
    annotate_enabled,
    annotation_values,
    assign_clusters,
    assign_clusters_by_project,
)

pytestmark = pytest.mark.unit


def pkg(fid, scanner, project=None, **over):
    fields = {
        "cve_id": "CVE-2024-0001",
        "package_name": "left-pad",
        "package_version": "1.0.0",
        "package_path": "node_modules/left-pad",
        "rule_id": "CVE-2024-0001",
        "workspace_project": project,
    }
    fields.update(over)
    return FlatVulnerability(
        id=fid,
        title="t",
        description="d",
        severity="HIGH",
        scanner=scanner,
        scanner_type="SCA",
        **fields,
    )


def model_with(annotate):
    return SimpleNamespace(
        ash_config=SimpleNamespace(
            global_settings=SimpleNamespace(
                deduplication=SimpleNamespace(annotate=annotate)
            )
        )
    )


class TestTheSwitch:
    def test_the_default_config_leaves_it_off(self):
        config = AshConfig()
        assert config.global_settings.deduplication.annotate is False
        assert annotate_enabled(SimpleNamespace(ash_config=config)) is False

    def test_the_config_file_key_turns_it_on(self):
        config = AshConfig.model_validate(
            {"global_settings": {"deduplication": {"annotate": True}}}
        )
        assert annotate_enabled(SimpleNamespace(ash_config=config)) is True

    def test_an_unknown_deduplication_key_is_refused(self):
        with pytest.raises(ValidationError):
            AshConfig.model_validate(
                {"global_settings": {"deduplication": {"fold": True}}}
            )

    @pytest.mark.parametrize("annotate", [False, None, "yes", 1, MagicMock()])
    def test_only_a_literal_true_counts(self, annotate):
        assert annotate_enabled(model_with(annotate)) is False

    @pytest.mark.parametrize(
        "model",
        [
            SimpleNamespace(),
            SimpleNamespace(ash_config=None),
            SimpleNamespace(ash_config=SimpleNamespace()),
            SimpleNamespace(ash_config=SimpleNamespace(global_settings=None)),
            MagicMock(),
        ],
        ids=["none", "no-config", "no-settings", "null-settings", "mock"],
    )
    def test_no_recorded_setting_is_off(self, model):
        assert annotate_enabled(model) is False

    def test_the_switch_is_on_when_recorded_true(self):
        assert annotate_enabled(model_with(True)) is True


class TestTheColumns:
    def test_the_columns_are_three_and_in_a_fixed_order(self):
        assert ANNOTATION_COLUMNS == ("cluster_id", "duplicate_of", "duplicate_sources")
        assert set(ANNOTATION_COLUMNS).isdisjoint(FlatVulnerability.model_fields), (
            "the columns are a layer over the flat model, not fields of it, so "
            "the default header and every other consumer of the model are unchanged"
        )

    def test_a_row_in_no_cluster_is_all_none(self):
        assert annotation_values(ClusterAssignment()) == dict.fromkeys(
            ANNOTATION_COLUMNS
        )

    def test_a_primary_and_a_duplicate_carry_what_applies_to_each(self):
        rows = [pkg("a", "grype"), pkg("b", "trivy")]
        one, two = (annotation_values(a) for a in assign_clusters(rows))
        # grype sorts before trivy on a tie, so "a" is the primary.
        assert one["cluster_id"] == two["cluster_id"] is not None
        assert one["duplicate_of"] is None
        assert one["duplicate_sources"] == [
            {"scanner": "trivy", "rule_id": "CVE-2024-0001", "id": "b", "severity": "HIGH"}
        ]
        assert two["duplicate_of"] == "a"
        assert two["duplicate_sources"] is None

    def test_the_values_are_copies(self):
        rows = [pkg("a", "grype"), pkg("b", "trivy")]
        primary = assign_clusters(rows)[0]
        annotation_values(primary)["duplicate_sources"][0]["id"] = "mutated"
        assert primary.duplicate_sources[0]["id"] == "b"


class TestProjects:
    def test_a_single_directory_scan_is_the_plain_call(self):
        rows = [pkg("a", "grype"), pkg("b", "trivy")]
        assert assign_clusters_by_project(rows) == assign_clusters(rows)

    def test_two_projects_never_share_a_cluster(self):
        rows = [
            pkg("a1", "grype", project="p1"),
            pkg("b1", "trivy", project="p2"),
            pkg("a2", "grype", project="p2"),
            pkg("b2", "trivy", project="p1"),
        ]
        assigned = assign_clusters_by_project(rows)
        by_id = {row.id: a for row, a in zip(rows, assigned, strict=True)}
        # Same CVE and path in both projects: one cluster per project, never one
        # across them.
        assert by_id["a1"].cluster_id == by_id["b2"].cluster_id is not None
        assert by_id["b1"].cluster_id == by_id["a2"].cluster_id is not None
        assert by_id["a1"].cluster_id != by_id["b1"].cluster_id

    def test_a_lone_finding_in_a_project_is_in_no_cluster(self):
        rows = [pkg("a", "grype", project="p1"), pkg("b", "trivy", project="p2")]
        assert assign_clusters_by_project(rows) == [ClusterAssignment()] * 2

    def test_input_order_is_kept(self):
        rows = [
            pkg("a1", "grype", project="p1"),
            pkg("x", "grype", project="p2", cve_id="CVE-2024-9999"),
            pkg("b1", "trivy", project="p1"),
        ]
        assigned = assign_clusters_by_project(rows)
        assert assigned[1] == ClusterAssignment()
        assert assigned[0].cluster_id == assigned[2].cluster_id is not None
