# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan closed from its results file is not reopened over a scan in its tree.

A scan that a poll closed from a results file while it was pending with no
runner no longer occupies its directory, so ``register_scan`` admits another
scan, and a runner that then claims the first scan may reopen it only while no
other scan occupies its tree. That check compared output directories by
equality, while registration compares trees: a workspace project writing under
``<root>/projects/web`` was not seen by the reopen of a scan of ``<root>``, and
both scans ran in one tree.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

pytestmark = pytest.mark.unit


def _document():
    return {
        "metadata": {"generated_at": "2024-01-01T00:00:00", "summary_stats": {}},
        "scanner_results": {
            "bandit": {
                "status": "PASSED",
                "finding_count": 1,
                "severity_counts": {"high": 1},
            }
        },
    }


def _register(registry, tmp_path, name, output):
    source = tmp_path / "src" / name
    source.mkdir(parents=True, exist_ok=True)
    return registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )


def _closed_from_file(registry, tmp_path, name, output):
    """A scan of ``name`` whose poll closed it from the results file in ``output``."""
    output.mkdir(parents=True, exist_ok=True)
    (output / "ash_aggregated_results.json").write_text(
        json.dumps(_document()), encoding="utf-8"
    )
    scan_id = _register(registry, tmp_path, name, output)
    registry.check_scan_progress(scan_id)
    assert registry.get_scan(scan_id).closed_from_file is True
    return scan_id


def test_the_reopen_is_refused_while_a_project_runs_under_the_tree(tmp_path):
    registry = ScanRegistry()
    root = tmp_path / "out"
    first = _closed_from_file(registry, tmp_path, "whole", root)
    project = _register(registry, tmp_path, "web", root / "projects" / "web")
    registry.update_scan_status(project, MCScanStatus.RUNNING)

    # RED at the base: the project's output differs from the root's, so the
    # equality compare found no scan in the tree and reopened the first scan.
    assert registry.update_scan_status(first, MCScanStatus.RUNNING) is False

    assert registry.get_scan(first).status is not MCScanStatus.RUNNING
    assert registry.get_scan(project).status is MCScanStatus.RUNNING


def test_the_reopen_is_refused_while_a_scan_runs_over_the_tree(tmp_path):
    registry = ScanRegistry()
    root = tmp_path / "out"
    first = _closed_from_file(registry, tmp_path, "web", root / "projects" / "web")
    whole = _register(registry, tmp_path, "whole", root)
    registry.update_scan_status(whole, MCScanStatus.RUNNING)

    assert registry.update_scan_status(first, MCScanStatus.RUNNING) is False

    assert registry.get_scan(first).status is not MCScanStatus.RUNNING


def test_the_reopen_works_beside_a_scan_in_a_sibling_directory(tmp_path):
    """Control, green on both sides: ``out`` and ``out-backup`` share nothing."""
    registry = ScanRegistry()
    first = _closed_from_file(registry, tmp_path, "whole", tmp_path / "out")
    other = _register(registry, tmp_path, "other", tmp_path / "out-backup")
    registry.update_scan_status(other, MCScanStatus.RUNNING)

    assert registry.update_scan_status(first, MCScanStatus.RUNNING) is True

    assert registry.get_scan(first).status is MCScanStatus.RUNNING
