# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ensure_directories never deletes through a link, whatever the sandbox mode.

It clears ``analysis``, ``reports``, ``scanners`` and ``converted`` under the output
directory before a scan. The default output directory, ``.ash/ash_output``, is inside
the scanned tree, so a repository can commit ``.ash``, ``.ash/ash_output`` or one of
the working directories as a symlink. Each test points such a link at a "host"
directory holding a marker file, and the marker must survive.

A link above an output directory outside the tree is the operator's own spelling and
keeps working. The output directory itself, and each working directory, is refused
when it is a link wherever it is: see test_linked_output_dir_is_refused.py.

``ash scan`` makes the same refusal itself (run_ash_scan._refuse_symlinked_output_dir),
before its logger opens ash.log in the output directory; the last test covers it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def orchestrator(source_dir: Path, output_dir: Path) -> ASHScanOrchestrator:
    """Constructed without initialize(); the constructor does no filesystem I/O."""
    return ASHScanOrchestrator(
        source_dir=source_dir,
        output_dir=output_dir,
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )


@pytest.fixture
def layout(tmp_path):
    tree = tmp_path / "tree"
    host = tmp_path / "host"
    tree.mkdir()
    host.mkdir()
    marker = host / "keep.txt"
    marker.write_text("host file\n")
    return tree, host, marker


def test_a_linked_working_directory_is_refused_not_cleared(layout):
    tree, host, marker = layout
    output = tree / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "scanners").symlink_to(host)

    with pytest.raises(ASHValidationError, match="scanners is a symlink"):
        orchestrator(tree, output).ensure_directories()

    assert marker.read_text() == "host file\n"
    assert (output / "scanners").is_symlink(), "the link is reported, not removed"


@pytest.mark.parametrize("linked", [".ash", ".ash/ash_output"])
def test_a_linked_component_inside_the_tree_is_refused(layout, linked):
    tree, host, marker = layout
    (host / "ash_output" / "scanners").mkdir(parents=True)
    (host / "ash_output" / "scanners" / "keep.txt").write_text("host file\n")
    (host / "scanners").mkdir()
    (host / "scanners" / "keep.txt").write_text("host file\n")
    link = tree / linked
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(host)
    output = tree / ".ash" / "ash_output"

    with pytest.raises(ASHValidationError, match="is a symlink"):
        orchestrator(tree, output).ensure_directories()

    assert marker.read_text() == "host file\n"
    assert (host / "ash_output" / "scanners" / "keep.txt").exists()
    assert (host / "scanners" / "keep.txt").exists()


def test_the_check_holds_with_the_sandbox_off(layout):
    """The sandbox's own check is skipped when it is off; this one is not."""
    tree, host, marker = layout
    (tree / ".ash").symlink_to(host)
    orch = orchestrator(tree, tree / ".ash" / "ash_output")
    orch.config = AshConfig(project_name="test")
    assert str(orch.config.sandbox.mode).endswith("off")

    with pytest.raises(ASHValidationError, match="--output-dir"):
        orch._refuse_linked_output_dir()
    with pytest.raises(ASHValidationError):
        orch.ensure_directories()

    assert marker.exists()


def test_an_output_directory_outside_the_tree_reached_through_a_link_works(
    layout, tmp_path
):
    """As ``/tmp`` is on macOS: the operator's own spelling is not examined."""
    tree, _, _ = layout
    real = tmp_path / "real-out-parent"
    (real / "out" / "scanners").mkdir(parents=True)
    stale = real / "out" / "scanners" / "previous.json"
    stale.write_text("{}")
    (tmp_path / "linked-parent").symlink_to(real)

    orchestrator(tree, tmp_path / "linked-parent" / "out").ensure_directories()

    assert (real / "out" / "scanners").is_dir()
    assert not stale.exists(), "the operator's own previous run is still cleared"


def test_an_ordinary_output_directory_inside_the_tree_works(layout):
    tree, _, _ = layout
    output = tree / ".ash" / "ash_output"
    (output / "analysis").mkdir(parents=True)
    (output / "analysis" / "previous.json").write_text("{}")

    orchestrator(tree, output).ensure_directories()

    assert (output / "analysis").is_dir()
    assert not (output / "analysis" / "previous.json").exists()
    for name in ("analysis", "reports", "scanners", "converted"):
        assert (output / name).is_dir()


def _scan_options(tree: Path, output_dir: Path):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    return ScanOptions(
        source_dir=tree, output_dir=output_dir, config_overrides=["sandbox.mode=off"]
    )


def test_ash_scan_refuses_it_before_writing_with_the_sandbox_off(layout):
    from automated_security_helper.interactions.run_ash_scan import (
        _refuse_symlinked_output_dir,
    )

    tree, host, _ = layout
    (tree / ".ash").symlink_to(host)

    with pytest.raises(SystemExit) as exited:
        _refuse_symlinked_output_dir(_scan_options(tree, tree / ".ash" / "ash_output"))

    assert exited.value.code == 3
    assert [p.name for p in host.iterdir()] == ["keep.txt"]
