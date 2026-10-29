# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``derived_roots`` is the one list of directories the scan derived from the repository.

A plugin context records on its config exactly the directories ``derived_roots``
returns, and a scanner that passes ``derived_dirs=derived_roots(self.context)``
judges the same list, the workspace output directory included.
"""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    derived_roots,
    refused_derived_product,
)

pytestmark = pytest.mark.unit


def test_the_list_holds_the_output_work_and_workspace_output_directories(tmp_path):
    context = SimpleNamespace(
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        workspace_output_dir=tmp_path / "ws-out",
    )

    assert derived_roots(context) == (
        tmp_path / "out",
        tmp_path / "out" / "work",
        tmp_path / "ws-out",
    )


def test_a_directory_the_context_does_not_hold_is_left_out(tmp_path):
    no_workspace = SimpleNamespace(
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        workspace_output_dir=None,
    )
    nothing_held = SimpleNamespace()

    assert derived_roots(no_workspace) == (tmp_path / "out", tmp_path / "out" / "work")
    assert derived_roots(nothing_held) == ()


def test_a_scanner_passing_the_list_refuses_under_the_workspace_output(tmp_path):
    """With a config that records nothing (None), the list alone decides."""
    base = tmp_path.resolve()
    source = base / "src"
    source.mkdir()
    context = SimpleNamespace(
        output_dir=base / "out",
        work_dir=base / "out" / "work",
        workspace_output_dir=base / "ws-out",
    )

    refused = refused_derived_product(
        base / "ws-out" / "other-project" / "x.yaml",
        source_dir=source,
        key="config_file",
        derived_dirs=derived_roots(context),
    )

    assert refused is True


def test_the_context_records_the_directories_the_list_returns(tmp_path):
    base = tmp_path.resolve()
    (base / "src").mkdir()
    config = AshConfig()
    context = PluginContext(
        source_dir=base / "src",
        output_dir=base / "out",
        work_dir=base / "out" / "work",
        config=config,
        workspace_output_dir=base / "ws-out",
    )

    expected = {Path(os.path.realpath(root)) for root in derived_roots(context)}

    assert len(expected) == 3
    assert set(config._derived_roots) == expected
