# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for the grep-family scanner tests.

``test_plugin_context`` (tests/conftest.py) places its source directory under
``tests/pytest-temp`` inside this repository's checkout. A test that expects a
local rules path to be PASSED to the tool cannot use it: ``config/path_trust``
refuses a path inside any git checkout, so a rules file beside that source
directory is refused wherever the checkout sits (the venue extract is a fresh git
repository; this host's worktree is one too). The fixture below builds the scan
tree under pytest's ``tmp_path``, which the runner keeps outside every checkout
(``--basetemp`` on the lane dir), so a rules file beside it is a path the scanner
may pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def context_outside_checkouts(tmp_path: Path):
    """A PluginContext whose source, output and work directories sit under
    ``tmp_path/tree``: outside every git checkout, so a rules file placed beside
    ``source_dir`` (``tmp_path/tree/rules-beside-the-tree``) is passable."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config

    tree = tmp_path / "tree"
    source_dir = tree / "src"
    source_dir.mkdir(parents=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=tree / "out",
        work_dir=tree / "work",
        config=get_default_config(),
    )
