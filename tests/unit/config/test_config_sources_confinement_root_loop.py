# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan source directory that is a symbolic link loop gives a confinement root.

``default_confinement_root`` resolved the config path with a guard against a
symbolic link loop, and the source directory with a bare ``Path.resolve``,
which raises RuntimeError on a loop on Python 3.10 to 3.12. The source
directory is now resolved with ``os.path.realpath``, which does not raise: a
looping directory holds no config, and the root is the config's own directory,
as it is on 3.13 and later.

Red at the base (3.10 to 3.12): RuntimeError escaped. On 3.13 and later
``Path.resolve`` no longer raises for a loop, so there the test pins the shape
without having been red.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import default_confinement_root

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]


def _config(tmp_path: Path) -> Path:
    config = tmp_path / "configs" / ".ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: demo\n", encoding="utf-8")
    return config


def test_a_looping_source_directory_falls_back_to_the_configs_directory(
    tmp_path: Path,
) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    config = _config(tmp_path)

    root = default_confinement_root(config, source_dir=loop)

    assert root == config.parent.resolve()


def test_a_source_directory_that_holds_the_config_is_the_root(tmp_path: Path) -> None:
    """The control: a real source directory that holds the config is the root."""
    config = _config(tmp_path)

    assert default_confinement_root(config, source_dir=tmp_path) == tmp_path.resolve()
