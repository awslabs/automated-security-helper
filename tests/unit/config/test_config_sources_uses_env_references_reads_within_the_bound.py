# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``uses_env_references`` reads a config file within the bounds every read has.

The commands that rewrite a config ask ``uses_env_references`` first. It
checked the file's type and then opened it with a plain blocking ``open`` and
read all of it, where every other read of a config file goes through
``read_config_bytes``: a non-blocking open, the opened file checked to be a
regular file, and at most ``ASH_CONFIG_MAX_FILE_BYTES`` read. A file past the
bound is now not read past it; the command's own load refuses it.

Red at the base: the file past the bound was read whole and answered True.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import uses_env_references
from automated_security_helper.core.constants import ASH_CONFIG_MAX_FILE_BYTES

pytestmark = pytest.mark.unit

REFERENCE_LINE = "project_name: ${ASH_BOUNDED_READ_NAME}\n"


def test_a_file_past_the_bound_is_not_read_past_it(tmp_path: Path) -> None:
    config = tmp_path / ".ash.yaml"
    filler = "# " + "x" * 78 + "\n"
    lines = ASH_CONFIG_MAX_FILE_BYTES // len(filler) + 1
    config.write_text(REFERENCE_LINE + filler * lines, encoding="utf-8")
    assert config.stat().st_size > ASH_CONFIG_MAX_FILE_BYTES, "premise"

    assert uses_env_references(config) is False


def test_a_file_within_the_bound_is_read(tmp_path: Path) -> None:
    """The control: the same reference in a small file is found."""
    config = tmp_path / ".ash.yaml"
    config.write_text(REFERENCE_LINE, encoding="utf-8")

    assert uses_env_references(config) is True
