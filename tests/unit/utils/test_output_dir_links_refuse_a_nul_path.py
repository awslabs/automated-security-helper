# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A path holding a NUL character names no file, and the link checks say so.

``os.lstat``, ``os.stat`` and ``os.path.realpath`` raise ``ValueError`` for such
a path, not ``OSError``, and the link readers caught ``OSError`` alone, so the
report command's output-directory arm, reached with an output directory from a
``--cli-json-input`` document that held a NUL, traced back one call after the
existence check that had already learned to answer it. The readers now answer
"not a link" / "no identity", and ``linked_output_component`` refuses the
directory before any of them is asked, naming the NUL.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.output_dir_links import (
    _identity,
    _kind,
    is_junction,
    is_link,
    linked_output_component,
)

pytestmark = pytest.mark.unit

NUL = chr(0)


def test_the_link_readers_answer_a_nul_path_without_raising(tmp_path):
    path = tmp_path / f"out{NUL}dir"

    assert is_link(path) is False
    assert is_junction(path) is False
    assert _identity(path) is None
    assert _kind(path) == "a directory junction"


def test_an_output_directory_holding_a_nul_is_refused_before_the_lookup(tmp_path):
    found = linked_output_component(tmp_path, tmp_path / f"out{NUL}dir")

    assert found is not None
    assert "NUL" in found


def test_control_an_ordinary_output_directory_is_still_accepted(tmp_path):
    (tmp_path / "out").mkdir()

    assert linked_output_component(tmp_path, tmp_path / "out") is None
