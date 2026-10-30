# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The shared stat probe the actionlint and zizmor scanners read paths with."""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.path_probe import probe_path

pytestmark = pytest.mark.unit


def test_a_path_that_answers_is_read_as_it_answers(tmp_path):
    (tmp_path / "file").write_text("x")
    assert probe_path(tmp_path / "file", "is_file") is True
    assert probe_path(tmp_path / "file", "is_dir") is False
    assert probe_path(tmp_path, "is_dir") is True
    assert probe_path(tmp_path / "missing", "exists") is False


def test_a_refused_stat_is_read_as_false(tmp_path, monkeypatch):
    """Before Python 3.13 the Path predicates raise the stat's PermissionError
    for a path under an unsearchable directory instead of answering."""
    denied = tmp_path / "denied" / "file"

    def is_file(self, *args, **kwargs):
        if self == denied:
            raise PermissionError(13, "Permission denied", str(self))
        return original(self, *args, **kwargs)

    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", is_file)

    assert probe_path(denied, "is_file") is False
    assert probe_path(tmp_path, "is_dir") is True


def test_an_error_that_is_not_a_stats_is_not_hidden(tmp_path):
    with pytest.raises(AttributeError):
        probe_path(tmp_path, "is_a_method_path_has_not")
