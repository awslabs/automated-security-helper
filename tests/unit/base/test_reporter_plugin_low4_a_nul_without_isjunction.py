# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A NUL in a report path is refused, not raised, on a Python without ``os.path.isjunction``.

Before Python 3.12 ``_is_junction`` falls back to ``os.lstat``, which raises
``ValueError`` on an embedded NUL where the 3.12 function answers False. The
reports directory is looked at by ``link_kind`` before ``confined_report_path``
can refuse it, so a NUL in it raised from there. These tests remove
``os.path.isjunction`` so the fallback runs on every Python.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.base.reporter_plugin import (
    confined_report_path,
    write_report_file,
)
from automated_security_helper.utils.report_path_links import link_kind

pytestmark = pytest.mark.unit


@pytest.fixture
def lstat_fallback(monkeypatch):
    """``os.path`` without ``isjunction``, as on Python 3.10 and 3.11."""
    monkeypatch.delattr(os.path, "isjunction", raising=False)


def test_a_path_holding_a_nul_is_no_link_on_the_lstat_fallback(
    lstat_fallback, tmp_path
):
    assert link_kind(Path(f"{tmp_path}\x00reports")) is None


def test_a_reports_directory_holding_a_nul_is_refused_by_confined_report_path(
    lstat_fallback, tmp_path
):
    assert confined_report_path(Path(f"{tmp_path}\x00reports"), "ash.json") is None


def test_a_reports_directory_holding_a_nul_is_not_written_to(lstat_fallback, tmp_path):
    assert (
        write_report_file(Path(f"{tmp_path}\x00reports"), "ash.json", "content") is None
    )


def test_a_file_name_holding_a_nul_is_not_written(lstat_fallback, tmp_path):
    assert write_report_file(tmp_path, "ash.a\x00b", "content") is None
    assert list(tmp_path.iterdir()) == []


def test_a_plain_name_in_a_plain_directory_is_still_written(lstat_fallback, tmp_path):
    written = write_report_file(tmp_path, "ash.json", "content")

    assert written == tmp_path / "ash.json"
    assert written.read_text(encoding="utf-8") == "content"
