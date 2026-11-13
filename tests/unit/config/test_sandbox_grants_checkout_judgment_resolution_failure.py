# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A name ``os.path.realpath`` raises on is judged inside, and the log says so.

``checkout_judgment`` treats a name it cannot resolve as one that cannot be ruled
out, the same fail-closed answer as a link walk that ends early. Every early end
of the link walk is logged once per name; this one has to be too, or a file read
as the repository's for this reason has no line saying why.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from automated_security_helper.config.sandbox_grants import checkout_judgment

pytestmark = pytest.mark.unit


def _realpath_raises_for(monkeypatch, name: Path, error: OSError) -> None:
    real = os.path.realpath
    spelled = os.fspath(name)

    def realpath(path, *args, **kwargs):
        if os.fspath(path) == spelled:
            raise error
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", realpath)


def _walk_lines(ash_log) -> list:
    return [
        record.getMessage()
        for record in ash_log
        if record.getMessage().startswith("The link walk for")
    ]


def test_a_name_that_cannot_be_resolved_is_judged_inside_and_logged(
    tmp_path, monkeypatch, ash_log, _warned_window
):
    name = tmp_path / "ops" / "cfg.yaml"
    name.parent.mkdir()
    name.write_text("project_name: x\n", encoding="utf-8")
    _realpath_raises_for(
        monkeypatch,
        name,
        OSError(errno.EIO, "Input/output error", os.fspath(name)),
    )

    judgment = checkout_judgment(name)
    checkout_judgment(name)

    assert judgment.verdict is True
    assert judgment.decided is False
    lines = _walk_lines(ash_log)
    assert len(lines) == 1, lines
    assert lines[0].startswith(f"The link walk for {name.as_posix()} stopped at "), (
        lines
    )
    assert "Input/output error" in lines[0], lines


def test_a_name_that_resolves_is_judged_outside_and_logs_nothing(
    tmp_path, ash_log, _warned_window
):
    name = tmp_path / "ops" / "cfg.yaml"
    name.parent.mkdir()
    name.write_text("project_name: x\n", encoding="utf-8")

    judgment = checkout_judgment(name)

    assert judgment.verdict is False
    assert judgment.decided is True
    assert _walk_lines(ash_log) == []
