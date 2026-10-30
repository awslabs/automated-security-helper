# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ``generate_schemas`` writes, and what it refuses to do.

The file-writing branch was the fallback for every ``output`` value other than
``dict`` and ``json``, so a mistyped mode rewrote the committed schemas in the
package directory and answered ``None``. And each schema was written in place
with ``write_text``, which truncates before it writes, so a run interrupted
between the two left an empty or partial file at the committed path. An unknown
mode is now refused before anything is generated, and a schema is written to a
temporary file beside its path and renamed over it.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

import automated_security_helper.schemas.generate_schemas as generate_schemas_module
from automated_security_helper.schemas.generate_schemas import (
    OUTPUTS,
    _write_if_changed,
    generate_schemas,
)

pytestmark = pytest.mark.unit


def test_an_unknown_output_mode_is_refused_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        generate_schemas_module, "__file__", str(tmp_path / "generate_schemas.py")
    )
    with pytest.raises(ValueError, match="file, json, dict"):
        generate_schemas("flie")  # type: ignore[arg-type]
    assert list(tmp_path.iterdir()) == []


def test_the_accepted_modes_are_the_three_named():
    assert OUTPUTS == ("file", "json", "dict")


def test_a_changed_schema_is_written_whole_and_an_unchanged_one_left_alone(tmp_path):
    target = tmp_path / "Model.json"
    assert _write_if_changed(target, "first\n") is True
    assert target.read_text(encoding="utf-8") == "first\n"
    assert _write_if_changed(target, "first\n") is False
    assert _write_if_changed(target, "second\n") is True
    assert target.read_text(encoding="utf-8") == "second\n"
    assert [path.name for path in tmp_path.iterdir()] == ["Model.json"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o644, 0o600, 0o664])
def test_a_rewritten_schema_keeps_the_mode_of_the_file_it_replaces(tmp_path, mode):
    """A temporary file made readable by its owner alone would carry that mode
    over the committed schema when renamed."""
    target = tmp_path / "Model.json"
    target.write_text("committed\n", encoding="utf-8")
    target.chmod(mode)
    assert _write_if_changed(target, "changed\n") is True
    assert stat.S_IMODE(target.stat().st_mode) == mode


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.parametrize(
    "umask, expected", [(0o022, 0o644), (0o002, 0o664), (0o077, 0o600)]
)
def test_a_new_schema_takes_the_mode_the_umask_allows(tmp_path, umask, expected):
    """As ``write_text`` did: ``0o666`` less the umask, not a fixed mode."""
    target = tmp_path / "Model.json"
    previous = os.umask(umask)
    try:
        assert _write_if_changed(target, "new\n") is True
    finally:
        os.umask(previous)
    assert stat.S_IMODE(target.stat().st_mode) == expected


def test_an_interrupted_write_leaves_the_existing_schema_intact(tmp_path, monkeypatch):
    """The rename is the only step that touches the committed path, so a failure
    before it leaves the old schema whole and no temporary file behind."""
    target = tmp_path / "Model.json"
    target.write_text("committed\n", encoding="utf-8")

    def refuse(source, destination):
        raise OSError("no space left on device")

    monkeypatch.setattr(generate_schemas_module.os, "replace", refuse)
    with pytest.raises(OSError, match="no space"):
        _write_if_changed(target, "half-written\n")
    assert target.read_text(encoding="utf-8") == "committed\n"
    assert [path.name for path in tmp_path.iterdir()] == ["Model.json"]
