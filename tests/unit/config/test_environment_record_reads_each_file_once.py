# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The values a run redacts come from the same read of a file as its config.

load_config_file_for_run loads a config and records which of its values and
keys came from the environment (``_environment_values``), for redaction, and
the reference each was written as (``_written_references``), for the record.
Finding them by reading each file once more, as written, would let a file that
changed between the two reads, by a writer racing the load, give a second view
that does not match the first: a value read from the environment would then be
neither redacted nor recorded as its reference. Both views come from the one
text the load read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import resolve_config as resolve_config_module

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"
WRITTEN = "project_name: ${ASH_PN}\n"
CHANGED = "project_name: changed-by-another-writer\n"


@pytest.fixture
def racing_writer(tmp_path, monkeypatch):
    """A config file that another writer changes right after the load reads it."""
    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(WRITTEN, encoding="utf-8")
    # Whichever function the load reads a file with: the file is changed after
    # its first read.
    for name in ("read_config_file", "read_config_text"):
        original = getattr(resolve_config_module, name, None)
        if original is None:
            continue

        def changing(file_path, _original=original, **kwargs):
            data = _original(file_path, **kwargs)
            if Path(file_path).resolve() == path.resolve():
                path.write_text(CHANGED, encoding="utf-8")
            return data

        monkeypatch.setattr(resolve_config_module, name, changing)
    return path


def test_the_values_come_from_the_text_the_load_read(racing_writer):
    _, config = resolve_config_module.load_config_file_for_run(racing_writer)
    # The control: the load read the file before it changed.
    read = config.project_name == CANARY
    assert read, "the load did not read the file as first written"
    # Booleans, so a failure does not print the value.
    redacted = CANARY in (config._environment_values or [])
    assert redacted, "the value read from the environment is not known to redact"
    referenced = [
        rewrite.written
        for rewrite in config._written_references or []
        if rewrite.path == ("project_name",)
    ] == ["${ASH_PN}"]
    assert referenced, "the value is not recorded as its reference"


def test_a_file_not_changed_reads_the_same(tmp_path, monkeypatch):
    """The control without the race: one text, the same values."""
    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(WRITTEN, encoding="utf-8")
    _, config = resolve_config_module.load_config_file_for_run(path)
    known = config._environment_values == [CANARY]
    assert known, "the value read from the environment is not known"
