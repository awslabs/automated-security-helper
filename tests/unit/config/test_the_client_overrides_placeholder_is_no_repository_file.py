# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``CLIENT_OVERRIDES_SOURCE`` names a source in the warnings and is no path.

``resolve_config`` adds ``Path("config_overrides")`` to the confined files when
an MCP client sent overrides. A step that resolves each entry would read it
against the working directory: it raised with that directory deleted, and
otherwise admitted ``<cwd>/config_overrides`` into the repository-file sets. The
steps that build those sets are given the files only.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import resolve_config as module
from automated_security_helper.config.resolve_config import (
    CLIENT_OVERRIDES_SOURCE,
    _honor_ignore_files_writers,
    resolve_config,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def repository(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print(1)\n", encoding="utf-8")
    monkeypatch.chdir(root)
    return root


def _spy(monkeypatch, name, position, seen):
    real = getattr(module, name)

    def spy(*args, **kwargs):
        seen[name] = list(args[position])
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, spy)


def test_the_steps_that_build_repository_file_sets_are_given_no_placeholder(
    repository, monkeypatch
):
    seen: dict = {}
    _spy(monkeypatch, "_with_operator_chain_reporters", 2, seen)
    _spy(monkeypatch, "_with_operator_chain_scanners", 2, seen)
    _spy(monkeypatch, "_take_confined_references", 3, seen)

    config = resolve_config(
        source_dir=repository,
        config_overrides=["project_name=client"],
        client_overrides=True,
    )

    assert config.project_name == "client"
    # Control: the three steps ran, and the placeholder is not among their files.
    assert set(seen) == {
        "_with_operator_chain_reporters",
        "_with_operator_chain_scanners",
        "_take_confined_references",
    }, seen
    for name, files in seen.items():
        assert CLIENT_OVERRIDES_SOURCE not in [Path(f) for f in files], (name, files)


def test_the_honor_writers_step_never_resolves_the_placeholder(tmp_path, monkeypatch):
    launched = tmp_path / "launched"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)
    # Control: this working directory really cannot be resolved against.
    with pytest.raises(FileNotFoundError):
        Path.cwd()

    named, decided_by = _honor_ignore_files_writers([CLIENT_OVERRIDES_SOURCE], [], {})

    assert named == [CLIENT_OVERRIDES_SOURCE]
    assert decided_by is None


def test_the_honor_writers_step_does_not_read_a_file_of_that_name_in_the_cwd(
    repository,
):
    """A ``config_overrides`` file in the working directory is not the
    placeholder: no document of it speaks for the overrides."""
    lookalike = (repository / "config_overrides").resolve()
    lookalike.write_text("honor_ignore_files: false\n", encoding="utf-8")
    documents = {lookalike: {"project_name": "does not write the key"}}

    named, _ = _honor_ignore_files_writers([CLIENT_OVERRIDES_SOURCE], [], documents)

    assert named == [CLIENT_OVERRIDES_SOURCE]
