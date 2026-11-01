# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``client_file_denials`` hands each document its own environment references.

ADD1 Row B7's direct unit for ``client_file_denials``: a documents map with one
patched copy whose own reference is in ``references`` draws no denial at the
copy's environment-read leaf, and the control with ``references=()`` keeps the
denial. Red/green by the keyword's presence at the inner call: at the base
(TIP A's tip, where ``client_file_denials`` takes no ``references`` keyword)
both ids raise ``TypeError``; with TIP B's cut, id 1 reads no denial and id 2
the denial.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import List, Sequence

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.environment_record import EnvironmentReference

pytestmark = pytest.mark.unit

CANARY = "ash-canary-t26b-0123456789"


@pytest.fixture
def trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A trusted config whose project_name the file wrote as a reference."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_T26", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text("project_name: ${ASH_T26}\n", encoding="utf-8")
    _, config = load_config_file_for_run(path)
    assert config.project_name == CANARY, "the control: the reference was read"
    return config


def _own_reference(trusted, copy: Path) -> EnvironmentReference:
    """The trusted record's project_name reference, as the copy's own."""
    reference = next(
        each
        for each in (getattr(trusted, "_environment_references", None) or ())
        if tuple(each.path) == ("project_name",) and not each.key
    )
    assert reference.written == "${ASH_T26}", "the control: the record's text"
    return replace(reference, origin=(copy, tuple(reference.path)))


def _denied(
    trusted,
    copy: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    references: Sequence[EnvironmentReference],
) -> List[str]:
    """Denial keys of a patched copy repeating the canary at project_name."""
    import automated_security_helper.cli.mcp.profile_registry as profile_registry

    # The copy stands for a session's client-patched profile, what
    # ``session_config_was_patched`` answers True for; the registry machinery
    # is not built here.
    monkeypatch.setattr(
        profile_registry, "session_config_was_patched", lambda _path: True
    )
    rules = ccp.ClientConfigRules(
        policy=RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/**"],
            denied_paths=["/project_name"],
        ),
        base=trusted,
    )
    found = ccp.client_file_denials(
        {copy: {"project_name": CANARY}},
        rules,
        scanned_root=copy.parent,
        all_delivered=True,
        references=references,
    )
    return [denial.key for _, denials in found for denial in denials]


def test_a_patched_copys_own_reference_admits_the_leaf(
    trusted, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Id 1: no denial when ``references`` holds the copy's own reference."""
    copy = tmp_path / "copy.yaml"
    own = _own_reference(trusted, copy)
    assert _denied(trusted, copy, monkeypatch, references=(own,)) == []


def test_without_references_the_denial_stands(
    trusted, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Id 2 (control): ``references=()`` keeps the denial."""
    copy = tmp_path / "copy.yaml"
    assert _denied(trusted, copy, monkeypatch, references=()) == ["project_name"]
