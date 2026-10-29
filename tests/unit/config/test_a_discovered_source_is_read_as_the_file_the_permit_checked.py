# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A discovered config source is read as the file the permit checked.

Under a caller's ``permit`` (the MCP session's gate) discovery checks every
source by the path it resolves to before anything opens it, but bound nothing
to that check: the load opened the name again with no identity expected of it,
so a name made to lead to another file between the check and the open was read.
The permit check now takes the identity of the file the name led to
(``ConfigSource.identity``), and ``resolve_config`` holds the load to it.

Red at the base: ``ConfigSource`` had no identity, and a selected source whose
identity names no file still loaded.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.config_sources import (
    ABSENT_FILE,
    SOURCE_KIND_DEDICATED,
    ConfigDiscovery,
    ConfigSource,
    config_file_changed,
    discover_config_source,
    identity_to_hold,
)
from automated_security_helper.config.resolve_config import resolve_config

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".ash.yaml").write_text("project_name: discovered\n", encoding="utf-8")
    return repo


def test_a_permitted_source_carries_the_identity_of_the_file_it_checked(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)

    discovery = discover_config_source(repo, permit=lambda path: True)

    assert discovery.selected is not None
    assert discovery.selected.identity == identity_to_hold(repo / ".ash.yaml")
    assert discovery.selected.identity != ABSENT_FILE


def test_without_a_permit_no_identity_is_taken(tmp_path: Path) -> None:
    """The control: a permit-less discovery checks nothing, as before."""
    repo = _repo(tmp_path)

    discovery = discover_config_source(repo)

    assert discovery.selected is not None
    assert discovery.selected.identity is None


def _discovering(monkeypatch: pytest.MonkeyPatch, selected: ConfigSource) -> None:
    """Stand in for discovery with ``selected`` as the source the permit checked."""
    discovery = ConfigDiscovery(selected=selected)
    monkeypatch.setattr(
        resolve_config_module,
        "discover_config_source",
        lambda search_dir, permit=None: discovery,
    )


def test_the_load_is_held_to_the_file_the_permit_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The name the permit judged led nowhere (ABSENT_FILE); a file at the name
    now is not the file that was checked, and the load refuses it."""
    repo = _repo(tmp_path)
    _discovering(
        monkeypatch,
        ConfigSource(repo / ".ash.yaml", SOURCE_KIND_DEDICATED, identity=ABSENT_FILE),
    )

    with pytest.raises(Exception) as caught:
        resolve_config(source_dir=repo, permit_base=lambda path: True)

    assert config_file_changed(caught.value), repr(caught.value)


def test_the_file_the_permit_checked_still_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the identity the check took is the file's own."""
    repo = _repo(tmp_path)
    _discovering(
        monkeypatch,
        ConfigSource(
            repo / ".ash.yaml",
            SOURCE_KIND_DEDICATED,
            identity=identity_to_hold(repo / ".ash.yaml"),
        ),
    )

    config = resolve_config(source_dir=repo, permit_base=lambda path: True)

    assert config.project_name == "discovered"
