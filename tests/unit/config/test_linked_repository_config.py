# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A repository's config that is a symlink to a file elsewhere is still the repository's.

The repository chose the link, so the file it reaches is held to what a config
inside the scanned tree may set, wherever that file is: its sandbox grants, plugin
modules, reporter destinations and tool config files come from the trusted base.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config


@pytest.fixture(autouse=True)
def _no_operator_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")


def _host_file(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "host" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo


def test_a_linked_repository_config_grants_no_read_paths(tmp_path: Path) -> None:
    host = _host_file(
        tmp_path,
        {"project_name": "linked", "sandbox": {"extra_read_paths": ["/data"]}},
    )
    repo = _repo(tmp_path)
    _symlink(repo / ".ash" / ".ash.yaml", host)

    config = resolve_config(source_dir=repo)

    assert config.project_name == "linked"
    assert config.sandbox.extra_read_paths == []


def test_a_linked_repository_config_directory_grants_no_read_paths(
    tmp_path: Path,
) -> None:
    host = _host_file(
        tmp_path,
        {"project_name": "linked", "sandbox": {"extra_read_paths": ["/data"]}},
    )
    repo = _repo(tmp_path)
    _symlink(repo / ".ash", host.parent)
    (host.parent / ".ash.yaml").write_text(host.read_text(), encoding="utf-8")

    config = resolve_config(source_dir=repo)

    assert config.project_name == "linked"
    assert config.sandbox.extra_read_paths == []


def test_positive_control_the_same_file_named_by_the_operator_grants(
    tmp_path: Path,
) -> None:
    host = _host_file(
        tmp_path,
        {"project_name": "linked", "sandbox": {"extra_read_paths": ["/data"]}},
    )
    repo = _repo(tmp_path)

    config = resolve_config(config_path=host, source_dir=repo)

    assert config.sandbox.extra_read_paths == ["/data"]
