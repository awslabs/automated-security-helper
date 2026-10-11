# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``client_supplied`` is set by ASH, never by the config that holds the entry.

The marking says a suppression, ignore path or scanner exclusion came from a
config an MCP client delivered. ASH sets it while resolving
(``config/client_config_policy.py``); a value written in a config file, of any
tier, or set by an override is cleared first.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config

_ENTRY = {"path": "vendor/**", "reason": "third party", "client_supplied": True}


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


def _marked_document() -> dict:
    return {
        "global_settings": {"ignore_paths": [_ENTRY], "suppressions": [_ENTRY]},
        "scanners": {
            "bandit": {"options": {"excluded_paths": [_ENTRY]}},
            "checkov": {"options": {"skip_path": [_ENTRY]}},
        },
    }


def _marks(config: Any) -> List[bool]:
    entries = (
        list(config.global_settings.ignore_paths)
        + list(config.global_settings.suppressions)
        + list(config.scanners.bandit.options.excluded_paths)
        + list(config.scanners.checkov.options.skip_path)
    )
    assert len(entries) == 4
    return [entry.client_supplied for entry in entries]


def test_a_repository_config_cannot_mark_its_own_entries(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(_marked_document()), encoding="utf-8"
    )
    assert _marks(resolve_config(source_dir=repo)) == [False] * 4


def test_an_operator_config_cannot_mark_its_entries_either(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(yaml.safe_dump(_marked_document()), encoding="utf-8")
    assert _marks(resolve_config(config_path=operator, source_dir=repo)) == [False] * 4


def test_an_override_cannot_mark_an_entry(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config = resolve_config(
        source_dir=repo,
        config_overrides=[
            (
                'global_settings.ignore_paths+=[{"path": "vendor/**", "reason": "r", '
                '"client_supplied": true}]'
            )
        ],
    )
    (entry,) = config.global_settings.ignore_paths
    assert entry.client_supplied is False
