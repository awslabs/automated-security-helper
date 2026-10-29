# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the operator lets snyk-code apply the scanned tree's own exclusion files.

``scanners.snyk-code.options.honor_tree_exclusions`` lets ``snyk code test`` leave
out the files a ``.snyk`` or ``.dcignore`` in the tree names. A config file inside
the scanned tree does not set it; the defaults, a config file outside the tree, or
``--config-overrides`` do (config/tool_config_trust.py). Under the MCP server it is
a default ``denied_paths`` entry.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.resolve_config import resolve_config

pytestmark = pytest.mark.unit

OPTION = "honor_tree_exclusions"


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _repo(tmp_path: Path, value: Any) -> Path:
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"scanners": {"snyk-code": {"options": {OPTION: value}}}}),
        encoding="utf-8",
    )
    return repo


def _honored(config: Any) -> Any:
    section = config.get_plugin_config("scanner", "snyk-code") or {}
    return (section.get("options") or {}).get(OPTION)


def test_a_repositorys_config_does_not_accept_its_own_exclusions(
    tmp_path: Path,
) -> None:
    config = resolve_config(source_dir=_repo(tmp_path, True))
    assert not _honored(config)


def test_an_override_accepts_them(tmp_path: Path) -> None:
    config = resolve_config(
        source_dir=_repo(tmp_path, False),
        config_overrides=[f"scanners.snyk-code.options.{OPTION}=true"],
    )
    assert _honored(config) is True


def test_an_mcp_clients_file_may_not_set_it() -> None:
    assert f"/scanners/snyk-code/options/{OPTION}" in (
        RuntimeOverridesConfig().denied_paths
    )
