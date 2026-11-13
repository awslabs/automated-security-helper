# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Config discovery honors the caller's ``permit_base``.

A source discovery finds in the scanned directory can be a symbolic link to any
file on the host. When the caller passes ``permit_base`` (the MCP server's
session gate), ``resolve_config`` hands it to ``discover_config_source``, which
checks every source that exists by the path it resolves to before anything
opens it, and refuses one that reaches outside with
``ASHConfigInputNotPermittedError``. Without ``permit_base`` nothing is
checked, as before: the link is followed and the file loads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigInputNotPermittedError,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _repo_with_linked_config(tmp_path: Path) -> Path:
    """A scanned tree whose discovered config is a symlink out of the tree."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    outside = tmp_path / "outside" / "planted.yaml"
    outside.parent.mkdir(parents=True)
    document: Dict[str, Any] = {"scanners": {"bandit": {"enabled": False}}}
    outside.write_text(yaml.safe_dump(document), encoding="utf-8")
    (repo / ".ash.yaml").symlink_to(outside)
    return repo


def _permit_inside(repo: Path):
    root = repo.resolve()

    def permit(path: Path) -> bool:
        resolved = Path(path).resolve()
        return resolved == root or root in resolved.parents

    return permit


def test_a_discovered_symlink_out_of_the_permitted_base_is_refused(
    tmp_path: Path,
) -> None:
    repo = _repo_with_linked_config(tmp_path)

    with pytest.raises(ASHConfigInputNotPermittedError):
        resolve_config(source_dir=repo, permit_base=_permit_inside(repo))


def test_without_a_permit_discovery_still_follows_the_link(tmp_path: Path) -> None:
    """The control: a permit-less call keeps today's ungated behavior."""
    repo = _repo_with_linked_config(tmp_path)

    config = resolve_config(source_dir=repo)

    section = config.get_plugin_config("scanner", "bandit") or {}
    assert section.get("enabled") is False
