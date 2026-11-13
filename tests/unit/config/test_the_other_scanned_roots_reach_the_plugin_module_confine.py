# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The other scanned roots a load names reach the plugin-module confine.

``resolve_config`` takes ``also_scanned``, the other roots whose trees count as
scanned (the results' repository for ``ash report``), and the sandbox and settle
steps judged by them. The plugin-module step takes the same roots
(``confine_plugin_modules``'s ``also_scanned``) but the load's call passed none,
so a module location inside one of those trees was judged as outside every
scanned tree. ``confine_to_trusted_base``, the same steps for a recorded config,
had no way to pass them at all. Both now hand the roots on.

Red at the base: the load's call carried no ``also_scanned``, and the recorded
config's entry point refused the argument.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import AshConfig
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> List[Dict[str, Any]]:
    """The keyword arguments of each plugin-module confine call the module
    makes; the step itself is not run."""
    calls: List[Dict[str, Any]] = []

    def record(*_args: Any, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(resolve_config_module, "confine_plugin_modules", record)
    return calls


def test_the_load_hands_the_other_roots_to_the_plugin_module_step(
    tmp_path: Path, recorded
) -> None:
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    other = tmp_path / "other"
    other.mkdir()
    config_file = repo / ".ash" / ".ash.yaml"
    config_file.parent.mkdir(parents=True)
    config_file.write_text("project_name: in-tree\n", encoding="utf-8")

    resolve_config_module.resolve_config(
        config_path=config_file, source_dir=repo, also_scanned=[str(other)]
    )

    assert recorded, "the premise: the in-tree config reaches the plugin-module step"
    assert all(call["also_scanned"] == [other] for call in recorded), recorded
    assert all(isinstance(root, Path) for root in recorded[0]["also_scanned"])


def test_the_recorded_config_entry_point_hands_the_other_roots_on(
    tmp_path: Path, recorded
) -> None:
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    other = tmp_path / "other"
    other.mkdir()

    resolve_config_module.confine_to_trusted_base(
        AshConfig(),
        AshConfig(),
        [],
        repo,
        [repo / ".ash" / ".ash.yaml"],
        also_scanned=[str(other)],
    )

    assert len(recorded) == 1, recorded
    assert recorded[0]["also_scanned"] == [other]


def test_with_no_other_roots_the_step_gets_an_empty_list(
    tmp_path: Path, recorded
) -> None:
    """The control: the default names no other root."""
    repo = tmp_path / "repo"
    mark_git_checkout(repo)

    resolve_config_module.confine_to_trusted_base(
        AshConfig(), AshConfig(), [], repo, [repo / ".ash" / ".ash.yaml"]
    )

    assert recorded[0]["also_scanned"] == []
