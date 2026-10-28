# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``session_config_was_patched`` also reads a session's recorded binding.

The first answer is by location: a file in a session's ``client-config/``
directory. A binding can name a config file anywhere (``config_path`` is passed
in by the caller), and when that binding carries ``patch_ops`` or
``override_yaml`` a client's patch is in the file wherever it sits. So a file
outside every ``client-config/`` directory is still the client's if a bound
session says so. These cells reach that second answer and its error arms:

* the location answer misses and a patched binding names the file: True;
* an unpatched binding, or a binding for another file: False;
* a bound state with no config path, and one whose path is a symlink loop, are
  skipped and the search goes on;
* a file whose own path is a symlink loop is not a patched profile, with the
  workspace root in place.

The loops are real symlink loops. Resolving one raises ``RuntimeError`` on
Python 3.12 and earlier and returns normally on 3.13, so on 3.13 these cells
check the answers and cannot reach the ``except`` arms.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.profile_registry import (
    bind_session_config,
    clear_session_state,
    session_config_was_patched,
)
from automated_security_helper.config.ash_config import AshConfig

PATCH = [{"op": "replace", "path": "/project_name", "value": "patched"}]


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    clear_session_state(None)
    yield workspace
    clear_session_state(None)


def _outside_file(tmp_path: Path, name: str = "ash.yaml") -> Path:
    """A config file beyond the workspace root, so the location answer misses."""
    directory = tmp_path / "elsewhere" / name.replace(".", "-")
    directory.mkdir(parents=True)
    path = directory / name
    path.write_text("project_name: x\n", encoding="utf-8")
    return path


def _bind(session_id: str, path, **binding) -> None:
    bind_session_config(
        session_id,
        config=AshConfig(),
        profile_name="p",
        config_path=None if path is None else str(path),
        **binding,
    )


def test_a_patched_binding_makes_its_file_the_clients_wherever_it_is(
    tmp_path, root
) -> None:
    target = _outside_file(tmp_path)
    assert root not in target.parents

    assert session_config_was_patched(target) is False
    _bind("s1", target, patch_ops=PATCH)

    assert session_config_was_patched(target) is True


def test_an_override_yaml_binding_counts_too(tmp_path) -> None:
    target = _outside_file(tmp_path)
    _bind("s1", target, override_yaml="project_name: patched\n")

    assert session_config_was_patched(target) is True


def test_an_unpatched_binding_does_not(tmp_path) -> None:
    target = _outside_file(tmp_path)
    _bind("s1", target)

    assert session_config_was_patched(target) is False


def test_a_patched_binding_for_another_file_does_not(tmp_path) -> None:
    bound = _outside_file(tmp_path, "bound.yaml")
    other = _outside_file(tmp_path, "other.yaml")
    _bind("s1", bound, patch_ops=PATCH)

    assert session_config_was_patched(bound) is True
    assert session_config_was_patched(other) is False


def test_a_state_with_no_config_path_is_skipped(tmp_path) -> None:
    target = _outside_file(tmp_path)
    _bind("no-path", None, patch_ops=PATCH)
    _bind("with-path", target, patch_ops=PATCH)

    assert session_config_was_patched(target) is True


def _symlink_loop(tmp_path: Path) -> Path:
    """A path that is a symlink loop (a -> b -> a); resolving it can fail."""
    directory = tmp_path / "looped"
    directory.mkdir()
    first = directory / "a"
    second = directory / "b"
    first.symlink_to(second)
    second.symlink_to(first)
    return first


def test_a_state_whose_path_is_a_symlink_loop_is_skipped(tmp_path) -> None:
    target = _outside_file(tmp_path)
    looped = _symlink_loop(tmp_path)
    _bind("looped", looped, patch_ops=PATCH)
    _bind("resolvable", target, patch_ops=PATCH)

    # The looped state comes first; the good one after it is still found.
    assert session_config_was_patched(target) is True
    assert session_config_was_patched(_outside_file(tmp_path, "z.yaml")) is False


def test_a_file_that_is_a_symlink_loop_is_not_a_patched_profile(tmp_path, root) -> None:
    looped = _symlink_loop(tmp_path)
    _bind("other", _outside_file(tmp_path), patch_ops=PATCH)
    # The workspace root is in place, so the location answer runs first and
    # resolves the same path.
    assert sandbox.shared_workspace_root() is not None
    assert root not in looped.parents

    assert session_config_was_patched(looped) is False
