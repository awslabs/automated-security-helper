# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project inside a submodule whose commit changed is changed throughout.

``git diff`` names such a submodule by its own path and lists no file inside it, so
the project's changed set was empty: the project was recorded as unchanged and not
scanned. ``changed_file_set`` now holds the project itself when the diff names a
submodule the project is inside (``get_scan_set.changed_paths_within``).

git is replaced by what it would answer: the repository root and the names the diff
lists, so the cases need no repository and start no process.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.workspace import execution

pytestmark = pytest.mark.unit


def _changed_set(
    monkeypatch: pytest.MonkeyPatch, repository: Path, project: Path, names: List[str]
):
    """``changed_file_set`` of *project* when the diff lists *names*."""
    monkeypatch.setattr(
        execution,
        "git_repository_root",
        lambda path, values=(): repository.resolve(),
    )
    monkeypatch.setattr(
        execution,
        "get_changed_files",
        lambda base_ref, cwd=None: [Path(name) for name in names],
    )
    plan = SimpleNamespace(path=project, key="api")
    settings = SimpleNamespace(changed_files_only=True, base_ref="main")
    return execution.changed_file_set(plan, settings)


def test_a_project_inside_a_moved_submodule_is_changed_throughout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    project = repository / "sub" / "api"
    project.mkdir(parents=True)

    changed = _changed_set(monkeypatch, repository, project, ["sub"])

    assert changed == {project.resolve()}


def test_a_project_outside_a_moved_submodule_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    project = repository / "api"
    project.mkdir(parents=True)

    changed = _changed_set(monkeypatch, repository, project, ["sub"])

    assert changed == set()


def test_a_changed_file_inside_the_project_is_kept_and_another_is_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    project = repository / "api"
    project.mkdir(parents=True)

    changed = _changed_set(
        monkeypatch, repository, project, ["api/main.py", "other/main.py"]
    )

    assert changed == {(project / "main.py").resolve()}
