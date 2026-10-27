# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace config reached through a link from inside the workspace is the repository's.

A workspace scan resolves each project's config twice: once into the plan
(``workspace/resolver.py``) and again when the project is scanned
(``workspace/execution.py``'s ``_project_config_with_policy``). A config file the
workspace holds is held to the limits of a config inside the scanned tree, and a
file that is a symlink from inside the tree to one outside it was put there
by the repository all the same: it is judged by the path that reached it, as a single-directory
scan judges it (config/sandbox_grants.py, ``files_inside``).

Both places judge such a file by the path that reached it:
- the plan records a project's config by its path in the project, so a project
  whose ``.ash/.ash.yaml`` links out is held to the limits of a config inside
  the scanned tree;
- the operator's ``--config`` is the trusted base only when the path given is
  outside the workspace, so a ``--config`` inside the workspace that links out
  is confined like a project's config.

A linked file's s3 reporter section, which turns the upload on and names the
bucket, does not reach the S3 reporter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import pytest

#: Turns the S3 upload on, to the repository's bucket.
_PAYLOAD = "reporters:\n  s3:\n    enabled: true\n    options:\n      bucket_name: repo-bucket\n"


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "wsroot"
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    workspace = root / "dev.code-workspace"
    workspace.write_text('{"folders": [{"path": "app"}]}', encoding="utf-8")
    return workspace


def _outside(tmp_path: Path) -> Path:
    payload = tmp_path / "outside" / "payload.yaml"
    payload.parent.mkdir(parents=True)
    payload.write_text(_PAYLOAD, encoding="utf-8")
    return payload


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")


def _s3_section(workspace: Path, operator: Optional[Path], tmp_path: Path) -> Any:
    """The s3 section the S3 reporter would run with in the workspace's one project."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
    )
    from automated_security_helper.workspace import execution
    from automated_security_helper.workspace.resolver import resolve_workspace

    default_config = str(operator) if operator is not None else None
    plan = resolve_workspace(workspace, default_config=default_config)
    (project,) = plan.projects
    settings = execution.ProjectScanSettings(
        output_dir=tmp_path / "out", default_config_path=default_config
    )
    config = execution._project_config_with_policy(project, settings)
    return reporter_section(config, S3Reporter)


def _sends_to_the_repositorys_bucket(section: Any) -> bool:
    if not isinstance(section, dict):
        return False
    options = section.get("options") or {}
    return bool(section.get("enabled")) and options.get("bucket_name") == "repo-bucket"


def test_a_project_config_that_links_out_does_not_choose_the_upload(tmp_path):
    workspace = _workspace(tmp_path)
    (workspace.parent / "app" / ".ash").mkdir()
    _symlink_or_skip(
        workspace.parent / "app" / ".ash" / ".ash.yaml", _outside(tmp_path)
    )

    section = _s3_section(workspace, None, tmp_path)

    assert not _sends_to_the_repositorys_bucket(section), section


def test_the_plan_names_a_linked_project_config_by_its_path_in_the_project(
    tmp_path,
):
    """The scan reads the config the plan names, so the plan names the link."""
    from automated_security_helper.workspace.resolver import resolve_workspace

    workspace = _workspace(tmp_path)
    (workspace.parent / "app" / ".ash").mkdir()
    link = workspace.parent / "app" / ".ash" / ".ash.yaml"
    _symlink_or_skip(link, _outside(tmp_path))

    (project,) = resolve_workspace(workspace).projects

    assert project.config_source == link.absolute().as_posix()


def test_a_workspace_config_inside_the_workspace_that_links_out_is_no_trusted_base(
    tmp_path,
):
    workspace = _workspace(tmp_path)
    operator = workspace.parent / "ci.yaml"
    _symlink_or_skip(operator, _outside(tmp_path))

    section = _s3_section(workspace, operator, tmp_path)

    assert not _sends_to_the_repositorys_bucket(section), section


def test_control_the_operators_config_outside_the_workspace_chooses_the_upload(
    tmp_path,
):
    """The same file, named where it is, outside the workspace: it is the
    operator's, and its upload goes ahead. Without this, a reporter that never
    got an s3 section would pass the tests above."""
    workspace = _workspace(tmp_path)

    section = _s3_section(workspace, _outside(tmp_path), tmp_path)

    assert _sends_to_the_repositorys_bucket(section), section


def test_control_a_project_with_its_own_config_gets_the_operators_upload(tmp_path):
    """The project has a config of its own, inside the workspace, and the
    operator's is outside it: the operator's is the trusted base the project's
    is confined from, and its upload goes ahead. Without this, a trusted base
    that was always the defaults would pass the no-trusted-base test above."""
    workspace = _workspace(tmp_path)
    (workspace.parent / "app" / ".ash").mkdir()
    (workspace.parent / "app" / ".ash" / ".ash.yaml").write_text(
        "project_name: app\n", encoding="utf-8"
    )

    section = _s3_section(workspace, _outside(tmp_path), tmp_path)

    assert _sends_to_the_repositorys_bucket(section), section
