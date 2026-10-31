# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan decides "is this the project's own config" by the planner's rule.

The planner decides whether a project's config is the operator's by one call,
``resolver.config_is_the_operators``, with the operator's two files (the default
config and the trusted base). The scan's check compared the project's config with
the default config alone, by a path-resolve equality of its own. Under the MCP
server the default config is the session's patched copy and the operator's
registered file is the trusted base, so a project whose config is the registered
file was planned as having no config of its own and then refused at scan time as
having one. A link or a case-spelled path the planner reads as one file was read
as two by the scan. The scan now asks the resolver's own predicates.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import operator_config_digest
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.workspace import resolver
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    _check_the_plans_operator_config,
)
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit


def _config(path: Path, **content) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(content or {"fail_on_findings": True}), "utf-8")
    return path


def _project(tmp_path: Path, **fields) -> ProjectPlan:
    project_dir = tmp_path / "workspace" / "api"
    project_dir.mkdir(parents=True, exist_ok=True)
    return ProjectPlan(
        key="api",
        relative_path="api",
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
        **fields,
    )


def _settings(tmp_path: Path, default: Path, trusted: Path | None = None):
    return ProjectScanSettings(
        output_dir=tmp_path / "out",
        phases=("scan",),
        default_config_path=default.as_posix(),
        trusted_config_path=trusted.as_posix() if trusted else None,
    )


def test_a_project_on_the_registered_profile_is_not_refused_under_a_patched_default(
    tmp_path,
):
    """The default config is the session's patched copy; the project's config is
    the registered profile, which the planner reads as the operator's.

    Red at the base: the scan compared the project's config with the patched copy
    alone, read it as the project's own, expected the operator's file to be
    layered over it, and refused a plan that layered nothing."""
    registered = _config(tmp_path / "ops" / "profile.yaml")
    patched = _config(tmp_path / "session" / "profile.yaml", fail_on_findings=False)
    project = _project(
        tmp_path,
        config_source=registered.as_posix(),
        operator_config=None,
        operator_config_digest=operator_config_digest(registered),
    )

    _check_the_plans_operator_config(project, _settings(tmp_path, patched, registered))


def test_a_config_the_planners_rule_reads_as_the_operators_is_not_refused(
    tmp_path, monkeypatch
):
    """A case-spelled path the resolver reads as the operator's file is read so
    here: the scan asks the resolver's own predicate, not a second one.

    Red at the base: the scan compared resolved paths, saw two files, and
    refused the project as having a config of its own."""
    operator = _config(tmp_path / "ops" / "ash.yaml")
    spelled = tmp_path / "ops" / "ASH.yaml"
    monkeypatch.setattr(
        resolver,
        "same_config_file",
        lambda first, second, cache=None: str(first).lower() == str(second).lower(),
    )
    project = _project(
        tmp_path,
        config_source=spelled.as_posix(),
        operator_config=None,
        operator_config_digest=operator_config_digest(operator),
    )

    _check_the_plans_operator_config(project, _settings(tmp_path, operator))


def test_a_project_with_its_own_config_is_still_planned_against_the_operators_file(
    tmp_path,
):
    """Control, green on both sides: a config that is neither of the operator's
    files is the project's own, and the plan must have layered the operator's."""
    operator = _config(tmp_path / "ops" / "ash.yaml")
    own = _config(tmp_path / "workspace" / "api" / ".ash.yaml", project_name="api")
    project = _project(
        tmp_path,
        config_source=own.as_posix(),
        operator_config=None,
        operator_config_digest=operator_config_digest(operator),
    )

    with pytest.raises(ASHConfigValidationError, match="was planned with operator"):
        _check_the_plans_operator_config(project, _settings(tmp_path, operator))


def test_a_project_on_the_operators_file_is_refused_when_the_digest_is_another_files(
    tmp_path,
):
    """The digest arm for a project with no config of its own: its config is the
    scan's default, and the digest the plan recorded is another file's content."""
    operator = _config(tmp_path / "ops" / "ash.yaml")
    another = _config(tmp_path / "ops" / "other.yaml", fail_on_findings=False)
    project = _project(
        tmp_path,
        config_source=operator.as_posix(),
        operator_config=None,
        operator_config_digest=operator_config_digest(another),
    )

    with pytest.raises(ASHConfigValidationError, match="does not hold the content"):
        _check_the_plans_operator_config(project, _settings(tmp_path, operator))


def test_a_project_on_the_operators_file_passes_with_its_own_digest(tmp_path):
    """Control, green on both sides."""
    operator = _config(tmp_path / "ops" / "ash.yaml")
    project = _project(
        tmp_path,
        config_source=operator.as_posix(),
        operator_config=None,
        operator_config_digest=operator_config_digest(operator),
    )

    _check_the_plans_operator_config(project, _settings(tmp_path, operator))
