# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The operator config's digest is checked for every project the file governs.

The resolver records ``operator_config_digest`` on every project the operator's
file governs: layered over the project's own config, or the project's config
itself because the project declares none. The scan's check read the digest only
when ``project.operator_config`` was set, which it never is for the second kind,
so a rewrite of the operator's file between plan and scan went undetected for
every project without a config of its own. The check now reads the operator's
file itself, the one the digest was taken from.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import operator_config_digest
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    _check_the_plans_operator_config,
)
from automated_security_helper.workspace.plan import ProjectPlan

pytestmark = pytest.mark.unit


def _operator(tmp_path: Path) -> Path:
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"fail_on_findings": True}), encoding="utf-8")
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


def _settings(tmp_path: Path, operator: Path) -> ProjectScanSettings:
    return ProjectScanSettings(
        output_dir=tmp_path / "out",
        phases=("scan",),
        default_config_path=operator.as_posix(),
    )


def test_a_project_without_its_own_config_is_refused_when_the_operators_file_changed(
    tmp_path,
):
    """The second kind: the operator's file IS the project's config, so the plan
    records no ``operator_config`` and the old check never compared the digest.
    Red at the base: no exception, the stale plan ran."""
    operator = _operator(tmp_path)
    project = _project(
        tmp_path,
        config_source=operator.as_posix(),
        operator_config=None,
        operator_config_digest="recorded-before-the-rewrite",
    )

    with pytest.raises(ASHConfigValidationError, match="does not hold the content"):
        _check_the_plans_operator_config(project, _settings(tmp_path, operator))


def test_a_project_without_its_own_config_passes_when_the_digest_still_matches(
    tmp_path,
):
    """Control: the same project with the digest the file has now is accepted,
    so the refusal above is the digest's doing and not the missing
    ``operator_config``."""
    operator = _operator(tmp_path)
    project = _project(
        tmp_path,
        config_source=operator.as_posix(),
        operator_config=None,
        operator_config_digest=operator_config_digest(operator),
    )

    _check_the_plans_operator_config(project, _settings(tmp_path, operator))


def test_a_project_with_its_own_config_is_still_refused_on_a_changed_operator_file(
    tmp_path,
):
    """The first kind keeps its check: the operator's file is layered over the
    project's own config, and a rewrite is refused as before."""
    operator = _operator(tmp_path)
    own = tmp_path / "workspace" / "api" / ".ash" / ".ash.yaml"
    own.parent.mkdir(parents=True, exist_ok=True)
    own.write_text(yaml.safe_dump({"project_name": "api"}), encoding="utf-8")
    project = _project(
        tmp_path,
        config_source=own.as_posix(),
        operator_config=operator.as_posix(),
        operator_config_digest="recorded-before-the-rewrite",
    )

    with pytest.raises(ASHConfigValidationError, match="does not hold the content"):
        _check_the_plans_operator_config(project, _settings(tmp_path, operator))


def test_a_plan_with_no_recorded_digest_is_not_refused(tmp_path):
    """Control: a plan written before the digest existed records None and is
    accepted, as before."""
    operator = _operator(tmp_path)
    project = _project(
        tmp_path,
        config_source=operator.as_posix(),
        operator_config=None,
        operator_config_digest=None,
    )

    _check_the_plans_operator_config(project, _settings(tmp_path, operator))
