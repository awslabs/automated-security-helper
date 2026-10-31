# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode hands the container the workspace policy the plan applied.

``_run_container_mode`` computes the policy hand-off once, through
``_workspace_policy_for_the_container``, which hands the as-named path over only
when it resolves to the file the plan read. A second computation of the same
value, without that check, then overwrote it: for a plan built without the
as-named spelling (an API caller's), discovery found the ``ash-workspace.yaml``
inside the workspace root, which the plan's resolution had skipped because an
explicit policy outside the root was given, and the container was handed the
repository's file in place of the operator's.

The container runner is replaced by a recorder, so nothing is started.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.subprocess_utils import create_completed_process
from automated_security_helper.workspace.resolver import resolve_workspace

pytestmark = pytest.mark.unit

OPERATOR_POLICY = "workspace:\n  max_severity_threshold: HIGH\n"
REPOSITORY_POLICY = "workspace:\n  max_severity_threshold: LOW\n"


@pytest.fixture
def handed_over(monkeypatch) -> Dict[str, Any]:
    """What _run_container_mode hands the container runner; nothing is started."""
    seen: Dict[str, Any] = {}

    def fake_run_ash_container(**kwargs):
        seen.update(kwargs)
        return rac._not_started(create_completed_process(args=[], returncode=4))

    monkeypatch.setattr(ras, "run_ash_container", fake_run_ash_container)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_args, **_kwargs: [])
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return seen


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "api").mkdir(parents=True)
    definition = root / "dev.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return definition


def _run(tmp_path: Path, plan, **extra) -> None:
    opts = ras.ScanOptions(
        source_dir=plan.workspace_root,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        workspace_plan=plan,
        build=False,
        run=True,
        progress=False,
        show_summary=False,
        **extra,
    )
    with pytest.raises(SystemExit):
        ras._run_container_mode(opts, MagicMock())


def test_an_api_callers_explicit_policy_is_not_replaced_by_the_roots_file(
    handed_over, tmp_path, monkeypatch
):
    """The plan applied the operator's policy outside the root; the root also
    holds an ash-workspace.yaml the repository wrote. A plan built without the
    as-named spelling hands over the file the plan read, never the root's."""
    definition = _workspace(tmp_path)
    repository_policy = definition.parent / "ash-workspace.yaml"
    repository_policy.write_text(REPOSITORY_POLICY, encoding="utf-8")
    operator_policy = tmp_path / "ops" / "policy.yaml"
    operator_policy.parent.mkdir()
    operator_policy.write_text(OPERATOR_POLICY, encoding="utf-8")
    plan = resolve_workspace(definition, workspace_config=operator_policy)
    assert plan.workspace_config_source == operator_policy.resolve().as_posix()
    monkeypatch.chdir(tmp_path)

    _run(tmp_path, plan)

    handed = handed_over["workspace_config"]
    assert handed == plan.workspace_config_source, handed
    assert Path(handed).resolve() != repository_policy.resolve(), handed


def test_the_policy_named_on_the_command_line_is_handed_over_by_its_name(
    handed_over, tmp_path, monkeypatch
):
    """Control: with the as-named spelling, the name itself is handed over when
    it resolves to the file the plan read."""
    definition = _workspace(tmp_path)
    operator_policy = tmp_path / "ops" / "policy.yaml"
    operator_policy.parent.mkdir()
    operator_policy.write_text(OPERATOR_POLICY, encoding="utf-8")
    plan = resolve_workspace(definition, workspace_config=operator_policy)
    monkeypatch.chdir(tmp_path)

    _run(tmp_path, plan, workspace_config_as_named="ops/policy.yaml")

    handed = handed_over["workspace_config"]
    assert handed == (tmp_path / "ops" / "policy.yaml").as_posix(), handed
    assert Path(handed).resolve() == operator_policy.resolve()


def test_a_policy_discovered_in_the_root_is_still_handed_over(
    handed_over, tmp_path, monkeypatch
):
    """The must-not twin: the only policy is the root's own, the plan read it,
    and that is what the container gets."""
    definition = _workspace(tmp_path)
    root_policy = definition.parent / "ash-workspace.yaml"
    root_policy.write_text(OPERATOR_POLICY, encoding="utf-8")
    plan = resolve_workspace(definition)
    assert plan.workspace_config_source == root_policy.resolve().as_posix()
    monkeypatch.chdir(tmp_path)

    _run(tmp_path, plan)

    handed = handed_over["workspace_config"]
    assert handed is not None
    assert Path(handed).resolve() == root_policy.resolve(), handed


def test_a_plan_with_no_policy_hands_none_over(handed_over, tmp_path, monkeypatch):
    definition = _workspace(tmp_path)
    plan = resolve_workspace(definition)
    assert plan.workspace_config_source is None
    monkeypatch.chdir(tmp_path)

    _run(tmp_path, plan)

    assert handed_over["workspace_config"] is None
