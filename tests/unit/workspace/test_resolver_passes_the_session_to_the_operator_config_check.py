# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The operator config's ``!ENV`` judgement at planning is the one each scan makes.

``check_operator_config`` judged which files of the operator config's chain may
resolve ``!ENV`` for a remote caller without the call's session id, so a
non-default session's own bound profile that uses ``!ENV`` was refused at
planning though each project's resolution, which judges with
``client_config_policy.session_id``, accepted it. The session now reaches the
check from the MCP tool through ``resolve_workspace``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config import resolve_config
from automated_security_helper.workspace import resolver
from automated_security_helper.workspace.resolver import resolve_workspace

pytestmark = pytest.mark.unit


def _workspace(root: Path, folders: List[str]) -> Path:
    for folder in folders:
        (root / folder).mkdir(parents=True, exist_ok=True)
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


def _operator(tmp_path: Path) -> Path:
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"fail_on_findings": True}), encoding="utf-8")
    return path


class TestResolveWorkspacePassesTheSession:
    @pytest.fixture
    def recorded(self, monkeypatch) -> List[Dict[str, Any]]:
        calls: List[Dict[str, Any]] = []

        def record(operator, root, **kwargs):
            calls.append({"operator": operator, "root": root, **kwargs})

        monkeypatch.setattr(resolver, "check_operator_config", record)
        monkeypatch.setattr(resolver, "operator_config_digest", lambda path: "digest")
        return calls

    def test_the_named_session_reaches_the_check(self, tmp_path, recorded):
        workspace = _workspace(tmp_path / "work", ["api"])

        resolve_workspace(
            workspace,
            default_config=_operator(tmp_path),
            remote_client=True,
            session_id="session-7",
        )

        (call,) = recorded
        # RED at the base: resolve_workspace takes no session_id (TypeError), and
        # the check was called with remote_client alone.
        assert call["remote_client"] is True
        assert call["session_id"] == "session-7"

    def test_with_no_session_the_rules_session_is_used(self, tmp_path, recorded):
        """The per-project resolution reads the rules' session; so does the check."""
        from automated_security_helper.config.ash_config import (
            AshConfig,
            RuntimeOverridesConfig,
        )
        from automated_security_helper.config.client_config_policy import (
            ClientConfigRules,
        )

        workspace = _workspace(tmp_path / "work", ["api"])
        # The rules carry a policy and a base config (both required); only the
        # session matters here.
        rules = ClientConfigRules(
            policy=RuntimeOverridesConfig(), base=AshConfig(), session_id="session-9"
        )

        resolve_workspace(
            workspace,
            default_config=_operator(tmp_path),
            client_config_rules=rules,
            remote_client=True,
        )

        (call,) = recorded
        assert call["session_id"] == "session-9"

    def test_a_local_resolve_names_no_session(self, tmp_path, recorded):
        """Control: the CLI path passes neither, and the check sees None."""
        workspace = _workspace(tmp_path / "work", ["api"])

        resolve_workspace(workspace, default_config=_operator(tmp_path))

        (call,) = recorded
        assert call["remote_client"] is False
        assert call["session_id"] is None


class TestCheckOperatorConfigJudgesEnvForTheSession:
    def test_the_env_rule_is_built_for_the_session(self, tmp_path, monkeypatch):
        asked: List[tuple] = []

        def env_refused_for(remote_client, session_id=None):
            asked.append((remote_client, session_id))
            return lambda path: False

        monkeypatch.setattr(resolve_config, "env_refused_for", env_refused_for)
        monkeypatch.setattr(
            resolve_config, "_load_overlay", lambda *args, **kwargs: "overlay"
        )
        monkeypatch.setattr(
            resolve_config, "_refuse_unless_the_operators", lambda overlay, root: None
        )

        resolve_config.check_operator_config(
            _operator(tmp_path), tmp_path, remote_client=True, session_id="session-7"
        )

        # RED at the base: check_operator_config takes no session_id.
        assert asked == [(True, "session-7")]


class TestTheMcpResolvePassesItsSession:
    def test_the_tool_s_session_reaches_resolve_workspace(self, monkeypatch):
        from automated_security_helper.cli.mcp import workspace as ws

        calls: List[Dict[str, Any]] = []

        def record(path, **kwargs):
            calls.append(kwargs)
            return "plan"

        monkeypatch.setattr(ws, "resolve_workspace", record)

        plan = ws._resolve(
            "/ws/dev.code-workspace",
            None,
            False,
            None,
            remote_client=True,
            session_id="session-7",
        )

        assert plan == "plan"
        (kwargs,) = calls
        # RED at the base: _resolve passed the session only to the project gate.
        assert kwargs["session_id"] == "session-7"
        assert kwargs["remote_client"] is True
