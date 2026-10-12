# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the calling session's ``config/`` directory holds files set aside for it.

``select_profile`` materializes a registered profile into the session's own
``config/`` directory, which only the server writes. A config path a client names
there is the operator's, and for a remote caller it resolves ``!ENV``. A file in
another session's ``config/`` directory is not set aside for this caller: the MCP
tools refuse such a path up front (``validate_config_input``), and
``client_named_config_is_untrusted`` and the ``!ENV`` rule count it as the
client's as well.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_profile_registry,
    clear_session_state,
    session_client_rules,
)

MINE = "session-a"
THEIRS = "session-b"
PROBE_VAR = "ASH_ENV_PROBE"
PROBE = "probe-value-3c9d"
TAGGED = f"project_name: !ENV ${{{PROBE_VAR}:unset}}\n"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE)
    clear_profile_registry()
    clear_session_state()
    yield root
    clear_profile_registry()
    clear_session_state()


def _config_file(root: Path, session: str, text: str = "project_name: x\n") -> Path:
    path = root / session / "config" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_another_sessions_config_dir_is_the_clients(_server: Path) -> None:
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
    )

    mine = _config_file(_server, MINE)
    theirs = _config_file(_server, THEIRS)

    assert client_named_config_is_untrusted(theirs, session_id=MINE) is True
    assert client_named_config_is_untrusted(mine, session_id=MINE) is False


def test_with_no_session_the_default_sessions_config_dir_is_set_aside(
    _server: Path,
) -> None:
    """``select_profile`` writes a caller with no session id under the default one."""
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
    )

    default = _config_file(_server, DEFAULT_SESSION_ID)
    other = _config_file(_server, MINE)

    assert client_named_config_is_untrusted(default) is False
    assert client_named_config_is_untrusted(other) is True


def test_the_env_rule_sets_aside_only_the_callers_config_dir(_server: Path) -> None:
    from automated_security_helper.config.config_sources import env_refused_for

    refused = env_refused_for(True, MINE)

    assert refused(_config_file(_server, THEIRS)) is True
    assert refused(_config_file(_server, MINE)) is False


def test_a_remote_scan_resolves_env_only_in_its_own_config_dir(
    _server: Path, tmp_path: Path
) -> None:
    """The rules a scan is resolved with carry the session they were built for."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import (
        ASHConfigEnvNotResolvedError,
    )

    target = tmp_path / "target"
    target.mkdir()
    rules = session_client_rules(MINE)

    mine = resolve_config(
        config_path=_config_file(_server, MINE, TAGGED),
        source_dir=target,
        remote_client=True,
        client_config_policy=rules,
    )
    assert mine.project_name == PROBE

    with pytest.raises(ASHConfigEnvNotResolvedError):
        resolve_config(
            config_path=_config_file(_server, THEIRS, TAGGED),
            source_dir=target,
            remote_client=True,
            client_config_policy=rules,
        )


# ---------------------------------------------------------------------------
# Each MCP route judges the file for the calling session
# ---------------------------------------------------------------------------
# A file in the caller's own config/ directory uses ``${VAR}`` and sets a field
# the default policy denies a client. Both are the operator's there, so every
# route accepts it; a route that judged it for another session (or for none)
# would refuse it as the client's.

OWN = f"project_name: ${{{PROBE_VAR}:unset}}\nfail_on_findings: false\n"


class _Stop(Exception):
    pass


@pytest.fixture
def own(_server: Path) -> Path:
    return _config_file(_server, MINE, OWN)


@pytest.fixture
def target(_server: Path) -> Path:
    """A directory in the caller's own sandbox, so a scan may target it."""
    path = _server / MINE / "source" / "app"
    path.mkdir(parents=True)
    (path / "main.py").write_text("x = 1\n", encoding="utf-8")
    return path


def test_the_scan_tool_judges_the_named_config_for_the_caller(own, target) -> None:
    from automated_security_helper.cli import mcp_tools

    with patch.object(mcp_tools, "_run_scan_async", AsyncMock()) as started:
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(
                directory_path=str(target), config_path=str(own), session_id=MINE
            )
        )

    assert result.get("success") is not False, result
    started.assert_called_once()


@pytest.mark.parametrize(
    "raw, shown",
    [(True, f"${{{PROBE_VAR}:unset}}"), (False, PROBE)],
    ids=["raw", "resolved"],
)
def test_get_config_judges_the_named_config_for_the_caller(
    own, raw: bool, shown: str
) -> None:
    """Raw shows an operator file's reference as written; resolved, its value."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    got = mcp_get_config(config_path=str(own), raw=raw, session_id=MINE)

    assert got.get("project_name") == shown, got
    assert got.get("fail_on_findings") is False, got


def _workspace(_server: Path, target: Path) -> Path:
    path = target.parent / "dev.code-workspace"
    path.write_text(json.dumps({"folders": [{"path": target.name}]}), encoding="utf-8")
    return path


@pytest.fixture
def own_policy(_server: Path) -> Path:
    path = _server / MINE / "config" / "ash-workspace.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("workspace:\n  max_severity_threshold: HIGH\n", encoding="utf-8")
    return path


def test_resolve_workspace_takes_a_policy_from_the_callers_config_dir(
    _server: Path, target: Path, own_policy: Path
) -> None:
    from automated_security_helper.cli.mcp import workspace as ws

    result = asyncio.run(
        ws.mcp_resolve_workspace(
            str(_workspace(_server, target)),
            workspace_config=str(own_policy),
            session_id=MINE,
        )
    )

    assert result.get("success") is True, result


def test_scan_workspace_takes_a_policy_from_the_callers_config_dir(
    _server: Path, target: Path, own_policy: Path
) -> None:
    """Stopped where the settings are built, which is after the policy check."""
    from automated_security_helper.cli.mcp import workspace as ws

    def stop(*args, **kwargs):
        raise _Stop

    with patch.object(ws, "build_project_scan_settings", stop):
        result = asyncio.run(
            ws.mcp_scan_workspace(
                str(_workspace(_server, target)),
                workspace_config=str(own_policy),
                session_id=MINE,
            )
        )

    assert result.get("error_type") == "_Stop", result


def test_the_exit_code_reader_judges_the_config_for_the_caller(own, target) -> None:
    """``fail_on_findings`` is read before the scan for the exit code, by the same rules."""
    from automated_security_helper.cli.mcp.sandbox import config_base_gate
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _resolve_config_fail_on_findings,
    )

    opts = ScanOptions(
        source_dir=target,
        output_dir=target.parent / "out",
        config=str(own),
        remote_client=True,
        client_config_policy=session_client_rules(MINE),
        config_base_gate=config_base_gate(MINE),
    )

    assert _resolve_config_fail_on_findings(opts) is False


def test_the_workspace_knobs_reader_judges_the_config_for_the_caller(
    _server: Path, target: Path
) -> None:
    from automated_security_helper.cli.mcp.sandbox import config_base_gate
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _resolve_workspace_execution_config,
    )

    knobs = _config_file(
        _server,
        MINE,
        f"project_name: ${{{PROBE_VAR}:unset}}\nworkspace:\n  max_parallel_projects: 3\n",
    )
    opts = ScanOptions(
        source_dir=target,
        output_dir=target.parent / "out",
        config=str(knobs),
        remote_client=True,
        client_config_policy=session_client_rules(MINE),
        config_base_gate=config_base_gate(MINE),
    )

    assert _resolve_workspace_execution_config(opts).max_parallel_projects == 3
