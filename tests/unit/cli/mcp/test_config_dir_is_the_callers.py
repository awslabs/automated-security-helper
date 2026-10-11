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

from pathlib import Path

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
