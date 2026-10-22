# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which config files resolve ``!ENV`` depends on who is calling the MCP server.

``!ENV`` reads the server's environment. For a remote caller
(``cli/mcp/sandbox.caller_is_remote``) every file of every chain resolves none,
and one that uses ``!ENV`` is refused, unless the operator set the file aside: it
is under ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` or in a session's ``config/``
directory. That covers a named path, a file discovered in a directory the client
names, the bases a refused file extends, and a scan target's own config. For a
local stdio caller, who launched the server and holds its environment already,
only a file under the MCP workspace root is refused, as for any caller; the
user's own repository config keeps ``!ENV``. See "Environment variables" in
``config/config_sources.py``.

``test_delivered_config_env.py`` covers files a client delivered. This module
covers the files a remote client only names or points at, and the stdio side.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_profile_registry,
    clear_all_session_state,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import exceptions as _exceptions

SESSION = "client-1"
PROBE_VAR = "ASH_ENV_PROBE"
PROBE = "probe-value-7f3a"
TAGGED = f"project_name: !ENV ${{{PROBE_VAR}:unset}}\n"
UNTAGGED = f"project_name: ${{{PROBE_VAR}:unset}}\n"
TOML = f'project_name = "${{{PROBE_VAR}:unset}}"\n'
ENV_REFUSED = "config_env_not_resolved"
# What get_config shows for the value a config read from the environment: the
# reference, marked, and never the value.
READ = f"<from ${{{PROBE_VAR}:unset}}>"


def _assert_read(got: dict) -> None:
    """get_config's config read ASH_ENV_PROBE from the environment, and shows it
    as the reference, not the value."""
    assert got.get("project_name") == READ, got
    assert PROBE not in json.dumps(got), got


ASHConfigEnvNotResolvedError = getattr(
    _exceptions,
    "ASHConfigEnvNotResolvedError",
    type("ASHConfigEnvNotResolvedErrorMissing", (Exception,), {}),
)


class _QuietLogger:
    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A scan root holding two repositories, an operator config root, and
    ``ASH_ENV_PROBE`` in the server's environment."""
    workspace = tmp_path / "workspaces"
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    other = scan_root / "other"
    other.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE)
    clear_profile_registry()
    clear_all_session_state()
    yield {
        "workspace": workspace,
        "scan_root": scan_root,
        "target": target,
        "other": other,
        "operator": operator,
        "tmp": tmp_path,
    }
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def stdio_repo(_server, monkeypatch) -> Path:
    """A local install with no grants, and the user's own repository using !ENV."""
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    repo = _server["tmp"] / "home" / "repo"
    (repo / ".ash").mkdir(parents=True)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    (repo / ".ash" / ".ash.yaml").write_text(UNTAGGED, encoding="utf-8")
    return repo


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _carries_probe(result: Any) -> bool:
    return PROBE in json.dumps(result, default=str)


def _scan_directory(
    directory: Path, config_path: Optional[Path], session_id: Optional[str]
) -> Tuple[Dict[str, Any], AsyncMock]:
    """mcp_scan_directory with the scan itself stubbed out."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    started = AsyncMock()
    with (
        patch.object(mcp_tools, "_run_scan_async", new=started),
        patch.object(mcp_tools, "get_scan_registry", return_value=ScanRegistry()),
    ):
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(
                directory_path=str(directory),
                config_path=str(config_path) if config_path else None,
                session_id=session_id,
            )
        )
    return result, started


def _ctx(session_id: str = SESSION) -> MagicMock:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session_id}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def _run_ash_scan(**kwargs: Any) -> Tuple[Dict[str, Any], AsyncMock]:
    """The run_ash_scan tool for a remote caller, with the scan stubbed out."""
    from automated_security_helper.cli import mcp_server, mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    started = AsyncMock()
    with (
        patch.object(mcp_tools, "_run_scan_async", new=started),
        patch.object(mcp_tools, "get_scan_registry", return_value=ScanRegistry()),
        patch.object(mcp_server, "monitor_scan_progress", new=AsyncMock()),
    ):
        result = asyncio.run(mcp_server.run_ash_scan(_ctx(), **kwargs))
    return result, started


def _scan(
    target: Path, config_path: Optional[Path], session_id: Optional[str]
) -> Tuple[Any, List[Any]]:
    """Run the real _run_scan_async; return its registry entry and what
    resolve_config returned or raised. A config it returns stops the scan."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    outcomes: List[Any] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> AshConfig:
        try:
            config = real(*args, **kwargs)
        except Exception as exc:
            outcomes.append(exc)
            raise
        outcomes.append(config)
        raise _StopAfterResolution

    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(target), output_directory=str(output)
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "resolve_config", recording),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=str(config_path) if config_path else None,
                session_id=session_id,
            )
        )
    assert outcomes, "the scan never reached config resolution"
    return registry.get_scan(scan_id), outcomes


# ---------------------------------------------------------------------------
# Local stdio caller: the user's own repository config keeps !ENV
# ---------------------------------------------------------------------------


def test_stdio_get_config_of_a_named_repo_config_resolves_env(stdio_repo):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    named = mcp_get_config(config_path=str(stdio_repo / ".ash" / ".ash.yaml"))
    discovered = mcp_get_config(search_dir=str(stdio_repo))

    _assert_read(named)
    _assert_read(discovered)


def test_stdio_scan_with_a_named_repo_config_starts_and_resolves_env(stdio_repo):
    config = stdio_repo / ".ash" / ".ash.yaml"

    result, started = _scan_directory(stdio_repo, config, None)
    _, outcomes = _scan(stdio_repo, config, None)

    assert result.get("success") is True, result
    started.assert_called_once()
    assert isinstance(outcomes[-1], AshConfig), outcomes
    assert outcomes[-1].project_name == PROBE


def test_stdio_validate_config_path_and_content_accept_env(stdio_repo):
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    by_path = mcp_validate_config(config_path=str(stdio_repo / ".ash" / ".ash.yaml"))
    by_content = mcp_validate_config(config_content=f"extends: []\n{UNTAGGED}")

    assert by_path["valid"] is True, by_path
    assert by_content["valid"] is True, by_content


def test_stdio_still_refuses_a_file_under_the_workspace_root(_server):
    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    # The stdio session's own sandbox, where a delivered file lands.
    delivered = _write(
        resolve_workspace_root() / DEFAULT_SESSION_ID / "source" / "ash.yaml",
        TAGGED,
    )

    result = mcp_get_config(config_path=str(delivered), session_id=DEFAULT_SESSION_ID)

    assert result.get("error_type") == ENV_REFUSED, result
    assert not _carries_probe(result)


# ---------------------------------------------------------------------------
# Remote caller: a file the operator did not set aside resolves no !ENV
# ---------------------------------------------------------------------------


def test_remote_named_config_outside_the_config_roots_is_refused(_server):
    from automated_security_helper.cli.mcp_tools import (
        mcp_get_config,
        mcp_validate_config,
    )

    named = _write(_server["other"] / "ash.yaml", TAGGED)

    got = mcp_get_config(config_path=str(named), session_id=SESSION)
    raw = mcp_get_config(config_path=str(named), raw=True, session_id=SESSION)
    validated = mcp_validate_config(config_path=str(named), session_id=SESSION)

    assert got.get("error_type") == ENV_REFUSED, got
    assert raw.get("error_type") == ENV_REFUSED, raw
    assert ENV_REFUSED in [e["type"] for e in validated["errors"]], validated
    assert not _carries_probe([got, raw, validated])


@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
@pytest.mark.parametrize(
    "name,text",
    [(".ash/.ash.yaml", TAGGED), (".ashrc.toml", TOML)],
    ids=["yaml", "toml"],
)
def test_remote_config_discovered_in_a_search_dir_is_refused(_server, name, text, raw):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    _write(_server["other"] / name, text)

    result = mcp_get_config(
        search_dir=str(_server["other"]), raw=raw, session_id=SESSION
    )

    assert result.get("error_type") == ENV_REFUSED, result
    assert not _carries_probe(result)


def test_remote_base_of_a_refused_root_is_refused(_server):
    from automated_security_helper.cli.mcp_tools import (
        mcp_get_config,
        mcp_validate_config,
    )

    _write(_server["other"] / "b.yaml", TAGGED)
    root = _write(_server["other"] / "a.yaml", "extends: b.yaml\n")

    got = mcp_get_config(config_path=str(root), session_id=SESSION)
    validated = mcp_validate_config(config_path=str(root), session_id=SESSION)
    entry, outcomes = _scan(_server["target"], root, SESSION)

    assert got.get("error_type") == ENV_REFUSED, got
    assert ENV_REFUSED in [e["type"] for e in validated["errors"]], validated
    assert isinstance(outcomes[-1], ASHConfigEnvNotResolvedError), outcomes
    assert "b.yaml" in str(outcomes[-1])
    assert not _carries_probe([got, validated, str(outcomes[-1]), entry.to_dict()])


@pytest.fixture
def set_aside_base(_server, monkeypatch) -> Path:
    """A base using ``!ENV`` in a directory the operator set aside, beside a root that is not.

    The set-aside directory is inside the root's own directory, so the base is
    inside the confinement root and the only thing that can refuse it is the
    file that names it.
    """
    shared = _server["other"] / "shared"
    monkeypatch.setenv(
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        os.pathsep.join([str(_server["operator"]), str(shared)]),
    )
    return _write(shared / "b.yaml", TAGGED)


def test_remote_set_aside_base_resolves_env_on_its_own(_server, set_aside_base):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    got = mcp_get_config(config_path=str(set_aside_base), session_id=SESSION)

    _assert_read(got)


def test_remote_set_aside_base_of_a_refused_root_is_refused(_server, set_aside_base):
    """Every base of a refused file is refused: the file that names a base chose it."""
    from automated_security_helper.cli.mcp_tools import (
        mcp_get_config,
        mcp_validate_config,
    )

    root = _write(_server["other"] / "a.yaml", "extends: shared/b.yaml\n")

    got = mcp_get_config(config_path=str(root), session_id=SESSION)
    validated = mcp_validate_config(config_path=str(root), session_id=SESSION)
    entry, outcomes = _scan(_server["target"], root, SESSION)

    assert got.get("error_type") == ENV_REFUSED, got
    assert ENV_REFUSED in [e["type"] for e in validated["errors"]], validated
    assert isinstance(outcomes[-1], ASHConfigEnvNotResolvedError), outcomes
    assert "b.yaml" in str(outcomes[-1])
    assert not _carries_probe([got, validated, str(outcomes[-1]), entry.to_dict()])


def test_remote_scan_target_own_config_is_refused(_server):
    _write(_server["target"] / ".ash" / ".ash.yaml", UNTAGGED)

    started_result, started = _run_ash_scan(source_dir=str(_server["target"]))
    entry, outcomes = _scan(_server["target"], None, SESSION)

    assert started_result.get("error_type") == ENV_REFUSED, started_result
    started.assert_not_called()
    assert isinstance(outcomes[-1], ASHConfigEnvNotResolvedError), outcomes
    assert entry.error_message == "ASH exited with code 3"
    assert not _carries_probe([started_result, str(outcomes[-1]), entry.to_dict()])


def test_remote_workspace_project_config_is_refused(_server):
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    _write(_server["target"] / ".ash" / ".ash.yaml", UNTAGGED)
    workspace_file = _write(
        _server["scan_root"] / "dev.code-workspace",
        json.dumps({"folders": [{"path": "target"}]}),
    )

    result = asyncio.run(
        mcp_resolve_workspace(workspace_file=str(workspace_file), session_id=SESSION)
    )

    assert result["success"] is False, result
    assert result["error_type"] == ENV_REFUSED, result
    assert result["exit_code"] == 3
    assert not _carries_probe(result)


def test_remote_precheck_error_type_does_not_depend_on_the_environment(
    _server, monkeypatch
):
    # The value would make the base a file outside the config roots, which the
    # chain check refuses as config_input_not_permitted if it reads the value.
    monkeypatch.setenv(PROBE_VAR, "/etc/hostname")
    _write(_server["other"] / "b.yaml", "project_name: base\n")
    root = _write(
        _server["other"] / "x.yaml", f"extends: !ENV ${{{PROBE_VAR}:b.yaml}}\n"
    )

    direct, started = _scan_directory(_server["target"], root, SESSION)
    tool, tool_started = _run_ash_scan(
        source_dir=str(_server["target"]), config_path=str(root)
    )

    assert direct.get("error_type") == ENV_REFUSED, direct
    assert tool.get("error_type") == ENV_REFUSED, tool
    started.assert_not_called()
    tool_started.assert_not_called()


def test_remote_content_using_env_is_refused_and_local_content_is_not(_server):
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    content = f"extends: []\n{UNTAGGED}"

    remote = mcp_validate_config(config_content=content, session_id=SESSION)
    local = mcp_validate_config(config_content=content, session_id=None)

    assert [e["type"] for e in remote["errors"]] == [ENV_REFUSED], remote
    assert local["valid"] is True, local


def test_remote_operator_config_under_the_config_roots_resolves_env(_server):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    operator = _write(_server["operator"] / "ash.yaml", TAGGED)

    got = mcp_get_config(config_path=str(operator), session_id=SESSION)
    _, outcomes = _scan(_server["target"], operator, SESSION)

    _assert_read(got)
    assert isinstance(outcomes[-1], AshConfig), outcomes
    assert outcomes[-1].project_name == PROBE


# ---------------------------------------------------------------------------
# Raw get_config and the suppression writer
# ---------------------------------------------------------------------------


def test_raw_get_config_shows_an_operator_reference_as_written(_server):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    operator = _write(_server["operator"] / "ash.yaml", TAGGED)

    result = mcp_get_config(config_path=str(operator), raw=True, session_id=SESSION)

    assert result == {"project_name": f"${{{PROBE_VAR}:unset}}"}


def test_a_suppression_shaped_like_a_reference_is_written_literally(tmp_path):
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    config = _write(tmp_path / ".ash.yaml", "project_name: demo\n")
    reference = f"${{{PROBE_VAR}:why}}"

    add_suppression_to_config(
        config,
        AshSuppression(rule_id="B101", path=f"{reference}/a.py", reason=reference),
    )

    loaded = AshConfig.from_file(config).global_settings.suppressions[0]
    assert loaded.path == f"{reference}/a.py"
    assert loaded.reason == reference


# ---------------------------------------------------------------------------
# The server's own config keeps !ENV for a remote caller
# ---------------------------------------------------------------------------
#
# The remote rule reaches only the chains a client can influence. ASH_CONFIG and
# the registered profile behind a session are the operator's, wherever they are,
# so each is read with the default rule even outside ASH_MCP_ALLOWED_CONFIG_ROOTS.

MODE_VAR = "ASH_ENV_MODE_PROBE"
OPERATOR_TEXT = (
    f"project_name: !ENV ${{{PROBE_VAR}:unset}}\n"
    f"sandbox:\n  mode: !ENV ${{{MODE_VAR}:off}}\n"
)


def _outside_the_config_roots(path: Path) -> Path:
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
    )

    # The remote rule would refuse the file if it reached it.
    assert client_named_config_is_untrusted(path)
    return path


def test_an_operator_ash_config_resolves_env_for_a_remote_caller(_server, monkeypatch):
    from automated_security_helper.cli.mcp.profile_registry import (
        session_client_rules,
    )
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    server = _outside_the_config_roots(
        _write(_server["tmp"] / "server" / "ash.yaml", OPERATOR_TEXT)
    )
    monkeypatch.setenv("ASH_CONFIG", str(server))
    monkeypatch.setenv(MODE_VAR, "bwrap")
    empty = _server["scan_root"] / "empty"
    empty.mkdir()
    untrusted = _write(_server["other"] / "ash.yaml", "project_name: other\n")

    # As the default config: nothing found in the directory searched, and a scan
    # of a target with no config of its own.
    got = mcp_get_config(search_dir=str(empty), session_id=SESSION)
    _, default = _scan(_server["target"], None, SESSION)
    # As the trusted base a client's config is held to, and the policy source.
    _, held = _scan(_server["target"], untrusted, SESSION)

    _assert_read(got)
    assert isinstance(default[-1], AshConfig), default
    assert default[-1].project_name == PROBE
    assert isinstance(held[-1], AshConfig), held
    assert held[-1].project_name == "other"
    assert held[-1].sandbox.mode == "bwrap"
    assert session_client_rules(SESSION).unreadable is None


def test_the_registered_profile_behind_a_session_resolves_env_for_a_remote_caller(
    _server, monkeypatch
):
    import yaml

    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        resolve_session_config_path,
        resolve_session_trusted_config_path,
        session_client_rules,
        session_profile_entry,
        set_profile_registry,
    )
    from automated_security_helper.cli.mcp.sandbox import config_base_gate
    from automated_security_helper.cli.mcp_tools import (
        mcp_get_config,
        mcp_select_profile,
    )
    from automated_security_helper.config.client_config_policy import _trusted_config
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv(MODE_VAR, "bwrap")
    _write(_server["other"] / "client.yaml", "project_name: client\n")
    profile = _outside_the_config_roots(
        _write(
            _server["tmp"] / "profiles" / "op.yaml",
            OPERATOR_TEXT
            + yaml.safe_dump(
                {
                    "global_settings": {
                        "mcp": {
                            "runtime_overrides": {
                                "enabled": True,
                                "allowed_paths": ["/project_name"],
                            }
                        }
                    }
                }
            ),
        )
    )
    set_profile_registry(register_profiles([f"op={profile}"]))

    # Bound as registered: the session's config/ copy.
    assert mcp_select_profile("op", session_id=SESSION)["success"] is True
    copy = Path(resolve_session_config_path(SESSION))
    got = mcp_get_config(config_path=str(copy), session_id=SESSION)
    _, bound = _scan(_server["target"], copy, SESSION)

    _assert_read(got)
    assert isinstance(bound[-1], AshConfig), bound
    assert bound[-1].project_name == PROBE

    # Patched by the client: the copy is the client's, and the session's config/
    # copy of the registered profile is the trusted base it is held to.
    patched = mcp_select_profile(
        "op",
        patch_ops=[{"op": "replace", "path": "/project_name", "value": "patched"}],
        session_id=SESSION,
    )
    assert patched["success"] is True, patched
    trusted = resolve_session_trusted_config_path(SESSION)
    assert trusted is not None
    _, held = _scan(
        _server["target"], Path(resolve_session_config_path(SESSION)), SESSION
    )

    assert isinstance(held[-1], AshConfig), held
    assert held[-1].project_name == "patched"
    assert held[-1].sandbox.mode == "bwrap"
    assert session_profile_entry(SESSION).config.project_name == PROBE
    assert session_client_rules(SESSION).unreadable is None
    for base in (trusted, profile):
        # The trusted base as the trust checks read it, whichever operator file
        # it is: the config/ copy, or a registered profile that uses !ENV itself.
        trusted_config = _trusted_config(
            base, _server["target"], config_base_gate(SESSION)
        )
        assert trusted_config.project_name == PROBE
        assert trusted_config.sandbox.mode == "bwrap"
        resolved = resolve_config(
            config_path=_server["other"] / "client.yaml",
            source_dir=_server["target"],
            permit_base=config_base_gate(SESSION),
            trusted_config_path=base,
            untrusted_config=True,
            remote_client=True,
        )
        assert resolved.project_name == "client"
        assert resolved.sandbox.mode == "bwrap"


# ---------------------------------------------------------------------------
# A named file that extends a base using !ENV
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "text"),
    [("base.yaml", UNTAGGED), ("base.yaml", TAGGED), ("base.toml", TOML)],
    ids=["plain", "tagged", "toml"],
)
def test_remote_named_file_whose_base_uses_env_is_refused_everywhere(
    _server, name, text
):
    """The base resolves no !ENV for a remote caller: get_config, validate, scan."""
    from automated_security_helper.cli.mcp_tools import (
        mcp_get_config,
        mcp_validate_config,
    )

    _write(_server["other"] / name, text)
    root = _write(_server["other"] / "named.yaml", f"extends: {name}\n")

    got = mcp_get_config(config_path=str(root), session_id=SESSION)
    validated = mcp_validate_config(config_path=str(root), session_id=SESSION)
    entry, outcomes = _scan(_server["target"], root, SESSION)

    assert got.get("error_type") == ENV_REFUSED, got
    assert ENV_REFUSED in [e["type"] for e in validated["errors"]], validated
    assert isinstance(outcomes[-1], ASHConfigEnvNotResolvedError), outcomes
    assert not _carries_probe([got, validated, str(outcomes[-1]), entry.to_dict()])


def test_stdio_named_repo_file_whose_base_uses_env_resolves(stdio_repo):
    """The local user's own repository keeps !ENV in its bases too, as designed."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    _write(stdio_repo / ".ash" / "base.yaml", UNTAGGED)
    root = _write(stdio_repo / ".ash" / "named.yaml", "extends: base.yaml\n")

    got = mcp_get_config(config_path=str(root))

    _assert_read(got)
