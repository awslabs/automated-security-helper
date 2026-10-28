# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file an MCP client delivered does not resolve ``!ENV``.

``!ENV`` reads the environment of the process loading the config, and under the
MCP server that is the server's. A file in a delivered tree, an upload named as
``config_path`` and ``validate_config``'s ``config_content`` are written by the
client, so such a file is refused with ``ASHConfigEnvNotResolvedError`` if it uses
``!ENV`` at all, before anything is read from the environment. See "Environment
variables" in ``config/config_sources.py``. Operator configs, and repository
configs scanned from the CLI, resolve ``!ENV`` as before.

Every test sets ``ASH_ENV_PROBE`` in the server's environment and checks that its
value appears in nothing the tools return. The name has the ``ASH_`` prefix, so
the interpolation allowlist in ``core/constants.py`` admits it: what refuses it
here is where the file came from, not its name.

The scans go through the real ``_run_scan_async``, ``run_ash_scan`` and
orchestrator. ``resolve_config`` is wrapped so that a config it returns stops the
scan before any scanner runs, and an error it raises is recorded and re-raised.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import exceptions as _exceptions

SESSION = "client-1"
PROBE_VAR = "ASH_ENV_PROBE"
PROBE = "probe-value-7f3a"
TAGGED = f"project_name: !ENV ${{{PROBE_VAR}:unset}}\n"
# The implicit resolver tags a plain scalar of this shape as !ENV without the tag.
UNTAGGED = f"project_name: ${{{PROBE_VAR}:unset}}\n"
ENV_REFUSED = "config_env_not_resolved"
#: The refusal's own words (config_sources._environment_read_refusal): given
#: before any reference is resolved, so it quotes no value and is the same
#: whether or not the variable is set.
REFUSAL_TEXT = (
    "reads a value from the environment (an !ENV tag or a ${VAR} reference), "
    "which a config an MCP client delivered may not, so the file is refused"
)
#: What raw get_config shows for a value the loader would read from the
#: environment: the reference as written, marked (mcp_tools.ENV_VALUE_PREFIX).
#: Raw mode asks for a document, not a run, so it judges nothing and reads
#: nothing from the environment.
AS_WRITTEN = f"!ENV ${{{PROBE_VAR}:unset}}"

#: Looked up rather than imported so that, against a tree without the class, each
#: test fails on its own instead of the module failing to collect.
ASHConfigEnvNotResolvedError = getattr(
    _exceptions,
    "ASHConfigEnvNotResolvedError",
    type("ASHConfigEnvNotResolvedErrorMissing", (Exception,), {}),
)


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A server with a workspace root, a scan root, an operator config root, and
    ``ASH_ENV_PROBE`` set in its environment."""
    workspace = tmp_path / "workspaces"
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE)
    clear_profile_registry()
    clear_all_session_state()
    yield {
        "workspace": workspace,
        "target": target,
        "operator": operator,
        "tmp": tmp_path,
    }
    clear_profile_registry()
    clear_all_session_state()


def _upload(files: Dict[str, str]) -> Path:
    """Deliver ``files`` through the real chunked zip upload; return the source dir."""
    from automated_security_helper.cli.mcp.source_delivery import (
        set_source_zip_chunk,
        set_source_zip_finalize,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    data = buffer.getvalue()
    set_source_zip_chunk(
        "u1", 0, base64.b64encode(data).decode("ascii"), True, session_id=SESSION
    )
    return set_source_zip_finalize(
        "u1", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )


def _ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": SESSION}
    ctx.info = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _get_config(config_path: Path, raw: bool = False) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_server

    return asyncio.run(
        mcp_server.get_config(_ctx(), config_path=str(config_path), raw=raw)
    )


def _validate_config(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_server

    return mcp_server.validate_config(_ctx(), **kwargs)


def _scan(target: Path, config_path: Optional[str] = None) -> Tuple[Any, List[Any]]:
    """Run an MCP scan of ``target``; return its registry entry and what
    ``resolve_config`` returned or raised, in call order."""
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
                config_path=config_path,
                session_id=SESSION,
            )
        )
    assert outcomes, "the scan never reached config resolution"
    return registry.get_scan(scan_id), outcomes


def _assert_refused_scan(entry: Any, outcomes: List[Any], named: str) -> None:
    """The scan stopped on the refusal, as an invalid config (exit 3)."""
    assert isinstance(outcomes[-1], ASHConfigEnvNotResolvedError), outcomes
    message = str(outcomes[-1])
    assert named in message
    assert REFUSAL_TEXT in message
    assert PROBE not in message
    # The code, then the text the CLI showed for the refusal
    # (mcp_tools._exit_message).
    assert entry.error_message.startswith("ASH exited with code 3"), entry.to_dict()
    assert PROBE not in json.dumps(entry.to_dict(), default=str)


def _assert_carries_no_probe(result: Any) -> None:
    assert PROBE not in json.dumps(result, default=str)


# ---------------------------------------------------------------------------
# A delivered tree's own .ash/.ash.yaml
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", [TAGGED, UNTAGGED], ids=["tagged", "untagged"])
def test_a_delivered_tree_config_using_env_refuses_the_scan(_server, text, capsys):
    source = _upload({".ash/.ash.yaml": text, "app.py": "x = 1\n"})

    entry, outcomes = _scan(source)

    _assert_refused_scan(entry, outcomes, ".ash/.ash.yaml")
    assert PROBE not in capsys.readouterr().out


@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
@pytest.mark.parametrize("text", [TAGGED, UNTAGGED], ids=["tagged", "untagged"])
def test_get_config_returns_nothing_from_the_environment(_server, text, raw):
    source = _upload({".ash/.ash.yaml": text})

    result = _get_config(source / ".ash" / ".ash.yaml", raw=raw)

    if raw:
        # The document as written, the reference marked and never read: the
        # plain scalar the loader would tag !ENV comes back marked too.
        assert result == {"project_name": AS_WRITTEN}, result
    else:
        assert result.get("error_type") == ENV_REFUSED, result
        assert ".ash/.ash.yaml" in result["error"]
    _assert_carries_no_probe(result)


def test_a_delivered_json_config_is_read_without_interpolation(_server):
    # JSON never had !ENV: a value shaped like a reference stays a string.
    reference = f"${{{PROBE_VAR}:unset}}"
    source = _upload({"ash.json": json.dumps({"project_name": reference})})

    result = _get_config(source / "ash.json")

    assert result["project_name"] == reference


@pytest.mark.parametrize("text", [TAGGED, UNTAGGED], ids=["tagged", "untagged"])
def test_validate_config_reports_the_refusal(_server, text):
    source = _upload({".ash/.ash.yaml": text})

    result = _validate_config(config_path=str(source / ".ash" / ".ash.yaml"))

    assert result["valid"] is False
    assert [e["type"] for e in result["errors"]] == [ENV_REFUSED], result
    _assert_carries_no_probe(result)


def test_a_delivered_toml_config_is_refused_naming_the_key(_server):
    source = _upload(
        {
            ".ashrc.toml": (
                'project_name = "delivered"\n'
                "[global_settings]\n"
                f'ignore_paths = ["${{{PROBE_VAR}:unset}}"]\n'
            )
        }
    )

    entry, outcomes = _scan(source)

    # Refused on the file's text, before the TOML is parsed into keys
    # (config_sources.parse_config_text), so the refusal names the file and no
    # key or value: the same words whether or not the variable is set.
    _assert_refused_scan(entry, outcomes, ".ashrc.toml")
    raw = _get_config(source / ".ashrc.toml", raw=True)
    # Raw mode judges nothing: the table as written, the one string the loader
    # would resolve marked, in its place (mcp_tools._mark_toml_references).
    assert raw == {
        "project_name": "delivered",
        "global_settings": {"ignore_paths": [AS_WRITTEN]},
    }, raw
    _assert_carries_no_probe(raw)


def test_a_delivered_base_using_env_is_refused(_server):
    source = _upload(
        {
            ".ash/.ash.yaml": "extends: base.yaml\nfail_on_findings: false\n",
            ".ash/base.yaml": TAGGED,
        }
    )

    entry, outcomes = _scan(source)

    _assert_refused_scan(entry, outcomes, "base.yaml")


def _run_ash_scan(**kwargs: Any) -> Tuple[Dict[str, Any], AsyncMock]:
    """Call the run_ash_scan tool with the scan itself stubbed out."""
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


def test_run_ash_scan_refuses_a_delivered_tree_before_starting(_server):
    source = _upload({".ash/.ash.yaml": TAGGED, "app.py": "x = 1\n"})

    result, started = _run_ash_scan(source_dir=str(source))

    assert result["success"] is False
    assert result["error_type"] == ENV_REFUSED, result
    assert ".ash/.ash.yaml" in result["error"]
    _assert_carries_no_probe(result)
    started.assert_not_called()


def test_run_ash_scan_refuses_an_uploaded_config_path_before_starting(_server):
    source = _upload({"ash.yaml": TAGGED})

    result, started = _run_ash_scan(
        source_dir=str(_server["target"]), config_path=str(source / "ash.yaml")
    )

    assert result["error_type"] == ENV_REFUSED, result
    _assert_carries_no_probe(result)
    started.assert_not_called()


def test_run_ash_scan_still_starts_for_a_delivered_tree_without_env(_server):
    source = _upload({".ash/.ash.yaml": "project_name: delivered\n"})

    result, started = _run_ash_scan(source_dir=str(source))

    assert result["success"] is True, result
    started.assert_called_once()


# ---------------------------------------------------------------------------
# An upload named as config_path
# ---------------------------------------------------------------------------


def test_an_uploaded_config_path_using_env_refuses_the_scan(_server):
    source = _upload({"ash.yaml": TAGGED})

    entry, outcomes = _scan(_server["target"], str(source / "ash.yaml"))

    _assert_refused_scan(entry, outcomes, "ash.yaml")


def test_an_uploaded_config_path_is_refused_by_get_and_validate(_server):
    source = _upload({"ash.yaml": TAGGED})

    got = _get_config(source / "ash.yaml")
    validated = _validate_config(config_path=str(source / "ash.yaml"))

    assert got["error_type"] == ENV_REFUSED, got
    assert [e["type"] for e in validated["errors"]] == [ENV_REFUSED], validated
    _assert_carries_no_probe([got, validated])


def test_validate_config_content_using_env_is_refused(_server):
    # extends sends the content through the chain reader too, which is the reader
    # that resolves; the file's own keys are read by the validator itself.
    content = f"extends: []\n{UNTAGGED}"

    result = _validate_config(config_content=content)

    assert result["valid"] is False
    assert [e["type"] for e in result["errors"]] == [ENV_REFUSED], result
    _assert_carries_no_probe(result)


# ---------------------------------------------------------------------------
# A symlink cannot change the answer
# ---------------------------------------------------------------------------


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")


def test_a_delivered_symlink_to_a_host_file_is_refused(_server):
    # In a directory the operator set aside, so the scan reads it: a link to a
    # file anywhere else is refused before it is read
    # (test_delivered_config_links.py). The link still makes it the client's.
    host = _server["operator"] / "ash.yaml"
    host.write_text(TAGGED, encoding="utf-8")
    source = _upload({"app.py": "x = 1\n"})
    # A zip upload refuses symlinks; a git clone keeps them, so a delivered tree
    # can hold one. Planted after the upload to stand in for that.
    _symlink(source / ".ash" / ".ash.yaml", host)

    entry, outcomes = _scan(source)

    _assert_refused_scan(entry, outcomes, ".ash/.ash.yaml")
    assert host.as_posix() not in str(outcomes[-1])


def test_client_supplied_is_judged_on_both_the_name_and_the_target(_server):
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    host = _server["tmp"] / "host" / "ash.yaml"
    host.parent.mkdir()
    host.write_text("project_name: host\n", encoding="utf-8")
    source = _upload({"ash.yaml": "project_name: delivered\n"})

    into_host = source / "link-out.yaml"
    _symlink(into_host, host)
    into_sandbox = _server["tmp"] / "elsewhere" / "link-in.yaml"
    _symlink(into_sandbox, source / "ash.yaml")

    assert config_is_client_supplied(into_host)
    assert config_is_client_supplied(into_sandbox)
    assert not config_is_client_supplied(host)


def test_the_name_may_spell_the_workspace_root_as_configured(_server, monkeypatch):
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    source = _upload({"app.py": "x = 1\n"})
    host = _server["tmp"] / "host" / "ash.yaml"
    host.parent.mkdir()
    host.write_text("project_name: host\n", encoding="utf-8")
    _symlink(source / "link-out.yaml", host)
    alias = _server["tmp"] / "alias"
    _symlink(alias, _server["workspace"])
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(alias))

    named = alias / source.relative_to(_server["workspace"]) / "link-out.yaml"
    assert config_is_client_supplied(named)


# ---------------------------------------------------------------------------
# Operator configs are unchanged
# ---------------------------------------------------------------------------


def test_an_operator_config_outside_the_workspace_resolves_env(_server):
    from automated_security_helper.config.resolve_config import resolve_config

    operator = _server["operator"] / "ash.yaml"
    operator.write_text(TAGGED, encoding="utf-8")

    assert resolve_config(config_path=operator).project_name == PROBE
    _, outcomes = _scan(_server["target"], str(operator))
    assert isinstance(outcomes[-1], AshConfig), outcomes
    assert outcomes[-1].project_name == PROBE


def test_a_repository_config_scanned_from_the_cli_resolves_env(_server):
    from automated_security_helper.config.resolve_config import resolve_config

    config = _server["target"] / ".ash" / ".ash.yaml"
    config.parent.mkdir()
    config.write_text(UNTAGGED, encoding="utf-8")

    resolved = resolve_config(source_dir=_server["target"])

    assert resolved.project_name == PROBE


# ---------------------------------------------------------------------------
# A client value saved into the session's config is not re-read as !ENV
# ---------------------------------------------------------------------------


def test_a_patched_profile_value_is_saved_and_read_back_literally(_server):
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = _server["operator"] / "profile.yaml"
    profile.write_text(
        yaml.safe_dump(
            {
                "project_name": "operator",
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "enabled": True,
                            "allowed_paths": ["/project_name"],
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"op={profile}"]))
    reference = f"${{{PROBE_VAR}:unset}}"

    bound = mcp_select_profile(
        "op",
        patch_ops=[{"op": "replace", "path": "/project_name", "value": reference}],
        session_id=SESSION,
    )
    assert bound["success"] is True, bound
    path = resolve_session_config_path(SESSION)
    assert path is not None

    result = _get_config(Path(path))

    assert result["project_name"] == reference
    _assert_carries_no_probe(result)


def test_save_round_trips_a_value_shaped_like_a_reference(tmp_path):
    reference = f"${{{PROBE_VAR}:unset}}"
    path = tmp_path / "saved.yaml"

    AshConfig(project_name=reference).save(path)

    assert AshConfig.from_file(path).project_name == reference
