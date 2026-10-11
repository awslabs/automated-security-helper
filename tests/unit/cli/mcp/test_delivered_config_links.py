# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file reached through a symlink is judged by every name it has.

``set_source_git`` clones a tree as it is, symlinks included, so a delivered
tree's ``.ash/.ash.yaml`` can be a link to a file outside the MCP workspace
root. Each file of a config's chain is judged by the name it was found or named
by, by each symlink followed on the way to it, and by the file it resolves to. A
file is a client's when any of those names is, and the repository's when any of
them is inside the scanned tree.

The trees here are delivered through the real ``set_source_git``, cloning a
local repository that holds the link. The scans go through the real
``_run_scan_async``, ``run_ash_scan`` and orchestrator, stopped after the config
is resolved.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.config.ash_config import AshConfig

SESSION = "client-1"

DENIED = "project_name: linked\nfail_on_findings: false\n"
SUPPRESSIONS = (
    "project_name: linked\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: 'tests/**'\n"
    "      reason: asserts in tests\n"
    "  ignore_paths:\n"
    "    - path: 'vendor/**'\n"
    "      reason: vendored code\n"
)
EXCLUSION = (
    "project_name: linked\n"
    "scanners:\n"
    "  bandit:\n"
    "    options:\n"
    "      excluded_paths:\n"
    "        - path: client-dir\n"
    "          reason: not ours\n"
)
#: Not a config at all: a host file whose text must not reach an error message.
NOT_A_CONFIG = "canary-text-5c1e9d2b on the first line\nsecond line\n"
CANARY = "canary-text-5c1e9d2b"
#: Not YAML: the parser's own message would quote this line.
YAML_CANARY = "canary-yaml-77aa31"
NOT_YAML = f"key: [unclosed {YAML_CANARY}\n"


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    workspace = tmp_path / "workspaces"
    host = tmp_path / "host"
    host.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_session_state()
    yield {"workspace": workspace, "host": host, "tmp": tmp_path}
    clear_profile_registry()
    clear_session_state()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create a symlink here: {exc}")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def _clone(tmp: Path, files: Dict[str, str], links: Dict[str, Path]) -> Path:
    """Deliver a tree holding ``files`` and ``links`` through the real git clone."""
    from automated_security_helper.cli.mcp.source_delivery import set_source_git

    origin = tmp / "origin"
    origin.mkdir()
    for name, text in files.items():
        _write(origin / name, text)
    for name, target in links.items():
        _symlink(origin / name, target)
    _git(origin, "init", "-q")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "tree")
    source = set_source_git(url=origin.as_uri(), session_id=SESSION)
    for name in links:
        assert (source / name).is_symlink(), f"the clone dropped the link {name}"
    return source


def _linked_tree(server: Dict[str, Path], text: str) -> Path:
    """A delivered tree whose ``.ash/.ash.yaml`` links to a host file holding ``text``."""
    host_file = _write(server["host"] / "ash.yaml", text)
    return _clone(server["tmp"], {"app.py": "x = 1\n"}, {".ash/.ash.yaml": host_file})


def _scan_resolution(target: Path) -> Any:
    """Start an MCP scan; return the config it resolved, or the error resolution raised."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    outcomes: List[Any] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> Any:
        try:
            outcomes.append(real(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 -- the outcome under test
            outcomes.append(exc)
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
                session_id=SESSION,
            )
        )
    assert outcomes, "the scan never reached config resolution"
    return outcomes[-1]


def _start_scan(target: Path) -> Dict[str, Any]:
    """Call the scan tool; the background scan itself is not started."""
    from automated_security_helper.cli import mcp_tools

    with patch.object(mcp_tools, "_run_scan_async", AsyncMock()) as started:
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(str(target), session_id=SESSION)
        )
    if result.get("success") is False:
        started.assert_not_called()
    return result


# ---------------------------------------------------------------------------
# The runtime-override policy
# ---------------------------------------------------------------------------


def test_a_linked_config_setting_a_denied_field_is_refused(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    source = _linked_tree(_server, DENIED)

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigFieldDeniedError), outcome
    assert "fail_on_findings" in str(outcome)


def test_the_scan_tool_refuses_a_linked_config_up_front(_server) -> None:
    source = _linked_tree(_server, DENIED)

    result = _start_scan(source)

    assert result.get("success") is False, result
    assert result.get("error_type") == "config_field_denied", result
    assert "fail_on_findings" in result.get("error", ""), result


def test_a_linked_config_widening_the_sandbox_is_refused(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    source = _linked_tree(
        _server,
        yaml.safe_dump(
            {
                "project_name": "linked",
                "sandbox": {"extra_read_paths": [str(_server["host"])]},
            }
        ),
    )

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigFieldDeniedError), outcome
    assert "sandbox.extra_read_paths" in str(outcome)


def test_positive_control_the_same_file_named_by_the_operator_is_not_refused(
    _server,
) -> None:
    """The refusals above come from how the file was reached, not from its text."""
    from automated_security_helper.config.resolve_config import resolve_config

    host_file = _write(_server["host"] / "ash.yaml", DENIED)
    elsewhere = _server["tmp"] / "elsewhere"
    elsewhere.mkdir()

    config = resolve_config(config_path=host_file, source_dir=elsewhere)

    assert config.fail_on_findings is False


# ---------------------------------------------------------------------------
# What the linked file hides is marked or moved
# ---------------------------------------------------------------------------


def test_a_linked_configs_suppressions_and_ignore_paths_are_marked(_server) -> None:
    source = _linked_tree(_server, SUPPRESSIONS)

    config = _scan_resolution(source)

    assert isinstance(config, AshConfig), config
    suppressions = config.global_settings.suppressions
    ignore_paths = config.global_settings.ignore_paths
    assert [entry.rule_id for entry in suppressions] == ["B101"]
    assert [entry.client_supplied for entry in suppressions] == [True]
    assert [entry.path for entry in ignore_paths] == ["vendor/**"]
    assert [entry.client_supplied for entry in ignore_paths] == [True]


def test_a_linked_configs_scanner_exclusion_is_moved_out_of_the_options(
    _server,
) -> None:
    source = _linked_tree(_server, EXCLUSION)

    config = _scan_resolution(source)

    assert isinstance(config, AshConfig), config
    options = config.get_plugin_config("scanner", "bandit")["options"]
    kept = [
        entry["path"] if isinstance(entry, dict) else entry
        for entry in options.get("excluded_paths") or []
    ]
    assert "client-dir" not in kept
    assert [
        (item.scanner, item.option, item.pattern)
        for item in config._client_scanner_exclusions
    ] == [("bandit", "excluded_paths", "client-dir")]


def test_a_linked_config_directory_is_judged_by_the_link(_server) -> None:
    """A symlinked ``.ash`` directory: the file sits in the host directory.

    The MCP scan refuses such a tree before it reads a config, because its
    output directory is under ``.ash``; any other resolve of the tree's config
    judges the file by the link.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    host_dir = _server["host"] / "configs"
    _write(host_dir / ".ash.yaml", DENIED)
    source = _clone(_server["tmp"], {"app.py": "x = 1\n"}, {".ash": host_dir})

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(source_dir=source)

    assert "fail_on_findings" in str(refused.value)
    # Named by the path in the delivered tree, not by the host file.
    assert str(host_dir) not in str(refused.value)


# ---------------------------------------------------------------------------
# A link crossed on the way to the file
# ---------------------------------------------------------------------------


def test_a_file_reached_through_a_delivered_link_is_the_clients(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The name a link sits at counts, not only the first name and the last."""
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
        config_is_client_supplied,
    )

    operator_dir = _server["tmp"] / "operator"
    operator_dir.mkdir()
    real = _write(operator_dir / "real.yaml", "project_name: real\n")
    source = _clone(_server["tmp"], {"app.py": "x = 1\n"}, {"hop.yaml": real})
    named = operator_dir / "ash.yaml"
    _symlink(named, source / "hop.yaml")

    assert config_is_client_supplied(named) is True
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator_dir))
    assert client_named_config_is_untrusted(named) is True
    # Positive control: the target named directly, and a link that stays in the
    # operator's directory, are the operator's.
    assert config_is_client_supplied(real) is False
    direct = operator_dir / "direct.yaml"
    _symlink(direct, real)
    assert config_is_client_supplied(direct) is False


# ---------------------------------------------------------------------------
# The error for a file that is not a config
# ---------------------------------------------------------------------------


def test_a_linked_file_that_is_not_a_config_is_not_quoted(_server) -> None:
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    source = _linked_tree(_server, NOT_A_CONFIG)

    outcome = _scan_resolution(source)

    assert isinstance(outcome, ASHConfigValidationError), outcome
    assert ".ash.yaml" in str(outcome)
    assert CANARY not in str(outcome)
    assert CANARY not in repr(outcome.args)


def test_a_linked_file_that_does_not_parse_is_not_quoted(_server) -> None:
    """The parser's message quotes the line it stopped at; the warning does not."""
    source = _linked_tree(_server, NOT_YAML)

    config = _scan_resolution(source)

    assert isinstance(config, AshConfig), config
    warnings = " ".join(config._resolution_warnings)
    assert "could not be parsed" in warnings, warnings
    assert ".ash.yaml" in warnings
    assert YAML_CANARY not in warnings


def test_the_scan_tool_does_not_quote_it_either(_server) -> None:
    source = _linked_tree(_server, NOT_A_CONFIG)

    result = _start_scan(source)

    assert CANARY not in repr(result)


def test_positive_control_an_operator_file_keeps_the_detailed_error(
    _server,
) -> None:
    """The operator's own file is reported with the validator's full detail."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    host_file = _write(_server["host"] / "ash.yaml", NOT_A_CONFIG)
    elsewhere = _server["tmp"] / "elsewhere"
    elsewhere.mkdir()

    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(config_path=host_file, source_dir=elsewhere)

    assert CANARY in str(raised.value)
