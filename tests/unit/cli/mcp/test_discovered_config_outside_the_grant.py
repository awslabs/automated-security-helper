# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config source discovery finds is checked against the caller's grant before it is opened.

A delivered tree can hold a ``pyproject.toml`` (or a dedicated config name, or a
``.ash`` directory) that is a symbolic link to a file anywhere on the server.
Discovery used to open such a link to look for a ``[tool.ash]`` table, so the
answer a remote client got told it whether the target existed and could be read:
a missing target and an unreadable one each refused the scan (exit 3, with the
errno in the message), and a readable one scanned.

Under a permit predicate -- the MCP server's ``config_base_gate`` -- discovery
checks every candidate that exists by the path it resolves to, before anything
opens it, and refuses one outside the grant with a message that names the
candidate as found and reads the same whatever the target is. Without a
predicate (the CLI) discovery is unchanged.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
)
from automated_security_helper.config import config_sources
from automated_security_helper.core.exceptions import ASHConfigInputNotPermittedError
from tests.utils.open_audit import record_opens

pytestmark = pytest.mark.unit

_SESSION = "client-one"
_MARKER = "TARGET-CONTENT-MARKER"
_REFUSED = "config_input_not_permitted"
TARGETS = ["missing", "unreadable", "readable"]


@pytest.fixture(autouse=True)
def _clean_policy_env(monkeypatch, tmp_path):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


class _Tree:
    """A granted scan root, a granted config root, and targets outside both."""

    def __init__(self, tmp_path: Path) -> None:
        self.scan = tmp_path / "scan"
        self.scan.mkdir()
        (self.scan / "app.py").write_text("x = 1\n", encoding="utf-8")
        self.grant = tmp_path / "policies" / ".ash"
        self.grant.mkdir(parents=True)
        self.elsewhere = tmp_path / "elsewhere"
        self.elsewhere.mkdir()
        table = f'[tool.ash]\nproject_name = "{_MARKER}"\n'
        self.targets = {
            "missing": self.elsewhere / "missing.toml",
            "unreadable": self.elsewhere / "unreadable.toml",
            "readable": self.elsewhere / "readable.toml",
        }
        self.targets["unreadable"].write_text(table, encoding="utf-8")
        self.targets["unreadable"].chmod(0)
        self.targets["readable"].write_text(table, encoding="utf-8")

    def link(self, target: str, name: str = "pyproject.toml") -> Path:
        link = self.scan / name
        if os.path.lexists(link):
            link.unlink()
        link.symlink_to(self.targets[target])
        return link

    def restore(self) -> None:
        self.targets["unreadable"].chmod(0o644)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    t = _Tree(tmp_path)
    monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(t.grant))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(t.scan))
    yield t
    t.restore()


def _record_opens(monkeypatch) -> List[Path]:
    """Every path opened while the test runs, by any route (the audit hook)."""
    return record_opens(monkeypatch, with_flags=False)


def _gate():
    return sandbox.config_base_gate(_SESSION)


def _run(coro):
    return asyncio.run(coro)


class TestDiscoveryChecksEachCandidateBeforeOpeningIt:
    @pytest.mark.parametrize("target", TARGETS)
    def test_a_candidate_reaching_outside_the_grant_is_refused_unopened(
        self, tree, monkeypatch, target
    ):
        link = tree.link(target)
        opened = _record_opens(monkeypatch)

        with pytest.raises(ASHConfigInputNotPermittedError):
            config_sources.discover_config_source(tree.scan, permit=_gate())

        assert link not in opened

    def test_the_refusal_reads_the_same_whatever_the_target_is(self, tree):
        messages = set()
        for target in TARGETS:
            tree.link(target)
            with pytest.raises(ASHConfigInputNotPermittedError) as excinfo:
                config_sources.discover_config_source(tree.scan, permit=_gate())
            messages.add(str(excinfo.value))

        assert len(messages) == 1, messages
        (message,) = messages
        assert "pyproject.toml" in message
        assert "Errno" not in message
        assert str(tree.elsewhere) not in message

    def test_a_candidate_behind_the_selected_source_is_checked_too(self, tree):
        """The ignored sources are reported, and a pyproject.toml's label reads it."""
        (tree.scan / ".ash.yaml").write_text("project_name: x\n", encoding="utf-8")
        tree.link("readable")

        with pytest.raises(ASHConfigInputNotPermittedError):
            config_sources.discover_config_source(tree.scan, permit=_gate())

    def test_a_dedicated_name_reaching_outside_the_grant_is_refused(self, tree):
        tree.targets["elsewhere.yaml"] = tree.elsewhere / "elsewhere.yaml"
        tree.targets["elsewhere.yaml"].write_text("project_name: x\n", encoding="utf-8")
        tree.link("elsewhere.yaml", name=".ash.yaml")

        with pytest.raises(ASHConfigInputNotPermittedError, match=r"\.ash\.yaml"):
            config_sources.discover_config_source(tree.scan, permit=_gate())

    @pytest.mark.parametrize("holds", ["a-config", "nothing", "unsearchable"])
    def test_a_linked_ash_directory_is_refused_whatever_it_holds(self, tree, holds):
        """Looking inside it would tell the client whether a file there exists."""
        outside = tree.elsewhere / "dot-ash"
        outside.mkdir()
        if holds == "a-config":
            (outside / ".ash.yaml").write_text("project_name: x\n", encoding="utf-8")
        (tree.scan / ".ash").symlink_to(outside)
        if holds == "unsearchable":
            outside.chmod(0)
        try:
            with pytest.raises(ASHConfigInputNotPermittedError) as excinfo:
                config_sources.discover_config_source(tree.scan, permit=_gate())
        finally:
            outside.chmod(0o755)

        assert "Errno" not in str(excinfo.value)
        assert str(outside) not in str(excinfo.value)

    def test_on_windows_a_candidate_linked_to_a_share_is_refused_unresolved(
        self, tree, monkeypatch
    ):
        """Resolving a link on Windows can open a connection to the host a UNC
        target names, so under a permit a source linked to a share is refused,
        not resolved, as an extends base outside the root is."""
        inside = tree.scan / "real.toml"
        inside.write_text('[tool.ash]\nproject_name = "x"\n', encoding="utf-8")
        (tree.scan / "pyproject.toml").symlink_to(inside)
        monkeypatch.setattr(config_sources, "_on_windows", lambda: True)
        real_readlink = os.readlink

        def readlink(path, *args, **kwargs):
            if Path(os.fspath(path)) == tree.scan / "pyproject.toml":
                return "\\\\server\\share\\pyproject.toml"
            return real_readlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "readlink", readlink)
        resolved = []
        real_realpath = os.path.realpath

        def recording_realpath(path, *args, **kwargs):
            resolved.append(Path(path))
            return real_realpath(path, *args, **kwargs)

        monkeypatch.setattr(os.path, "realpath", recording_realpath)

        with pytest.raises(ASHConfigInputNotPermittedError):
            config_sources.discover_config_source(tree.scan, permit=_gate())

        assert tree.scan / "pyproject.toml" not in resolved

    def test_control_on_windows_a_plain_candidate_is_still_checked_and_used(
        self, tree, monkeypatch
    ):
        (tree.scan / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "x"\n', encoding="utf-8"
        )
        monkeypatch.setattr(config_sources, "_on_windows", lambda: True)

        discovery = config_sources.discover_config_source(tree.scan, permit=_gate())

        assert discovery.selected.path == tree.scan / "pyproject.toml"

    def test_on_windows_a_candidate_linked_to_a_local_file_inside_the_grant_is_used(
        self, tree, monkeypatch
    ):
        """A link whose chain stays on local names is resolved and judged by the
        permit as the file it names, so one that stays inside the grant is
        discovered."""
        inside = tree.scan / "real.toml"
        inside.write_text('[tool.ash]\nproject_name = "x"\n', encoding="utf-8")
        (tree.scan / "pyproject.toml").symlink_to(inside)
        monkeypatch.setattr(config_sources, "_on_windows", lambda: True)

        discovery = config_sources.discover_config_source(tree.scan, permit=_gate())

        assert discovery.selected.path == tree.scan / "pyproject.toml"

    def test_control_a_candidate_inside_the_grant_is_discovered(self, tree):
        (tree.scan / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "in-tree"\n', encoding="utf-8"
        )

        discovery = config_sources.discover_config_source(tree.scan, permit=_gate())

        assert discovery.selected.path == tree.scan / "pyproject.toml"

    def test_control_without_a_gate_discovery_is_unchanged(self, tree):
        tree.link("readable")

        discovery = config_sources.discover_config_source(tree.scan)

        assert discovery.selected.path == tree.scan / "pyproject.toml"


class TestResolutionDiscoversUnderTheGate:
    """resolve_config's own discovery, for a caller that passes permit_base directly."""

    @pytest.mark.parametrize("target", TARGETS)
    def test_discovery_with_no_config_named_is_refused_unopened(
        self, tree, monkeypatch, target
    ):
        from automated_security_helper.config.resolve_config import resolve_config

        link = tree.link(target)
        opened = _record_opens(monkeypatch)

        with pytest.raises(ASHConfigInputNotPermittedError) as excinfo:
            resolve_config(source_dir=tree.scan, permit_base=_gate())

        assert link not in opened
        assert _MARKER not in str(excinfo.value)

    def test_the_ignored_sources_of_a_named_config_are_found_under_the_gate(
        self, tree, monkeypatch
    ):
        """A named config at a discovery location gets the sources discovery would
        ignore reported; finding them must not open one outside the grant."""
        from automated_security_helper.config.resolve_config import resolve_config

        named = tree.scan / ".ash.yaml"
        named.write_text("project_name: in-tree\n", encoding="utf-8")
        link = tree.link("readable")
        opened = _record_opens(monkeypatch)

        config = resolve_config(
            config_path=named, source_dir=tree.scan, permit_base=_gate()
        )

        assert config.project_name == "in-tree"
        assert link not in opened
        assert not any("pyproject" in str(w) for w in config._resolution_warnings)


def _ctx(session_id: str = _SESSION) -> MagicMock:
    from unittest.mock import AsyncMock

    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session_id}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


class TestGetConfigDiscoversUnderTheGate:
    """get_config with no config_path discovers in the server's working directory."""

    @pytest.mark.parametrize("raw", [True, False])
    def test_the_response_is_the_same_whatever_the_target_is(
        self, tree, monkeypatch, raw
    ):
        from automated_security_helper.cli import mcp_server

        monkeypatch.chdir(tree.scan)
        opened = _record_opens(monkeypatch)
        responses = []
        for target in TARGETS:
            link = tree.link(target)
            opened.clear()
            result = _run(mcp_server.get_config(_ctx(), raw=raw))
            assert link not in opened, target
            responses.append(json.dumps(result, sort_keys=True, default=str))

        assert len(set(responses)) == 1, responses
        result = json.loads(responses[0])
        assert result["success"] is False
        assert result["error_type"] == _REFUSED
        assert _MARKER not in responses[0]
        assert "Errno" not in responses[0]

    def test_control_a_source_inside_the_grant_is_returned(self, tree, monkeypatch):
        from automated_security_helper.cli import mcp_server

        (tree.scan / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "in-tree"\n', encoding="utf-8"
        )
        monkeypatch.chdir(tree.scan)

        result = _run(mcp_server.get_config(_ctx(), raw=True))

        assert result["project_name"] == "in-tree", result


class TestScanDirectoryRefusesBeforeTheScanStarts:
    def _scan(self, tree) -> Dict[str, Any]:
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        with patch(
            "automated_security_helper.cli.mcp_tools._run_scan_async"
        ) as started:
            result = _run(
                mcp_scan_directory(directory_path=str(tree.scan), session_id=_SESSION)
            )
        result["_started"] = started.called
        return result

    def test_the_response_is_the_same_whatever_the_target_is(self, tree):
        responses = []
        for target in TARGETS:
            tree.link(target)
            result = self._scan(tree)
            responses.append(
                (
                    result["success"],
                    result.get("error_type"),
                    result.get("error"),
                    result["_started"],
                )
            )

        assert len(set(responses)) == 1, responses
        success, error_type, error, started = responses[0]
        assert success is False
        assert error_type == _REFUSED
        assert started is False
        assert _MARKER not in json.dumps(responses)
        assert "Errno" not in error

    def test_control_a_tree_whose_config_is_inside_the_grant_starts_the_scan(
        self, tree
    ):
        (tree.scan / ".ash.yaml").write_text(
            "project_name: in-tree\n", encoding="utf-8"
        )

        result = self._scan(tree)

        assert result["success"] is True, result
        assert result["_started"] is True


class TestTheScanRunnerDiscoversUnderTheGate:
    """run_ash_scan's own discovery, for a caller that did not go through the MCP tool."""

    def _opts(self, tree):
        from automated_security_helper.interactions import run_ash_scan as ras

        return ras.ScanOptions(
            source_dir=tree.scan,
            output_dir=tree.scan / ".ash" / "ash_output",
            config_base_gate=_gate(),
        )

    @pytest.mark.parametrize("target", TARGETS)
    def test_the_exit_code_readers_do_not_open_it(self, tree, monkeypatch, target):
        from automated_security_helper.interactions import run_ash_scan as ras

        link = tree.link(target)
        opened = _record_opens(monkeypatch)

        assert ras._load_config_file(self._opts(tree)) is None
        assert link not in opened

    def test_the_workspace_settings_reader_refuses_it(self, tree):
        from automated_security_helper.interactions import run_ash_scan as ras

        tree.link("readable")

        with pytest.raises(ASHConfigInputNotPermittedError):
            ras._resolve_workspace_execution_config(self._opts(tree))

    @pytest.mark.parametrize("target", TARGETS)
    def test_the_scan_exits_3_before_the_orchestrator_is_built(
        self, tree, monkeypatch, target
    ):
        from automated_security_helper.interactions import run_ash_scan as ras

        link = tree.link(target)
        opened = _record_opens(monkeypatch)

        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        # The run resolves its config once, inside the orchestrator it builds
        # (run_ash_scan._run_local_mode); the refusal must come from that
        # resolution, before any scanner runs.
        with (
            patch.object(ASHScanOrchestrator, "execute_scan") as execute_scan,
            pytest.raises(SystemExit) as excinfo,
        ):
            ras._run_local_mode(self._opts(tree), MagicMock())

        assert excinfo.value.code == 3
        execute_scan.assert_not_called()
        assert link not in opened
