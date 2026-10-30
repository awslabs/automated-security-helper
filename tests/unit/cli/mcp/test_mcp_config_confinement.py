# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP tools confine every path they read or write to the session's allowed roots.

Two rules are pinned here.

1. Every file in a config's ``extends`` chain is checked with the same rule as a
   config path the caller names directly (``sandbox.validate_config_input``).
   ``config_sources`` confines a chain to the directory of the root config, or
   to the parent of ``.ash/`` for a file in ``.ash/``. That is the CLI rule and it
   is unchanged. Under MCP the session's grant is passed into resolution as well,
   so a grant naming a ``.ash/`` directory confines the chain to that directory.

2. Every MCP tool parameter that names a path or a local clone URL goes through
   the session's allowed roots before anything is read, written, or cloned.
   ``TestEveryPathParameterIsAudited`` lists those parameters from the live tool
   registration, so a new path-taking parameter fails the suite until it is
   added to ``_AUDITED`` with a refusal case.

Refusals use a stable ``error_type``, carry nothing from the refused file, and
read the same whether or not the refused file exists.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp import sandbox
from tests.utils.scan_task_stubs import end_the_scans_scope_as_its_task_would
from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core import exceptions as _exceptions

pytestmark = pytest.mark.unit

_SESSION = "client-one"
_OUTSIDE_MARKER = "OUTSIDE-THE-GRANT-MARKER"
_CONFIG_REFUSED = "config_input_not_permitted"

#: Looked up rather than imported so that, against a tree without the class, each
#: test fails on its own instead of the module failing to collect.
ASHConfigInputNotPermittedError = getattr(
    _exceptions,
    "ASHConfigInputNotPermittedError",
    type("ASHConfigInputNotPermittedErrorMissing", (Exception,), {}),
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_policy_env(monkeypatch, tmp_path):
    """No grant, stdio, and a workspace root this test owns.

    Same shape as ``test_session_sandbox``: ``setenv`` rather than ``delenv`` for
    the transport so monkeypatch records an undo for it.
    """
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


class _Layout:
    """A granted ``.ash/`` config root, a granted scan root, and files outside both."""

    def __init__(self, tmp_path: Path) -> None:
        self.policies = tmp_path / "policies"
        self.grant = self.policies / ".ash"
        self.grant.mkdir(parents=True)
        self.scan = tmp_path / "scan"
        self.scan.mkdir()
        (self.scan / "app.py").write_text("x = 1\n", encoding="utf-8")

        # Beside the granted .ash/ directory: inside #712's default confinement
        # root (the parent of .ash/), outside the grant.
        self.sibling = self.policies / "outside.yaml"
        self.sibling.write_text(f"project_name: {_OUTSIDE_MARKER}\n", encoding="utf-8")

        # Outside every root, and outside #712's root too.
        self.elsewhere = tmp_path / "elsewhere"
        self.elsewhere.mkdir()
        self.far = self.elsewhere / "far.yaml"
        self.far.write_text(f"project_name: {_OUTSIDE_MARKER}\n", encoding="utf-8")

        self.config = self.grant / ".ash.yaml"
        self.in_grant_base = self.grant / "base.yaml"
        self.in_grant_base.write_text("project_name: in-grant-base\n", encoding="utf-8")

    def write_config(self, extends: str) -> Path:
        self.config.write_text(
            f"extends: {json.dumps(extends)}\nfail_on_findings: false\n",
            encoding="utf-8",
        )
        return self.config


@pytest.fixture
def layout(tmp_path, monkeypatch) -> _Layout:
    lay = _Layout(tmp_path)
    monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(lay.grant))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(lay.scan))
    return lay


def _ctx(session_id: str = _SESSION) -> MagicMock:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": session_id}
    ctx.info = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _run(coro):
    return asyncio.run(coro)


def _assert_carries_nothing_from(result: Any) -> None:
    assert _OUTSIDE_MARKER not in json.dumps(result, default=str)


# ---------------------------------------------------------------------------
# 1. The extends chain, at the resolution layer
# ---------------------------------------------------------------------------


class TestExtendsChainUnderAnMcpGrant:
    """Each chain file passes ``validate_config_input`` for the calling session."""

    @pytest.mark.parametrize(
        "spelling",
        ["sibling", "parent", "beyond_cli_root", "absolute"],
    )
    def test_a_base_outside_the_grant_is_refused(self, layout, spelling):
        # "beyond_cli_root" leaves #712's root as well as the grant, so it is
        # caught by the lexical check before resolve(). That is also the path an
        # absolute ref takes on Windows; both must report the same refusal.
        extends = {
            "sibling": "../outside.yaml",
            "parent": "../../policies/outside.yaml",
            "beyond_cli_root": "../../elsewhere/far.yaml",
            "absolute": str(layout.far),
        }[spelling]
        cfg = layout.write_config(extends)

        with pytest.raises(ASHConfigInputNotPermittedError) as excinfo:
            resolve_config(
                config_path=cfg,
                source_dir=layout.scan,
                permit_base=sandbox.config_base_gate(_SESSION),
            )
        assert _OUTSIDE_MARKER not in str(excinfo.value)

    def test_a_base_reached_through_a_symlink_is_refused(self, layout):
        link = layout.grant / "linked.yaml"
        try:
            link.symlink_to(layout.sibling)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available on this platform")
        cfg = layout.write_config("linked.yaml")

        with pytest.raises(ASHConfigInputNotPermittedError):
            resolve_config(
                config_path=cfg,
                source_dir=layout.scan,
                permit_base=sandbox.config_base_gate(_SESSION),
            )

    def test_a_base_inside_the_grant_still_resolves(self, layout):
        cfg = layout.write_config("base.yaml")

        config = resolve_config(
            config_path=cfg,
            source_dir=layout.scan,
            permit_base=sandbox.config_base_gate(_SESSION),
        )
        assert config.project_name == "in-grant-base"

    def test_a_nested_base_is_checked_too(self, layout):
        (layout.grant / "middle.yaml").write_text(
            "extends: ../outside.yaml\n", encoding="utf-8"
        )
        cfg = layout.write_config("middle.yaml")

        with pytest.raises(ASHConfigInputNotPermittedError):
            resolve_config(
                config_path=cfg,
                source_dir=layout.scan,
                permit_base=sandbox.config_base_gate(_SESSION),
            )

    def test_the_refusal_reads_the_same_whether_or_not_the_base_exists(self, layout):
        cfg = layout.write_config("../outside.yaml")
        gate = sandbox.config_base_gate(_SESSION)

        with pytest.raises(ASHConfigInputNotPermittedError) as present:
            resolve_config(config_path=cfg, source_dir=layout.scan, permit_base=gate)
        layout.sibling.unlink()
        with pytest.raises(ASHConfigInputNotPermittedError) as absent:
            resolve_config(config_path=cfg, source_dir=layout.scan, permit_base=gate)

        assert str(present.value) == str(absent.value)

    def test_without_a_gate_the_cli_rule_is_unchanged(self, layout):
        # #712's root for a file in .ash/ is the parent of .ash/, so the sibling
        # resolves when no MCP grant is passed in.
        cfg = layout.write_config("../outside.yaml")

        config = resolve_config(config_path=cfg, source_dir=layout.scan)
        assert config.project_name == _OUTSIDE_MARKER

    def test_the_cli_root_still_applies_under_the_gate(self, layout, monkeypatch):
        # A grant wider than #712's root does not widen the chain: both rules apply.
        monkeypatch.setenv(
            ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(layout.grant.parent.parent)
        )
        cfg = layout.write_config(str(layout.far))

        from automated_security_helper.core.exceptions import ASHConfigSourceError

        with pytest.raises(ASHConfigSourceError):
            resolve_config(
                config_path=cfg,
                source_dir=layout.scan,
                permit_base=sandbox.config_base_gate(_SESSION),
            )


# ---------------------------------------------------------------------------
# 2. The extends chain, through the scan path
# ---------------------------------------------------------------------------


class TestRunAshScanConfinesTheChain:
    def test_a_config_whose_chain_leaves_the_grant_is_refused_before_the_scan(
        self, layout
    ):
        from automated_security_helper.cli import mcp_server

        cfg = layout.write_config("../outside.yaml")
        with patch.object(mcp_server, "mcp_scan_directory") as started:
            result = _run(
                mcp_server.run_ash_scan(
                    _ctx(), source_dir=str(layout.scan), config_path=str(cfg)
                )
            )

        assert result["success"] is False
        assert result["error_type"] == _CONFIG_REFUSED
        started.assert_not_called()
        _assert_carries_nothing_from(result)

    def test_a_config_whose_chain_stays_in_the_grant_starts_the_scan(self, layout):
        from automated_security_helper.cli import mcp_server

        cfg = layout.write_config("base.yaml")
        with (
            patch.object(
                mcp_server,
                "mcp_scan_directory",
                new=AsyncMock(return_value={"success": True, "scan_id": "s-1"}),
            ) as started,
            patch.object(mcp_server, "monitor_scan_progress", new=AsyncMock()),
        ):
            result = _run(
                mcp_server.run_ash_scan(
                    _ctx(), source_dir=str(layout.scan), config_path=str(cfg)
                )
            )

        assert result["success"] is True, result
        started.assert_awaited_once()

    def test_mcp_scan_directory_refuses_the_chain_when_called_directly(self, layout):
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        cfg = layout.write_config("../outside.yaml")
        with patch(
            "automated_security_helper.cli.mcp_tools._run_scan_async"
        ) as started:
            result = _run(
                mcp_scan_directory(
                    directory_path=str(layout.scan),
                    config_path=str(cfg),
                    session_id=_SESSION,
                )
            )

        assert result["success"] is False
        assert result["error_type"] == _CONFIG_REFUSED
        started.assert_not_called()

    def test_mcp_scan_directory_refuses_a_named_config_outside_the_grant(self, layout):
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        with patch(
            "automated_security_helper.cli.mcp_tools._run_scan_async"
        ) as started:
            result = _run(
                mcp_scan_directory(
                    directory_path=str(layout.scan),
                    config_path=str(layout.far),
                    session_id=_SESSION,
                )
            )

        assert result["success"] is False
        assert result["error_type"] == _CONFIG_REFUSED
        started.assert_not_called()

    def test_an_unparseable_config_outside_the_grant_is_refused_unread(self, layout):
        """Confinement is checked before the file is parsed, so a file outside the
        grant is refused as outside it, and nothing about its contents -- not even
        that it does not parse -- reaches the client."""
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        layout.far.write_text(f"project_name: [{_OUTSIDE_MARKER}\n", encoding="utf-8")
        with patch(
            "automated_security_helper.cli.mcp_tools._run_scan_async"
        ) as started:
            result = _run(
                mcp_scan_directory(
                    directory_path=str(layout.scan),
                    config_path=str(layout.far),
                    session_id=_SESSION,
                )
            )

        assert result["success"] is False
        assert result["error_type"] == _CONFIG_REFUSED
        # The path holds the test's name, so look for the parser's own words.
        assert "could not parse" not in json.dumps(result)
        assert "while parsing" not in json.dumps(result)
        _assert_carries_nothing_from(result)
        started.assert_not_called()

    def test_the_load_check_does_not_read_a_file_outside_the_grant(self, layout):
        """config_load_error leaves a refused file to validate_config_chain, unread."""
        layout.far.write_text(f"project_name: [{_OUTSIDE_MARKER}\n", encoding="utf-8")

        assert (
            sandbox.config_load_error(
                layout.far, session_id=_SESSION, source_dir=layout.scan
            )
            is None
        )

    def test_the_scan_itself_receives_the_sessions_gate(self, layout):
        """The preflight is not the only check: the scan resolves under the grant too."""
        from automated_security_helper.cli import mcp_tools
        from automated_security_helper.core.resource_management.scan_registry import (
            get_scan_registry,
        )

        captured: Dict[str, Any] = {}

        def fake_run_ash_scan(**kwargs):
            captured.update(kwargs)
            return None

        cfg = layout.write_config("../outside.yaml")
        output_dir = layout.scan / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        registry = get_scan_registry()
        scan_id = registry.register_scan(
            directory_path=str(layout.scan),
            output_directory=str(output_dir),
            severity_threshold="MEDIUM",
            config_path=str(cfg),
        )
        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
            side_effect=fake_run_ash_scan,
        ):
            _run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(layout.scan),
                    output_dir=str(output_dir),
                    severity_threshold="MEDIUM",
                    config_path=str(cfg),
                    session_id=_SESSION,
                )
            )

        gate = captured.get("config_base_gate")
        assert callable(gate)
        assert gate(layout.sibling.resolve()) is False
        assert gate(layout.in_grant_base.resolve()) is True
        # The only caller that hands run_ash_scan a gate scans one directory in
        # local mode, the one shape run_ash_scan accepts a gate for (it refuses
        # a gate with a container or nix mode or a workspace plan).
        from automated_security_helper.core.enums import RunMode

        assert captured.get("mode") == RunMode.local
        assert captured.get("workspace_plan") is None

    def test_every_config_read_in_a_scan_honors_the_gate(self, layout):
        """The orchestrator and the exit-code/workspace readers all pass it on."""
        from automated_security_helper.interactions import run_ash_scan as ras

        cfg = layout.write_config("../outside.yaml")
        opts = ras.ScanOptions(
            source_dir=layout.scan,
            output_dir=layout.scan / ".ash" / "ash_output",
            config=str(cfg),
            config_base_gate=sandbox.config_base_gate(_SESSION),
        )
        # _load_config_file swallows errors and returns None; without the gate it
        # would return the merged config with the sibling's project_name.
        assert ras._load_config_file(opts) is None

        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        orchestrator = ASHScanOrchestrator(
            source_dir=layout.scan,
            output_dir=layout.scan / ".ash" / "ash_output",
            config_path=cfg,
            config_base_gate=sandbox.config_base_gate(_SESSION),
        )
        with pytest.raises(ASHConfigInputNotPermittedError):
            orchestrator.initialize()


#: A config a scan of the target discovers, as a link to a file outside every
#: root: where the link is, and what the outside file holds. Two of them stop
#: parsing on the marker's line, whose position a refusal must not give.
_LINKED_OUT = {
    "ash-yaml-in-dot-ash": (
        ".ash/.ash.yaml",
        f"project_name: {_OUTSIDE_MARKER}\n",
    ),
    "ashrc-toml-that-does-not-parse": (
        ".ashrc.toml",
        f'project_name = "demo"\n{_OUTSIDE_MARKER} = = 1\n',
    ),
    "pyproject-that-does-not-parse": (
        "pyproject.toml",
        f'[tool.ash]\nproject_name = "{_OUTSIDE_MARKER}\n',
    ),
}


@pytest.fixture
def scans_started(monkeypatch) -> list:
    """The scans scan_directory starts, none of which runs.

    The runner is a stand-in that only gives back what a scan holds of its
    session (``scan_claim``), as the real one does when it ends. Closed unrun,
    the claim stayed taken, and a later test in the same worker that changed
    this session's source was refused as if a scan were running.
    """
    from automated_security_helper.cli import mcp_tools

    started: list = []

    async def runner(**kwargs) -> None:
        claim = kwargs.get("scan_claim")
        if claim is not None:
            claim.release_scan()

    def record(scan_id, coroutine, **start_options) -> None:
        # The stand-in never awaits, so one step runs it to the end. The
        # start's keywords (ran, if_never_run) are accepted and left alone.
        with pytest.raises(StopIteration):
            coroutine.send(None)
        started.append(scan_id)
        # The real start holds the scan's log scope until its task is done;
        # this stand-in's "task" is already done.
        end_the_scans_scope_as_its_task_would()

    monkeypatch.setattr(mcp_tools, "_run_scan_async", runner)
    monkeypatch.setattr(mcp_tools, "_start_scan_task", record)
    return started


class TestScanDirectoryConfinesTheDiscoveredConfig:
    """A config the scan discovers in its target is checked as a named one is.

    For a remote caller, one linked out of the permitted roots must not be read all the
    same: an outside file that parses would configure the scan, and one that does
    not would fail the scan on it (were only an ``extends`` base checked). It is refused before it is read, as a
    named config outside the roots is, with neither its path nor its contents.
    """

    @pytest.mark.parametrize("cell", _LINKED_OUT)
    def test_a_discovered_config_linked_out_of_the_roots_is_refused(
        self, layout, scans_started, cell
    ):
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        relative, text = _LINKED_OUT[cell]
        outside = layout.elsewhere / Path(relative).name
        outside.write_text(text, encoding="utf-8")
        link = layout.scan / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside)

        result = _run(
            mcp_scan_directory(directory_path=str(layout.scan), session_id=_SESSION)
        )

        assert result["success"] is False, result
        assert result["error_type"] == _CONFIG_REFUSED, result
        assert scans_started == [], "the scan started with the outside config"
        _assert_carries_nothing_from(result)
        assert str(layout.elsewhere) not in json.dumps(result, default=str), result

    @pytest.mark.parametrize("extends", ["absolute", "dot-dot", "link"])
    def test_a_discovered_config_extending_out_of_the_roots_is_refused(
        self, layout, scans_started, extends
    ):
        """The discovered file is in the roots and its ``extends`` base is not.

        The chain is checked, not only the file: with a check of the file
        alone these cells start the scan.
        """
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        if extends == "absolute":
            base = str(layout.far)
        elif extends == "dot-dot":
            base = os.path.relpath(layout.far, layout.scan / ".ash")
        else:
            link = layout.scan / "base.yaml"
            link.symlink_to(layout.far)
            base = "../base.yaml"
        config = layout.scan / ".ash" / ".ash.yaml"
        config.parent.mkdir()
        config.write_text(f"extends: {json.dumps(base)}\n", encoding="utf-8")

        result = _run(
            mcp_scan_directory(directory_path=str(layout.scan), session_id=_SESSION)
        )

        assert result["success"] is False, result
        assert result["error_type"] == _CONFIG_REFUSED, result
        assert scans_started == [], "the scan started with the outside base"
        _assert_carries_nothing_from(result)

    @pytest.mark.parametrize("cell", _LINKED_OUT)
    def test_a_link_out_to_a_missing_file_is_refused_like_one_to_a_present_file(
        self, layout, scans_started, cell
    ):
        """Only candidates whose target was a file were checked, so a link to a
        missing outside path started the scan where a link to a present one was
        refused: the answer told whether that path exists on the server."""
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        relative, _text = _LINKED_OUT[cell]
        link = layout.scan / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(layout.elsewhere / "not-there" / Path(relative).name)

        result = _run(
            mcp_scan_directory(directory_path=str(layout.scan), session_id=_SESSION)
        )

        assert result["success"] is False, result
        assert result["error_type"] == _CONFIG_REFUSED, result
        assert scans_started == [], "the scan started"
        assert str(layout.elsewhere) not in json.dumps(result, default=str), result

    def test_control_a_discovered_config_linked_inside_the_roots_starts_the_scan(
        self, layout, scans_started
    ):
        from automated_security_helper.cli.mcp_tools import mcp_scan_directory

        inside = layout.scan / "configs" / "ash.yaml"
        inside.parent.mkdir()
        inside.write_text("project_name: demo\n", encoding="utf-8")
        link = layout.scan / ".ash" / ".ash.yaml"
        link.parent.mkdir()
        link.symlink_to(inside)

        result = _run(
            mcp_scan_directory(directory_path=str(layout.scan), session_id=_SESSION)
        )

        assert result["success"] is True, result
        assert scans_started == [result["scan_id"]], result


# ---------------------------------------------------------------------------
# 3. get_config and validate_config
# ---------------------------------------------------------------------------


#: A pyproject.toml linked out of the roots, one that discovery parses and one it
#: cannot; the second's parse error would quote its line and column.
_LINKED_OUT_PYPROJECT = {
    "parses": f'[tool.ash]\nproject_name = "{_OUTSIDE_MARKER}"\n',
    "does-not-parse": f'[tool.ash]\nproject_name = "{_OUTSIDE_MARKER}\n',
}

#: The position a TOML parse error names, "(at line 2, column 15)".
_PARSE_POSITION = re.compile(r"line \d+, column \d+")

#: The resolved paths whose opens ``_record_opens`` records, and what it recorded.
_WATCHED_OPENS: list = []
_RECORDED_OPENS: list = []


def _record_opens(event: str, args: Any) -> None:
    if event != "open" or not _WATCHED_OPENS:
        return
    path = args[0]
    if isinstance(path, (str, bytes, os.PathLike)):
        try:
            resolved = os.path.realpath(os.fsdecode(path))
        except (OSError, ValueError):
            return
        if resolved in _WATCHED_OPENS:
            _RECORDED_OPENS.append(resolved)


sys.addaudithook(_record_opens)


@pytest.fixture
def opens_of():
    """``opens_of(path)`` starts recording every open of ``path``; yields the record."""

    def watch(path: Path) -> list:
        _RECORDED_OPENS.clear()
        _WATCHED_OPENS.append(os.path.realpath(path))
        return _RECORDED_OPENS

    yield watch
    _WATCHED_OPENS.clear()
    _RECORDED_OPENS.clear()


class TestGetConfigIsConfined:
    @pytest.mark.parametrize("raw", [True, False])
    @pytest.mark.parametrize("cell", sorted(_LINKED_OUT_PYPROJECT))
    def test_a_discovered_pyproject_linked_out_is_refused_before_it_is_read(
        self, layout, opens_of, cell, raw
    ):
        """Discovery reads a pyproject.toml to learn whether it configures ASH.

        get_config discovered first and checked the file it found after, so a
        pyproject.toml linked out of the roots was read by discovery itself: one
        that parsed was then refused, and one that did not was reported with the
        outside file's line and column.
        """
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        outside = layout.elsewhere / "pyproject.toml"
        outside.write_text(_LINKED_OUT_PYPROJECT[cell], encoding="utf-8")
        (layout.scan / "pyproject.toml").symlink_to(outside)
        opened = opens_of(outside)

        result = mcp_get_config(
            search_dir=str(layout.scan), raw=raw, session_id=_SESSION
        )

        assert opened == [], "the outside pyproject.toml was read"
        assert result.get("success") is False, result
        assert result["error_type"] == _CONFIG_REFUSED, result
        _assert_carries_nothing_from(result)
        text = json.dumps(result, default=str)
        # The outside file's parse position, as a TOML error names it. Not the bare
        # word: the refusal quotes the test's own paths, which may hold "column".
        assert _PARSE_POSITION.search(text) is None, result
        assert str(layout.elsewhere) not in text, result

    def test_a_discovered_link_to_a_missing_outside_file_is_refused(self, layout):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        link = layout.scan / ".ash" / ".ash.yaml"
        link.parent.mkdir()
        link.symlink_to(layout.elsewhere / "not-there.yaml")

        result = mcp_get_config(search_dir=str(layout.scan), session_id=_SESSION)

        assert result.get("success") is False, result
        assert result["error_type"] == _CONFIG_REFUSED, result
        assert str(layout.elsewhere) not in json.dumps(result, default=str), result

    @pytest.mark.parametrize("raw", [True, False])
    def test_a_path_outside_the_roots_is_refused(self, layout, raw):
        from automated_security_helper.cli import mcp_server

        result = _run(
            mcp_server.get_config(_ctx(), config_path=str(layout.far), raw=raw)
        )

        assert result["success"] is False
        assert result["error_type"] == _CONFIG_REFUSED
        _assert_carries_nothing_from(result)

    def test_an_absent_path_outside_the_roots_reads_like_a_present_one(self, layout):
        from automated_security_helper.cli import mcp_server

        present = _run(mcp_server.get_config(_ctx(), config_path=str(layout.far)))
        missing = layout.elsewhere / "missing.yaml"
        absent = _run(mcp_server.get_config(_ctx(), config_path=str(missing)))

        assert present["error_type"] == absent["error_type"] == _CONFIG_REFUSED
        assert present["error"].replace("far.yaml", "") == absent["error"].replace(
            "missing.yaml", ""
        )

    def test_an_extends_chain_leaving_the_grant_is_refused(self, layout):
        from automated_security_helper.cli import mcp_server

        cfg = layout.write_config("../outside.yaml")
        result = _run(mcp_server.get_config(_ctx(), config_path=str(cfg)))

        assert result["success"] is False
        assert result["error_type"] == _CONFIG_REFUSED
        _assert_carries_nothing_from(result)

    @pytest.mark.parametrize("raw", [True, False])
    def test_a_path_inside_the_grant_still_works(self, layout, raw):
        from automated_security_helper.cli import mcp_server

        cfg = layout.write_config("base.yaml")
        result = _run(mcp_server.get_config(_ctx(), config_path=str(cfg), raw=raw))

        if raw:
            assert result["extends"] == "base.yaml"
        else:
            assert result["project_name"] == "in-grant-base"

    def test_a_discovered_config_outside_the_roots_is_refused(
        self, layout, monkeypatch
    ):
        from automated_security_helper.cli import mcp_server

        (layout.elsewhere / ".ash.yaml").write_text(
            f"project_name: {_OUTSIDE_MARKER}\n", encoding="utf-8"
        )
        monkeypatch.chdir(layout.elsewhere)
        result = _run(mcp_server.get_config(_ctx(), raw=True))

        assert result["success"] is False
        assert result["error_type"] == _CONFIG_REFUSED
        _assert_carries_nothing_from(result)

    def test_discovery_outside_the_roots_does_not_say_whether_a_config_exists(
        self, layout, monkeypatch
    ):
        from automated_security_helper.cli import mcp_server

        monkeypatch.chdir(layout.elsewhere)
        absent = _run(mcp_server.get_config(_ctx(), raw=True))
        (layout.elsewhere / ".ash.yaml").write_text(
            f"project_name: {_OUTSIDE_MARKER}\n", encoding="utf-8"
        )
        present = _run(mcp_server.get_config(_ctx(), raw=True))

        assert absent == present
        assert present["error_type"] == _CONFIG_REFUSED


class TestValidateConfigIsConfined:
    def test_a_path_outside_the_roots_is_refused(self, layout):
        from automated_security_helper.cli import mcp_server

        result = mcp_server.validate_config(_ctx(), config_path=str(layout.far))

        assert result["valid"] is False
        assert [e["type"] for e in result["errors"]] == [_CONFIG_REFUSED]
        _assert_carries_nothing_from(result)

    def test_an_absent_path_outside_the_roots_is_refused_the_same_way(self, layout):
        from automated_security_helper.cli import mcp_server

        missing = layout.elsewhere / "missing.yaml"
        result = mcp_server.validate_config(_ctx(), config_path=str(missing))

        assert [e["type"] for e in result["errors"]] == [_CONFIG_REFUSED]

    def test_an_extends_chain_leaving_the_grant_is_refused(self, layout):
        from automated_security_helper.cli import mcp_server

        cfg = layout.write_config("../outside.yaml")
        result = mcp_server.validate_config(_ctx(), config_path=str(cfg))

        assert result["valid"] is False
        assert _CONFIG_REFUSED in [e["type"] for e in result["errors"]]
        _assert_carries_nothing_from(result)

    def test_content_whose_extends_names_a_file_outside_the_roots_is_refused(
        self, layout
    ):
        from automated_security_helper.cli import mcp_server

        result = mcp_server.validate_config(
            _ctx(), config_content=f"extends: {json.dumps(str(layout.far))}\n"
        )

        assert result["valid"] is False
        assert _CONFIG_REFUSED in [e["type"] for e in result["errors"]]
        _assert_carries_nothing_from(result)

    def test_a_path_inside_the_grant_still_works(self, layout):
        from automated_security_helper.cli import mcp_server

        cfg = layout.write_config("base.yaml")
        result = mcp_server.validate_config(_ctx(), config_path=str(cfg))

        assert result["valid"] is True, result


# ---------------------------------------------------------------------------
# 4. Every path-taking MCP tool parameter
# ---------------------------------------------------------------------------


def _is_path_like(name: str) -> bool:
    return name.endswith(("_path", "_dir", "_file", "_config")) or name == "url"


def _results_dir(root: Path) -> Path:
    out = root / ".ash" / "ash_output"
    (out / "reports").mkdir(parents=True, exist_ok=True)
    (out / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    return out


_Call = Callable[[Any, _Layout], Any]


def _call_run_ash_scan_source(srv, lay):
    return srv.run_ash_scan(_ctx(), source_dir=str(lay.elsewhere))


def _call_run_ash_scan_config(srv, lay):
    return srv.run_ash_scan(_ctx(), source_dir=str(lay.scan), config_path=str(lay.far))


def _call_resolve_ws_file(srv, lay):
    return srv.resolve_ash_workspace(
        _ctx(), workspace_file=str(lay.elsewhere / "x.code-workspace")
    )


def _call_resolve_ws_config(srv, lay):
    return srv.resolve_ash_workspace(
        _ctx(),
        workspace_file=str(lay.grant / "x.code-workspace"),
        workspace_config=str(lay.far),
    )


def _call_run_ws_file(srv, lay):
    return srv.run_ash_workspace_scan(
        _ctx(), workspace_file=str(lay.elsewhere / "x.code-workspace")
    )


def _call_run_ws_config(srv, lay):
    return srv.run_ash_workspace_scan(
        _ctx(),
        workspace_file=str(lay.grant / "x.code-workspace"),
        workspace_config=str(lay.far),
    )


def _call_run_ws_output(srv, lay):
    return srv.run_ash_workspace_scan(
        _ctx(),
        workspace_file=str(lay.grant / "x.code-workspace"),
        output_dir=str(lay.elsewhere / "out"),
    )


def _call_get_scan_results(srv, lay):
    return srv.get_scan_results(_ctx(), output_dir=str(_results_dir(lay.elsewhere)))


def _call_get_scan_summary(srv, lay):
    return srv.get_scan_summary(_ctx(), output_dir=str(_results_dir(lay.elsewhere)))


def _call_get_scan_result_paths(srv, lay):
    return srv.get_scan_result_paths(
        _ctx(), output_dir=str(_results_dir(lay.elsewhere))
    )


def _call_explain_finding(srv, lay):
    return srv.explain_finding(
        _ctx(), finding_id="f-1", results_path=str(_results_dir(lay.elsewhere))
    )


def _call_get_config(srv, lay):
    return srv.get_config(_ctx(), config_path=str(lay.far))


def _call_get_config_search(srv, lay):
    return srv.get_config(_ctx(), search_dir=str(lay.elsewhere))


def _call_validate_config(srv, lay):
    return srv.validate_config(_ctx(), config_path=str(lay.far))


def _call_diff_before(srv, lay):
    out = _results_dir(lay.elsewhere)
    inside = _results_dir(lay.scan)
    return srv.diff_scan_results(
        _ctx(),
        before_path=str(out / "ash_aggregated_results.json"),
        after_path=str(inside / "ash_aggregated_results.json"),
    )


def _call_diff_after(srv, lay):
    out = _results_dir(lay.elsewhere)
    inside = _results_dir(lay.scan)
    return srv.diff_scan_results(
        _ctx(),
        before_path=str(inside / "ash_aggregated_results.json"),
        after_path=str(out / "ash_aggregated_results.json"),
    )


def _call_suggest_suppression(srv, lay):
    out = _results_dir(lay.elsewhere)
    return srv.suggest_suppression(
        _ctx(),
        finding_id="f-1",
        results_path=str(out / "ash_aggregated_results.json"),
    )


def _call_set_source_git(srv, lay):
    return srv.set_source_git(_ctx(), url=str(lay.elsewhere))


#: (tool, parameter) -> a call that names a location outside every root through
#: that parameter. Each must be refused without touching the location.
_AUDITED: Dict[Tuple[str, str], _Call] = {
    ("run_ash_scan", "source_dir"): _call_run_ash_scan_source,
    ("run_ash_scan", "config_path"): _call_run_ash_scan_config,
    ("resolve_ash_workspace", "workspace_file"): _call_resolve_ws_file,
    ("resolve_ash_workspace", "workspace_config"): _call_resolve_ws_config,
    ("run_ash_workspace_scan", "workspace_file"): _call_run_ws_file,
    ("run_ash_workspace_scan", "workspace_config"): _call_run_ws_config,
    ("run_ash_workspace_scan", "output_dir"): _call_run_ws_output,
    ("get_scan_results", "output_dir"): _call_get_scan_results,
    ("get_scan_summary", "output_dir"): _call_get_scan_summary,
    ("get_scan_result_paths", "output_dir"): _call_get_scan_result_paths,
    ("explain_finding", "results_path"): _call_explain_finding,
    ("get_config", "config_path"): _call_get_config,
    ("get_config", "search_dir"): _call_get_config_search,
    ("validate_config", "config_path"): _call_validate_config,
    ("diff_scan_results", "before_path"): _call_diff_before,
    ("diff_scan_results", "after_path"): _call_diff_after,
    ("suggest_suppression", "results_path"): _call_suggest_suppression,
    ("set_source_git", "url"): _call_set_source_git,
}


def _refused(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    if "valid" in result:
        return result["valid"] is False and any(
            e.get("type") == _CONFIG_REFUSED for e in result.get("errors", [])
        )
    return result.get("success") is False and (
        result.get("error_type")
        in {_CONFIG_REFUSED, "scan_target_not_permitted", "output_dir_not_permitted"}
        or result.get("error_category") == "invalid_path"
    )


class TestEveryPathParameterIsAudited:
    def test_the_audit_covers_every_registered_path_parameter(self):
        from automated_security_helper.cli.mcp_server import mcp

        async def _live() -> set:
            found = set()
            for tool in await mcp.list_tools():
                for name in tool.input_schema.get("properties", {}):
                    if _is_path_like(name):
                        found.add((tool.name, name))
            return found

        assert _run(_live()) == set(_AUDITED)

    def test_no_resource_template_takes_a_path(self):
        from automated_security_helper.cli.mcp_server import mcp

        assert _run(mcp.list_resource_templates()) == []

    @pytest.mark.parametrize("key", sorted(_AUDITED), ids=lambda k: f"{k[0]}.{k[1]}")
    def test_a_location_outside_the_roots_is_refused(self, layout, key):
        from automated_security_helper.cli import mcp_server

        call = _AUDITED[key]
        with (
            patch("automated_security_helper.cli.mcp.source_delivery._run_git") as git,
            patch("automated_security_helper.cli.mcp_tools._run_scan_async") as scan,
        ):
            result = call(mcp_server, layout)
            if asyncio.iscoroutine(result):
                result = _run(result)

        assert _refused(result), result
        git.assert_not_called()
        scan.assert_not_called()
        _assert_carries_nothing_from(result)
        assert not (layout.elsewhere / "out").exists()


class TestANamedFilesSearchDirCrossesTheRootGateToo:
    """The named-file branch has its own search_dir gate, audited here.

    ``_AUDITED`` holds one call per (tool, parameter), and its
    ``("get_config", "search_dir")`` entry passes no ``config_path``, so it
    exercises only the discovery branch's gate. The named-file branch checks
    the same parameter through its own gate (after ``config_path``'s own
    checks pass), and removing that gate alone left every cell here green
    until these were added.
    """

    def _named(self, layout) -> str:
        return str(layout.write_config("base.yaml"))

    def test_a_named_file_with_a_search_dir_outside_the_roots_is_refused(self, layout):
        from automated_security_helper.cli import mcp_server

        with (
            patch("automated_security_helper.cli.mcp.source_delivery._run_git") as git,
            patch("automated_security_helper.cli.mcp_tools._run_scan_async") as scan,
        ):
            result = _run(
                mcp_server.get_config(
                    _ctx(),
                    config_path=self._named(layout),
                    search_dir=str(layout.elsewhere),
                )
            )

        assert _refused(result), result
        git.assert_not_called()
        scan.assert_not_called()
        _assert_carries_nothing_from(result)

    @pytest.mark.parametrize(
        "spelling",
        [
            "abs_exists",
            "abs_missing",
            "link_in_roots_to_outside",
            "dotdot",
            "trailing_slash",
            "relative",
        ],
    )
    def test_every_spelling_of_an_outside_search_dir_is_refused(
        self, layout, monkeypatch, tmp_path, spelling
    ):
        from automated_security_helper.cli import mcp_tools

        if spelling == "link_in_roots_to_outside":
            link = layout.scan / "way-out"
            try:
                link.symlink_to(layout.elsewhere)
            except (OSError, NotImplementedError):
                pytest.skip("symlinks are not available on this platform")
            search = str(link)
        elif spelling == "relative":
            monkeypatch.chdir(tmp_path)
            search = "elsewhere"
        else:
            search = {
                "abs_exists": str(layout.elsewhere),
                "abs_missing": str(layout.elsewhere / "no-such-dir"),
                "dotdot": str(layout.scan / ".." / "elsewhere"),
                "trailing_slash": str(layout.elsewhere) + os.sep,
            }[spelling]

        answer = mcp_tools.mcp_get_config(
            config_path=self._named(layout), search_dir=search, session_id=_SESSION
        )

        assert answer.get("success") is False, answer
        # The scan tool's own refusal of the same target: the gate is the
        # scan root policy, not the config-input roots.
        assert answer.get("error_type") == "scan_target_not_permitted", answer
        assert answer.get("exit_code") == 4, answer
        _assert_carries_nothing_from(answer)

    def test_the_refusal_reads_the_same_whether_or_not_the_directory_exists(
        self, layout
    ):
        """A gate that fires only for a directory that exists would answer
        whether a path outside the roots exists. Byte-identical with the
        path replaced, as the chain refusal's equality cell pins it."""
        from automated_security_helper.cli import mcp_tools

        present = str(layout.elsewhere)
        absent = str(layout.elsewhere / "no-such-dir")

        config = self._named(layout)
        with_present = mcp_tools.mcp_get_config(
            config_path=config, search_dir=present, session_id=_SESSION
        )
        with_absent = mcp_tools.mcp_get_config(
            config_path=config, search_dir=absent, session_id=_SESSION
        )

        a = json.dumps(with_present, default=str).replace(present, "<outside>")
        b = json.dumps(with_absent, default=str).replace(absent, "<outside>")
        assert a == b, (a, b)

    @pytest.mark.parametrize("named", [True, False], ids=["named-file", "discovery"])
    def test_a_directory_under_the_config_roots_is_refused_as_a_scan_refuses_it(
        self, layout, named
    ):
        """A directory the caller may read config from is still no scan
        target: the config roots grant reads of config files, not scans. The
        gate is the scan tool's own root policy, so the refusal is the one a
        scan of the same directory answers."""
        from automated_security_helper.cli import mcp_tools

        in_config_roots = str(layout.grant)

        answer = mcp_tools.mcp_get_config(
            config_path=self._named(layout) if named else None,
            search_dir=in_config_roots,
            session_id=_SESSION,
        )

        assert answer.get("success") is False, answer
        assert answer.get("error_type") == "scan_target_not_permitted", answer
        assert answer.get("exit_code") == 4, answer
        _assert_carries_nothing_from(answer)

    def test_the_config_roots_refusal_reads_the_same_whether_the_dir_exists(
        self, layout
    ):
        """The same no-existence-read property for the new gate's reach: a
        present config-roots directory and a missing one under it answer
        byte-identically with the path replaced."""
        from automated_security_helper.cli import mcp_tools

        present = str(layout.grant)
        absent = str(layout.grant / "no-such-dir")

        config = self._named(layout)
        with_present = mcp_tools.mcp_get_config(
            config_path=config, search_dir=present, session_id=_SESSION
        )
        with_absent = mcp_tools.mcp_get_config(
            config_path=config, search_dir=absent, session_id=_SESSION
        )

        a = json.dumps(with_present, default=str).replace(present, "<target>")
        b = json.dumps(with_absent, default=str).replace(absent, "<target>")
        assert a == b, (a, b)

    def test_the_refused_directory_is_never_opened(self, layout, monkeypatch):
        """The gate answers from the root policy alone: nothing under the
        refused directory -- the named config file inside it included -- is
        opened or listed on the way to the refusal. The instrument records
        every open/scandir/listdir under the directory, and its own planted
        open at the end proves it sees one."""
        import builtins

        from automated_security_helper.cli import mcp_tools

        config = self._named(layout)
        refused_prefix = str(layout.grant)
        touched: list = []

        def _recording(original):
            def wrapper(path, *args, **kwargs):
                try:
                    text = os.fspath(path)
                except TypeError:
                    text = str(path)
                if isinstance(text, bytes):
                    text = text.decode(errors="replace")
                if isinstance(text, str) and text.startswith(refused_prefix):
                    touched.append(text)
                return original(path, *args, **kwargs)

            return wrapper

        monkeypatch.setattr(builtins, "open", _recording(builtins.open))
        monkeypatch.setattr(os, "open", _recording(os.open))
        monkeypatch.setattr(os, "scandir", _recording(os.scandir))
        monkeypatch.setattr(os, "listdir", _recording(os.listdir))

        answer = mcp_tools.mcp_get_config(
            config_path=config,
            search_dir=str(layout.grant),
            session_id=_SESSION,
        )

        assert answer.get("error_type") == "scan_target_not_permitted", answer
        assert touched == [], touched

        # Must-flag control: the instrument sees an open under the prefix.
        with open(config, encoding="utf-8"):
            pass
        assert touched, "the instrument recorded no opens at all"

    def test_a_directory_inside_the_scan_roots_still_answers(self, layout):
        """Control: the scan root policy, not a narrower one -- a directory
        inside the allowed scan roots keeps the answer."""
        from automated_security_helper.cli import mcp_tools

        answer = mcp_tools.mcp_get_config(
            config_path=self._named(layout),
            search_dir=str(layout.scan),
            session_id=_SESSION,
        )

        assert answer.get("success") is not False, answer
        assert "error_type" not in answer, answer


class TestInsideTheRootsStillWorks:
    """The positive half of the audit for the tools this change touched."""

    def test_diff_scan_results_inside_the_roots(self, layout):
        from automated_security_helper.cli import mcp_server

        a = _results_dir(layout.scan) / "ash_aggregated_results.json"
        with patch.object(
            mcp_server, "mcp_diff_scan_results", wraps=mcp_server.mcp_diff_scan_results
        ) as inner:
            _run(
                mcp_server.diff_scan_results(
                    _ctx(), before_path=str(a), after_path=str(a)
                )
            )
        inner.assert_called_once()

    def test_suggest_suppression_inside_the_roots_reaches_the_lookup(self, layout):
        from automated_security_helper.cli import mcp_server

        a = _results_dir(layout.scan) / "ash_aggregated_results.json"
        result = _run(
            mcp_server.suggest_suppression(
                _ctx(), finding_id="f-1", results_path=str(a)
            )
        )
        assert result.get("error_type") not in {
            "scan_target_not_permitted",
            _CONFIG_REFUSED,
        }
        assert result.get("error_category") != "invalid_path"

    def test_explain_finding_inside_the_roots_reaches_the_lookup(self, layout):
        from automated_security_helper.cli import mcp_server

        result = _run(
            mcp_server.explain_finding(
                _ctx(), finding_id="f-1", results_path=str(_results_dir(layout.scan))
            )
        )
        assert result.get("error_category") != "invalid_path"

    def test_get_scan_result_paths_reads_the_sessions_own_sandbox(self, layout):
        from automated_security_helper.cli import mcp_server

        own = sandbox.session_sandbox(_SESSION).source_dir
        own.mkdir(parents=True)
        result = _run(
            mcp_server.get_scan_result_paths(_ctx(), output_dir=str(_results_dir(own)))
        )
        assert result["success"] is True, result

    def test_set_source_git_with_a_remote_url_reaches_git(self, layout, monkeypatch):
        from automated_security_helper.cli import mcp_server

        # The tool clones only from hosts the operator lists.
        monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "example.com")

        def fake_run(cmd, **kw):
            res = MagicMock()
            res.returncode = 0
            res.stdout = res.stderr = ""
            return res

        with patch(
            "automated_security_helper.cli.mcp.source_delivery._run_git",
            side_effect=fake_run,
        ) as git:
            result = _run(
                mcp_server.set_source_git(_ctx(), url="https://example.com/r.git")
            )
        assert result["success"] is True, result
        git.assert_called()

    @pytest.mark.parametrize("url", ["--upload-pack=touch x", "ext::sh -c true"])
    def test_set_source_git_reports_url_rules_before_confinement(self, layout, url):
        from automated_security_helper.cli import mcp_server

        with patch("automated_security_helper.cli.mcp.source_delivery._run_git") as git:
            result = _run(mcp_server.set_source_git(_ctx(), url=url))

        assert result["success"] is False
        assert "outside the permitted roots" not in result["error"]
        assert result.get("error_type") != "scan_target_not_permitted"
        git.assert_not_called()

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/r.git",
            "ssh://git@example.com/r.git",
            "git@example.com:org/r.git",
            "example.com:r.git",
        ],
    )
    def test_remote_url_forms_are_not_local_paths(self, url):
        from automated_security_helper.cli.mcp.source_delivery import (
            local_clone_path,
        )

        assert local_clone_path(url) is None

    @pytest.mark.parametrize(
        "url, expected",
        [
            ("/srv/repo", "/srv/repo"),
            ("./repo", "repo"),
            ("repo", "repo"),
            ("file:///srv/repo", "/srv/repo"),
            ("FILE:///srv/a%20b", "/srv/a b"),
            ("/srv/a:b", "/srv/a:b"),
        ],
    )
    def test_local_url_forms_are_local_paths(self, url, expected):
        from automated_security_helper.cli.mcp.source_delivery import (
            local_clone_path,
        )

        assert local_clone_path(url) == Path(expected)


class TestALocalCallerKeepsItsDefaults:
    """stdio with no grant: unchanged apart from the system-directory net."""

    def test_get_config_reads_an_ordinary_path(self, tmp_path):
        from automated_security_helper.cli import mcp_server

        cfg = tmp_path / "proj" / ".ash.yaml"
        cfg.parent.mkdir()
        cfg.write_text("project_name: local\n", encoding="utf-8")
        result = _run(
            mcp_server.get_config(
                MagicMock(headers=None), config_path=str(cfg), raw=True
            )
        )
        assert result == {"project_name": "local"}

    def test_a_local_extends_chain_keeps_the_cli_rule(self, tmp_path):
        policies = tmp_path / "policies"
        (policies / ".ash").mkdir(parents=True)
        (policies / "base.yaml").write_text("project_name: beside\n", encoding="utf-8")
        cfg = policies / ".ash" / ".ash.yaml"
        cfg.write_text("extends: ../base.yaml\n", encoding="utf-8")

        config = resolve_config(
            config_path=cfg,
            source_dir=tmp_path,
            permit_base=sandbox.config_base_gate(None),
        )
        assert config.project_name == "beside"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX system directory")
    def test_a_system_directory_base_is_refused_locally_too(self, tmp_path):
        cfg = tmp_path / ".ash.yaml"
        cfg.write_text("extends: /etc/ash-not-a-real-file.yaml\n", encoding="utf-8")

        with pytest.raises(ASHConfigInputNotPermittedError):
            resolve_config(
                config_path=cfg,
                source_dir=tmp_path,
                permit_base=sandbox.config_base_gate(None),
            )
