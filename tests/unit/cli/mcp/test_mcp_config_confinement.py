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
from pathlib import Path
from typing import Any, Callable, Dict, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core import exceptions as _exceptions

_SESSION = "client-one"
_SECRET = "OUTSIDE-THE-GRANT-MARKER"
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
        self.sibling.write_text(f"project_name: {_SECRET}\n", encoding="utf-8")

        # Outside every root, and outside #712's root too.
        self.elsewhere = tmp_path / "elsewhere"
        self.elsewhere.mkdir()
        self.far = self.elsewhere / "far.yaml"
        self.far.write_text(f"project_name: {_SECRET}\n", encoding="utf-8")

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
    assert _SECRET not in json.dumps(result, default=str)


# ---------------------------------------------------------------------------
# 1. The extends chain, at the resolution layer
# ---------------------------------------------------------------------------


class TestExtendsChainUnderAnMcpGrant:
    """Each chain file passes ``validate_config_input`` for the calling session."""

    @pytest.mark.parametrize(
        "spelling",
        ["sibling", "parent", "absolute"],
    )
    def test_a_base_outside_the_grant_is_refused(self, layout, spelling):
        extends = {
            "sibling": "../outside.yaml",
            "parent": "../../policies/outside.yaml",
            "absolute": str(layout.far),
        }[spelling]
        cfg = layout.write_config(extends)

        with pytest.raises(ASHConfigInputNotPermittedError) as excinfo:
            resolve_config(
                config_path=cfg,
                source_dir=layout.scan,
                permit_base=sandbox.config_base_gate(_SESSION),
            )
        assert _SECRET not in str(excinfo.value)

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
        assert config.project_name == _SECRET

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


# ---------------------------------------------------------------------------
# 3. get_config and validate_config
# ---------------------------------------------------------------------------


class TestGetConfigIsConfined:
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
            f"project_name: {_SECRET}\n", encoding="utf-8"
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
            f"project_name: {_SECRET}\n", encoding="utf-8"
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
            patch(
                "automated_security_helper.cli.mcp.source_delivery.subprocess.run"
            ) as git,
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

    def test_set_source_git_with_a_remote_url_reaches_git(self, layout):
        from automated_security_helper.cli import mcp_server

        def fake_run(cmd, **kw):
            res = MagicMock()
            res.returncode = 0
            res.stdout = res.stderr = ""
            return res

        with patch(
            "automated_security_helper.cli.mcp.source_delivery.subprocess.run",
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

        with patch(
            "automated_security_helper.cli.mcp.source_delivery.subprocess.run"
        ) as git:
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
