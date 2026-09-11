#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP workspace tools report failures; they never exit the process.

Why this file exists
--------------------
The CLI's workspace path is built to exit. ``interactions/run_ash_scan.py``
dispatches the workspace branch and then calls ``sys.exit`` on a non-zero code,
and ``_run_workspace_mode`` calls ``sys.exit`` on all three of its failure
paths. That is correct for a process whose only job is one scan.

It is fatal for an MCP server. ``SystemExit`` derives from ``BaseException``,
not from ``Exception``, so the ``except Exception`` handler that wraps the
existing MCP tools in ``cli/mcp_tools.py`` does not catch it. A single malformed
``.code-workspace`` file handed to the server by one client would therefore
terminate the interpreter and take every other session's in-flight scan with
it -- and it would do so silently from the client's point of view, because the
connection simply drops.

So the MCP surface calls ``workspace/resolver.py::resolve_workspace`` and
``workspace/execution.py::execute_workspace`` directly. Both raise
(``WorkspaceDefinitionError``, ``ASHConfigValidationError``) and neither exits.
This file pins that: every failure comes back as a response dictionary carrying
the exit code the CLI would have exited with, and nothing here ever unwinds the
process.

How the "must not raise SystemExit" assertion is made to bite
-------------------------------------------------------------
``pytest.raises`` has no negative form, and letting a ``SystemExit`` escape
would report the run with the exit status as its message rather than naming the
defect. Every call in this file therefore goes through :func:`_call`, which
catches ``SystemExit`` specifically -- catching ``Exception`` would miss it for
exactly the reason the production handler misses it -- and converts it into a
``pytest.fail`` that says what went wrong.

The second half of the same guarantee is that the MCP path must not reach the
CLI entry point at all. A response cannot show that: with a valid workspace the
CLI call would succeed and the response would look identical. The
``no_cli_entry_point`` fixture makes the route observable by replacing
``interactions.run_ash_scan.run_ash_scan`` with a recorder.

The exit-code contract is read from the codebase, not restated here
------------------------------------------------------------------
The numbers come from ``models.workspace.WorkspaceExitCode``, and each
assertion also checks that the number it got is the one ``core/constants.py``
documents for that meaning. Two independent sources have to agree with the
response, which is what stops a wrong-but-self-consistent mapping (everything
to 1, say) from passing.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.workspace import WorkspaceExitCode

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"

#: The two registered tools, by the name the module must export them under.
TOOL_NAMES = ("mcp_resolve_workspace", "mcp_scan_workspace")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool(name: str):
    """Look the tool up at call time so a missing module fails one test, not all.

    Imported inside the test body rather than at module scope, matching
    ``test_scan_target_enforcement.py``. A top-level import of a module that
    does not exist yet turns the whole file into a collection error, which
    reports one problem for every test and hides which behaviour each was
    pinning.
    """
    return getattr(importlib.import_module(MODULE_UNDER_TEST), name)


async def _call(tool, **kwargs) -> Dict[str, Any]:
    """Await *tool*, turning a process exit into a named test failure.

    ``except SystemExit`` and not ``except Exception``: the whole point of this
    module is that ``SystemExit`` is a ``BaseException`` and slips past an
    ``Exception`` handler, so a test that used the broader clause would repeat
    the production defect it exists to detect.
    """
    try:
        return await tool(**kwargs)
    except SystemExit as exc:  # pragma: no cover -- the defect under test
        pytest.fail(
            f"{getattr(tool, '__name__', tool)!r} raised SystemExit({exc.code!r}) "
            f"instead of returning an error response. SystemExit derives from "
            f"BaseException, so cli/mcp_tools.py's 'except Exception' would not "
            f"catch it: the MCP server process would terminate and every other "
            f"session's in-flight scan would die with it."
        )


def _workspace(root: Path, folders, name: str = "dev.code-workspace") -> Path:
    """Write a workspace file listing *folders* and return its path."""
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": entry} for entry in folders]}),
        encoding="utf-8",
    )
    return path


def _project(root: Path, relative: str) -> Path:
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    return project


def _valid_workspace(root: Path) -> Path:
    """A workspace that resolves cleanly, so an injected failure is the only one.

    Every exception-mapping test below uses this. If the injection failed to
    take effect the call succeeds, the asserted exit code is absent or zero, and
    the test fails -- rather than passing because the fixture was broken in the
    same direction as the assertion.
    """
    _project(root, "api")
    _project(root, "web")
    return _workspace(root, ["api", "web"])


def _patch_both(monkeypatch, defining_module, attribute: str, replacement) -> None:
    """Replace *attribute* on its defining module and on the module under test.

    This package binds imported names both ways. ``cli/mcp_server.py`` imports
    at module scope, while ``interactions/run_ash_scan.py`` imports
    ``workspace.execution`` lazily inside the function specifically to keep
    ``workspace`` off the import-time dependency graph. Patching only the
    defining module does nothing under the first style; patching only the
    consuming module does nothing under the second. Doing both works under
    either, and leaves the assertion -- not the patch target -- deciding the
    outcome.
    """
    monkeypatch.setattr(defining_module, attribute, replacement)
    module = importlib.import_module(MODULE_UNDER_TEST)
    if hasattr(module, attribute):
        monkeypatch.setattr(module, attribute, replacement)


def _make_resolution_raise(monkeypatch, error: BaseException) -> None:
    from automated_security_helper.workspace import resolver as resolver_module

    def _raise(*args, **kwargs):
        raise error

    _patch_both(monkeypatch, resolver_module, "resolve_workspace", _raise)


def _make_execution_raise(monkeypatch, error: BaseException) -> None:
    from automated_security_helper.workspace import execution as execution_module

    def _raise(*args, **kwargs):
        raise error

    _patch_both(monkeypatch, execution_module, "execute_workspace", _raise)


def _documented(code: int) -> str:
    return ASH_EXIT_CODES[code]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    """No allowlist configured, so confinement is not what these tests measure."""
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture(autouse=True)
def no_cli_entry_point(monkeypatch) -> List[Tuple[tuple, dict]]:
    """Record any call into ``interactions.run_ash_scan``, which must never happen.

    That function is where the ``sys.exit`` calls live. Reusing it would import
    the exit behaviour wholesale, and on a *valid* workspace the resulting
    response would be indistinguishable from a correct one -- the failure would
    only appear later, in production, on a malformed file. Recording the call
    makes the route itself observable.

    Raising as well as recording means a wrong implementation fails loudly
    whichever way it handles the error: if it lets the exception through, the
    test reports this message; if it swallows it into an error response, the
    explicit ``== []`` assertion in each test reports the call.
    """
    from automated_security_helper.interactions import run_ash_scan as module

    calls: List[Tuple[tuple, dict]] = []

    def _record(*args, **kwargs):
        calls.append((args, kwargs))
        raise RuntimeError(
            "the MCP workspace path called interactions.run_ash_scan, which "
            "calls sys.exit on a non-zero workspace exit code; it must call "
            "resolve_workspace and execute_workspace directly instead"
        )

    monkeypatch.setattr(module, "run_ash_scan", _record)
    return calls


# ---------------------------------------------------------------------------
# 1. A malformed workspace file is an error response, not a process exit
# ---------------------------------------------------------------------------


class TestMalformedWorkspaceDoesNotExit:
    """The case that would kill the server: a workspace file ASH cannot use."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", TOOL_NAMES)
    async def test_invalid_json_returns_an_error_response(
        self, tmp_path, tool_name, no_cli_entry_point
    ):
        """Bad JSON reaches ``load_workspace_file``, which raises exit-4.

        Not a contrived injection: this is the shape an operator produces by
        leaving a trailing comma in a file VS Code itself tolerates.
        """
        broken = tmp_path / "dev.code-workspace"
        broken.write_text('{"folders": [{"path": "api"},]}', encoding="utf-8")

        response = await _call(_tool(tool_name), workspace_file=str(broken))

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR)
        assert _documented(response["exit_code"]) == (
            "workspace definition or policy error"
        )
        assert no_cli_entry_point == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", TOOL_NAMES)
    async def test_a_folder_that_does_not_exist_returns_an_error_response(
        self, tmp_path, tool_name, no_cli_entry_point
    ):
        """The other everyday malformation: a project nobody cloned.

        Kept alongside the bad-JSON case because the two fail at different
        points -- parsing versus ``_apply_existence_checks`` -- and an
        implementation that wrapped only the parse would pass one and not the
        other.
        """
        _project(tmp_path, "api")
        workspace = _workspace(tmp_path, ["api", "never-cloned"])

        response = await _call(_tool(tool_name), workspace_file=str(workspace))

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR)
        assert no_cli_entry_point == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", TOOL_NAMES)
    async def test_an_absent_workspace_file_returns_an_error_response(
        self, tmp_path, tool_name, no_cli_entry_point
    ):
        """A path that names nothing. The tool must not resolve it to the cwd.

        ``load_workspace_file`` checks existence first, so this is exit-4 too.
        Included because "the file is not there" is the most likely thing a
        client gets wrong, and an unhandled ``FileNotFoundError`` here would
        surface as the generic internal-error code rather than as the workspace
        code that tells the caller what to fix.
        """
        absent = tmp_path / "nothing-here.code-workspace"
        assert not absent.exists()

        response = await _call(_tool(tool_name), workspace_file=str(absent))

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR)
        assert no_cli_entry_point == []


# ---------------------------------------------------------------------------
# 2. The three exception classes map to the three documented codes
# ---------------------------------------------------------------------------


class TestExceptionToExitCodeMapping:
    """Each raise type becomes the code ``core/constants.py`` documents for it.

    Injected rather than provoked, for two reasons. "Anything else" has no
    natural trigger -- an internal error is by definition not something a
    workspace file can ask for -- and provoking the other two through real
    inputs would test the resolver's classification a second time rather than
    this module's mapping.

    The fixture workspace is valid throughout, so an injection that failed to
    take effect resolves cleanly and the assertion fails.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", TOOL_NAMES)
    async def test_workspace_definition_error_is_four(
        self, tmp_path, monkeypatch, tool_name, no_cli_entry_point
    ):
        workspace = _valid_workspace(tmp_path)
        _make_resolution_raise(
            monkeypatch, WorkspaceDefinitionError("two entries name one directory")
        )

        response = await _call(_tool(tool_name), workspace_file=str(workspace))

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR)
        assert _documented(response["exit_code"]) == (
            "workspace definition or policy error"
        )
        assert "two entries name one directory" in response["error"]
        assert no_cli_entry_point == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", TOOL_NAMES)
    async def test_config_validation_error_is_three(
        self, tmp_path, monkeypatch, tool_name, no_cli_entry_point
    ):
        """3, not 4. The distinction routes to a different person.

        A workspace error means the workspace definition is wrong, which is the
        operator's file. An invalid project config means the workspace is fine
        and one project's own config is not, which is that project's owner. The
        resolver keeps the exception type separate for exactly this reason and
        the MCP surface has to preserve it.
        """
        workspace = _valid_workspace(tmp_path)
        _make_resolution_raise(
            monkeypatch, ASHConfigValidationError("project 'api' has a bad config")
        )

        response = await _call(_tool(tool_name), workspace_file=str(workspace))

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.INVALID_PROJECT_CONFIG)
        assert _documented(response["exit_code"]) == "invalid config"
        assert "project 'api' has a bad config" in response["error"]
        assert no_cli_entry_point == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", TOOL_NAMES)
    async def test_any_other_exception_is_one(
        self, tmp_path, monkeypatch, tool_name, no_cli_entry_point
    ):
        """An unexpected failure is an internal error, not a workspace error.

        Reporting an ASH bug as exit 4 would send the operator to inspect a
        workspace file that is correct. This is also the arm that stops the
        other two passing by accident: an implementation with a single
        ``except Exception`` returning 4 satisfies the first test and fails
        this one.
        """
        workspace = _valid_workspace(tmp_path)
        _make_resolution_raise(monkeypatch, RuntimeError("an ASH bug, not yours"))

        response = await _call(_tool(tool_name), workspace_file=str(workspace))

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.INTERNAL_ERROR)
        assert _documented(response["exit_code"]) == ("scan errors / scanner failures")
        assert no_cli_entry_point == []


# ---------------------------------------------------------------------------
# 3. The execution stage is wrapped too, not only resolution
# ---------------------------------------------------------------------------


class TestExecutionStageFailuresAlsoMap:
    """``execute_workspace`` raises as well, and its raises map the same way.

    Easy to get wrong by wrapping only the ``resolve_workspace`` call: the
    happy path then works, every resolution failure maps correctly, and the
    execution-stage refusals -- an enabled reporter that cannot produce a
    workspace artefact, a project that is not a git repository under
    ``precommit`` -- fall through to whatever the outer handler does.
    """

    @pytest.mark.asyncio
    async def test_a_workspace_error_from_execution_is_four(
        self, tmp_path, monkeypatch, no_cli_entry_point
    ):
        workspace = _valid_workspace(tmp_path)
        _make_execution_raise(
            monkeypatch,
            WorkspaceDefinitionError("reporter(s) sarif cannot run in workspace mode"),
        )

        response = await _call(
            _tool("mcp_scan_workspace"), workspace_file=str(workspace)
        )

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.WORKSPACE_ERROR)
        assert "cannot run in workspace mode" in response["error"]
        assert no_cli_entry_point == []

    @pytest.mark.asyncio
    async def test_an_unexpected_error_from_execution_is_one(
        self, tmp_path, monkeypatch, no_cli_entry_point
    ):
        workspace = _valid_workspace(tmp_path)
        _make_execution_raise(monkeypatch, RuntimeError("thread pool exploded"))

        response = await _call(
            _tool("mcp_scan_workspace"), workspace_file=str(workspace)
        )

        assert response["success"] is False
        assert response["exit_code"] == int(WorkspaceExitCode.INTERNAL_ERROR)
        assert no_cli_entry_point == []


# ---------------------------------------------------------------------------
# 4. Positive control: the mapping is a mapping, not a constant
# ---------------------------------------------------------------------------


class TestSuccessIsReportedAsSuccess:
    """Without this, "return exit code 4 always" satisfies everything above."""

    @pytest.mark.asyncio
    async def test_resolving_a_valid_workspace_succeeds_at_zero(self, tmp_path):
        workspace = _valid_workspace(tmp_path)

        response = await _call(
            _tool("mcp_resolve_workspace"), workspace_file=str(workspace)
        )

        assert response["success"] is True
        assert response["exit_code"] == int(WorkspaceExitCode.SUCCESS)
        assert _documented(response["exit_code"]) == "success"
