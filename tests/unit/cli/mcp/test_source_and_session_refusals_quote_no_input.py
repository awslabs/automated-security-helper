# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The source-delivery, session and config refusals quote no input a model refused.

Why this exists
---------------
These refusals put the text of an error they caught into the response a client
reads, or into ``ctx.error``: ``set_source_git``'s refusals, the zipped-source
upload's unavailable workspace, ``check_installation``'s unusable session header
and ``get_config``'s config outside the roots. None of the errors they catch
comes from pydantic today, but each catches a broad type (ValueError, OSError,
RuntimeError) or wraps an error it was given, so one raised from a
ValidationError would reach the client with pydantic's text, which quotes every
refused input. Each is driven here with a ValidationError whose input holds a
canary, or an error raised from one that quotes it, and the canary must not
reach the client.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from automated_security_helper.cli.mcp import source_delivery
from tests.unit.cli.mcp.test_scan_refusal_quotes_no_input import (
    CANARY,
    _validation_error,
)

SESSION = "client-one"


def _raised_from_one(kind: Callable[[str], BaseException]) -> BaseException:
    """``kind`` raised from a ValidationError, with a message that quotes it."""
    error = _validation_error()
    try:
        raise kind(f"it failed: {error}") from error
    except BaseException as wrapped:  # noqa: BLE001 -- returned, not handled
        return wrapped


def _git_command_error(message: str) -> BaseException:
    return source_delivery.GitCommandError(message, source_delivery.GIT_CLONE_FAILED)


@pytest.fixture(autouse=True)
def _control() -> None:
    """The canary is in the text each error carries, so its absence is withheld."""
    assert CANARY in str(_validation_error())
    assert CANARY in str(_raised_from_one(RuntimeError))


def _quotes_nothing(response: Dict[str, Any], *also: str) -> None:
    assert response["success"] is False, response
    text = "\n".join([json.dumps(response, default=str), *also])
    assert CANARY not in text, text


def _raises(error: BaseException) -> Callable[..., Any]:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return _raise


ERRORS_SET_SOURCE_GIT_RAISES = {
    "a ValidationError": _validation_error,
    "a workspace error raised from one": lambda: _raised_from_one(
        source_delivery.SessionWorkspaceError
    ),
    "a git failure raised from one": lambda: _raised_from_one(_git_command_error),
    "a RuntimeError raised from one": lambda: _raised_from_one(RuntimeError),
}


@pytest.mark.parametrize(
    "make", ERRORS_SET_SOURCE_GIT_RAISES.values(), ids=ERRORS_SET_SOURCE_GIT_RAISES
)
def test_set_source_git_refuses_without_the_input(make, monkeypatch) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_set_source_git

    monkeypatch.setattr(source_delivery, "set_source_git", _raises(make()))

    response = mcp_set_source_git(
        "https://example.com/org/repo.git", session_id=SESSION
    )

    _quotes_nothing(response)


@pytest.mark.parametrize("step", ["chunk", "finalize"])
def test_an_upload_whose_workspace_is_unavailable_quotes_no_input(
    step, monkeypatch
) -> None:
    from automated_security_helper.cli import mcp_tools

    error = _raised_from_one(source_delivery.SessionWorkspaceError)
    if step == "chunk":
        monkeypatch.setattr(source_delivery, "set_source_zip_chunk", _raises(error))
        response = mcp_tools.mcp_set_source_zip_chunk(
            "up-1", 0, "", True, session_id=SESSION
        )
    else:
        monkeypatch.setattr(source_delivery, "set_source_zip_finalize", _raises(error))
        response = mcp_tools.mcp_set_source_zip_finalize(
            "up-1", "0" * 64, session_id=SESSION
        )

    assert response["error_type"] == source_delivery.SESSION_WORKSPACE_UNAVAILABLE
    _quotes_nothing(response)


def test_an_unusable_session_header_quotes_no_input(monkeypatch) -> None:
    from automated_security_helper.cli import mcp_server

    monkeypatch.setattr(mcp_server, "resolve_session_id", _raises(_validation_error()))
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": SESSION}
    ctx.error = AsyncMock()
    ctx.info = AsyncMock()

    response = asyncio.run(mcp_server.check_installation(ctx))

    told: List[str] = [str(call.args[0]) for call in ctx.error.await_args_list]
    assert told, "the refusal was not reported to the client"
    _quotes_nothing(response, *told)


def test_a_config_refusal_quotes_no_input(tmp_path: Path, monkeypatch) -> None:
    from automated_security_helper.cli.mcp import sandbox
    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from automated_security_helper.core.resource_management.error_handling import (
        ErrorCategory,
        MCPResourceError,
    )

    validation_error = _validation_error()
    refusal = MCPResourceError(
        f"Config input is outside the permitted roots: {validation_error}",
        context={"error_category": ErrorCategory.INVALID_PATH.value},
    )
    refusal.__cause__ = validation_error
    monkeypatch.setattr(
        sandbox, "validate_config_input", lambda *args, **kwargs: refusal
    )

    response = mcp_get_config(
        config_path=str(tmp_path / ".ash.yaml"), session_id=SESSION
    )

    assert response["error_type"] == "config_input_not_permitted", response
    _quotes_nothing(response)
