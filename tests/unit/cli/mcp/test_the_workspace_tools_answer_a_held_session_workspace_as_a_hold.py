# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace tools answer a session workspace another request holds as a hold.

When a session's bound profile has to be written to its workspace again and the
sweep is removing that workspace, the session's write hold is refused with
``SessionWorkspaceBusyError``, a ``RuntimeError``. ``resolve_workspace`` and
``scan_workspace`` answered it as a config refusal, exit 3, so a client read its
own config as wrong, while every other tool answers the hold under the error's own
``error_type`` with exit 1 and the client sends the request again. They now
answer it as the other tools do.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.cli.mcp.sessions import SessionWorkspaceBusyError
from tests.unit.cli.mcp.test_the_workspace_tools_answer_an_unwritable_workspace_as_the_servers_failure import (
    _ask,
    bound,  # noqa: F401
)

pytestmark = pytest.mark.unit


class _HeldWorkspace:
    """A write hold that is refused on entry, as it is while the sweep removes."""

    def __enter__(self) -> None:
        raise SessionWorkspaceBusyError("the session's workspace is being removed")

    def __exit__(self, *exc_info: object) -> bool:
        return False


def _a_held_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    """The profile stays registered; the session's write hold is refused.

    The hold is raised where the product raises it, on entry to
    ``writing_session_state``, which the bound profile's rewrite takes before
    its try block and imports when it runs.
    """
    from automated_security_helper.cli.mcp import sessions

    monkeypatch.setattr(
        sessions, "writing_session_state", lambda session_id: _HeldWorkspace()
    )


@pytest.mark.parametrize("tool", ["mcp_resolve_workspace", "mcp_scan_workspace"])
def test_a_held_session_workspace_is_a_hold_the_client_retries(
    bound,  # noqa: F811
    monkeypatch,
    tool,
) -> None:
    """Red at the base: exit 3 and INVALID_PROJECT_CONFIG, the config refusal."""
    _a_held_workspace(monkeypatch)

    response = _ask(tool, bound["ws"])

    assert response["success"] is False, response
    assert response["exit_code"] == 1, response
    assert response["error_type"] == SessionWorkspaceBusyError.error_type, response


@pytest.mark.parametrize("operation", ["resolve_workspace", "scan_workspace"])
def test_the_refusal_helper_answers_the_hold_under_the_errors_own_type(
    operation,
) -> None:
    error = SessionWorkspaceBusyError("the session's workspace is being removed")

    response: Dict[str, Any] = workspace_module._session_config_refusal(
        error, operation
    )

    assert response["exit_code"] == 1, response
    assert response["error_type"] == error.error_type, response


def test_another_error_stays_the_config_refusal() -> None:
    """Control, green on both sides: the helper's other answer is not changed."""
    response = workspace_module._session_config_refusal(
        RuntimeError("an error that is not a hold"), "scan_workspace"
    )

    assert response["exit_code"] == 3, response
