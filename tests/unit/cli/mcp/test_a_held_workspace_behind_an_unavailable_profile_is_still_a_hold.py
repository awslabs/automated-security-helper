# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A hold that reaches the workspace tools wrapped is still answered as a hold.

The bound profile's rewrite (``_rematerialize_binding``) catches every
``OSError`` and ``RuntimeError`` of the writer and raises
``BoundProfileUnavailableError(workspace_unwritable=True)`` from it. The hold
``SessionWorkspaceBusyError`` is a ``RuntimeError``, so it reaches
``_session_config_refusal`` as the chained cause of that error and not as the
error itself. The helper looked for the hold only on the error, so a held
workspace was answered as an unwritable one (``bound_profile_unavailable``)
and not under the hold's own ``error_type``. It now looks at the cause first.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.cli.mcp.profile_registry import (
    BoundProfileUnavailableError,
)
from automated_security_helper.cli.mcp.sessions import SessionWorkspaceBusyError
from automated_security_helper.cli.mcp_tools import _bound_profile_unavailable

pytestmark = pytest.mark.unit


def _wrapped(cause: BaseException) -> BoundProfileUnavailableError:
    try:
        try:
            raise cause
        except (OSError, RuntimeError) as exc:
            raise BoundProfileUnavailableError(
                "this session's bound profile could not be written again",
                workspace_unwritable=True,
            ) from exc
    except BoundProfileUnavailableError as wrapped:
        return wrapped


@pytest.mark.parametrize("operation", ["resolve_workspace", "scan_workspace"])
def test_a_hold_behind_the_wrapper_is_answered_under_its_own_type(operation):
    hold = SessionWorkspaceBusyError("the session's workspace is being removed")

    response = workspace_module._session_config_refusal(_wrapped(hold), operation)

    # RED at the base: "bound_profile_unavailable", the unwritable-workspace answer.
    assert response["exit_code"] == 1, response
    assert response["error_type"] == hold.error_type, response


def test_an_unwritable_workspace_behind_the_wrapper_keeps_its_answer():
    """Control, green on both sides: a writer's own failure is not a hold."""
    wrapped = _wrapped(PermissionError("the workspace is read-only"))

    response = workspace_module._session_config_refusal(wrapped, "scan_workspace")

    assert response == _bound_profile_unavailable(wrapped, "scan_workspace")
    assert response["error_type"] == "bound_profile_unavailable", response


def test_a_profile_that_is_no_longer_registered_keeps_its_answer():
    """Control, green on both sides: no chained cause, so no hold."""
    gone = BoundProfileUnavailableError("the bound profile is no longer registered")

    response = workspace_module._session_config_refusal(gone, "scan_workspace")

    assert response == _bound_profile_unavailable(gone, "scan_workspace")
