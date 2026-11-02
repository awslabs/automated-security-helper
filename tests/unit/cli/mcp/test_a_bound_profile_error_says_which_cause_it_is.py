# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bound profile's error says which of its two causes it is.

``BoundProfileUnavailableError`` has two causes with two owners. The profile is
no longer registered: the caller's config to fix, a config refusal (exit 3). Or
the profile is still registered and the session's workspace could not be
written: the server's failure, for its operator (exit 1, the cause's category,
a warning in the log). The answers used to tell them apart by whether an error
happened to be chained as the cause, so an error built another way, or chained
for another reason, was answered as the other kind. The error now carries
``workspace_unwritable``, set where the writer's failure is wrapped, and every
answer reads it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    BoundProfileUnavailableError,
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import (
    _bound_profile_unavailable,
    mcp_select_profile,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

SESSION = "bound-profile-cause"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    document: Dict[str, Any] = {"project_name": "operator-registered"}
    profile = tmp_path / "op.yaml"
    profile.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={profile}"]))
    yield
    clear_profile_registry()
    clear_all_session_state()


def _bind_and_remove_the_copy() -> None:
    result = mcp_select_profile("op", session_id=SESSION)
    assert result["success"] is True, result
    bound = resolve_session_config_path(SESSION)
    assert bound is not None
    Path(bound).unlink()


def test_an_unregistered_profile_is_not_the_workspace_failure() -> None:
    _bind_and_remove_the_copy()
    clear_profile_registry()

    with pytest.raises(BoundProfileUnavailableError) as refused:
        resolve_session_config_path(SESSION)

    assert refused.value.workspace_unwritable is False


def test_a_workspace_that_cannot_be_written_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from automated_security_helper.cli.mcp import profile_registry

    _bind_and_remove_the_copy()

    def cannot_write(sid, config, patched):
        raise PermissionError(13, "Permission denied", "config")

    monkeypatch.setattr(profile_registry, "materialize_session_binding", cannot_write)

    with pytest.raises(BoundProfileUnavailableError) as refused:
        resolve_session_config_path(SESSION)

    assert refused.value.workspace_unwritable is True
    assert isinstance(refused.value.__cause__, PermissionError)


def test_the_answer_follows_the_flag_not_a_chained_cause() -> None:
    """Red at the base: an error chained from anything was the workspace failure
    (exit 1), whatever it said about itself."""
    try:
        try:
            raise KeyError("some other lookup")
        except KeyError as inner:
            raise BoundProfileUnavailableError("the profile is gone") from inner
    except BoundProfileUnavailableError as error:
        chained = error

    answer = _bound_profile_unavailable(chained, "get_config")

    assert answer["exit_code"] == 3, answer
    assert answer["error_category"] == "file_not_found", answer


def test_a_writer_failure_is_the_servers_even_with_nothing_chained(caplog) -> None:
    """Red at the base: with no chained cause the error was the config refusal
    (exit 3) and nothing was logged."""
    error = BoundProfileUnavailableError(
        "could not be written", workspace_unwritable=True
    )

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        answer = _bound_profile_unavailable(error, "get_config")

    assert answer["exit_code"] == 1, answer
    assert answer["error_category"] == "unexpected_error", answer
    assert any("could not be written" in r.getMessage() for r in caplog.records)


def test_a_permission_error_cause_names_the_permission_category() -> None:
    try:
        try:
            raise PermissionError(13, "Permission denied", "config")
        except PermissionError as inner:
            raise BoundProfileUnavailableError(
                "could not be written", workspace_unwritable=True
            ) from inner
    except BoundProfileUnavailableError as error:
        unwritable = error

    answer = _bound_profile_unavailable(unwritable, "get_config")

    assert answer["exit_code"] == 1, answer
    assert answer["error_category"] == "permission_denied", answer
