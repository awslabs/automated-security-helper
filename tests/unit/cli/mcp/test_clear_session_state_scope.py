# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``clear_session_state(None)`` means the stdio session, never every session.

``session_has_binding`` and the other accessors read ``None`` as the stdio
session (``DEFAULT_SESSION_ID``). A clear whose ``None`` meant "every session"
right next to them was a wipe-everything footgun for anyone trusting that
sentence, so the clear-all arm is its own function,
``clear_all_session_state``. The id is a required argument: a call that names no
session raises ``TypeError`` instead of clearing the stdio session.
"""

from __future__ import annotations

import inspect

import pytest

from automated_security_helper.cli.mcp import profile_registry, sessions
from automated_security_helper.config.ash_config import AshConfig


def test_the_session_id_has_no_default() -> None:
    parameter = inspect.signature(profile_registry.clear_session_state).parameters[
        "session_id"
    ]

    assert parameter.default is inspect.Parameter.empty, (
        "a default lets a caller written for another meaning of a bare call "
        "do less than it expects without an error"
    )


def test_a_call_that_names_no_session_raises_and_clears_nothing() -> None:
    profile_registry.bind_session_config(
        profile_registry.DEFAULT_SESSION_ID,
        config=AshConfig(),
        profile_name="strict",
    )
    profile_registry.bind_session_config(
        "http-3", config=AshConfig(), profile_name="strict"
    )
    try:
        with pytest.raises(TypeError):
            profile_registry.clear_session_state()  # type: ignore[call-arg]

        assert profile_registry.session_has_binding(None)
        assert profile_registry.session_has_binding("http-3")
    finally:
        profile_registry.clear_all_session_state()


def test_clear_session_state_none_clears_only_the_stdio_session() -> None:
    profile_registry.bind_session_config(
        profile_registry.DEFAULT_SESSION_ID,
        config=AshConfig(),
        profile_name="strict",
    )
    profile_registry.bind_session_config(
        "http-1", config=AshConfig(), profile_name="strict"
    )
    try:
        profile_registry.clear_session_state(None)

        assert not profile_registry.session_has_binding(None)
        assert profile_registry.session_has_binding("http-1"), (
            "clearing the stdio session wiped another session's profile"
        )
    finally:
        profile_registry.clear_all_session_state()
    assert not profile_registry.session_has_binding("http-1")
    assert not profile_registry.session_has_binding(None)


def test_clear_all_session_state_drops_every_session() -> None:
    profile_registry.bind_session_config(
        profile_registry.DEFAULT_SESSION_ID,
        config=AshConfig(),
        profile_name="strict",
    )
    profile_registry.bind_session_config(
        "http-2", config=AshConfig(), profile_name="strict"
    )

    profile_registry.clear_all_session_state()

    assert not profile_registry.session_has_binding(None)
    assert not profile_registry.session_has_binding("http-2")


def _bind_the_stdio_session() -> None:
    profile_registry.bind_session_config(
        None, config=AshConfig(), profile_name="strict"
    )


def test_clearing_an_empty_id_leaves_the_stdio_binding() -> None:
    """Only an explicit ``None`` is the stdio session; an empty string is an id."""
    _bind_the_stdio_session()
    try:
        profile_registry.clear_session_state("")

        assert profile_registry.session_has_binding(None), (
            "an empty id dropped the stdio session's binding"
        )
    finally:
        profile_registry.clear_all_session_state()


def test_clearing_an_empty_id_drops_the_binding_made_under_it() -> None:
    """An empty string is an id of its own: clearing it drops what was bound under
    it, and only that, so the stdio session keeps its binding."""
    profile_registry.bind_session_config("", config=AshConfig(), profile_name="strict")
    _bind_the_stdio_session()
    try:
        assert profile_registry.session_has_binding("")

        profile_registry.clear_session_state("")

        assert not profile_registry.session_has_binding("")
        assert profile_registry.session_has_binding(None)
    finally:
        profile_registry.clear_all_session_state()


def test_an_empty_id_has_no_binding_while_the_stdio_session_has_one() -> None:
    _bind_the_stdio_session()
    try:
        assert not profile_registry.session_has_binding("")
        assert profile_registry.session_has_binding(None)
    finally:
        profile_registry.clear_all_session_state()


def test_an_empty_id_looks_up_no_state_while_the_stdio_session_has_one() -> None:
    _bind_the_stdio_session()
    try:
        assert profile_registry.get_session_state("") is None
        assert profile_registry.get_session_state(None) is not None
    finally:
        profile_registry.clear_all_session_state()


def test_ending_an_empty_session_id_leaves_the_stdio_binding(
    tmp_path, monkeypatch
) -> None:
    """``end_session`` reaches ``clear_session_state`` with the id it was given."""
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    sessions.reset_default_registry_for_tests()
    _bind_the_stdio_session()
    try:
        sessions.end_session("")

        assert profile_registry.session_has_binding(None)
    finally:
        profile_registry.clear_all_session_state()
        sessions.reset_default_registry_for_tests()
