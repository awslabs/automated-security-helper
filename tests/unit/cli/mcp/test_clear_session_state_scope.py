# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``clear_session_state(None)`` means the stdio session, never every session.

``session_has_binding`` and the other accessors read ``None`` as the stdio
session (``DEFAULT_SESSION_ID``). A clear whose ``None`` meant "every session"
right next to them was a wipe-everything footgun for anyone trusting that
sentence, so the clear-all arm is its own function,
``clear_all_session_state``.
"""

from __future__ import annotations

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config.ash_config import AshConfig


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
