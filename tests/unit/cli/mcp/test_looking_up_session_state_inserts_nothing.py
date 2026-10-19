# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Looking up a session's profile state does not create it.

An entry made by a lookup for an id with no workspace is one the TTL sweep and
``end_session`` never find, so a reader must not leave one behind.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config.ash_config import AshConfig


@pytest.fixture(autouse=True)
def clean_state():
    profile_registry.clear_session_state()
    yield
    profile_registry.clear_session_state()


def _known_ids() -> set:
    with profile_registry._session_lock:
        return set(profile_registry._session_state)


def test_a_lookup_of_an_unknown_id_inserts_nothing() -> None:
    state = profile_registry.get_session_state("never-seen")

    assert _known_ids() == set()
    assert state.session_id == "never-seen"
    assert state.bound_config is None
    assert state.profile_name is None


def test_a_lookup_with_no_id_inserts_nothing() -> None:
    profile_registry.get_session_state()

    assert _known_ids() == set()


def test_a_lookup_returns_the_state_a_binding_made() -> None:
    bound = profile_registry.bind_session_config(
        "bound", config=AshConfig(), profile_name="strict"
    )

    assert profile_registry.get_session_state("bound") is bound
    assert _known_ids() == {"bound"}
