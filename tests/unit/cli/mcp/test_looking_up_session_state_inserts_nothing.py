# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Looking up a session's profile state does not create it.

An entry made by a lookup for an id with no workspace is one the TTL sweep and
``end_session`` never find, so a reader must not leave one behind. A lookup of an id
with no binding returns None, so no caller can write into a state that is not stored.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def clean_state():
    profile_registry.clear_all_session_state()
    yield
    profile_registry.clear_all_session_state()


def _known_ids() -> set:
    with profile_registry._session_lock:
        return set(profile_registry._session_state)


def test_a_lookup_of_an_unknown_id_inserts_nothing() -> None:
    state = profile_registry.get_session_state("never-seen")

    assert _known_ids() == set()
    assert state is None


def test_a_lookup_with_no_id_inserts_nothing() -> None:
    state = profile_registry.get_session_state()

    assert _known_ids() == set()
    assert state is None


def test_a_lookup_returns_the_state_a_binding_made() -> None:
    bound = profile_registry.bind_session_config(
        "bound", config=AshConfig(), profile_name="strict"
    )

    assert profile_registry.get_session_state("bound") is bound
    assert _known_ids() == {"bound"}
