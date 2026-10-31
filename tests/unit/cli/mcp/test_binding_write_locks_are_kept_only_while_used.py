# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session's binding lock exists only while someone is using it.

``profile_registry.binding_writes`` hands each session id its own lock. The map
of locks once only grew: a server that sees one new id per client (a stateless
server that trusts the upstream session id) kept a lock for every id it had
ever seen. An entry is now created by the first caller and dropped by the last,
whether that caller leaves normally or by an exception.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.profile_registry import binding_writes

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _an_empty_map_of_locks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts from, and reads, a map of its own."""
    monkeypatch.setattr(profile_registry, "_binding_write_locks", {})


def test_a_lock_used_once_is_not_kept() -> None:
    """Red at the base: the entry of each session stayed for the life of the
    server, one per id ever seen."""
    for index in range(25):
        with binding_writes(f"client-{index}"):
            pass

    assert profile_registry._binding_write_locks == {}


def test_the_lock_is_there_while_it_is_held_and_gone_after() -> None:
    with binding_writes("held-session"):
        assert list(profile_registry._binding_write_locks) == ["held-session"]

    assert profile_registry._binding_write_locks == {}


def test_a_nested_use_keeps_the_entry_until_the_outer_use_leaves() -> None:
    """The inner use is the holder taking its lock again. Its leaving must not
    drop the entry the outer use still holds, or a second thread would make a
    new lock beside the one the holder still has."""
    with binding_writes("nested-session"):
        with binding_writes("nested-session"):
            pass
        assert list(profile_registry._binding_write_locks) == ["nested-session"]

    assert profile_registry._binding_write_locks == {}


def test_an_exception_inside_the_use_still_releases_it() -> None:
    with pytest.raises(RuntimeError, match="inside"):
        with binding_writes("failing-session"):
            raise RuntimeError("inside")

    assert profile_registry._binding_write_locks == {}


def test_the_default_session_is_counted_like_any_other() -> None:
    with binding_writes(None):
        assert list(profile_registry._binding_write_locks) == [
            profile_registry.DEFAULT_SESSION_ID
        ]

    assert profile_registry._binding_write_locks == {}
