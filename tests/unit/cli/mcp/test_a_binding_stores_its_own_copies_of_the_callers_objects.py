# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A binding is the registry's own copy, not a view of the caller's objects.

``bind_session_config`` stores ``patch_ops`` as a tuple of deep-copied ops and
``config`` as a deep model copy. Without that, the state held the caller's
objects themselves: mutating the list or the config object after binding changed
what ``get_session_state`` returned.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    bind_session_config,
    clear_all_session_state,
    get_session_state,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolate_records():
    clear_all_session_state()
    yield
    clear_all_session_state()


def test_mutating_the_callers_patch_ops_after_binding_changes_nothing() -> None:
    ops = [{"op": "replace", "path": "/project_name", "value": "bound"}]
    bind_session_config(
        "copied", config=AshConfig(project_name="t"), profile_name="p", patch_ops=ops
    )

    ops[0]["value"] = "edited-after-binding"
    ops.append({"op": "add", "path": "/other", "value": 1})

    state = get_session_state("copied")
    assert state is not None
    stored = state.patch_ops
    assert stored == ({"op": "replace", "path": "/project_name", "value": "bound"},)


def test_mutating_a_nested_value_inside_an_op_changes_nothing() -> None:
    """A deep copy, not a shallow tuple(): the ops' own dicts are copied too."""
    ops = [{"op": "add", "path": "/x", "value": {"keep": 1}}]
    bind_session_config(
        "nested", config=AshConfig(project_name="t"), profile_name="p", patch_ops=ops
    )

    ops[0]["value"]["keep"] = 999

    state = get_session_state("nested")
    assert state is not None
    stored = state.patch_ops
    assert stored is not None
    assert stored[0]["value"] == {"keep": 1}


def test_mutating_the_callers_config_after_binding_changes_nothing() -> None:
    config = AshConfig(project_name="before")
    bind_session_config("held", config=config, profile_name="p")

    config.project_name = "after"

    state = get_session_state("held")
    assert state is not None
    bound = state.bound_config
    assert bound is not None
    assert bound.project_name == "before"


def test_an_unpatched_binding_still_reads_none_for_patch_ops() -> None:
    """Control: the copies change nothing about an unpatched binding's shape."""
    bind_session_config("plain", config=AshConfig(project_name="t"), profile_name="p")

    state = get_session_state("plain")
    assert state is not None
    assert state.patch_ops is None
    assert state.profile_name == "p"


def test_an_empty_patch_is_stored_as_an_empty_tuple_and_is_no_client_change() -> None:
    """Control: an empty list of ops is stored as an empty tuple, not collapsed to
    None, so the binding still records that the session chose inherit-and-patch.

    It is not a client's change: ``SessionState.client_changed`` reads a binding
    with no ops as the operator's own profile, which is the rule
    ``session_config_was_patched`` answers by
    (``test_an_empty_patch_leaves_the_profile_the_operators``)."""
    bind_session_config(
        "empty", config=AshConfig(project_name="t"), profile_name="p", patch_ops=[]
    )

    state = get_session_state("empty")
    assert state is not None
    assert state.patch_ops == ()
    assert state.client_changed is False
