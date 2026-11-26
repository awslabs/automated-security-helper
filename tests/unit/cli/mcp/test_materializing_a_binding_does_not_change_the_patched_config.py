# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``materialize_session_binding`` writes files and leaves the configs it was given as they were.

The client's copy of a profile is written with the environment references the
registered profile read, and the function set them on the caller's patched config
to do it, sharing the registry entry's object with the binding's stored config
(``_rematerialize_binding`` passes that stored config in) from outside
``_session_lock``, against the promise that a binding holds its own copies. The
references are now set on a copy that is the one written.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import session_profiles
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


def _stage_that_records_what_it_is_given(monkeypatch):
    seen = []

    def stage(session_id, config, *, client_patched=False, **kwargs):
        seen.append((config, client_patched))
        # Stop before anything is written: the cell is about the arguments.
        raise RuntimeError("stopped before writing")

    monkeypatch.setattr(session_profiles, "_stage_session_config", stage)
    return seen


def test_the_patched_config_is_not_given_the_registered_references(monkeypatch):
    """Red at the base: the patched config was the one handed to the writer, with
    the registered profile's references assigned onto it."""
    registered = AshConfig(project_name="registered")
    registered._environment_references = ("registered-reference",)
    patched = AshConfig(project_name="patched")
    original = patched._environment_references
    seen = _stage_that_records_what_it_is_given(monkeypatch)

    with pytest.raises(RuntimeError, match="stopped before writing"):
        session_profiles.materialize_session_binding(None, registered, patched)

    written, client_patched = seen[0]
    assert client_patched is True
    assert written is not patched
    assert written._environment_references == ("registered-reference",)
    assert patched._environment_references is original


def test_a_patch_that_followed_the_references_is_written_as_it_is(monkeypatch):
    """Control: a config whose references the patch already followed is not given
    the registered profile's, and needs no copy."""
    registered = AshConfig(project_name="registered")
    registered._environment_references = ("registered-reference",)
    patched = AshConfig(project_name="patched")
    patched._environment_references = ("followed-reference",)
    patched._references_followed = True
    seen = _stage_that_records_what_it_is_given(monkeypatch)

    with pytest.raises(RuntimeError, match="stopped before writing"):
        session_profiles.materialize_session_binding(None, registered, patched)

    written, _ = seen[0]
    assert written._environment_references == ("followed-reference",)
