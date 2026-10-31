# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A select_profile that lands while a gone profile file is written again wins.

A bound session whose materialized profile is gone has it written again from
the binding before a scan reads it (``_rematerialize_binding``). That rewrite
read the binding, released the state lock, wrote the files, and only then
checked whether the binding was still the one it read. A ``select_profile``
that landed between the read and the write had its files replaced by the
older profile's: both files existed afterward, so no later read repaired them,
and the session's config held one profile while its state and client rules
said another. The session's write hold keeps the sweep off the workspace but
admits two writers at once, so it did not order the two.

Both writers now take one lock per session around the write
(``profile_registry.binding_writes``), and the rewrite reads the binding again
under it before writing anything: a binding that changed meanwhile is the
answer, and its files are left as the newer select_profile wrote them.
When those files are gone too (a ``clear_source`` between its select_profile and
the rewrite), it is the binding that is written again, from its own profile, and
not a path to nothing.
"""

import contextlib
import threading
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "client-7"


@pytest.fixture
def two_registered_profiles():
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    entries = {
        name: profile_registry.ProfileEntry(
            name=name,
            path=Path(f"/registered/{name}.yaml"),
            config=AshConfig(project_name=name),
            path_sha256="0" * 64,
        )
        for name in ("p", "q")
    }
    profile_registry.set_profile_registry(entries)
    yield entries
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()


def test_the_rewrite_does_not_overwrite_a_binding_made_while_it_ran(
    tmp_path, monkeypatch, two_registered_profiles
):
    """Red at the base: the rewrite of profile p landed p's file after q was
    bound and written, so the session's config file held p while its binding
    said q."""
    entries = two_registered_profiles
    config_dir = tmp_path / "workspaces" / SESSION / "config"
    config_dir.mkdir(parents=True)
    written = config_dir / "ash.yaml"
    rewrite_started = threading.Event()
    let_the_rewrite_finish = threading.Event()
    order = []

    def a_write_that_names_its_profile(session_id, registered, patched=None):
        # The rewrite of the gone file (profile p) is held mid-write until the
        # test says so; select_profile's write (profile q) goes through at once.
        name = registered.project_name
        if name == "p":
            rewrite_started.set()
            if not let_the_rewrite_finish.wait(timeout=10):
                raise RuntimeError("control: the rewrite was never released")
        written.write_text(name, encoding="utf-8")
        order.append(name)
        return str(written), str(written)

    monkeypatch.setattr(
        profile_registry,
        "materialize_session_binding",
        a_write_that_names_its_profile,
    )
    # Bound to p with its file gone, so the next read writes it again.
    profile_registry.bind_session_config(
        SESSION,
        config=entries["p"].config,
        profile_name="p",
        config_path=str(written),
        trusted_config_path=str(written),
    )
    outcomes = {}

    def rewrite_p():
        outcomes["rewrite"] = profile_registry.resolve_session_config_path(SESSION)

    def bind_q():
        outcomes["bind"] = mcp_tools.mcp_select_profile("q", session_id=SESSION)

    rewrite = threading.Thread(target=rewrite_p, name="rewrite-p")
    rewrite.start()
    if not rewrite_started.wait(timeout=10):
        raise RuntimeError("control: the rewrite never reached its write")
    bind = threading.Thread(target=bind_q, name="bind-q")
    bind.start()
    # Give select_profile every chance to run while the rewrite is mid-write:
    # at the base it does, and p's write then lands on top of q's. With the
    # lock it is still waiting a second later, which is what is asserted: a
    # join that returned either way showed nothing about the order.
    bind.join(timeout=1.0)
    waited_on_the_rewrite = bind.is_alive()
    let_the_rewrite_finish.set()
    rewrite.join(timeout=10)
    bind.join(timeout=10)
    if rewrite.is_alive() or bind.is_alive():
        raise RuntimeError(("control: a writer did not finish", order))

    assert waited_on_the_rewrite, "select_profile ran while the rewrite was writing"
    assert outcomes["rewrite"] == str(written), outcomes["rewrite"]
    assert outcomes["bind"].get("success") is True, outcomes["bind"]
    state = profile_registry.get_session_state(SESSION)
    assert state is not None and state.profile_name == "q", state
    assert written.read_text(encoding="utf-8") == "q", (
        "the session's config file holds the older profile",
        order,
    )
    assert order == ["p", "q"], order


@pytest.fixture
def a_bind_lands_before_the_rewrites_hold(
    monkeypatch, tmp_path, two_registered_profiles
):
    """Bound to p with its file gone; a ``select_profile`` of q lands in the window
    between the rewrite's first read of the binding and its taking the session's
    write hold, the window the second read under the lock exists for.

    Returns ``(written, order, after_the_bind)``: the file every write goes to,
    the names written in order, and a list the test appends a callable to, run
    right after q's bind (to take q's files away, say).
    """
    from automated_security_helper.cli.mcp import sessions

    entries = two_registered_profiles
    config_dir = tmp_path / "workspaces" / SESSION / "config"
    config_dir.mkdir(parents=True)
    written = config_dir / "ash.yaml"
    order = []
    after_the_bind = []

    def a_write_that_names_its_profile(session_id, registered, patched=None):
        written.write_text(registered.project_name, encoding="utf-8")
        order.append(registered.project_name)
        return str(written), str(written)

    monkeypatch.setattr(
        profile_registry,
        "materialize_session_binding",
        a_write_that_names_its_profile,
    )
    profile_registry.bind_session_config(
        SESSION,
        config=entries["p"].config,
        profile_name="p",
        config_path=str(written),
        trusted_config_path=str(written),
    )
    real_hold = sessions.writing_session_state
    fired = []

    @contextlib.contextmanager
    def bind_q_first(session_id):
        if not fired:
            # Once: select_profile takes this same hold, and must not bind again.
            fired.append("once")
            outcome = mcp_tools.mcp_select_profile("q", session_id=SESSION)
            assert outcome.get("success") is True, outcome
            for step in after_the_bind:
                step()
        with real_hold(session_id):
            yield

    monkeypatch.setattr(sessions, "writing_session_state", bind_q_first)
    return written, order, after_the_bind


def test_a_binding_made_before_the_hold_is_the_answer_and_p_is_never_written(
    a_bind_lands_before_the_rewrites_hold,
):
    """The second read under the lock. The rewrite read p; q was bound before the
    rewrite held the session; q's files are there, so they are the answer and the
    older profile's file is never written over them."""
    written, order, _ = a_bind_lands_before_the_rewrites_hold

    answered = profile_registry.resolve_session_config_path(SESSION)

    state = profile_registry.get_session_state(SESSION)
    assert state is not None and state.profile_name == "q", state
    assert answered == state.config_path, (answered, state.config_path)
    assert order == ["q"], ("the older profile was written", order)
    assert written.read_text(encoding="utf-8") == "q"


def test_a_newer_binding_whose_files_are_gone_is_written_again_from_itself(
    a_bind_lands_before_the_rewrites_hold,
):
    """Red at the base: the newer binding's paths came back unchecked, so a file
    gone since its select_profile (a clear_source between the two) was answered
    as a path to nothing, and the scan read "config not found". The rewrite now
    writes the newer binding again from its own profile, not the one it read."""
    written, order, after_the_bind = a_bind_lands_before_the_rewrites_hold
    after_the_bind.append(written.unlink)

    answered = profile_registry.resolve_session_config_path(SESSION)

    assert answered is not None and Path(answered).is_file(), answered
    assert written.read_text(encoding="utf-8") == "q", order
    assert order == ["q", "q"], ("select_profile's write, then the rewrite's", order)
    state = profile_registry.get_session_state(SESSION)
    assert state is not None and state.profile_name == "q", state
