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
"""

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
    # at the base it does, and p's write then lands on top of q's.
    bind.join(timeout=1.0)
    let_the_rewrite_finish.set()
    rewrite.join(timeout=10)
    bind.join(timeout=10)
    if rewrite.is_alive() or bind.is_alive():
        raise RuntimeError(("control: a writer did not finish", order))

    assert outcomes["bind"].get("success") is True, outcomes["bind"]
    state = profile_registry.get_session_state(SESSION)
    assert state is not None and state.profile_name == "q", state
    assert written.read_text(encoding="utf-8") == "q", (
        "the session's config file holds the older profile",
        order,
    )
    assert order == ["p", "q"], order
