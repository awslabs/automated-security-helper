# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two scans that find a bound profile's files gone write them once, not twice.

``_rematerialize_binding`` takes the session's binding-write lock and, when the
binding is the one it read, wrote the files again unconditionally. Two scans that
both found the files gone (after a ``clear_source``) both reached the lock: the
first wrote the files and updated the binding in place, and the second, which had
waited, saw the same binding and wrote everything again while the first scan was
reading. On Windows that rename waits out the reader for about half a second and
then fails a healthy session as ``BoundProfileUnavailableError``; a failed rename of
the operator copy deletes the client copy the first scan was handed.

The files are looked at again under the lock: when they are there, they are the answer.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.config import session_profiles
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "client-7"


@pytest.fixture
def bound_to_p_with_its_file_gone(tmp_path, monkeypatch):
    session_profiles.clear_profile_registry()
    session_profiles.clear_all_session_state()
    config = AshConfig(project_name="p")
    session_profiles.set_profile_registry(
        {
            "p": session_profiles.ProfileEntry(
                name="p",
                path=Path("/registered/p.yaml"),
                config=config,
                path_sha256="0" * 64,
            )
        }
    )
    config_dir = tmp_path / "workspaces" / SESSION / "config"
    config_dir.mkdir(parents=True)
    written = config_dir / "ash.yaml"
    session_profiles.bind_session_config(
        SESSION,
        config=config,
        profile_name="p",
        config_path=str(written),
        trusted_config_path=str(written),
    )
    yield written
    session_profiles.clear_profile_registry()
    session_profiles.clear_all_session_state()


def _users_of_the_binding_lock() -> int:
    held = session_profiles._binding_write_locks.get(SESSION)
    return 0 if held is None else held.users


def test_the_second_resolve_that_waited_for_the_lock_writes_nothing(
    bound_to_p_with_its_file_gone, monkeypatch
):
    """Red at the base: the second thread wrote the files a second time."""
    written = bound_to_p_with_its_file_gone
    first_is_writing = threading.Event()
    let_the_first_finish = threading.Event()
    writes = []

    def write(session_id, registered, patched=None):
        writes.append(threading.current_thread().name)
        first_is_writing.set()
        if not let_the_first_finish.wait(timeout=10):
            raise RuntimeError("control: the first write was never released")
        written.write_text("p", encoding="utf-8")
        return str(written), str(written)

    monkeypatch.setattr(session_profiles, "materialize_session_binding", write)
    answers = {}

    def resolve(name):
        answers[name] = session_profiles.resolve_session_config_path(SESSION)

    first = threading.Thread(target=resolve, args=("first",), name="first")
    first.start()
    if not first_is_writing.wait(timeout=10):
        raise RuntimeError("control: the first resolve never reached its write")
    second = threading.Thread(target=resolve, args=("second",), name="second")
    second.start()
    deadline = time.monotonic() + 10
    while _users_of_the_binding_lock() < 2:
        if time.monotonic() > deadline:
            raise RuntimeError("control: the second resolve never reached the lock")
        time.sleep(0.01)
    let_the_first_finish.set()
    first.join(timeout=10)
    second.join(timeout=10)
    if first.is_alive() or second.is_alive():
        raise RuntimeError(("control: a resolve did not finish", writes))

    assert writes == ["first"], writes
    assert answers == {"first": str(written), "second": str(written)}, answers
    assert written.read_text(encoding="utf-8") == "p"


def test_a_binding_whose_files_are_still_gone_is_written_by_the_one_that_holds_the_lock(
    bound_to_p_with_its_file_gone, monkeypatch
):
    """Control: the check under the lock does not skip a write that is needed. A
    resolve with the files gone and nobody ahead of it writes them."""
    written = bound_to_p_with_its_file_gone
    writes = []

    def write(session_id, registered, patched=None):
        writes.append(registered.project_name)
        written.write_text("p", encoding="utf-8")
        return str(written), str(written)

    monkeypatch.setattr(session_profiles, "materialize_session_binding", write)

    assert session_profiles.resolve_session_config_path(SESSION) == str(written)
    assert writes == ["p"]
    # And read again with the file there: no second write.
    assert session_profiles.resolve_session_config_path(SESSION) == str(written)
    assert writes == ["p"]
