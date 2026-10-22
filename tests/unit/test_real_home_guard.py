# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The guard on the real ~/.ash watches the right roots and can fail.

tests/conftest.py moves HOME for the run and for each test, which keeps out anything
that finds the home through $HOME. tests/utils/real_home_guard.py catches what finds it
another way, in the test's own process. tests/unit/test_home_isolation.py runs a test
that writes into the developer's ~/.ash in a child pytest, and checks the guard fails it.
"""

import os
import stat
import types
from pathlib import Path

import pytest

from automated_security_helper.utils.download_utils import write_receipt
from tests.utils import real_home_guard


def _finish_session(conftest, session, exitstatus):
    """Drive the root conftest's pytest_sessionfinish as pluggy drives an
    old-style hookwrapper: advance the generator to its yield, then resume it
    with the call outcome. A direct call only returns the generator, so none
    of its body -- the redaction half or the real-home and run-scope
    reporters in its finally -- would run. pluggy sends a Result object; the
    wrapper under test never reads it, so a stand-in with the Result surface
    is sent, and a wrapper that yields a second time -- which pluggy treats
    as an error -- fails here instead of silently dropping its tail."""
    gen = conftest.pytest_sessionfinish(session, exitstatus)
    next(gen)
    outcome = types.SimpleNamespace(
        get_result=lambda: None, exception=None, excinfo=None, force_result=None
    )
    try:
        gen.send(outcome)
    except StopIteration:
        return
    raise AssertionError("pytest_sessionfinish yielded a second time")


def test_the_finish_driver_fails_a_wrapper_that_yields_twice():
    """The drive helper's own control: pluggy treats a second yield as a
    wrapper error, so a conftest regression to a two-yield wrapper fails
    the cells that drive it loudly instead of silently dropping the
    wrapper's tail."""

    def _two_yield_wrapper(session, exitstatus):
        yield
        yield

    stub = types.SimpleNamespace(pytest_sessionfinish=_two_yield_wrapper)
    with pytest.raises(AssertionError, match="second time"):
        _finish_session(stub, types.SimpleNamespace(), pytest.ExitCode.OK)


def test_the_run_watches_the_passwd_home_and_the_home_it_started_with(
    developer_home,
):
    """``~/.ash`` of each, which is where receipts and the default bin directory are."""
    watched = real_home_guard.watched_roots()
    expected = real_home_guard.guarded_roots(
        [real_home_guard.passwd_home(), developer_home]
    )
    assert expected, "no home to guard"
    assert set(expected) <= set(watched), watched


def test_a_receipt_written_with_no_home_of_its_own_stays_in_the_tests_home(
    tmp_path, developer_home
):
    """The shape under test: a receipt written with no HOME of its own set."""
    written = write_receipt(tmp_path / "bin", "fixture-tool", {"sha256": "0" * 64})
    assert written is not None
    assert Path.home() in written.parents
    assert developer_home / ".ash" not in written.parents
    assert real_home_guard.drain() == []


@pytest.mark.skipif(os.name == "nt", reason="the guard's roots are POSIX paths here")
def test_a_write_through_a_link_into_a_guarded_root_is_refused(tmp_path):
    """The path written is elsewhere as text; the directory it lands in is guarded."""
    root = tmp_path / "fake-real-home" / ".ash"
    root.mkdir(parents=True)
    link = tmp_path / "elsewhere"
    link.symlink_to(root, target_is_directory=True)
    with real_home_guard.watching(root):
        with pytest.raises(PermissionError, match="refused by the test guard"):
            (link / "x.json").write_text("{}", encoding="utf-8")
        recorded = real_home_guard.drain()
    assert [event for event, _ in recorded] == ["open"], recorded
    assert not (root / "x.json").exists()


def test_a_hard_link_out_of_a_guarded_root_is_refused(tmp_path):
    """A hard link is the same file, so a later write through it changes the guarded one.

    The link's own path is outside the root; its source is inside.
    """
    root = tmp_path / "fake-real-home" / ".ash"
    root.mkdir(parents=True)
    existing = root / "existing.json"
    existing.write_text("{}", encoding="utf-8")
    outside = tmp_path / "elsewhere.json"
    with real_home_guard.watching(root):
        with pytest.raises(PermissionError, match="refused by the test guard"):
            os.link(existing, outside)
        recorded = real_home_guard.drain()
    assert [event for event, _ in recorded] == ["os.link"], recorded
    assert not outside.exists()
    assert existing.read_text(encoding="utf-8") == "{}"


@pytest.mark.skipif(
    not hasattr(os, "setxattr"), reason="no extended attributes on this platform"
)
def test_an_extended_attribute_under_a_guarded_root_is_refused(tmp_path):
    root = tmp_path / "fake-real-home" / ".ash"
    root.mkdir(parents=True)
    target = root / "tool"
    target.write_text("", encoding="utf-8")
    with real_home_guard.watching(root):
        with pytest.raises(PermissionError, match="refused by the test guard"):
            os.setxattr(target, "user.ash-test", b"1")
        with pytest.raises(PermissionError, match="refused by the test guard"):
            os.removexattr(target, "user.ash-test")
        recorded = real_home_guard.drain()
    assert [event for event, _ in recorded] == ["os.setxattr", "os.removexattr"]


def test_a_write_left_after_the_last_test_fails_the_session(request, tmp_path):
    """A write after the last teardown, or in the xdist controller, is drained at the end.

    Nothing else would report it: the teardown check only runs for a test.
    """
    from tests.unit.test_conftest_helpers import _root_conftest

    conftest = _root_conftest(request.config)
    root = tmp_path / "fake-real-home" / ".ash"
    root.mkdir(parents=True)
    with real_home_guard.watching(root):
        with pytest.raises(PermissionError):
            (root / "late").mkdir()
    session = types.SimpleNamespace(
        exitstatus=pytest.ExitCode.OK,
        config=types.SimpleNamespace(
            pluginmanager=types.SimpleNamespace(get_plugin=lambda name: None)
        ),
    )
    _finish_session(conftest, session, pytest.ExitCode.OK)
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
    assert real_home_guard.drain() == []


def _session(exitstatus=pytest.ExitCode.OK, **config) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        exitstatus=exitstatus,
        config=types.SimpleNamespace(
            pluginmanager=types.SimpleNamespace(get_plugin=lambda name: None),
            **config,
        ),
    )


def test_a_workers_late_write_is_sent_to_its_controller(request, tmp_path):
    """An xdist worker's session end is not the run's: it passes its record on."""
    from tests.unit.test_conftest_helpers import _root_conftest

    conftest = _root_conftest(request.config)
    root = tmp_path / "fake-real-home" / ".ash"
    root.mkdir(parents=True)
    with real_home_guard.watching(root):
        with pytest.raises(PermissionError):
            (root / "late").mkdir()
    session = _session(workerinput={"workerid": "gw3"}, workeroutput={})
    _finish_session(conftest, session, pytest.ExitCode.OK)
    sent = session.config.workeroutput[conftest._WORKER_WRITES_KEY]
    # The worker redacts each path with its own environment's values before
    # sending it, so the comparison goes through the same redaction.
    from tests.utils.env_assertions import redacted_environment_values

    assert sent == [["os.mkdir", redacted_environment_values(str(root / "late"))]], sent
    assert real_home_guard.drain() == []


def test_the_controller_reports_what_its_workers_sent(request, capsys):
    from tests.unit.test_conftest_helpers import _root_conftest

    conftest = _root_conftest(request.config)
    node = types.SimpleNamespace(
        gateway=types.SimpleNamespace(id="gw3"),
        workeroutput={conftest._WORKER_WRITES_KEY: [["open", "/x/.ash/late"]]},
    )
    conftest.pytest_testnodedown(node, None)
    session = _session()
    _finish_session(conftest, session, pytest.ExitCode.OK)
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
    assert "gw3: open: /x/.ash/late" in capsys.readouterr().err
    clean = _session()
    _finish_session(conftest, clean, pytest.ExitCode.OK)
    assert clean.exitstatus == pytest.ExitCode.OK, "a report is made once"


def test_a_worker_that_sent_nothing_fails_nothing(request):
    """A crashed worker has no workeroutput; nothing is invented for it."""
    from tests.unit.test_conftest_helpers import _root_conftest

    conftest = _root_conftest(request.config)
    conftest.pytest_testnodedown(types.SimpleNamespace(), RuntimeError("crashed"))
    session = _session()
    _finish_session(conftest, session, pytest.ExitCode.OK)
    assert session.exitstatus == pytest.ExitCode.OK


@pytest.mark.skipif(os.name == "nt", reason="the guard's roots are POSIX paths here")
def test_the_guard_refuses_and_records_writes_under_a_guarded_root(tmp_path):
    """Control: a guard that never fires would pass every suite.

    Watches a stand-in root and writes through each path the receipt writer uses
    (mkdir, open for write, chmod, replace). Each is refused, so nothing lands, and
    each is recorded, which is what fails a test whose code swallows the refusal.
    Drained before the test ends so the teardown check does not fail this test.
    """
    root = tmp_path / "fake-real-home" / ".ash"
    receipts = root / "install-receipts"
    receipts.mkdir(parents=True)
    existing = receipts / "x.json"
    existing.write_text("{}", encoding="utf-8")
    os.chmod(existing, 0o600)
    writes = {
        "os.mkdir": lambda: (receipts / "new").mkdir(),
        "open": lambda: (receipts / "y.json").write_text("{}", encoding="utf-8"),
        "os.chmod": lambda: os.chmod(existing, 0o644),
        "os.rename": lambda: os.replace(existing, receipts / "z.json"),
    }
    with real_home_guard.watching(root):
        for event, write in writes.items():
            with pytest.raises(PermissionError, match="refused by the test guard"):
                write()
        # A read is not a write.
        assert existing.read_text(encoding="utf-8") == "{}"
        recorded = real_home_guard.drain()
    events = [event for event, _ in recorded]
    assert sorted(set(events)) == sorted(writes), recorded
    assert len([e for e in events if e == "open"]) == 1, recorded
    assert all(str(root) in path for _, path in recorded)
    assert sorted(p.name for p in receipts.iterdir()) == ["x.json"]
    assert stat.S_IMODE(existing.stat().st_mode) == 0o600
