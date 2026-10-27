# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The die-now kill removes the recorded cleanup files before the process dies.

Both die-now endings re-raise under ``SIG_DFL``, so the process dies with no
unwinding: a ``finally`` holding a temp file's removal never runs. The
container launcher writes the operator's environment values into a 0600 env
file inside a private temp directory and removes both in such a ``finally``,
so two shutdown signals -- in any order, two SIGTERMs, two Ctrl-Cs, or the
mixed pairs -- left the values on disk. The launcher records the file for the
die-now walk the way it records its child pids; each die-now ending unlinks
the recorded files and removes their directories with plain ``os`` calls
beside the recorded-group kill, and the launcher's own removal discards the
record. A removal that fails must never stall the die-now.

Every cell invokes the installed handlers directly with a synthetic frame and
records the re-raise, as the SIGTERM handler cells do; nothing signals the
test runner. After each die-now the whole temp root is swept: no
``ash-container-env-*`` directory remains and no file left under the root
holds the planted value.
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import CancelEvent

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the installer is deliberately a no-op on Windows: TerminateProcess "
    "ends a process without running Python signal handlers",
)

#: Planted where an operator's environment value would sit in the env file.
_CANARY = "operator-value-mz84q"


@pytest.fixture
def signal_state(monkeypatch):
    """Both handlers' module state fresh -- the latches, scopes, mirrors and
    cleanup records, as the SIGTERM handler cells reset them -- and both
    process signals put back."""
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    monkeypatch.setattr(cancellation, "_SIGTERM_SEEN", False)
    monkeypatch.setattr(cancellation, "_SIGINT_SEEN", False, raising=False)
    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)
    monkeypatch.setattr(cancellation, "_PREVIOUS_SIGTERM", None)
    monkeypatch.setattr(cancellation, "_PREVIOUS_SIGINT", None, raising=False)
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    monkeypatch.setattr(cancellation, "_CLEANUP_FILES", (), raising=False)
    try:
        yield cancellation
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)


@pytest.fixture
def raised_signals(monkeypatch) -> List[int]:
    """Each signal the handler re-raises, recorded instead of delivered."""
    raised: List[int] = []
    monkeypatch.setattr(signal, "raise_signal", raised.append)
    return raised


def _installed_handler():
    handler = signal.getsignal(signal.SIGTERM)
    assert handler is cancellation._handle_sigterm, "the handler is not installed"
    return handler


def _installed_sigint_handler():
    handler = signal.getsignal(signal.SIGINT)
    assert handler is cancellation._handle_sigint, "the handler is not installed"
    return handler


def _recorded_env_file(tmp_path) -> Tuple[Path, Path, Path]:
    """A 0600 env file holding the planted value, recorded for the die-now walk,
    laid out the way the container launcher lays its own out: the file inside
    a private directory of its own under the temp root."""
    temp_root = tmp_path / "temp-root"
    temp_root.mkdir()
    env_dir = temp_root / "ash-container-env-x7q2"
    env_dir.mkdir()
    env_file = env_dir / ".env"
    env_file.write_text(f"ASH_SECRET={_CANARY}\n", encoding="utf-8")
    env_file.chmod(0o600)
    cancellation.record_die_now_cleanup(env_file)
    return temp_root, env_dir, env_file


def _no_trace_left(temp_root: Path) -> None:
    """The sweep: the env directory is gone and nothing left holds the value."""
    assert not list(temp_root.glob("ash-container-env-*")), (
        f"the env directory outlived the die-now: {sorted(temp_root.iterdir())}"
    )
    for path in temp_root.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert _CANARY not in text, (
                f"{path} still holds the operator's value after the die-now"
            )


def test_two_sigterms_remove_the_recorded_env_file(
    signal_state, raised_signals, tmp_path
):
    temp_root, env_dir, env_file = _recorded_env_file(tmp_path)
    signal_state.install_sigterm_shutdown()
    event = CancelEvent()
    with signal_state.shutdown_cancels(event):
        handler = _installed_handler()
        handler(signal.SIGTERM, None)
        assert env_file.exists(), (
            "the first SIGTERM is cooperative: the run step's own finally "
            "owns the removal while the process still unwinds"
        )
        handler(signal.SIGTERM, None)
    assert not env_file.exists(), "the die-now left the env file on disk"
    assert not env_dir.exists(), "the die-now left the env directory on disk"
    _no_trace_left(temp_root)
    assert raised_signals == [signal.SIGTERM]


def test_two_ctrl_cs_remove_the_recorded_env_file(
    signal_state, raised_signals, tmp_path
):
    temp_root, env_dir, env_file = _recorded_env_file(tmp_path)
    signal_state.install_sigint_shutdown()
    event = CancelEvent()
    with signal_state.shutdown_cancels(event):
        handler = _installed_sigint_handler()
        with pytest.raises(KeyboardInterrupt):
            handler(signal.SIGINT, None)
        assert env_file.exists(), (
            "the first Ctrl-C stays an interrupt: the unwinding cleanup owns "
            "the removal"
        )
        handler(signal.SIGINT, None)
    assert not env_file.exists(), "the die-now left the env file on disk"
    assert not env_dir.exists(), "the die-now left the env directory on disk"
    _no_trace_left(temp_root)
    assert raised_signals == [signal.SIGINT]


def test_a_sigterm_then_a_ctrl_c_removes_the_recorded_env_file(
    signal_state, raised_signals, tmp_path
):
    temp_root, env_dir, env_file = _recorded_env_file(tmp_path)
    signal_state.install_sigterm_shutdown()
    signal_state.install_sigint_shutdown()
    event = CancelEvent()
    with signal_state.shutdown_cancels(event):
        _installed_handler()(signal.SIGTERM, None)
        assert env_file.exists()
        # Caught rather than expected, as the mixed-pair group cells do: the
        # broken shape fails this cell's own assertions instead of aborting
        # the run.
        interrupted = False
        try:
            _installed_sigint_handler()(signal.SIGINT, None)
        except KeyboardInterrupt:
            interrupted = True
    assert not interrupted
    assert not env_file.exists(), "the die-now left the env file on disk"
    assert not env_dir.exists(), "the die-now left the env directory on disk"
    _no_trace_left(temp_root)
    assert raised_signals == [signal.SIGINT]


def test_a_ctrl_c_then_a_sigterm_removes_the_recorded_env_file(
    signal_state, raised_signals, tmp_path
):
    temp_root, env_dir, env_file = _recorded_env_file(tmp_path)
    signal_state.install_sigterm_shutdown()
    signal_state.install_sigint_shutdown()
    event = CancelEvent()
    with signal_state.shutdown_cancels(event):
        with pytest.raises(KeyboardInterrupt):
            _installed_sigint_handler()(signal.SIGINT, None)
        assert env_file.exists()
        _installed_handler()(signal.SIGTERM, None)
    assert not env_file.exists(), "the die-now left the env file on disk"
    assert not env_dir.exists(), "the die-now left the env directory on disk"
    _no_trace_left(temp_root)
    assert raised_signals == [signal.SIGTERM]


def test_a_sigterm_with_no_scan_removes_the_recorded_env_file(
    signal_state, raised_signals, tmp_path
):
    """The no-scan branch dies by the default disposition the same way, and a
    launcher's env file can already exist when nothing registered a scope."""
    temp_root, env_dir, env_file = _recorded_env_file(tmp_path)
    signal_state.install_sigterm_shutdown()
    _installed_handler()(signal.SIGTERM, None)
    assert not env_file.exists(), "the die-now left the env file on disk"
    assert not env_dir.exists(), "the die-now left the env directory on disk"
    _no_trace_left(temp_root)
    assert raised_signals == [signal.SIGTERM]


def test_a_discarded_record_is_left_alone(signal_state, raised_signals, tmp_path):
    """The launcher's own finally removes the file and discards the record;
    a later die-now must not reach for a path it no longer owns."""
    temp_root, env_dir, env_file = _recorded_env_file(tmp_path)
    cancellation.discard_die_now_cleanup(env_file)
    signal_state.install_sigterm_shutdown()
    handler = _installed_handler()
    event = CancelEvent()
    with signal_state.shutdown_cancels(event):
        handler(signal.SIGTERM, None)
        handler(signal.SIGTERM, None)
    assert env_file.exists(), (
        "a discarded record was removed by the die-now: the walk owns only "
        "what is still recorded"
    )
    assert raised_signals == [signal.SIGTERM]


def test_a_removal_that_fails_never_stalls_the_die_now(
    signal_state, raised_signals, tmp_path
):
    """A recorded file already gone, and a directory still holding another
    file, leave nothing removable: the die-now must still reach its default
    kill, and the unrelated file must survive."""
    temp_root, env_dir, env_file = _recorded_env_file(tmp_path)
    bystander = env_dir / "unrelated.txt"
    bystander.write_text("kept\n", encoding="utf-8")
    env_file.unlink()
    signal_state.install_sigterm_shutdown()
    handler = _installed_handler()
    event = CancelEvent()
    with signal_state.shutdown_cancels(event):
        handler(signal.SIGTERM, None)
        handler(signal.SIGTERM, None)
    assert raised_signals == [signal.SIGTERM], (
        "a removal with nothing to remove must not replace the default kill "
        "with an exception out of the handler"
    )
    assert bystander.exists(), "a non-empty directory must be left as it is"
    assert env_dir.exists(), (
        "the directory still holds another file, so rmdir has nothing safe to do"
    )
