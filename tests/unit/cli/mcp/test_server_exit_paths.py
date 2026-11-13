# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every way `ash mcp` ends stops its scans and ends their scanners' tools.

A scanner's tool runs in a session of its own (utils/subprocess_utils), so the
server's exit does not end it. Every transport has to stop its scans and kill
the tools' groups on the way out, as the stdio server does; an HTTP transport
that did neither would cancel the scans with the ordinary ten-second grace and
wait on a graceful uvicorn stop, and SIGHUP, which uvicorn does not handle,
would end the process at once, leaving every tool running and writing into
.ash/ash_output.

- The streamable-HTTP and SSE apps stop the scans promptly and kill what is
  left of the tools' groups when their lifespan ends.
- `_run_uvicorn` treats SIGHUP as a request to stop, as it treats SIGTERM, and
  kills what is left of the groups when the server returns or raises.
- The stdio server only watches for SIGTERM on the main thread; started on
  another one, the watcher would raise "set_wakeup_fd only works in main
  thread" into a server that has closed cleanly.
- After the stdio transport returns, a SIGTERM still exits 0. Were the asyncio
  watcher gone by then, while the interpreter waits for scan threads, the
  client's SIGTERM would end the server with -15 (tests/integration/cli/
  test_mcp_stdio_shutdown.py drives this through a real process).
- Ctrl-C (SIGINT) takes the SIGTERM path on stdio, before and after the
  transport returns, and exits 130; so do the HTTP transports, whose Ctrl-C
  uvicorn hands back as KeyboardInterrupt once it has stopped.
- SIGHUP takes the SIGTERM path on stdio too, and exits 0, rather than ending
  the process at once with the tools running and the previous results set aside.
  A process started with SIGHUP ignored, as nohup starts one, keeps it ignored.
- An HTTP server that Ctrl-C or SIGHUP stopped exits once its stop is done,
  with 130 or 0, when a scan busy in Python did not stop. asyncio and then the
  interpreter would otherwise wait for that scan's thread before the process
  could exit.
- A second Ctrl-C, which uvicorn takes as a force quit, kills the tools' groups
  and ends an HTTP server at once, with 130. It skips the app's lifespan;
  without that kill and exit, the server would go on waiting for every
  connection a client kept open, with the tools running
  (tests/integration/cli/test_mcp_http_shutdown.py drives this through a real
  process).
- A SIGINT or SIGHUP the process started with ignored stays ignored on every
  transport. Were uvicorn to replace the SIGINT with a handler of its own, a
  Ctrl-C meant for the job in a shell's foreground would stop an HTTP server
  running in the background; were the server's own SIGHUP handler to replace
  an ignored SIGHUP, closing the terminal would stop a server nohup had
  started.

A SIGKILL cannot be handled; docs/content/docs/mcp-server-guide.md says what it
leaves behind.
"""

from __future__ import annotations

import asyncio
import io
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.utils import subprocess_utils

# Windows has no SIGHUP, and the status tables further down read signal.SIGHUP when
# the module is imported, which raised AttributeError at collection. The whole
# module is about POSIX signals, so it is skipped before those lines run.
if sys.platform == "win32":
    pytest.skip("POSIX signals", allow_module_level=True)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

_SLEEP = [sys.executable, "-c", "import time; time.sleep(60)"]


@pytest.fixture
def recorded_group():
    """A process group recorded as a cancellable spawn's, as a scan's tool is."""
    child = subprocess.Popen(_SLEEP, start_new_session=True)
    subprocess_utils._register_group(child)
    yield child
    if child.poll() is None:
        child.kill()
    child.wait(timeout=10)


def _exited(child: subprocess.Popen) -> bool:
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return False
    return True


@pytest.fixture
def stops(monkeypatch) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []

    async def stop_running_scans(reason, timeout, promptly=False):
        calls.append({"reason": reason, "timeout": timeout, "promptly": promptly})

    monkeypatch.setattr(mcp_server, "stop_running_scans", stop_running_scans)
    return calls


#: A loopback app accepts only its own address, port included, so it is built
#: for the port it listens on (cli/mcp._transport_security). TestClient binds
#: nothing, so any port names the app's own origin here.
_PORT = 8000


def _apps():
    import functools

    from automated_security_helper.cli.mcp import (
        build_sse_app,
        build_streamable_http_app,
    )

    return {
        "streamable-http": functools.partial(build_streamable_http_app, port=_PORT),
        "sse": functools.partial(build_sse_app, port=_PORT),
    }


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
@pytest.mark.integration
def test_an_http_server_that_stops_kills_the_tools_groups(
    transport, recorded_group, stops
):
    from starlette.testclient import TestClient

    with TestClient(_apps()[transport]()):
        assert recorded_group.poll() is None

    assert _exited(recorded_group), (
        f"the {transport} server stopped and left a scanner's tool running"
    )


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
@pytest.mark.unit
def test_an_http_server_that_stops_stops_its_scans_promptly(transport, stops):
    from starlette.testclient import TestClient

    with TestClient(_apps()[transport]()):
        assert stops == []

    assert len(stops) == 1, stops
    assert stops[0]["promptly"] is True, stops


class _FakeServer:
    """uvicorn.Server, reduced to what _run_uvicorn uses."""

    def __init__(self, config) -> None:
        self.config = config
        self.should_exit = False
        self.force_exit = False
        self.ran = False
        # uvicorn's startup sets this before run() serves; the runner reads a
        # server that returned without it as a failed start.
        self.started = False

    def handle_exit(self, sig, frame) -> None:
        if self.should_exit and sig == signal.SIGINT:
            self.force_exit = True
        else:
            self.should_exit = True

    def run(self, sockets=None) -> None:
        self.ran = True
        self.started = True
        handler = signal.getsignal(signal.SIGHUP)
        if callable(handler):
            handler(signal.SIGHUP, None)


@pytest.fixture
def fake_uvicorn(monkeypatch):
    """uvicorn.Server replaced by a _FakeServer class that records its instances.

    A class, not a factory function: _run_uvicorn subclasses the server class
    _uvicorn_server_class returns (its ``startup`` logs where a socket ASH bound
    listens), so a function in uvicorn.Server's place fails the subclass statement
    with "function() argument 'code' must be code, not str".

    And SIGINT not ignored when ASH started, as for a server in the foreground:
    that is read from the process (cli.SIGINT_IGNORED_AT_START), and in a test run
    started as ``cmd &`` it is ignored. The server for an ignored SIGINT is tested
    with uvicorn's own, by test_an_http_server_leaves_a_sigint_ignored_at_start_ignored.
    """
    import uvicorn

    from automated_security_helper import cli

    monkeypatch.setattr(cli, "SIGINT_IGNORED_AT_START", False)
    servers: List[_FakeServer] = []

    class _RecordedFakeServer(_FakeServer):
        def __init__(self, config) -> None:
            super().__init__(config)
            servers.append(self)

    monkeypatch.setattr(uvicorn, "Server", _RecordedFakeServer)
    return servers


@pytest.fixture
def sighup_left_alone():
    """A SIGHUP handler of the test's own, so nothing here can end the worker."""
    seen: List[int] = []

    def sentinel(signum, frame):
        seen.append(signum)

    previous = signal.signal(signal.SIGHUP, sentinel)
    yield sentinel
    signal.signal(signal.SIGHUP, previous)


@pytest.mark.unit
def test_the_http_servers_wait_for_open_requests_is_bounded_at_5_seconds(
    fake_uvicorn, sighup_left_alone
):
    """So that the whole stop, with the scans' prompt stop after the wait, ends
    inside the 10 s docker stop gives a container before SIGKILL."""
    from automated_security_helper.cli.mcp import _run_uvicorn
    from automated_security_helper.core.enums import AshLogLevel

    _run_uvicorn(object(), "127.0.0.1", 0, AshLogLevel.INFO)

    (server,) = fake_uvicorn
    assert server.config.timeout_graceful_shutdown == 5


@pytest.mark.unit
def test_sighup_asks_the_http_server_to_stop(fake_uvicorn, sighup_left_alone):
    from automated_security_helper.cli.mcp import _run_uvicorn
    from automated_security_helper.core.enums import AshLogLevel

    _run_uvicorn(object(), "127.0.0.1", 0, AshLogLevel.INFO)

    (server,) = fake_uvicorn
    assert server.ran
    assert server.should_exit, "SIGHUP did not ask uvicorn to stop"
    assert signal.getsignal(signal.SIGHUP) is sighup_left_alone, (
        "the previous SIGHUP handler was not put back"
    )


@pytest.fixture
def sighup_ignored():
    """SIGHUP ignored, as nohup starts a command, and put back afterwards."""
    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    yield
    signal.signal(signal.SIGHUP, previous)


@pytest.mark.unit
def test_an_http_server_leaves_a_sighup_ignored_at_start_ignored(
    fake_uvicorn, sighup_ignored
):
    """So that one nohup started outlives its terminal, as a stdio server does."""
    from automated_security_helper.cli.mcp import _run_uvicorn
    from automated_security_helper.core.enums import AshLogLevel

    _run_uvicorn(object(), "127.0.0.1", 0, AshLogLevel.INFO)

    (server,) = fake_uvicorn
    assert server.ran
    assert not server.should_exit, "a SIGHUP the process ignored stopped the server"
    assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN


@pytest.mark.unit
def test_the_signal_that_stops_the_http_server_is_noted_while_it_runs(
    monkeypatch, fake_uvicorn, sighup_left_alone
):
    from automated_security_helper.cli import mcp as cli_mcp
    from automated_security_helper.core.enums import AshLogLevel

    noted: List[Optional[int]] = []
    run = _FakeServer.run

    def run_and_note(self, sockets=None) -> None:
        run(self, sockets=sockets)
        noted.append(cli_mcp._stop_signal)

    monkeypatch.setattr(_FakeServer, "run", run_and_note)
    monkeypatch.setattr(cli_mcp, "_stop_signal", None)

    cli_mcp._run_uvicorn(object(), "127.0.0.1", 0, AshLogLevel.INFO)

    assert noted == [signal.SIGHUP], noted
    assert cli_mcp._stop_signal is None, "the stop signal outlived the server"


@pytest.mark.unit
def test_a_sigint_the_http_server_drops_is_not_noted(
    monkeypatch, stop_signals_put_back
):
    from automated_security_helper import cli
    from automated_security_helper.cli import mcp as cli_mcp

    monkeypatch.setattr(cli, "SIGINT_IGNORED_AT_START", True)
    monkeypatch.setattr(cli_mcp, "_stop_signal", None)
    server = _uvicorn_server()
    cli_mcp._note_the_signal_that_stops(server)

    server.handle_exit(signal.SIGINT, None)
    assert cli_mcp._stop_signal is None
    server.handle_exit(signal.SIGTERM, None)
    server.handle_exit(signal.SIGINT, None)
    assert cli_mcp._stop_signal == signal.SIGTERM


@pytest.mark.unit
def test_the_http_servers_stop_handler_is_bound_to_the_server(
    monkeypatch, stop_signals_put_back
):
    """As uvicorn's own handler is. sse_starlette finds the server from the
    SIGTERM handler's __self__, to end its event streams when the server stops,
    if its patch of uvicorn's Server.handle_exit did not take."""
    from automated_security_helper import cli
    from automated_security_helper.cli import mcp as cli_mcp

    monkeypatch.setattr(cli, "SIGINT_IGNORED_AT_START", False)
    server = _uvicorn_server()
    cli_mcp._note_the_signal_that_stops(server)

    with server.capture_signals():
        handler = signal.getsignal(signal.SIGTERM)
    assert getattr(handler, "__self__", None) is server, handler


@pytest.fixture
def forced_exits(monkeypatch) -> List[int]:
    """The statuses exit_at_once would have exited with, for a server whose
    second SIGINT is uvicorn's force quit."""
    from automated_security_helper import cli
    from automated_security_helper.cli import mcp as cli_mcp

    exits: List[int] = []
    monkeypatch.setattr(cli, "SIGINT_IGNORED_AT_START", False)
    monkeypatch.setattr(cli_mcp, "_stop_signal", None)
    monkeypatch.setattr(mcp_server.os, "_exit", exits.append)
    monkeypatch.setattr(mcp_server.logging, "shutdown", lambda: None)
    return exits


@pytest.mark.integration
def test_a_second_ctrl_c_ends_the_tools_and_the_http_server_from_the_loop(
    forced_exits, recorded_group
):
    """uvicorn's force quit skips the lifespan that stops the scans, and its
    server then waits on for the open connections, so the exit is made here.

    On the event loop, after the handler: one run in the handler could interrupt
    kill_running_groups while it holds its lock, or a write to stdout."""
    from automated_security_helper.cli import mcp as cli_mcp

    server = _uvicorn_server()
    cli_mcp._note_the_signal_that_stops(server)

    async def ctrl_c_twice() -> List[List[int]]:
        seen = []
        server.handle_exit(signal.SIGINT, None)
        await asyncio.sleep(0)
        seen.append(list(forced_exits))
        server.handle_exit(signal.SIGINT, None)
        seen.append(list(forced_exits))
        await asyncio.sleep(0)
        seen.append(list(forced_exits))
        # Only the Ctrl-C that forces the stop exits; another one does not again.
        server.handle_exit(signal.SIGINT, None)
        await asyncio.sleep(0)
        seen.append(list(forced_exits))
        return seen

    seen = asyncio.run(ctrl_c_twice())

    assert seen == [[], [], [130], [130]], seen
    assert server.force_exit
    assert cli_mcp._stop_signal == signal.SIGINT
    assert _exited(recorded_group), "the forced exit left a scanner's tool running"


@pytest.mark.integration
def test_a_ctrl_c_that_forces_the_stop_outside_the_loop_exits_at_once(
    forced_exits, recorded_group
):
    from automated_security_helper.cli import mcp as cli_mcp

    server = _uvicorn_server()
    cli_mcp._note_the_signal_that_stops(server)

    server.handle_exit(signal.SIGINT, None)
    assert forced_exits == []
    server.handle_exit(signal.SIGINT, None)

    assert forced_exits == [130], forced_exits
    assert _exited(recorded_group), "the forced exit left a scanner's tool running"


@pytest.mark.integration
def test_signals_that_do_not_force_the_http_server_to_stop_do_not_exit(
    forced_exits, recorded_group
):
    """uvicorn forces a stop on a second SIGINT only; SIGTERM and SIGHUP after a
    first signal leave the graceful stop to finish."""
    from automated_security_helper.cli import mcp as cli_mcp

    server = _uvicorn_server()
    cli_mcp._note_the_signal_that_stops(server)

    server.handle_exit(signal.SIGTERM, None)
    server.handle_exit(signal.SIGTERM, None)
    server.handle_exit(signal.SIGHUP, None)

    assert not server.force_exit
    assert forced_exits == []
    assert recorded_group.poll() is None


#: The status an HTTP server a signal stopped exits with when a scan did not
#: stop, or None where it is left to uvicorn.
_HTTP_EXIT_STATUS = {signal.SIGINT: 130, signal.SIGHUP: 0, signal.SIGTERM: None}


@pytest.mark.parametrize("still_running", [True, False], ids=["busy", "stopped"])
@pytest.mark.parametrize(
    "signum",
    [signal.SIGINT, signal.SIGHUP, signal.SIGTERM, None],
    ids=["sigint", "sighup", "sigterm", "no-signal"],
)
@pytest.mark.integration
def test_an_http_server_exits_once_its_stop_is_done_if_a_scan_did_not_stop(
    monkeypatch, recorded_group, signum, still_running
):
    """Without waiting for the scan's thread, which asyncio and then the
    interpreter would wait for, as a stdio server exits after the same stop."""
    from starlette.testclient import TestClient

    from automated_security_helper.cli import mcp as cli_mcp

    exits: List[int] = []
    stopped: List[bool] = []

    async def stop_running_scans(reason, timeout, promptly=False):
        stopped.append(promptly)
        return still_running

    monkeypatch.setattr(mcp_server, "stop_running_scans", stop_running_scans)
    monkeypatch.setattr(mcp_server.os, "_exit", exits.append)
    monkeypatch.setattr(mcp_server.logging, "shutdown", lambda: None)
    monkeypatch.setattr(cli_mcp, "_stop_signal", signum)

    with TestClient(_apps()["streamable-http"]()):
        pass

    status = _HTTP_EXIT_STATUS.get(signum)
    assert stopped == [True], stopped
    assert exits == ([status] if still_running and status is not None else []), exits
    assert _exited(recorded_group), "the server stopped and left a scanner's tool"


@pytest.mark.integration
def test_an_http_server_that_fails_kills_the_tools_groups(
    monkeypatch, fake_uvicorn, sighup_left_alone, recorded_group
):
    from automated_security_helper.cli.mcp import _run_uvicorn
    from automated_security_helper.core.enums import AshLogLevel

    def crash(self, sockets=None) -> None:
        raise RuntimeError("the server failed")

    monkeypatch.setattr(_FakeServer, "run", crash)

    with pytest.raises(RuntimeError, match="the server failed"):
        _run_uvicorn(object(), "127.0.0.1", 0, AshLogLevel.INFO)

    assert _exited(recorded_group), "the failed server left a scanner's tool running"


async def _a_transport_that_yields() -> None:
    for _ in range(3):
        await asyncio.sleep(0.01)


@pytest.mark.unit
def test_a_stdio_server_on_a_worker_thread_closes_cleanly(monkeypatch):
    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _a_transport_that_yields)
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: False)
    raised: Dict[str, BaseException] = {}

    def serve() -> None:
        try:
            asyncio.run(mcp_server._serve_stdio())
        except BaseException as error:  # noqa: BLE001 -- what the test is about
            raised["error"] = error

    thread = threading.Thread(target=serve)
    thread.start()
    thread.join(timeout=30)

    assert not thread.is_alive()
    assert "error" not in raised, repr(raised.get("error"))


#: The exit status each signal gets from a stdio server.
_STOP_STATUS = {signal.SIGTERM: 0, signal.SIGINT: 130, signal.SIGHUP: 0}

_STOP_SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]
_STOP_SIGNAL_IDS = ["sigterm", "sigint", "sighup"]


def _left_alone(signum, frame) -> None:
    """A SIGHUP handler of the test's own: not ignored, and ends nothing."""


@pytest.fixture
def stop_signals_put_back():
    """The stop signals' handlers as they were, after a test that sets them.

    _serve_stdio leaves its late handlers for each, which exit the process.
    Meanwhile SIGINT gets Python's own handler and SIGHUP one of the test's own,
    so that a worker started with either ignored (in the background, or by
    nohup) watches what any other worker watches.
    """
    previous = {signum: signal.getsignal(signum) for signum in _STOP_STATUS}
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGHUP, _left_alone)
    yield previous
    for signum, handler in previous.items():
        signal.signal(signum, handler)


@pytest.mark.parametrize("signum", _STOP_SIGNALS, ids=_STOP_SIGNAL_IDS)
@pytest.mark.unit
def test_a_signal_after_the_stdio_transport_returns_still_stops_the_server(
    monkeypatch, stop_signals_put_back, signum
):
    """The handler the stdio server leaves for each signal once its watcher is gone."""
    exits: List[int] = []

    def recorded_exit(code: int) -> None:
        exits.append(code)

    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _a_transport_that_yields)
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: False)
    monkeypatch.setattr(mcp_server.os, "_exit", recorded_exit)
    monkeypatch.setattr(mcp_server.logging, "shutdown", lambda: None)
    asyncio.run(mcp_server._serve_stdio())
    handler = signal.getsignal(signum)
    assert callable(handler) and handler not in (
        stop_signals_put_back[signum],
        signal.SIG_DFL,
        signal.default_int_handler,
        _left_alone,
    ), (
        f"{signal.Signals(signum).name} is left to {handler!r} once the transport returns"
    )
    handler(signum, None)

    assert exits == [_STOP_STATUS[signum]], exits


def _receiver_delivering(signum: Optional[int], subscribed: List[tuple]):
    """anyio.open_signal_receiver, delivering ``signum`` once, or nothing for None.

    Records the signals it was opened for, so the process is never signalled.
    """

    class _Receiver:
        def __init__(self, *signals) -> None:
            subscribed.append(signals)

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> bool:
            return False

        def __aiter__(self):
            return self._one()

        async def _one(self):
            if signum is not None:
                yield signum

    return _Receiver


@pytest.mark.parametrize("signum", _STOP_SIGNALS, ids=_STOP_SIGNAL_IDS)
@pytest.mark.integration
def test_a_signal_while_serving_stops_the_scans_promptly_then_exits(
    monkeypatch, stops, recorded_group, stop_signals_put_back, signum
):
    """The watcher: SIGTERM and SIGHUP exit 0, Ctrl-C 130, all after the same stop."""
    exits: List[int] = []
    subscribed: List[tuple] = []

    monkeypatch.setattr(
        mcp_server.anyio,
        "open_signal_receiver",
        _receiver_delivering(signum, subscribed),
    )
    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _a_transport_that_yields)
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: False)
    # Recorded, not raised: the watcher then waits for the next signal, and the
    # transport returns as it would have.
    monkeypatch.setattr(mcp_server.os, "_exit", exits.append)
    monkeypatch.setattr(mcp_server.logging, "shutdown", lambda: None)

    asyncio.run(mcp_server._serve_stdio())

    assert len(subscribed) == 1 and set(subscribed[0]) == set(_STOP_STATUS), subscribed
    assert exits == [_STOP_STATUS[signum]], exits
    assert len(stops) == 1 and stops[0]["promptly"] is True, stops
    assert signal.Signals(signum).name in stops[0]["reason"], stops
    assert _exited(recorded_group), "the server exited and left a scanner's tool"


@pytest.mark.unit
def test_a_sigint_ignored_at_start_stays_ignored(monkeypatch, stop_signals_put_back):
    """A shell starts a background job with SIGINT ignored, so that Ctrl-C reaches
    only the job in the foreground. The server leaves it ignored, as Python and
    asyncio do; SIGTERM and SIGHUP are still watched."""
    subscribed: List[tuple] = []

    monkeypatch.setattr(
        mcp_server.anyio, "open_signal_receiver", _receiver_delivering(None, subscribed)
    )
    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _a_transport_that_yields)
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: False)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    asyncio.run(mcp_server._serve_stdio())

    assert len(subscribed) == 1, subscribed
    assert set(subscribed[0]) == {signal.SIGTERM, signal.SIGHUP}, subscribed
    assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN


@pytest.mark.unit
def test_a_sighup_ignored_at_start_stays_ignored(monkeypatch, stop_signals_put_back):
    """nohup starts a command with SIGHUP ignored, so that it outlives the terminal
    it was started from. The server leaves it ignored, as it leaves an ignored
    SIGINT, while it serves and once the transport has returned; SIGTERM and
    Ctrl-C are still watched."""
    subscribed: List[tuple] = []

    monkeypatch.setattr(
        mcp_server.anyio, "open_signal_receiver", _receiver_delivering(None, subscribed)
    )
    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _a_transport_that_yields)
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: False)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    asyncio.run(mcp_server._serve_stdio())

    assert len(subscribed) == 1, subscribed
    assert set(subscribed[0]) == {signal.SIGTERM, signal.SIGINT}, subscribed
    assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN


def _uvicorn_server():
    """The server _run_uvicorn would run, not started."""
    import uvicorn

    from automated_security_helper.cli.mcp import _uvicorn_server_class

    # log_config=None, or uvicorn reconfigures the worker's logging.
    return _uvicorn_server_class()(uvicorn.Config(app=object(), log_config=None))


@pytest.mark.unit
def test_an_http_server_leaves_a_sigint_ignored_at_start_ignored(
    monkeypatch, stop_signals_put_back
):
    """uvicorn points SIGINT at its own handler whatever was set; SIGTERM still
    asks the server to stop."""
    from automated_security_helper import cli

    monkeypatch.setattr(cli, "SIGINT_IGNORED_AT_START", True)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    server = _uvicorn_server()

    with server.capture_signals():
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
        assert signal.getsignal(signal.SIGTERM) == server.handle_exit
        # A SIGINT delivered before the server ignored it again.
        server.handle_exit(signal.SIGINT, None)
    assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    assert not server.should_exit, "a SIGINT the process ignored stopped the server"

    # Outside capture_signals, which raises a signal it handled again on its way
    # out, and SIGTERM would end the worker.
    server.handle_exit(signal.SIGTERM, None)
    assert server.should_exit, "SIGTERM no longer stops the server"


@pytest.mark.unit
def test_an_http_server_is_uvicorns_own_when_sigint_was_not_ignored(monkeypatch):
    import uvicorn

    from automated_security_helper import cli
    from automated_security_helper.cli.mcp import _uvicorn_server_class

    monkeypatch.setattr(cli, "SIGINT_IGNORED_AT_START", False)

    assert _uvicorn_server_class() is uvicorn.Server


@pytest.mark.parametrize("claims_fd_1", [True, False])
@pytest.mark.unit
def test_stdout_is_taken_off_the_wire_only_when_the_transport_had_it(
    monkeypatch, stop_signals_put_back, claims_fd_1
):
    """When sys.stdout is fd 1, the transport hands fd 1 back to the client's pipe."""
    diverted: List[bool] = []

    monkeypatch.setattr(mcp_server.mcp, "run_stdio_async", _a_transport_that_yields)
    monkeypatch.setattr(mcp_server, "_stdout_is_fd_1", lambda: claims_fd_1)
    monkeypatch.setattr(
        mcp_server, "_keep_stdout_off_the_wire", lambda: diverted.append(True)
    )
    asyncio.run(mcp_server._serve_stdio())

    assert diverted == ([True] if claims_fd_1 else []), diverted


@pytest.mark.unit
def test_the_stdio_lifespan_flushes_stdout_before_the_transport_gets_it_back(
    monkeypatch, stops
):
    """While fd 1 still points at stderr, so nothing buffered reaches the wire."""
    flushed: List[bool] = []

    monkeypatch.setattr(mcp_server, "_serving_stdio", True)
    monkeypatch.setattr(mcp_server, "_flush_stdout", lambda: flushed.append(True))

    async def serve_and_leave() -> None:
        async with mcp_server._lifespan(mcp_server.mcp):
            pass

    asyncio.run(serve_and_leave())

    assert stops and stops[0]["promptly"] is True, stops
    assert flushed == [True], flushed


class _FlushRaises:
    """A stdout whose flush raises ``error``."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    def flush(self) -> None:
        raise self._error


@pytest.mark.parametrize(
    "error",
    [
        OSError("broken pipe"),
        ValueError("I/O operation on closed file"),
        RuntimeError("reentrant call inside <_io.BufferedWriter name='<stdout>'>"),
    ],
    ids=["os-error", "value-error", "runtime-error"],
)
@pytest.mark.unit
def test_flushing_stdout_for_the_exit_swallows_what_a_flush_can_raise(
    monkeypatch, error
):
    monkeypatch.setattr(sys, "stdout", _FlushRaises(error))

    mcp_server._flush_stdout()


@pytest.mark.unit
def test_flushing_stdout_for_the_exit_does_not_swallow_every_error(monkeypatch):
    """The control: the catch is for those three, not for whatever a flush raises."""
    monkeypatch.setattr(sys, "stdout", _FlushRaises(KeyError("not a flush error")))

    with pytest.raises(KeyError):
        mcp_server._flush_stdout()


@pytest.mark.unit
def test_a_stdout_flush_from_inside_a_stdout_flush_is_swallowed(monkeypatch):
    """What a termination signal handled during the flush does, on a real writer.

    The raw stream's write stands for the signal handler: it flushes stdout while
    the flush that called it is still running.
    """
    flushed_inside: List[bool] = []

    class _Raw(io.RawIOBase):
        def writable(self) -> bool:
            return True

        def write(self, data) -> int:
            mcp_server._flush_stdout()
            flushed_inside.append(True)
            return len(data)

    stream = io.TextIOWrapper(io.BufferedWriter(_Raw()), write_through=False)
    monkeypatch.setattr(sys, "stdout", stream)
    stream.write("x")

    stream.flush()

    assert flushed_inside == [True]


@pytest.mark.parametrize("signum", _STOP_SIGNALS, ids=_STOP_SIGNAL_IDS)
@pytest.mark.unit
def test_a_late_signal_handled_inside_the_stdout_flush_still_exits_with_its_status(
    monkeypatch, signum
):
    """The late handlers are installed before stdout is taken off the wire, so a
    termination signal can be handled inside that flush.

    The handler's own flush then re-enters the buffered writer the interrupted
    flush is using, which Python refuses with a RuntimeError. It must not leave
    the handler before the exit.
    """
    exits: List[int] = []

    monkeypatch.setattr(
        sys,
        "stdout",
        _FlushRaises(RuntimeError("reentrant call inside <_io.BufferedWriter>")),
    )
    monkeypatch.setattr(mcp_server.os, "_exit", exits.append)
    monkeypatch.setattr(mcp_server.logging, "shutdown", lambda: None)

    mcp_server._exit_on_late_signal(signum, None)

    assert exits == [_STOP_STATUS[signum]], exits


class _RecordingExecutor:
    """A pool that records how it was shut down and runs nothing."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self.calls.append({"wait": wait, "cancel_futures": cancel_futures})


@pytest.fixture
def recording_pools(monkeypatch):
    clone, delivery = _RecordingExecutor(), _RecordingExecutor()
    monkeypatch.setattr(mcp_server, "_CLONE_EXECUTOR", clone)
    monkeypatch.setattr(mcp_server, "_DELIVERY_EXECUTOR", delivery)
    return clone, delivery


async def _leave_the_stdio_lifespan() -> None:
    async with mcp_server._lifespan(mcp_server.mcp):
        pass


@pytest.mark.unit
def test_the_stdio_lifespan_shuts_the_source_pools_down_and_drops_their_queue(
    monkeypatch, stops, recording_pools
):
    monkeypatch.setattr(mcp_server, "_serving_stdio", True)

    asyncio.run(_leave_the_stdio_lifespan())

    for pool in recording_pools:
        assert pool.calls[0] == {"wait": False, "cancel_futures": True}, pool.calls


@pytest.mark.unit
def test_the_lifespan_leaves_the_source_pools_alone_when_it_is_not_the_stdio_serving(
    monkeypatch, stops, recording_pools
):
    monkeypatch.setattr(mcp_server, "_serving_stdio", False)

    asyncio.run(_leave_the_stdio_lifespan())

    assert [pool.calls for pool in recording_pools] == [[], []]


@pytest.mark.unit
def test_an_http_server_that_stops_shuts_the_source_pools_down_and_drops_their_queue(
    stops, recording_pools
):
    asyncio.run(mcp_server.stop_scans_at_server_exit("the HTTP server is stopping"))

    for pool in recording_pools:
        assert pool.calls[0] == {"wait": False, "cancel_futures": True}, pool.calls


@pytest.fixture
def a_clone_pool_of_one(monkeypatch):
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ash-test-clone")
    monkeypatch.setattr(mcp_server, "_CLONE_EXECUTOR", pool)
    yield pool
    pool.shutdown(wait=False, cancel_futures=True)


@pytest.mark.unit
def test_a_running_clone_gets_a_bounded_wait_and_a_queued_one_is_dropped(
    monkeypatch, stops, a_clone_pool_of_one
):
    """The running job is waited for, not killed; the one behind it never starts."""
    monkeypatch.setattr(mcp_server, "_serving_stdio", True)
    monkeypatch.setattr(mcp_server, "STDIO_SCAN_STOP_TIMEOUT_SECONDS", 0.3)
    started = threading.Event()
    release = threading.Event()

    def running_clone() -> str:
        started.set()
        release.wait(timeout=60)
        return "finished"

    running = a_clone_pool_of_one.submit(running_clone)
    queued = a_clone_pool_of_one.submit(lambda: "never starts")
    assert started.wait(timeout=30)
    try:
        began = time.monotonic()
        asyncio.run(_leave_the_stdio_lifespan())
        waited = time.monotonic() - began

        assert queued.cancelled(), "a queued clone was left to run after the shutdown"
        assert not running.done(), "the running clone was ended by the shutdown"
        assert mcp_server._source_jobs_left_running is True
        assert 0.25 <= waited < 20, waited
    finally:
        release.set()
    assert running.result(timeout=30) == "finished"


@pytest.mark.unit
def test_an_http_server_that_stops_reports_a_clone_still_running(
    stops, a_clone_pool_of_one, monkeypatch
):
    monkeypatch.setattr(mcp_server, "STDIO_SCAN_STOP_TIMEOUT_SECONDS", 0.3)
    started = threading.Event()
    release = threading.Event()

    def running_clone() -> None:
        started.set()
        release.wait(timeout=60)

    running = a_clone_pool_of_one.submit(running_clone)
    assert started.wait(timeout=30)
    try:
        still_running = asyncio.run(mcp_server.stop_scans_at_server_exit("stopping"))
    finally:
        release.set()
    running.result(timeout=30)

    assert still_running is True


@pytest.mark.unit
def test_idle_source_pools_do_not_hold_the_stop_up(
    monkeypatch, stops, a_clone_pool_of_one
):
    monkeypatch.setattr(mcp_server, "_serving_stdio", True)
    assert a_clone_pool_of_one.submit(lambda: "done").result(timeout=30) == "done"

    began = time.monotonic()
    asyncio.run(_leave_the_stdio_lifespan())
    waited = time.monotonic() - began

    assert mcp_server._source_jobs_left_running is False
    assert waited < mcp_server.STDIO_SCAN_STOP_TIMEOUT_SECONDS, waited
    assert asyncio.run(mcp_server.stop_scans_at_server_exit("stopping")) is False


@pytest.mark.parametrize(
    "jobs_left_running", [True, False], ids=["a-job-is-running", "no-job-is-running"]
)
@pytest.mark.unit
def test_the_late_stop_handlers_are_kept_only_while_a_source_job_is_running(
    monkeypatch, stop_signals_put_back, jobs_left_running
):
    """The interpreter's exit waits for the pools' threads after run_mcp_server returns.

    A SIGTERM then, left to the handler that was in place before, would end the
    server with -15 and the tools' groups running.
    """

    async def serve() -> None:
        for signum in _STOP_STATUS:
            signal.signal(signum, mcp_server._exit_on_late_signal)
        mcp_server._source_jobs_left_running = jobs_left_running

    monkeypatch.setattr(mcp_server, "_source_jobs_left_running", False)
    monkeypatch.setattr(mcp_server, "_serve_stdio", serve)
    before = {signum: signal.getsignal(signum) for signum in _STOP_STATUS}

    mcp_server.run_mcp_server()

    for signum, handler in before.items():
        left = signal.getsignal(signum)
        name = signal.Signals(signum).name
        if jobs_left_running:
            assert left is mcp_server._exit_on_late_signal, (name, left)
        else:
            assert left == handler, (name, left, handler)
