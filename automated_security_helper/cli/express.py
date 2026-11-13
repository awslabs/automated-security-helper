# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash express``: manage the resident warm daemon scans delegate to.

The daemon itself lives in :mod:`automated_security_helper.express.daemon`; this
module is only the management surface. ``start`` launches it detached (or in
the foreground with ``--foreground``), ``stop`` retires it, ``status`` reports
what is running. Scans never need these commands: a scan uses the daemon
automatically when its socket exists, and ``ash scan --express`` starts it on
demand. See docs/content/how-to/express-mode.md.
"""

import json
import os
import time
from typing import Annotated, Optional

import typer

from automated_security_helper.utils.console import echo
from automated_security_helper.utils.process_env import set_environ, snapshot_environ

express_app = typer.Typer(
    name="express",
    help=(
        "Manage the express daemon: a resident warm ASH process that removes "
        "startup cost from every scan. Unix only; scans fall back to ordinary "
        "cold runs wherever the daemon is unavailable."
    ),
    no_args_is_help=True,
)


def _unavailable_exit(exc: Exception) -> "typer.Exit":
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    echo(f"express mode is unavailable here: {exc}", err=True)
    return typer.Exit(ASH_EXIT_USAGE_ERROR)


@express_app.command(name="start")
def start_daemon(
    idle_seconds: Annotated[
        Optional[int],
        typer.Option(
            "--idle-seconds",
            help=(
                "Seconds of inactivity after which the daemon exits. Defaults "
                "to the ASH_EXPRESS_IDLE_SECONDS environment variable, else 1800."
            ),
            min=1,
        ),
    ] = None,
    foreground: Annotated[
        bool,
        typer.Option(
            "--foreground",
            help=(
                "Run the daemon in this process, attached to this terminal, "
                "instead of detaching it. Useful for watching its log live."
            ),
        ),
    ] = False,
) -> None:
    """Start the express daemon for this user and ASH version (idempotent)."""
    from automated_security_helper.express import client, runtime

    try:
        path = runtime.socket_path()
    except runtime.ExpressUnavailable as exc:
        raise _unavailable_exit(exc) from None
    status = client.control_request(path, {"op": "status"})
    if status is not None and not status.get("ok"):
        # Something answered on the socket and it was not a healthy daemon's
        # status. Starting over it would only race whatever it is; say so.
        echo(
            f"something is listening at {path} but did not answer as an express "
            "daemon; run 'ash express stop', or remove whatever holds the "
            "socket, before starting one.",
            err=True,
        )
        raise typer.Exit(1)
    if status is not None and status.get("ok"):
        # "Already running" counts only for a daemon a scan would actually
        # use: one whose protocol and installed-package fingerprint match
        # this invocation's. A stale one would refuse every scan, so an idle
        # stale daemon is replaced here, and a busy one is reported rather
        # than killed out from under its running scans.
        stale = status.get(
            "fingerprint"
        ) != runtime.runtime_fingerprint() or status.get("protocol") != (
            runtime.PROTOCOL_VERSION
        )
        if not stale:
            echo(f"express daemon already running (pid {status.get('pid')}) at {path}")
            return
        if status.get("active_scans"):
            echo(
                "a stale express daemon is still running scans; new scans fall "
                "back to cold runs until it retires. Run 'ash express stop' to "
                "end it now.",
                err=True,
            )
            raise typer.Exit(1)
        echo("replacing a stale express daemon")
        client.stop_daemon(path)
    if idle_seconds is not None:
        # The spawned daemon and the foreground serve both read the
        # environment's idle setting; the option is written there so one
        # mechanism decides.
        set_environ(runtime.IDLE_ENV, str(idle_seconds))
    if foreground:
        from automated_security_helper.express.daemon import serve

        serve(idle_timeout=runtime.idle_seconds())
        return
    # Never client.autostart here: this command runs after the whole CLI
    # import, where a bare fork would carry rich, typer, logging and main's
    # signal handlers into the daemon. A fresh interpreter starts it instead.
    started = client.spawn_daemon_process(snapshot_environ())
    sock = client.await_daemon(path) if started else None
    if sock is None:
        echo(
            f"the express daemon did not come up; its log is {runtime.log_path()}",
            err=True,
        )
        raise typer.Exit(1)
    sock.close()
    echo(f"express daemon started at {path} (log: {runtime.log_path()})")


@express_app.command(name="stop")
def stop_daemon() -> None:
    """Stop the express daemon. A scan it is running is sent SIGTERM."""
    from automated_security_helper.express import client, runtime

    try:
        path = runtime.socket_path()
    except runtime.ExpressUnavailable as exc:
        raise _unavailable_exit(exc) from None
    answer = client.control_request(path, {"op": "stop"})
    if answer is None:
        if os.path.exists(path) or client.daemon_lock_is_held(path):
            # The socket file (or its daemon lock) is there and nothing
            # answered: a wedged daemon (stuck imports, SIGSTOP) or a foreign
            # holder. "No daemon" would be a lie a script acts on, and every
            # implicit scan keeps paying the connect timeout against this
            # socket until it is resolved.
            echo(
                f"something holds the socket at {path} (or its .lock) but did "
                "not answer the stop; the process may be wedged. Find it "
                "(fuser or lsof on the socket) and stop it, or remove the "
                "socket file.",
                err=True,
            )
            raise typer.Exit(1)
        echo("no express daemon is running")
        return
    if not answer.get("ok"):
        # Something answered, and it refused or was not a daemon. "Stopped"
        # would be a lie that a caller (a test teardown, a script) acts on.
        echo(
            f"whatever is listening at {path} did not acknowledge the stop: "
            f"{answer.get('reason', 'no reason given')}",
            err=True,
        )
        raise typer.Exit(1)
    # Wait on the daemon's own pid where it gave one; the daemon unlinks its
    # socket itself (and only its own; see the client's stop_daemon). The
    # success claim is verified, not assumed: a daemon still alive at the
    # deadline -- a scan refusing to die, a wedged loop -- is reported as
    # exactly that, with a non-zero exit.
    pid = answer.get("pid")
    # Longer than the daemon's own child grace (runtime.STOP_GRACE_SECONDS,
    # plus its select tick and reaping): a stop that lands while a scan takes
    # its whole grace to die must not read as a daemon that refused to exit.
    deadline = time.monotonic() + runtime.STOP_WAIT_SECONDS
    stopped = False
    while time.monotonic() < deadline:
        if isinstance(pid, int):
            try:
                os.kill(pid, 0)
            except OSError:
                stopped = True
                break
        elif not os.path.exists(path):
            stopped = True
            break
        time.sleep(0.05)
    if not stopped:
        what = f"pid {pid}" if isinstance(pid, int) else f"the socket at {path}"
        echo(
            f"the express daemon acknowledged the stop but {what} is still "
            f"there after {runtime.STOP_WAIT_SECONDS:.0f} seconds; it may be "
            "finishing a scan. Check 'ash express status'.",
            err=True,
        )
        raise typer.Exit(1)
    echo("express daemon stopped")


@express_app.command(name="status")
def daemon_status(
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Print the daemon's status object as JSON."),
    ] = False,
) -> None:
    """Report whether the express daemon is running, and what it has served."""
    from automated_security_helper.express import client, runtime

    try:
        path = runtime.socket_path()
    except runtime.ExpressUnavailable as exc:
        raise _unavailable_exit(exc) from None
    status = client.control_request(path, {"op": "status"})
    if status is None:
        socket_exists = os.path.exists(path)
        if socket_exists or client.daemon_lock_is_held(path):
            # A socket file (or a held daemon lock) with no answer is not
            # "not running": a wedged daemon or a foreign holder sits there,
            # and every implicit scan pays the connect timeout against it.
            if as_json:
                echo(
                    json.dumps(
                        {
                            "running": False,
                            "answered": False,
                            "socket_exists": socket_exists,
                            "socket": os.fspath(path),
                        }
                    )
                )
            else:
                echo(
                    f"express daemon: something holds the socket at {path} "
                    "(or its .lock) but did not answer; the process may be "
                    "wedged. Find it (fuser or lsof on the socket) and stop "
                    "it, or remove the socket file.",
                    err=True,
                )
            raise typer.Exit(1)
        if as_json:
            echo(json.dumps({"running": False, "socket": os.fspath(path)}))
        else:
            echo(f"express daemon: not running (socket would be {path})")
        raise typer.Exit(1)
    if not status.get("ok"):
        # Answered, but not as a daemon's status: that is its own state, not
        # "not running" -- a scan would consult this socket and be refused.
        if as_json:
            echo(
                json.dumps(
                    {
                        "running": False,
                        "answered": True,
                        "socket": os.fspath(path),
                        "reason": status.get("reason", "not a status answer"),
                    }
                )
            )
        else:
            echo(
                f"express daemon: something is listening at {path} but did not "
                "answer as a daemon; run 'ash express stop' to clear it.",
                err=True,
            )
        raise typer.Exit(1)
    if as_json:
        status["running"] = True
        echo(json.dumps(status, sort_keys=True))
        return
    echo(
        "express daemon: running\n"
        f"  pid:            {status.get('pid')}\n"
        f"  ash version:    {status.get('version')}\n"
        f"  socket:         {status.get('socket')}\n"
        f"  active scans:   {status.get('active_scans')}\n"
        f"  scans served:   {status.get('scans_served')}\n"
        f"  idle timeout:   {status.get('idle_timeout_seconds')}s\n"
        f"  concurrency:    {status.get('concurrency_cap')}"
    )
