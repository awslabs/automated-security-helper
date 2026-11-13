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
        client._stop_daemon(path)
    if idle_seconds is not None:
        # The autostart and the foreground serve both read the environment's
        # idle setting; the option is written there so one mechanism decides.
        os.environ[runtime.IDLE_ENV] = str(idle_seconds)
    if foreground:
        from automated_security_helper.express.daemon import serve

        serve(idle_timeout=runtime.idle_seconds())
        return
    client.autostart(os.environ)
    sock = client.await_daemon(path)
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
        echo("no express daemon is running")
        return
    # Wait on the daemon's own pid where it gave one; the daemon unlinks its
    # socket itself (and only its own; see the client's _stop_daemon).
    pid = answer.get("pid")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if isinstance(pid, int):
            try:
                os.kill(pid, 0)
            except OSError:
                break
        elif not os.path.exists(path):
            break
        time.sleep(0.05)
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
    if status is None or not status.get("ok"):
        if as_json:
            echo(json.dumps({"running": False, "socket": os.fspath(path)}))
        else:
            echo(f"express daemon: not running (socket would be {path})")
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
