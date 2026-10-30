"""Run an ASH scan inside a Nix development shell that supplies the scanner toolchain.

Nix mode exists because the other two ways of obtaining scanners both fail an adopter.
No container image is published, so ``--mode container`` obliges everyone to build one.
And ``--mode local`` degrades quietly: a scanner whose binary is absent reports MISSING,
contributes zero findings, and the run still writes a complete-looking report.

The shape here deliberately mirrors container mode. That re-execs ASH inside an image and
the inner run is an ordinary local scan; this re-execs ASH inside ``nix develop`` and the
inner run is likewise local. Nix mode is simpler in one important way: a development shell
changes PATH but not the filesystem, so there is no mount translation and none of container
mode's path-mapping logic is needed here.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - re-executing ASH inside `nix develop` is this module's purpose
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from automated_security_helper.core.cancellation import (
    ScanCancelled,
    current_cancel_event,
    raise_if_cancelled,
    record_tool_pid,
)
from automated_security_helper.core.constants import ASH_REPO_URL
from automated_security_helper.utils.console import echo, secho
from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.python_child import python_code_argv
from automated_security_helper.utils.subprocess_utils import (
    HeldInterrupt,
    child_environ,
    discard_tool_pid_before_reap,
    discard_tool_pid_once_exited,
    find_executable,
    shown_arguments,
    stop_after_interrupt,
)

# Recursion guard, following the existing ASH_IN_CONTAINER precedent. The inner invocation
# is rewritten to --mode local, so this should never be observed as already set; it is
# checked anyway because the alternative to a loud failure is a fork bomb.
ASH_IN_NIX_ENV_VAR = "ASH_IN_NIX"

# Overrides which flake supplies the toolchain. Documented because the default cannot be
# right for every installation, and a wrong flake reference otherwise produces a Nix error
# with no hint that it is configurable.
ASH_NIX_FLAKE_REF_ENV_VAR = "ASH_NIX_FLAKE_REF"

# Both features are DISABLED by default on a stock multi-user Nix install: /etc/nix/nix.conf
# carries only build-users-group, and every flake operation then fails with "experimental
# Nix feature 'nix-command' is disabled". Passing them explicitly on each invocation means
# an adopter does not have to edit a system config file first.
#
# Do NOT probe with `nix flake --help` to decide whether flakes are available. That succeeds
# on an installation where they are disabled, because it only proves the subcommand is
# compiled in.
_EXPERIMENTAL_FEATURES = "nix-command flakes"


class NixModeRefused(RuntimeError):
    """Nix mode cannot start here: `nix` is not on PATH, or this is already a Nix-mode run.

    A subclass of RuntimeError so that callers which caught that keep working. The CLI
    catches this class and prints the message, where a bare RuntimeError would end the
    command in a traceback.
    """


def _repo_flake_dir() -> Optional[Path]:
    """Return the repository root if ASH is running from a source checkout with a flake.

    A packaged install (pip, pipx, uvx) does not ship flake.nix, so this returns None and
    the caller falls back to a remote reference.
    """
    # .../automated_security_helper/interactions/run_ash_nix.py -> repo root is three up.
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root if (repo_root / "flake.nix").is_file() else None


def resolve_flake_ref(explicit: Optional[str] = None) -> str:
    """Decide which flake provides the scanners.

    Order is explicit argument, then the environment override, then a local checkout, then
    the published repository at the running version.
    """
    if explicit:
        return explicit

    from_env = os.environ.get(ASH_NIX_FLAKE_REF_ENV_VAR)
    if from_env:
        return from_env

    local = _repo_flake_dir()
    if local is not None:
        # `path:` rather than a bare path so Nix does not require the flake to be committed.
        # A bare path is evaluated as a git tree, which silently ignores uncommitted changes
        # to flake.nix -- so an edit under test would appear to have no effect.
        return f"path:{local}"

    # Pinned to the running version rather than the default branch, so the scanner set that
    # produced a report can be reconstructed later. `automated_security_helper.__version__`
    # is imported lazily because importing the package root from here at module scope is
    # circular.
    #
    # This requires the released tag to actually contain flake.nix, which is only true from
    # the first release that ships it. Before then a packaged install reaches this branch
    # and nix fails with "path '«github:...»/flake.nix' does not exist" -- an error about
    # the ref, not about the user's setup. Set ASH_NIX_FLAKE_REF to a checkout in that case.
    from automated_security_helper import __version__

    owner_repo = ASH_REPO_URL.replace("https://github.com/", "")
    return f"github:{owner_repo}/v{__version__}"


def rewrite_mode_args(argv: List[str]) -> List[str]:
    """Rewrite the caller's arguments so the inner invocation runs a local scan.

    The caller's argv is forwarded verbatim apart from ``--mode``, rather than rebuilt from
    parsed options. Rebuilding is how a forwarded invocation quietly loses a flag: every
    option has to be handled explicitly, and one that is missed simply does not reach the
    inner scan. Container mode has to rebuild because its paths need remapping. A Nix shell
    does not move any files, so verbatim forwarding is both simpler and safer here.
    """
    out: List[str] = []
    skip_next = False
    saw_mode = False

    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--mode":
            # Two-token form: drop the flag and its value, then emit the replacement.
            out.extend(["--mode", "local"])
            saw_mode = True
            skip_next = True
            continue
        if arg.startswith("--mode="):
            out.append("--mode=local")
            saw_mode = True
            continue
        out.append(arg)

    if not saw_mode:
        # Nix mode can be selected by config file rather than on the command line, in which
        # case argv carries no --mode at all. Without this the inner scan would inherit
        # nix mode from that same config and recurse.
        out.extend(["--mode", "local"])

    return out


#: How the shell starts the inner scan: this interpreter, by absolute path, running
#: the same entry point as the ``ash`` script, so the inner scan is the ASH that is
#: running now. ``sys.argv[0]`` is set so its messages name ``ash``, not ``-c``.
_INNER_ENTRY_POINT = (
    "import sys; sys.argv[0] = 'ash'; "
    "from automated_security_helper.cli.entrypoint import main; main()"
)


def _this_ash() -> List[str]:
    """The command that starts the ASH running now inside the shell.

    This ASH's interpreter rather than whichever ``ash`` comes first on the shell's
    PATH, so the inner run is the same ASH as the outer one: the flake supplies
    scanners, not ASH, and an older ``ash`` earlier on PATH would scan without
    writing the completion record the outer process reads back
    (utils/inner_run_outcome.py).

    ``nix develop --command`` starts it in the scan's own directory, which ``-c``
    puts first on ``sys.path``: an ``automated_security_helper/`` there would run in
    place of ASH. The directory is left as it is, and the command drops that entry
    (``utils/python_child.python_code_argv``). A directory ``PYTHONPATH`` names
    stays on ``sys.path``, the working directory included: Python makes a ``.`` or
    an empty entry there absolute, so no check of the entry tells it apart.
    """
    return python_code_argv(_INNER_ENTRY_POINT)


def build_nix_command(
    flake_ref: str,
    inner_args: List[str],
    nix_executable: str,
) -> List[str]:
    """Assemble the `nix develop ... --command <this ASH> ...` invocation."""
    return [
        nix_executable,
        "--extra-experimental-features",
        _EXPERIMENTAL_FEATURES,
        "develop",
        flake_ref,
        "--command",
        *_this_ash(),
        *inner_args,
    ]


def nix_executable_for_this_run() -> str:
    """The ``nix`` this run enters its shell with, or :class:`NixModeRefused`.

    The two refusals of Nix mode, in one place so the scan entry point can ask
    them before it clears the previous run's output: a refused run never starts
    a shell, so it must not delete the reports of one that did. ``run_ash_nix``
    asks them again for a caller that reaches it directly.

    Raises:
        NixModeRefused: if `nix` is not installed, or if called from inside a Nix-mode run.
    """
    if os.environ.get(ASH_IN_NIX_ENV_VAR, "NO").upper() in ["YES", "1", "TRUE"]:
        raise NixModeRefused(
            "ASH is already running inside a Nix shell but was asked to enter one again. "
            "The inner invocation should carry --mode local; this is a bug, not a "
            "configuration problem."
        )

    nix_executable = find_executable("nix")
    if nix_executable is None:
        # Deliberately an error rather than a fallback to local mode. Silently downgrading
        # is exactly how a run ends up with MISSING scanners and a clean-looking report,
        # which is the failure Nix mode exists to prevent.
        raise NixModeRefused(
            "--mode nix requires Nix, which was not found on PATH. Install it from "
            "https://nixos.org/download/ (Linux and macOS; on Windows use WSL2), or "
            "choose a different --mode. ASH will not fall back to --mode local here, "
            "because that would scan with whatever tools happen to be installed and "
            "report the absent ones as MISSING."
        )
    return nix_executable


def run_ash_nix(
    argv: Optional[List[str]] = None,
    flake_ref: Optional[str] = None,
    debug: bool = False,
    outer_run_id: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Re-execute this scan inside a Nix shell holding the pinned scanners.

    ``outer_run_id`` is handed to the inner run, which writes it into its results
    file when it completes (utils/inner_run_outcome.py).

    Raises:
        NixModeRefused: if `nix` is not installed, or if called from inside a Nix-mode run.
    """
    nix_executable = nix_executable_for_this_run()

    resolved_ref = resolve_flake_ref(flake_ref)
    inner_args = rewrite_mode_args(list(argv if argv is not None else sys.argv[1:]))
    cmd = build_nix_command(resolved_ref, inner_args, nix_executable)

    # The environment every child of a scan gets, copied under ENVIRON_LOCK
    # (utils/process_env.snapshot_environ, through child_environ): no PATH entry
    # inside the scanned tree unless the operator allowed in-tree tools. nix
    # develop prepends the shell's packages to this PATH.
    env = child_environ()
    env[ASH_IN_NIX_ENV_VAR] = "1"
    # The flake already supplies every scanner, so stop the thirteen scanners that prefer
    # `uv tool install` from fetching their own copies and shadowing the pinned ones.
    # utils/uv_tool_runner.py takes its skip-installation path when this is set.
    env["ASH_OFFLINE"] = "YES"
    if outer_run_id is not None:
        env[OUTER_RUN_ID_ENV] = outer_run_id

    ASH_LOGGER.info(f"Entering Nix shell from flake: {resolved_ref}")
    # Each --config-overrides value as its key: it can be a credential.
    shown = " ".join(shown_arguments(cmd))
    ASH_LOGGER.debug(f"Nix command: {shown}")

    if debug:
        secho("\nDebug: Nix command", fg="blue", bold=True)
        echo(f"Command: {shown}")

    # The status is returned, not checked, so the caller decides what a non-zero one
    # means. A scan that finds something exits non-zero by design, so raising here
    # would turn a successful scan into an error.
    return _enter_shell(cmd, env=env)


# The refusals travel with the runner. The scan entry point asks
# ``run_ash_nix.preflight()`` before it clears the previous run's output, so a
# refused run never deletes the reports of one that ran; it reads the attribute
# off whatever ``run_ash_nix`` is bound to, so a stand-in runner that starts no
# shell (a test's recorder, a caller's own launcher) is asked nothing about a
# ``nix`` it will not use.
run_ash_nix.preflight = nix_executable_for_this_run  # type: ignore[attr-defined]


def _enter_shell(cmd: List[str], env: Dict[str, str]) -> subprocess.CompletedProcess:
    """Run the Nix shell, passing Ctrl-C on to it as container mode does its runtime.

    `nix develop --command` execs the command in place (measured with nix 2.35.2:
    the process started here is the inner ASH), so the interrupt reaches the inner
    scan, which stops as an interrupted local scan does. It gets the same grace as
    a container runtime, then is killed. subprocess.run gave it 0.25 s, killed it,
    and passed nothing on when the interrupt reached this process alone.

    The wait also reads the scan's cancel event (core/cancellation.py): when it
    is set while the shell runs, the shell is stopped the same way and
    :class:`ScanCancelled` is raised. Without that read, a SIGTERM to ASH set
    the event and nothing looked at it, so the scan ran to completion as though
    no signal had arrived.
    """
    # A scan already cancelled starts no shell: the wait below only reads
    # the event once the child exists, so without this check a SIGTERM that
    # landed just before this point still started the shell mid-cancel.
    # Checked before the held window, as the spawn paths in
    # utils/subprocess_utils.py check theirs: a Ctrl-C arriving here is an
    # ordinary unheld interrupt that starts nothing.
    raise_if_cancelled()

    # A Ctrl-C while the shell is being started is held until the process is in
    # hand: raised inside Popen, it left nothing to stop. Not recorded for the MCP
    # server's kill at its stop (subprocess_utils.run_ended_with_the_server): an
    # MCP scan runs in local mode and never reaches Nix mode.
    with HeldInterrupt() as held:
        process = subprocess.Popen(  # nosec B603 - argument list is built here, not shell-parsed
            cmd,
            # The inner scan reads nothing from standard input; nix and the scanners
            # it starts get an empty one, not this process's.
            stdin=subprocess.DEVNULL,
            env=env,
            text=True,
        )
        # The shell shares this process's group, so the die-now branches' group
        # kill cannot name it: recorded by pid and forgotten the moment its
        # exit is observed, before the reap.
        record_tool_pid(process.pid)
        try:
            held.release()
            cancel_event = current_cancel_event()
            if cancel_event is None:
                # Never signaled and healthy: wait for its end with the record
                # kept the whole time, not only for the bound a killed child gets.
                discard_tool_pid_before_reap(process, just_killed=False)
                returncode = process.wait()
            else:
                while not discard_tool_pid_once_exited(process):
                    if cancel_event.is_set():
                        # The scan was cancelled: the CLI's SIGTERM handler does
                        # nothing but set the event, so this wait is where the
                        # stop happens, through the same path as the Ctrl-C arm
                        # below. The signal was delivered to this process alone,
                        # so the shell has not been interrupted yet, whatever
                        # the terminal probe would say.
                        stop_after_interrupt(process, child_got_the_interrupt=False)
                        raise ScanCancelled(
                            "the scan was cancelled while the Nix shell ran"
                        ) from None
                    time.sleep(0.1)
                returncode = process.wait()
        except KeyboardInterrupt:
            stop_after_interrupt(process)
            raise
        finally:
            # The stop paths and the loops above discard the record themselves;
            # this net catches an exit that landed between an observation and
            # its reap. A child still running keeps its record: it is exactly
            # the one a die-now signal must still be able to kill.
            discard_tool_pid_once_exited(process)
    return subprocess.CompletedProcess(args=cmd, returncode=returncode)
