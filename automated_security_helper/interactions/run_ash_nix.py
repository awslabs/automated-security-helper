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
import re
import subprocess  # nosec B404 - re-executing ASH inside `nix develop` is this module's purpose
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

from automated_security_helper.core.cancellation import (
    CancelEvent,
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
    could_not_stop_sentence,
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

# The operator's own PYTHONPATH, handed to the inner run under another name. The flake's
# shell hook unsets PYTHONPATH, because nixpkgs' Python setup hook appends the scanners'
# dependency closure to it and those modules are built against another interpreter. An
# ASH, or a plugin module, importable only through the operator's PYTHONPATH would be
# lost with it, so the inner command puts those directories back on sys.path itself.
# Set by this module and read only by the inner command (_INNER_ENTRY_POINT).
OUTER_PYTHONPATH_ENV_VAR = "ASH_NIX_OUTER_PYTHONPATH"

# The environment variables the scan CLI reads as the value of a scan option
# (`envvar=` on cli/scan.py's options). An explicit argv states the whole option
# set of the scan inside the shell, and an option left at its default is left
# OFF the command line, which is where these would decide it instead: a library
# call with ``scanners=[]`` in a process holding ASH_SCANNERS=grype scanned with
# grype alone, ASH_CHANGED_FILES_ONLY=1 filtered findings the call never asked
# to filter (and there is no --no-changed-files-only to undo it), and
# ASH_WORKSPACE made the inner --source-dir scan refuse. So they are removed from
# the shell's environment when ``run_ash_nix`` is given an argv; a caller
# forwarding its own command line (argv None) keeps them, since that command line
# was read against them already. ASH_CONFIG stays in every case: the host side
# resolves its own config reads through the same variable (run_ash_scan's
# ASH_CONFIG fallbacks), so inner and outer agree on it; removing it would make
# the inner scan discover a different file. ASH_MODE is listed although
# rewrite_mode_args appends --mode local, so the inner scan is never one
# environment variable away from recursing.
INNER_SCAN_OPTION_VARIABLES: tuple = (
    "ASH_SOURCE_DIR",
    "ASH_OUTPUT_DIR",
    "ASH_SCANNERS",
    "ASH_EXCLUDED_SCANNERS",
    "ASH_PLUGIN_MODULES",
    "ASH_MODE",
    "ASH_VERBOSE",
    "ASH_DEBUG",
    "ASH_CHANGED_FILES_ONLY",
    "ASH_BASE_REF",
    "ASH_SHARD_INDEX",
    "ASH_SHARD_COUNT",
    "ASH_WORKSPACE",
    "ASH_WORKSPACE_CONFIG",
)

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
    # In a packaged install the same arithmetic lands on the environment's
    # site-packages directory, which ships no pyproject.toml. A flake.nix left there
    # by something else would otherwise be taken for this repository's and replace
    # the published, version-pinned toolchain without a word.
    if not (repo_root / "flake.nix").is_file():
        return None
    return repo_root if (repo_root / "pyproject.toml").is_file() else None


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
        #
        # A `path:` reference is a URL, and nix reads it as one: `#` starts the attribute
        # and `?` the query, and a space is no URL character at all, so a checkout under a
        # directory named with any of them was misparsed and the shell never opened.
        # Percent-encoded they are plain path characters again; nix decodes the path.
        # surrogateescape so a path name that is not UTF-8 encodes to its own bytes.
        return f"path:{quote(str(local), safe='/', errors='surrogateescape')}"

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


#: The userinfo of a URL flake reference: everything between ``scheme://`` and the
#: ``@`` before the host. Greedy to the last ``@`` of the authority, so a user name
#: that holds one is covered too; a path, query or fragment ends the authority.
_URL_USERINFO = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*)@")


#: A query parameter of a URL flake reference whose name says it carries a
#: credential (``?private_token=...``, ``&access_token=...``), and its value.
#: Matched on the name only: a value read as a secret by its shape would hide
#: ordinary refs and revisions.
_URL_QUERY_CREDENTIAL = re.compile(
    r"([?&;][^=&#\s]*(?:token|secret|pass(?:word|wd)?|key|auth|credential|sig)"
    r"[^=&#\s]*=)[^&#\s]*",
    re.IGNORECASE,
)


def shown_flake_ref(ref: str) -> str:
    """``ref`` as a log line or a debug echo shows it: a URL's credentials replaced.

    A flake reference can be a URL (``git+https://user:token@host/repo``), and the
    token in its userinfo is a credential the operator put in ASH_NIX_FLAKE_REF so
    nix can fetch the flake. So is the value of a query parameter named for one
    (``?private_token=...``), the form a git host's API accepts. The INFO line and
    the debug command line are written to the console and to ash.log in the
    output directory, which neither should carry. The reference nix is given is not
    changed; a reference with neither is returned as it is.
    """
    shown = _URL_USERINFO.sub(r"\1<userinfo>@", ref, count=1)
    return _URL_QUERY_CREDENTIAL.sub(r"\1<hidden>", shown)


#: Given to the inner scan, as container mode gives it to the scan in the image: the
#: outer process prints the metrics table and the exit-code legend from the results
#: it reads back, so the inner scan's own would be a second copy of both.
_NO_SHOW_SUMMARY = "--no-show-summary"


def rewrite_mode_args(argv: List[str]) -> List[str]:
    """Rewrite the caller's arguments so the inner invocation runs a local scan.

    The argv given is forwarded verbatim apart from ``--mode`` and the summary
    switch; this function rebuilds nothing. Which argv that is depends on the
    caller: a program forwarding its own command line (``run_ash_nix(argv=None)``
    reads ``sys.argv[1:]``) hands over what the operator typed, while the scan
    entry point (``run_ash_scan._run_nix_mode``) builds the argv from the call's
    ScanOptions (``_nix_inner_argv``), because a library caller has no command
    line of its own and the host program's would run the wrong scan. Rebuilding
    is how a forwarded invocation can quietly lose a flag, so that builder's
    field list is guarded by a test over ``ScanOptions.model_fields`` (every
    field forwarded, refused or excluded by name). Container mode rebuilds too,
    with path remapping; a Nix shell moves no files, so the paths pass as given.

    Everything after a bare ``--`` is positional whatever it looks like, so it is
    forwarded as it is, and the options this adds are placed before it; a ``--mode``
    there is a value, not the option.
    """
    out: List[str] = []
    skip_next = False
    saw_mode = False
    positional: List[str] = []

    for index, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            positional = argv[index:]
            break
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
        if arg == "--show-summary":
            # Dropped: the switch is decided below, and the later of the two
            # spellings would win inside the shell.
            continue
        out.append(arg)

    if not saw_mode:
        # Nix mode can be selected by config file rather than on the command line, in which
        # case argv carries no --mode at all. Without this the inner scan would inherit
        # nix mode from that same config and recurse.
        out.extend(["--mode", "local"])
    if _NO_SHOW_SUMMARY not in out:
        out.append(_NO_SHOW_SUMMARY)

    return out + positional


#: How the shell starts the inner scan: this interpreter, by absolute path, running
#: the same entry point as the ``ash`` script, so the inner scan is the ASH that is
#: running now. ``sys.argv[0]`` is set so its messages name ``ash``, not ``-c``.
#:
#: Before the first import of ASH, the directories the operator's own PYTHONPATH
#: named are put back on ``sys.path`` (made absolute, as Python makes PYTHONPATH's),
#: read from OUTER_PYTHONPATH_ENV_VAR: the shell unset PYTHONPATH itself. The variable
#: is removed so the scanners the inner scan starts do not see it. A fixed string,
#: with no path of this host in it: the command is recorded by the snapshot tests.
_INNER_ENTRY_POINT = (
    "import os, sys; "
    f"outer = os.environ.pop({OUTER_PYTHONPATH_ENV_VAR!r}, ''); "
    "sys.path[:0] = [os.path.abspath(d) for d in outer.split(os.pathsep)] "
    "if outer else []; "
    "sys.argv[0] = 'ash'; "
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
    an empty entry there absolute, so no check of the entry tells it apart. Inside
    the shell those directories come from OUTER_PYTHONPATH_ENV_VAR, not from
    PYTHONPATH, which the flake's shell hook unsets (flake.nix); the command puts
    them back before it imports ASH, so an ASH or a plugin module importable only
    through the operator's PYTHONPATH still imports in the inner scan.
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
    if argv is not None:
        # The argv states the whole option set; see INNER_SCAN_OPTION_VARIABLES.
        for name in INNER_SCAN_OPTION_VARIABLES:
            env.pop(name, None)
    env[ASH_IN_NIX_ENV_VAR] = "1"
    # The flake already supplies every scanner, so stop the thirteen scanners that prefer
    # `uv tool install` from fetching their own copies and shadowing the pinned ones.
    # utils/uv_tool_runner.py takes its skip-installation path when this is set.
    env["ASH_OFFLINE"] = "YES"
    if outer_run_id is not None:
        env[OUTER_RUN_ID_ENV] = outer_run_id
    # The operator's own PYTHONPATH, for the inner command to put back on sys.path
    # once the shell's hook has unset PYTHONPATH (OUTER_PYTHONPATH_ENV_VAR). Read
    # from this process's environment: it is what made this ASH importable.
    outer_pythonpath = os.environ.get("PYTHONPATH")
    if outer_pythonpath:
        env[OUTER_PYTHONPATH_ENV_VAR] = outer_pythonpath

    # The flake reference without a URL's userinfo, and each --config-overrides value
    # as its key: either can be a credential, and both lines reach the console and
    # ash.log. The command that runs carries them as given.
    shown_ref = shown_flake_ref(resolved_ref)
    ASH_LOGGER.info(f"Entering Nix shell from flake: {shown_ref}")
    shown = " ".join(
        shown_arguments(build_nix_command(shown_ref, inner_args, nix_executable))
    )
    ASH_LOGGER.debug(f"Nix command: {shown}")

    if debug:
        secho("\nDebug: Nix command", fg="blue", bold=True)
        echo(f"Command: {shown}")

    # The status is returned, not checked, so the caller decides what a non-zero one
    # means. A scan that finds something exits non-zero by design, so raising here
    # would turn a successful scan into an error.
    return _enter_shell(cmd, env=env)


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
                        stopped = stop_after_interrupt(
                            process, child_got_the_interrupt=False
                        )
                        if stopped:
                            raise ScanCancelled(
                                "the scan was cancelled while the Nix shell ran"
                            ) from None
                        # The grace ran out and the kernel refused the kill, so
                        # the shell, which is the inner scan, may still run. The
                        # cancel says so and carries the pid as data, as the
                        # spawn layer's cancels do, and the event records it for
                        # the exit line, which names survivors from the records,
                        # never from the text.
                        if isinstance(cancel_event, CancelEvent):
                            cancel_event.note_could_not_stop("nix", process.pid)
                        raise ScanCancelled(
                            "the scan was cancelled while the Nix shell ran; "
                            + could_not_stop_sentence(
                                f"the Nix shell (pid {process.pid})"
                            ),
                            could_not_stop=(("nix", process.pid),),
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
