"""Centralized subprocess execution utilities for ASH.

Batch programs on Windows
-------------------------
A tool that is a ``.bat`` or ``.cmd`` file (a RubyGems ``.bat``, an npm ``.cmd``) is not
started by Windows itself: ``CreateProcess`` runs ``cmd.exe`` on it, and cmd.exe reads
the whole command line. The batch file then passes its arguments on with ``%*``, so
cmd.exe reads them a second time. ``subprocess`` writes the argument list as one line
with ``list2cmdline``, which quotes an argument only when it is empty or holds a space
or tab, and writes a double quote as ``\\"``, which cmd.exe does not read as an escape.
So to cmd.exe an unquoted ``<``, ``>``, ``|`` or ``&`` is a redirection, a pipe or a
command separator, ``^`` is its escape character, and ``%name%`` is replaced by the
variable's value even inside double quotes. A parenthesis matters in the second read: a
wrapper can hold ``%*`` inside a parenthesized block such as
``IF EXIST ... ( ... %* ) ELSE ( ... %* )``, where a bare ``)`` from an argument closes
the block early. A caret put before an operator protects it in the first read only: the
batch file's second read finds it bare. The one spelling both reads leave alone is an
argument inside double quotes. Quoting every argument would need the command line as
one string, which the spawn helpers, the sandbox plan and the callers of
:func:`resolve_command` do not carry, so an argument that ``list2cmdline`` would not
quote is refused instead of rewritten.

When the lookup resolves the program to a batch file, :func:`_resolve_for_spawn` checks
the argument list once, so every helper below applies the same rule and hands ``Popen``
the list as it was:

* an argument that ``list2cmdline`` puts in double quotes (it is empty or holds a space
  or tab) is passed as it is: inside double quotes cmd.exe reads ``< > | & ^ ( )`` as
  plain text in both reads;
* any other argument that holds one of ``< > | & ^ ( )`` is refused with an ``OSError``
  (``errno.EINVAL``) before anything starts. The program path is read the same way and
  is never rewritten. The refusal is the choice made over quoting: an argument such as
  ``pkg@^1.0.0`` or ``a&b`` is refused, loudly, where an argument with a space is
  passed as it is, so a version range can be written ``>=1.0.0 <2.0.0``, and the
  message says so for a caret;
* a double quote or a line break in any argument is refused: a line written by
  ``list2cmdline`` has no escape for either;
* a percent sign is passed only when it is the only one in the command line, the
  program path included: cmd.exe looks for ``%name%`` across the whole line, double
  quotes do not stop it and nothing escapes it, so two or more are refused.

The message names the program and the argument's position, not its text.

Delayed expansion (``!``) is a known limitation, not changed: cmd.exe has it off unless
the machine turns it on (the ``DelayedExpansion`` registry setting, or ``cmd /v:on``),
and with it on ``!name!`` is replaced in the batch file's read of the arguments. ASH
neither refuses nor protects ``!``. What a batch file does with the arguments it was
given is its own business.
"""

import atexit
import contextlib
import contextvars
import enum
import errno
import gc
import locale
import logging
import ntpath
import os
import platform
import re
import shutil
import signal
import subprocess  # nosec B404 - suprocess module required for the nature of this package to orchestrate SAST/SCA/IAC/SBOM scanners
import sys
import sysconfig
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from typing_extensions import Self

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    current_cancel_event,
    discard_tool_group,
    discard_tool_pid,
    raise_if_cancelled,
    record_tool_group,
    stop_grace_in_progress,
)
from automated_security_helper.core.constants import (
    ASH_BIN_PATH,
    ash_bin_path_from_environment,
    warn_if_home_unusable,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP, delivers
from automated_security_helper.utils.offline_tool_env import offline_tool_environment
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.redacted_model import value_tuple
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.scanned_tree import is_inside_tree
from automated_security_helper.utils.terminal_text import (
    shown_not_obeyed,
    shown_on_one_line,
)
from automated_security_helper.utils.threads import ash_thread

if TYPE_CHECKING:
    from automated_security_helper.utils.sandbox.backends import SpawnPlan


# (command, sandbox, tree scope key, PATH, ASH_BIN_PATH)
#   -> (path or None, refused in-tree file or None). The directories searched are
# part of the key, so one environment's answer is not another's.
_find_executable_cache: Dict[
    Tuple[str, bool, Tuple[Tuple[str, ...], bool], Optional[str], str],
    Tuple[Optional[str], Optional[str]],
] = {}
# How many times clear_find_executable_cache has run. A lookup remembers what it
# found only if no clear ran while it searched: a search that began before an
# install found what was there before it, and the clear after the install is what
# makes the next lookup search again. The lock makes the check and the write one
# step against a clear; no search runs under it.
_find_executable_generation = 0
_find_executable_lock = threading.Lock()
#: How many lookups the cache keeps. A long-running server scans many trees, and
#: each tree's root is part of the key, so the cache grew with every scan; past
#: the bound the oldest entries go. A miss is never kept: it is searched for
#: again on every call anyway (_lookup), so keeping it only spent memory.
_FIND_EXECUTABLE_CACHE_LIMIT = 1024


def _is_executable_file(path: str) -> bool:
    """A file this process may execute: not a directory, and on POSIX with the
    execute bit. Windows decides by the file's suffix, which the candidate names
    (``_executable_candidate_names``) already give, so there a file is enough."""
    if not os.path.isfile(path):
        return False
    return platform.system().lower() == "windows" or os.access(path, os.X_OK)


def _spawn_env(env: Optional[Dict[str, str]]) -> Dict[str, str]:
    """The environment to hand a child: the caller's, or a copy of ours.

    Never None. On Linux, CPython 3.10+ spawns with vfork, and with ``env=None``
    the child execs against the parent's live ``environ`` array. Scanners run in
    parallel threads and some of them change the environment while they work
    (cdk_nag_wrapper's JSII variables), which can free that array under a child
    that has not reached ``execve`` yet; the spawn then fails with
    ``[Errno 14] Bad address``. A copy is built into a fresh ``envp`` that no other
    thread can touch, and the child sees the same variables. See
    ``utils/process_env.py``.

    In offline mode the variables that turn off each tool's own update, version
    and telemetry checks are set over it (``utils/offline_tool_env.py``), so a
    version probe or any other spawn of a tool stays off the network as its scan
    does.

    PATH keeps its anchored entries only (see :func:`_is_anchored`). A child looks
    programs up by name itself, through a ``#!/usr/bin/env node`` line, a binstub or
    a scanner starting git, and a relative or empty entry would let that search
    answer from the child's working directory. A PATH with no entry left, or one the
    caller set to the empty string, is replaced by the system's default directories
    (:func:`_default_search_path`). A PATH that is not set is left unset.
    """
    env = env if env is not None else snapshot_environ()
    offline = offline_tool_environment()
    if offline:
        env = {**env, **offline}
    scope = _TREE_SCOPE.get()
    if scope is not None:
        env = _without_in_tree_path_entries(env, scope)
    return _with_anchored_path_entries(env)


def _default_search_path() -> str:
    """``os.defpath`` with the entries that are not anchored taken off.

    The PATH a child gets when none of the one it was given is left to use. It is
    not ``os.defpath`` as it is: an empty PATH is read as the working directory, and
    on Windows ``os.defpath`` is ``.;C:\\bin``, whose ``.`` is the working directory
    too. When no entry of it is anchored, a fixed list of system directories stands
    in, so the result is never empty and never relative.
    """
    kept = [
        entry for entry in os.defpath.split(os.pathsep) if entry and _is_anchored(entry)
    ]
    if platform.system().lower() == "windows":
        fixed = ["C:\\Windows\\System32", "C:\\Windows"]
    else:
        fixed = ["/usr/bin", "/bin"]
    return os.pathsep.join(kept or fixed)


def _with_anchored_path_entries(env: Dict[str, str]) -> Dict[str, str]:
    """``env`` with PATH's entries that are not anchored taken off.

    Returned unchanged when there are none. When no entry is left, or PATH is the
    empty string, PATH is :func:`_default_search_path`: an empty PATH is read as the
    working directory. A PATH that is not set is not an empty one, and is left unset.
    """
    path_value = env.get("PATH")
    if path_value is None:
        return env
    entries = path_value.split(os.pathsep)
    kept = [entry for entry in entries if entry and _is_anchored(entry)]
    if kept and len(kept) == len(entries):
        return env
    env = dict(env)
    env["PATH"] = os.pathsep.join(kept) if kept else _default_search_path()
    return env


# Exit code reported for a command killed at its timeout, matching coreutils
# ``timeout(1)``. run_command keeps its own -1 for compatibility; see there.
TIMEOUT_RETURNCODE = 124


class TimedOutProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a command that was killed at its timeout.

    ``run_command_with_output_handling`` reports a timeout as ``timed_out: True``
    in its dict. Anything that converts that dict into a ``CompletedProcess`` has
    to keep the fact, and a plain ``CompletedProcess`` has no field for it:
    ``UVToolRunner.run_tool`` used to rebuild the result from returncode, stdout
    and stderr alone, so every uv-run scanner (checkov, bandit, semgrep) reported
    a timeout as the missing results file it left behind. Returning this type
    instead lets the flag survive the conversion without changing the return
    type callers already check for. It keeps the response's ``error`` too.
    """

    timed_out = True
    #: Whether the stop at the timeout failed to end the child, which then has no
    #: exit code and may still be running. Class-default False; set on the
    #: instance from the spawn record's ``not_stopped()`` (a refused stop
    #: included), never from any text the run produced.
    could_not_stop = False
    #: The pid the could-not-stop reason names, carried as data beside the flag
    #: so a report whose reason text is lost can still name the process; None
    #: whenever ``could_not_stop`` is False.
    could_not_stop_pid: Optional[int] = None
    #: Uniform signal carrier (see PostRunErrorProcess); never True here: a
    #: timeout is ASH's own stop, not a signal the tool died by.
    signaled = False
    #: As on PostRunErrorProcess: None on every unsignaled instance.
    signal: Optional[int] = None

    def __init__(
        self,
        args: Any,
        # An int, or None for a child the stop did not end: it has no code.
        returncode: Any,
        stdout: Any = None,
        stderr: Any = None,
        error: str = "",
    ) -> None:
        super().__init__(args, returncode, stdout, stderr)
        self.error = error


# Exit code reported for a command that never started: the OS refused to spawn it
# (missing or non-executable binary, a bad cwd, EFAULT/ETXTBSY from exec). Shells
# use 127 for "command not found or not runnable" and no scanner accepts it, so a
# spawn failure is never read as a tool that ran and signalled findings.
#
# It used to be 1, the generic failure code. bandit and semgrep both accept 1, so
# a uv binary that failed to exec with [Errno 14] Bad address let the scan carry
# on, and the only error anyone saw was the SARIF file the tool never wrote.
#
# The runners' own failures (an exception that is not an OSError, from building
# the spawn or from reading the tool's output) report it too, for the same
# reason: ASH did not get a run it can vouch for, and 1 would read as one.
SPAWN_FAILURE_RETURNCODE = 127

#: How a run whose stop did not end the child says so, up to the pid. Human-
#: readable text only, written once (_StartedChild.not_stopped) so every report
#: of this ending reads the same; nothing parses it back. The fact itself
#: travels as the ``could_not_stop`` carrier: a class-default-False attribute on
#: the typed results below, set on the instance from the spawn record's
#: ``not_stopped()``, and a key on dict-shaped responses, read with ``.get``. A
#: tool is free to print these words itself, and that stays data.
COULD_NOT_STOP_MARKER = "ASH could not stop the tool (pid"

#: The ending of every sentence that says a tool ASH could not stop may still be
#: running, written once so the sites that compose it cannot drift apart. The
#: reasons below, the spawn record's reason and the spawn layer's cancels all end
#: with it, the cancels through :func:`could_not_stop_sentence`. No module outside
#: this one spells it (tests/unit/utils/test_the_could_not_stop_wording_has_one_home.py).
#: Human-readable text only; nothing parses it back.
COULD_NOT_STOP_SUFFIX = "which may still be running"


def could_not_stop_sentence(referent: str) -> str:
    """The whole sentence that says ASH could not stop ``referent`` (a phrase that
    already names what it could not stop and how to find it: "the tool (pid N)",
    "python3 (pid N)"), ending as every such sentence ends. Human-readable text
    only."""
    return f"ASH could not stop {referent}, {COULD_NOT_STOP_SUFFIX}"


#: How a timeout message ends when ASH's stop did not end the tool, and when it
#: did: the two endings every timeout text uses, so no site words its own. Each
#: site adds its own punctuation after them. Text only; the choice between them
#: is :func:`response_could_not_stop`.
COULD_NOT_STOP_REASON = could_not_stop_sentence("the tool")
COULD_NOT_STOP_ENDING = f", and {COULD_NOT_STOP_REASON}"
WAS_KILLED_ENDING = " and was killed"


def could_not_stop_default(pid: Any) -> str:
    """The default could-not-stop reason, for a response whose own text is
    missing or unreadable: it names ``pid`` when that is a real int (a bool is
    not one), and is :data:`COULD_NOT_STOP_REASON` otherwise."""
    if isinstance(pid, int) and not isinstance(pid, bool):
        return f"{COULD_NOT_STOP_MARKER} {pid}), {COULD_NOT_STOP_SUFFIX}"
    return COULD_NOT_STOP_REASON


#: The one spelling of a process id inside a could-not-stop reason: the
#: parenthetical :func:`could_not_stop_default` writes and a referent such as
#: ``python3 (pid 7)`` carries into :func:`could_not_stop_sentence`.
_PROCESS_ID_PARENTHETICAL = re.compile(r"\s*\(pid [0-9]+\)")


def without_process_ids(text: str) -> str:
    """``text`` with every ``(pid N)`` parenthetical dropped, and nothing else.

    For the texts a remote client is shown: a reason recorded by the executor
    names the pid of the tool the stop could not end, which a server-side
    operator can act on and a client on a network transport cannot, and should
    not learn. ``could_not_stop_default(4242)`` becomes
    :data:`COULD_NOT_STOP_REASON`; a text with no pid is returned as it is."""
    return _PROCESS_ID_PARENTHETICAL.sub("", text)


def response_could_not_stop(response: Any) -> bool:
    """Whether a runner's response records a stop that failed.

    The one test every consumer of a response applies, from the recorded state
    alone, never from text: the ``could_not_stop`` key, or the shape the runner
    gives this ending -- ``timed_out`` with no exit code, since a timeout whose
    stop worked always has one (``TIMEOUT_RETURNCODE``, or run_command's -1).
    The recorders (``PluginBase._could_not_stop_state``) set their state
    through this, and the sites that read the response itself call it, so the
    two cannot disagree.
    """
    if not isinstance(response, dict):
        return False
    return response.get("could_not_stop") is True or (
        response.get("timed_out") is True and response.get("returncode") is None
    )


def exit_status(returncode: int) -> int:
    """A process's exit code as a shell reports it: ``128 + N`` when signal N ended it.

    ``subprocess`` reports a child a signal ended as ``-N``. Its absolute value is a
    small number that success sets contain: a tool killed by SIGHUP would read as
    exit 1, "findings found", for a scanner that accepts ``{0, 1}``. ``128 + N`` is
    what bwrap and ``uv tool run`` already return for the same child, and no scanner
    accepts it.
    """
    return 128 - returncode if returncode < 0 else returncode


class SpawnFailedProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a command the OS could not start.

    The counterpart of ``TimedOutProcess``: ``run_command_with_output_handling``
    reports the fact as ``spawn_failed: True`` in its dict, and this type keeps it
    when a caller (``UVToolRunner.run_tool``) converts that dict back, with the
    response's ``error``.
    """

    spawn_failed = True
    #: Uniform carrier (see COULD_NOT_STOP_MARKER); never True here: a command
    #: that did not start left nothing to stop.
    could_not_stop = False
    #: The pid the could-not-stop reason names, carried as data beside the flag
    #: so a report whose reason text is lost can still name the process; None
    #: whenever ``could_not_stop`` is False.
    could_not_stop_pid: Optional[int] = None
    #: Uniform signal carrier (see PostRunErrorProcess); never True here: a
    #: command that did not start could not die by a signal.
    signaled = False
    #: As on PostRunErrorProcess: None on every unsignaled instance.
    signal: Optional[int] = None

    def __init__(
        self,
        args: Any,
        returncode: int,
        stdout: Any = None,
        stderr: Any = None,
        error: str = "",
    ) -> None:
        super().__init__(args, returncode, stdout, stderr)
        self.error = error


class PostRunErrorProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a command that ran, after which ASH failed.

    ``run_command_with_output_handling`` reports it as ``post_run_error: True``
    with the tool's own exit code and the ``error``; this type keeps both when a
    caller (``UVToolRunner.run_tool``) converts that dict back, as
    ``SpawnFailedProcess`` keeps ``spawn_failed``. A tool that had ended on a
    signal ASH did not send keeps its negative code, so the kept result also says
    ``signaled: True`` with the signal's number: the code is the tool's own
    ending, not ASH's failure, and no accepted exit code is negative.
    """

    post_run_error = True
    signaled = False
    #: The number of the signal that ended the tool, read only beside a True
    #: ``signaled``; None on every unsignaled instance, so reading it never
    #: raises. Class-default like the could-not-stop carrier's fields.
    signal: Optional[int] = None
    #: Uniform carrier (see COULD_NOT_STOP_MARKER); set on the instance when the
    #: failure came while the child ran and the stop ASH then sent did not end it.
    could_not_stop = False
    #: The pid the could-not-stop reason names, carried as data beside the flag
    #: so a report whose reason text is lost can still name the process; None
    #: whenever ``could_not_stop`` is False.
    could_not_stop_pid: Optional[int] = None

    def __init__(
        self,
        args: Any,
        # An int, or None when ASH stopped the tool while it still ran: the signal
        # ASH sent is ASH's, never the tool's code.
        returncode: Any,
        stdout: Any = None,
        stderr: Any = None,
        error: str = "",
        signaled: bool = False,
        # One name end to end: the producers' dict key, this parameter, the
        # attribute, and SignaledProcess's parameter are all ``signal``, so a
        # producer's flags dict splats in with no per-site translation. The
        # local shadow of the signal module is confined to this body, which
        # does not use the module. Read only with ``signaled``, and derived
        # from a kept negative code when not given, as SignaledProcess
        # derives it.
        signal: Optional[int] = None,
    ) -> None:
        super().__init__(args, returncode, stdout, stderr)
        self.error = error
        if signaled:
            self.signaled = True
            if signal is None and isinstance(returncode, int) and returncode < 0:
                signal = -returncode
            self.signal = signal


class PostRunError(subprocess.SubprocessError):
    """What run_command raises with ``check=True`` when ASH failed after the tool
    started: the exception counterpart of PostRunErrorProcess.

    ``post_run_error`` is True, ``returncode`` is the tool's own exit code, or
    None when ASH stopped the tool while it ran and saw none, and the text is
    ASH's reason. The error ASH hit is its ``__cause__``. A kept negative code
    says ``signaled`` with the signal's number, as the result does.
    """

    post_run_error = True
    signaled = False
    #: As on PostRunErrorProcess: None on every unsignaled instance.
    signal: Optional[int] = None

    def __init__(
        self,
        cmd: Any,
        returncode: Any,
        error: str,
        stdout: Any = None,
        stderr: Any = None,
        signaled: bool = False,
        # The same name end to end as on PostRunErrorProcess, for the same
        # splat; the module is not used in this body.
        signal: Optional[int] = None,
    ) -> None:
        super().__init__(error)
        self.cmd = cmd
        self.returncode = returncode
        self.error = error
        self.stdout = self.output = stdout
        self.stderr = stderr
        if signaled:
            self.signaled = True
            if signal is None and isinstance(returncode, int) and returncode < 0:
                signal = -returncode
            self.signal = signal


class CancelledProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a command whose scan was cancelled while it ran.

    The response says ``cancelled: True``, and this type keeps it, with the
    response's ``error``, when a caller (``UVToolRunner.run_tool``) converts that
    dict back, as ``TimedOutProcess`` keeps ``timed_out``. A plain
    CompletedProcess would read a cancelled run as the tool's own exit code.
    """

    cancelled = True
    #: Uniform carrier (see COULD_NOT_STOP_MARKER).
    could_not_stop = False
    #: The pid the could-not-stop reason names, carried as data beside the flag
    #: so a report whose reason text is lost can still name the process; None
    #: whenever ``could_not_stop`` is False.
    could_not_stop_pid: Optional[int] = None
    #: Uniform signal carrier (see PostRunErrorProcess); never True here: a
    #: cancel is ASH's own stop, not a signal the tool died by.
    signaled = False
    #: As on PostRunErrorProcess: None on every unsignaled instance.
    signal: Optional[int] = None

    def __init__(
        self,
        args: Any,
        returncode: Any,
        stdout: Any = None,
        stderr: Any = None,
        error: str = "",
    ) -> None:
        super().__init__(args, returncode, stdout, stderr)
        self.error = error


class ResultRejectedProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a run whose result ASH rejected.

    A remote executor's result that failed validation. The response says
    ``result_rejected: True`` with ASH's fixed code, and this type keeps both,
    with the response's ``error``, when a caller (``UVToolRunner.run_tool``)
    converts that dict back. The code the result claimed is never reported.
    """

    result_rejected = True
    #: Uniform carrier (see COULD_NOT_STOP_MARKER).
    could_not_stop = False
    #: The pid the could-not-stop reason names, carried as data beside the flag
    #: so a report whose reason text is lost can still name the process; None
    #: whenever ``could_not_stop`` is False.
    could_not_stop_pid: Optional[int] = None
    #: Uniform signal carrier (see PostRunErrorProcess); never True here: the
    #: code a rejected result claimed is never read as the tool's own ending.
    signaled = False
    #: As on PostRunErrorProcess: None on every unsignaled instance.
    signal: Optional[int] = None

    def __init__(
        self,
        args: Any,
        returncode: Any,
        stdout: Any = None,
        stderr: Any = None,
        error: str = "",
    ) -> None:
        super().__init__(args, returncode, stdout, stderr)
        self.error = error


class SignaledProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a tool that ended on a signal ASH did not send.

    An OOM kill or a hang-up, say. The response says ``signaled: True`` with the
    signal's number as ``signal``, and keeps the negative returncode subprocess
    gives it; this type keeps all three, with the error, when a caller
    (``UVToolRunner.run_tool``) converts that dict back. No accepted exit code is
    negative, so the run never reads as one that finished.
    """

    signaled = True
    #: Uniform carrier (see COULD_NOT_STOP_MARKER).
    could_not_stop = False
    #: The pid the could-not-stop reason names, carried as data beside the flag
    #: so a report whose reason text is lost can still name the process; None
    #: whenever ``could_not_stop`` is False.
    could_not_stop_pid: Optional[int] = None

    def __init__(
        self,
        args: Any,
        returncode: Any,
        stdout: Any = None,
        stderr: Any = None,
        error: str = "",
        signal: Optional[int] = None,
    ) -> None:
        super().__init__(args, returncode, stdout, stderr)
        self.error = error
        if signal is None and isinstance(returncode, int) and returncode < 0:
            signal = -returncode
        self.signal = signal


#: The flags a run's response sets to say what happened to it. A response that
#: carries an ``error`` sets one of them, and a later failure handling the response
#: keeps the one it set.
RESPONSE_FLAGS = (
    "spawn_failed",
    "post_run_error",
    "timed_out",
    "cancelled",
    "result_rejected",
    "signaled",
)

#: The code judging reads for a flagged response that carries none, per flag,
#: in the runner's own flag-precedence order. Each is the code shell
#: convention gives the same outcome: 124 a timeout, 130 an interrupt
#: (128+SIGINT), 125 the run wrapper's own failure (the run could not be
#: judged), 127 a command that never started. A signal death normally
#: carries its negative returncode on the response itself, and judging reads
#: that; the row here covers one that carries NONE -- the flag alone does
#: not say which signal, so it grades as the wrapper's own failure rather
#: than inventing a 128+N.
_CODELESS_FLAG_CODES: Tuple[Tuple[str, int], ...] = (
    ("timed_out", TIMEOUT_RETURNCODE),
    ("cancelled", 130),
    ("result_rejected", 125),
    ("post_run_error", 125),
    ("signaled", 125),
    ("spawn_failed", SPAWN_FAILURE_RETURNCODE),
)

#: The flags in the judging precedence order, for consumers that need the
#: order and not the codes. This is the code table's own flag column --
#: ``RESPONSE_FLAGS`` holds the same members in a different order -- so a
#: row added to or moved in the table moves this with it.
FLAG_ORDER: Tuple[str, ...] = tuple(flag for flag, _ in _CODELESS_FLAG_CODES)


def flagged_returncode(response: Any) -> Optional[int]:
    """The conventional code of a codeless flagged response, or ``None``.

    For the exit-code readers that hold only a response dict. The response
    keeps its ``returncode: None`` -- no printer may invent a code the tool
    never returned -- while judging reads the flag's own code through this,
    so an exit-code default of 0 cannot read as an accepted run.
    """
    if not isinstance(response, dict):
        return None
    for flag, code in _CODELESS_FLAG_CODES:
        if response.get(flag) is True:
            return code
    return None


def is_exit_code(value: Any) -> bool:
    """Whether *value* is a code a process returned: an int, and not a bool.

    bool is an int subclass, so a response whose returncode is False reads
    as an accepted 0 through a bare integer check -- and True as a 1 some
    accepted sets admit. A bool is a flag's stand-in, never an exit code.
    Shared by the exit-code readers, so their idea of "has a code" cannot
    drift the way their flag tables could before flagged_returncode.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def run_succeeded(result: Any) -> bool:
    """Whether a run's result, or response, says the tool ran and exited 0.

    The flags are read before the code: a run whose output ASH could not record
    keeps the tool's own code, which can be 0, and one ASH stopped has none, so
    a result carrying any of RESPONSE_FLAGS is no success whatever its code.
    """
    if isinstance(result, dict):
        if any(result.get(flag) is True for flag in RESPONSE_FLAGS):
            return False
        code = result.get("returncode")
    else:
        if any(getattr(result, flag, False) is True for flag in RESPONSE_FLAGS):
            return False
        code = getattr(result, "returncode", None)
    # Through is_exit_code, as every exit-code reader: a returncode of False
    # is a flag's stand-in, not a 0, and read as a success through ``== 0``.
    return is_exit_code(code) and code == 0


def signal_ending(returncode: Any, cmd_str: str) -> Optional[Tuple[int, str]]:
    """The signal a negative code names, with the death worded WITHOUT an
    attribution, or None for a code that is no signal's.

    For a reader whose producer withheld the ``signaled`` flag: the post-run
    builders drop it when ASH's own stop may have been the sender (a kill
    while the server stops, after a failed wait), so such a death is named
    but not attributed. POSIX only; Windows has no signal deaths.
    """
    if os.name == "nt" or not isinstance(returncode, int) or returncode >= 0:
        return None
    number = -returncode
    try:
        name = signal.Signals(number).name
    except ValueError:
        name = f"signal {number}"
    return number, f"{cmd_str} ended on {name} (signal {number})"


def signal_death(returncode: Any, cmd_str: str) -> Optional[Tuple[int, str]]:
    """The signal that ended a run that returned, with the reason to give, or None.

    subprocess gives a child that ended on a signal the negative of its number.
    Only a run that returned is asked: ASH's own stops raise (a timeout, a
    cancel, a failure while waiting), so a signal here is one ASH did not send.
    A result that carries a ``signaled`` flag has already had that call made by
    its builder: read the flag, and use :func:`signal_ending` when it is unset.
    POSIX only; Windows has no signal deaths.
    """
    ending = signal_ending(returncode, cmd_str)
    if ending is None:
        return None
    number, text = ending
    return number, f"{text}, a signal ASH did not send"


def _signaled_failure(
    returncode: Any,
    cmd_str: str,
    error: str,
    *,
    log_the_death: bool,
    after_a_failed_wait: bool = False,
) -> Tuple[Dict[str, Any], str]:
    """``({"signaled": True, "signal": N}, error led by the death)`` for a kept
    code that is a signal death, else ``({}, error)`` unchanged.

    The post-run-error builders keep the tool's own exit code. When that code is
    negative, the tool had already ended on a signal ASH did not send before
    ASH's own failure, so the kept result carries the flag and the number along
    with ``post_run_error``, and the reason leads with the death: an ending such
    as an OOM kill stays diagnosable from the report. A code of None (a child
    ASH stopped) and a non-negative code add nothing.

    Each death is logged in exactly one record. ``log_the_death`` has no default,
    so every caller says which record that is: False where the caller's own
    failure line logs the returned reason, True where the caller has no failure
    line (the failure-after-the-start builders), and the death line is logged
    here.

    ``after_a_failed_wait`` says the code came from a run that raised rather than
    returned, which ``signal_death``'s own contract excludes: there the server's
    final stop can be what killed the child, and ASH's own signal is never
    reported as one it did not send. The spawn record does not say whether that
    stop signaled this group, so the gate is by the number: while the server is
    stopping, the signals ASH's stops send (SIGKILL and SIGTERM) are withheld,
    and a tool's own ending by any other signal keeps its label even then.
    """
    death = signal_death(returncode, cmd_str)
    if death is None:
        return {}, error
    number, ended = death
    if (
        after_a_failed_wait
        and number in (int(signal.SIGKILL), int(signal.SIGTERM))
        and _server_stopping()
    ):
        return {}, error
    if log_the_death:
        ASH_LOGGER.error(shown_on_one_line(ended), extra=NO_MARKUP)
    return {"signaled": True, "signal": number}, f"{ended}; {error}"


#: What ``run_command_stream_output``, which returns a bare exit code and so has no
#: ``post_run_error`` to set, returns once the tool started and ASH then failed:
#: relaying its output, waiting on it, or stopping it afterwards. No scanner accepts
#: it, it is never the tool's own code, and it is not 127, which names a command
#: that never started. The runners that return a response keep the tool's own code
#: and flag ASH's failure instead.
UNRECORDED_RUN_RETURNCODE = 255


def spawn_failure_message(cmd_str: str, exc: BaseException) -> str:
    """The text for a command that never ran, raw.

    ``exc`` is whatever the spawn raised: an OSError from the OS, or anything a
    step before it raised (a sandbox wrapper that could not be prepared, Popen's
    own argument checks). Its text can hold a newline or a terminal control, so a
    caller logs it as ``shown_on_one_line(message)``, one line with the controls
    as escapes. The stderr it returns holds the message as it is, as the stderr of
    a command that ran holds the tool's text: every reader of that field shows it
    where it displays it, and an escaped copy would be shown a second time there.
    """
    return (
        f"Could not start {cmd_str}: {exc}. The command never ran "
        f"(exit code {SPAWN_FAILURE_RETURNCODE})."
    )


def clear_find_executable_cache() -> None:
    """Forget every path find_executable remembered, and what uv_tool_runner's
    lookups remembered from it.

    A miss is never remembered, so a tool installed after a lookup missed it is
    found without this. Call it after an install that may put a different copy
    ahead of one a lookup already found. A lookup still searching when it runs
    answers what it found, and does not remember it.
    """
    global _find_executable_generation
    with _find_executable_lock:
        _find_executable_generation += 1
        _find_executable_cache.clear()
    # Looked up in sys.modules, not imported: uv_tool_runner imports this module, and
    # when it is not imported it has remembered nothing.
    uv_tool_runner = sys.modules.get("automated_security_helper.utils.uv_tool_runner")
    if uv_tool_runner is not None:
        uv_tool_runner._forget_lookups()


def _bin_path() -> Optional[Path]:
    """The ASH bin directory, resolved when asked rather than at import time.

    ``core.constants.ASH_BIN_PATH`` is computed the first time that module is
    imported. ``ash dependencies install --bin-path X`` sets ASH_BIN_PATH in the
    environment after that has already happened, so a lookup against the constant
    would search the default directory and report a tool ASH had just installed
    into X as absent.

    The module-level constant remains the fallback, so tests that patch
    ``subprocess_utils.ASH_BIN_PATH`` keep working.

    A relative value is returned as it is, and :func:`find_executable` does not
    search it (see there); the first time each relative value is seen, one
    warning says so. None when there is no bin directory: ASH_BIN_PATH is unset
    and there is no usable home for ``~/.ash/bin`` (``core.constants.home_bin_path``),
    and one warning says that too.
    """
    from_env = ash_bin_path_from_environment()
    path = Path(from_env) if from_env else ASH_BIN_PATH
    if path is None:
        warn_if_home_unusable()
        return None
    if not _is_anchored(str(path)):
        _warn_relative_bin_path(str(path))
    return path


def ignored_relative_bin_path() -> Optional[str]:
    """The ASH bin directory when it is relative, and so not searched; else None.

    For the incomplete-scan message, which names it next to the MISSING tools.
    Read from the environment, as _bin_path() does, so it answers in any process.
    None too when there is no bin directory at all.
    """
    from_env = ash_bin_path_from_environment()
    path = Path(from_env) if from_env else ASH_BIN_PATH
    if path is None:
        return None
    return None if _is_anchored(str(path)) else str(path)


#: The relative ASH_BIN_PATH values already warned about in this process.
_warned_relative_bin_paths: set = set()


def _warn_relative_bin_path(value: str) -> None:
    """Say, once per value, that a relative ASH_BIN_PATH is not searched."""
    if value in _warned_relative_bin_paths:
        return
    _warned_relative_bin_paths.add(value)
    ASH_LOGGER.warning(
        f"ASH_BIN_PATH is the relative path {value!r}, which would be read relative "
        "to the working directory (usually the repository being scanned), so ASH "
        "does not look for tools there. Set ASH_BIN_PATH to an absolute path.",
        extra=NO_MARKUP,
    )


def _sysconfig_scripts_dir() -> Optional[str]:
    """The running interpreter's scripts directory, where pip installs commands."""
    return sysconfig.get_path("scripts")


def own_environment_dirs() -> List[Path]:
    """The directories of ASH's own environment that hold its commands.

    First the directory of ``sys.executable``: a virtual environment, pipx, uv
    tool or uvx environment keeps the interpreter and the console scripts of its
    packages together there. Then the interpreter's scripts directory, which is a
    different one on a Windows Python outside a virtual environment: python.exe
    is in ``<prefix>`` and pip puts commands in ``<prefix>\\Scripts``.

    Only absolute directories. An empty or relative ``sys.executable`` (an
    embedded interpreter) would otherwise turn the lookup into a search of the
    working directory, which is usually the tree being scanned.
    """
    dirs: List[Path] = []
    interpreter = sys.executable or ""
    if os.path.isabs(interpreter):
        dirs.append(Path(interpreter).parent)
    scripts = _sysconfig_scripts_dir()
    if scripts and os.path.isabs(scripts) and Path(scripts) not in dirs:
        dirs.append(Path(scripts))
    return dirs


def path_independent_dirs() -> List[Path]:
    """The directories ``find_executable`` searches whatever PATH says, in order.

    These are the fallbacks after ``shutil.which``: ASH's bin directory, then
    /usr/local/bin except on Windows. A tool in one of them is found by every
    later lookup in any environment, which is not true of a tool found only
    through PATH -- a different shell, a CI job or a cron entry may not have the
    same PATH. ``download_utils.find_verified_pinned_executable`` relies on that
    difference, so the list lives here, where ``find_executable`` reads it too,
    rather than being restated there.

    After the ASH bin directory come the directories of ASH's own environment
    (:func:`own_environment_dirs`), where pip and uv put the console scripts of
    packages installed into it (ferret-scan, detect-secrets). pipx and uv tool keep
    them off PATH. They are part of ASH's own install, as the interpreter is.

    A directory ``ash dependencies install --bin-path`` installed into is searched
    only when ``ASH_BIN_PATH`` names it; the installer prints how to set it. With no
    bin directory (:func:`_bin_path` is None) the list starts with ASH's own
    environment.
    """
    bin_path = _bin_path()
    dirs = [bin_path] if bin_path is not None else []
    for directory in own_environment_dirs():
        if directory not in dirs:
            dirs.append(directory)
    if platform.system().lower() != "windows":
        dirs.append(Path("/usr/local/bin"))
    return dirs


def _executable_candidate_names(command: str) -> List[str]:
    """The filenames to try for ``command``, in the order to try them.

    On POSIX this is the command itself and nothing else, so the search there is
    what it was before this function existed.

    Windows needs more, because the file carrying a tool's name is often not the
    file Windows can execute. ``CreateProcess`` runs PE images and nothing else:
    handed a text file with a shebang it fails with ``[WinError 193] %1 is not a
    valid Win32 application``. Package managers therefore write a wrapper Windows
    *can* run beside the script, and expect the wrapper to be what gets invoked.

    Why these three suffixes, in this order:

    * ``.exe`` first. A real PE image should always beat a wrapper.
    * ``.bat`` next, for RubyGems, which writes exactly this and only this.
      ``Gem::Installer#generate_windows_script`` builds
      ``formatted_program_filename(filename) + ".bat"`` (rubygems/installer.rb)
      and is called from ``generate_bin_script`` immediately after the
      extensionless binstub is written -- so on Windows a gem's bindir holds both
      ``cfn_nag_scan`` and ``cfn_nag_scan.bat``, and only the second one runs.
      Read from the installer source rather than recalled, because guessing
      between ``.bat`` and ``.cmd`` here is the whole bug.
    * ``.cmd`` last of the three, for npm, whose shims are ``npm.cmd`` and
      ``node_modules/.bin/*.cmd``. ``npm_audit_scanner`` resolves ``npm`` through
      this same function, so it had the same defect for the same reason.

    The bare name stays in the list, last, as a fallback rather than a preference.
    ``shutil.which`` on Windows can legitimately resolve a name that already
    carries a non-PATHEXT extension, and a directory probe can find a file Windows
    happens to be able to run; dropping the bare name would turn both into "not
    found". Putting it last is what fixes cfn-nag: the extensionless binstub does
    exist in ASH's bin directory, so a search that reaches it first returns the one
    file that cannot be executed, which is what ``[WinError 193]`` was.

    Ordering is also now fixed rather than incidental. The previous list was built
    through ``set()``, so on Windows whether the bare name or ``.exe`` was tried
    first depended on set iteration order -- fine while both lookups failed
    identically, not fine once one of the candidates is the wrong file rather than
    a missing one.

    A command already ending in one of the suffixes is returned unchanged;
    appending ``.exe`` to ``foo.bat`` only adds a lookup that cannot hit.
    """
    if platform.system().lower() != "windows":
        return [command]

    suffixes = (".exe", ".bat", ".cmd")
    if command.lower().endswith(suffixes):
        return [command]
    return [f"{command}{suffix}" for suffix in suffixes] + [command]


def _is_anchored(path: str, pathmod: Any = os.path) -> bool:
    """Whether ``path`` names a location without reference to the cwd.

    ``isabs`` alone is not enough on Windows: before Python 3.13 ``\\tools`` counts
    as absolute there, but it is rooted on whichever drive is current. A drive
    letter or UNC share is required as well.
    """
    if not pathmod.isabs(path):
        return False
    if pathmod.__name__ == "ntpath":
        return bool(pathmod.splitdrive(path)[0])
    return True


def _absolute_path_entries() -> List[str]:
    """The PATH entries that name a directory without reference to the cwd."""
    return [
        entry
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and _is_anchored(entry)
    ]


def _which_outside_working_directory(cmd: str) -> Optional[str]:
    """``shutil.which(cmd)``, except that nothing is found through the cwd.

    ``shutil.which`` on Windows looks in the working directory before PATH, and on
    every platform a relative PATH entry (``.``, an empty entry, ``bin``) names a
    directory under it. ASH usually runs from the repository it scans, so a file
    found that way is part of the repository. Both kinds of hit come back as a path
    that is not anchored; when ``which`` returns one for a bare name, the search is
    made again over the anchored PATH entries alone. A ``cmd`` with a directory
    part is answered only when it is anchored itself: ``./tool`` is a path into
    the working directory.
    """
    if os.path.dirname(cmd):
        return shutil.which(cmd) if _is_anchored(cmd) else None
    found = shutil.which(cmd)
    if found is None or _is_anchored(found):
        return found
    for entry in _absolute_path_entries():
        found = shutil.which(os.path.join(entry, cmd))
        if found:
            return found
    return None


# ---------------------------------------------------------------------------
# Tools inside the scanned tree
#
# A program on PATH can be part of the repository being scanned: an activated
# in-repo virtual environment (`uv run` puts .venv/bin first on PATH), npm's
# node_modules/.bin under `npm run`, or a committed bin directory someone added to
# PATH. Starting one of those runs repository content. While a scan is in progress
# (scanning_tree), every lookup refuses a candidate inside a scanned tree, by its
# path as found, its parent's real path, its own real path, or the device and inode
# of an ancestor, and goes on to the next candidate; children are started with the
# tree's directories taken off PATH. The operator can allow in-tree tools with
# ASH_ALLOW_IN_TREE_TOOLS=1 or --allow-in-tree-tools. A repository's config cannot,
# and `ash mcp` never honors the opt-in.
#
# The state is per scan, in a context variable, so concurrent scans in one process
# (an MCP server, a workspace's project pool) do not see each other's trees. Scanner
# threads are started with a copy of the scan's context.
# ---------------------------------------------------------------------------

#: The environment variable that lets ASH start a tool from inside the scanned tree.
#: Read from the process environment only, which belongs to the operator.
ALLOW_IN_TREE_TOOLS_ENV = "ASH_ALLOW_IN_TREE_TOOLS"
ALLOW_IN_TREE_TOOLS_FLAG = "--allow-in-tree-tools"

#: Decision point: whether this process honors the operator's opt-in at all.
#: ``ash mcp`` turns it off (see cli/mcp_server.py, MCP_HONORS_IN_TREE_OPT_IN): an
#: MCP client's scans never run a tool from a scanned or delivered tree, even with
#: ASH_ALLOW_IN_TREE_TOOLS set in the server's environment.
_opt_in_honored = True

#: Decision point: whether the opt-in also covers the scanner sandbox's own
#: programs (bwrap, firejail, readlink, true). It does; with it off they are refused
#: like any other in-tree tool.
SANDBOX_PROGRAMS_FOLLOW_OPT_IN = True


def parse_allow_in_tree_tools(value: Optional[str]) -> bool:
    """The one reading of ASH_ALLOW_IN_TREE_TOOLS: ``1``, ``true``, ``yes`` or ``on``."""
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def honor_in_tree_opt_in(honored: bool) -> None:
    """Set whether this process honors the opt-in. ``ash mcp`` calls it with False."""
    global _opt_in_honored
    _opt_in_honored = honored


def in_tree_tools_allowed() -> bool:
    """Whether a scan starting now may run tools from inside its tree.

    The active scan's answer if there is one, so a scan keeps the decision it
    started with; otherwise the operator's environment, if this process honors it.
    """
    scope = _TREE_SCOPE.get()
    if scope is not None:
        return scope.allow
    return _opt_in_honored and parse_allow_in_tree_tools(
        os.environ.get(ALLOW_IN_TREE_TOOLS_ENV)
    )


@dataclass
class _TreeScope:
    roots: Tuple[str, ...]
    allow: bool
    # command -> the in-tree file a lookup refused, when that lookup found nothing
    # else. Shared by the scan's threads; read for MISSING reasons and spawn refusals.
    refusals: Dict[str, str] = field(default_factory=dict)
    # Every refused lookup in order, cache hits included, so a caller can tell
    # which refusals happened while it was looking (recording_in_tree_refusals).
    events: List[str] = field(default_factory=list)
    warned: set = field(default_factory=set)

    @property
    def key(self) -> Tuple[Tuple[str, ...], bool]:
        return (self.roots, self.allow)


_TREE_SCOPE: contextvars.ContextVar[Optional[_TreeScope]] = contextvars.ContextVar(
    "ash_scanned_tree_scope", default=None
)


@contextmanager
def scanning_tree(root: "str | os.PathLike[str]") -> Iterator[_TreeScope]:
    """Treat ``root`` as a scanned tree for every tool lookup in this context.

    Nested scopes add their root to the enclosing scope's, keep its decision on the
    opt-in, and record refusals in the enclosing scope's records: the orchestrator
    opens its own scope inside run_ash_scan's, and the incomplete-scan message,
    printed after the orchestrator's has closed, names the tools refused in it.
    Threads see the scope only when started with a copy of this context
    (``contextvars.copy_context().run``), as the scan phase starts them.
    """
    parent = _TREE_SCOPE.get()
    key = os.path.abspath(os.fspath(root))
    roots = parent.roots if parent is not None else ()
    if key not in roots:
        roots = (*roots, key)
    if parent is None:
        scope = _TreeScope(roots=roots, allow=in_tree_tools_allowed())
    else:
        scope = _TreeScope(
            roots=roots,
            allow=parent.allow,
            refusals=parent.refusals,
            events=parent.events,
            warned=parent.warned,
        )
    token = _TREE_SCOPE.set(scope)
    try:
        yield scope
    finally:
        _TREE_SCOPE.reset(token)


def scanned_trees() -> List[str]:
    """The roots of the active scan, or none."""
    scope = _TREE_SCOPE.get()
    return list(scope.roots) if scope is not None else []


def tree_scope_key() -> Tuple[Tuple[str, ...], bool]:
    """What a lookup's answer depends on, for caches keyed by it."""
    scope = _TREE_SCOPE.get()
    return scope.key if scope is not None else ((), False)


def in_tree_refusal(command: str) -> Optional[str]:
    """Why ``command`` was not found in this scan, when the reason is the tree.

    For the MISSING reason a scanner records and for refusing a spawn; None when no
    lookup of ``command`` in the active scan refused an in-tree copy and found
    nothing else.
    """
    scope = _TREE_SCOPE.get()
    path = scope.refusals.get(command) if scope is not None else None
    if path is None:
        return None
    return _refusal_text(command, path, sandbox=False)


def _remedy(sandbox: bool) -> str:
    """What the operator can do, saying the opt-in only where it would work."""
    if _opt_in_honored and (not sandbox or SANDBOX_PROGRAMS_FOLLOW_OPT_IN):
        return (
            f"install it outside the scanned tree, or set {ALLOW_IN_TREE_TOOLS_ENV}=1 "
            f"or pass {ALLOW_IN_TREE_TOOLS_FLAG} to allow tools from the tree"
        )
    return "install it outside the scanned tree"


def _refusal_text(command: str, path: str, sandbox: bool) -> str:
    return (
        f"{command} was found only inside the scanned tree, at {path}, and ASH does "
        f"not run tools from the tree: {_remedy(sandbox)}"
    )


def _own_path(path: str) -> str:
    """``path`` as the process names it: absolute, case-folded, links kept."""
    return os.path.normcase(os.path.abspath(path))


def _is_running_interpreter(candidate: str) -> bool:
    """The Python running ASH: already started, so refusing it protects nothing.

    Compared by path first, never by inode alone. A tree's virtual environment
    links its python to the interpreter running ASH, and ``samefile`` calls the
    two one file; started through the venv's path, that python reads the tree's
    pyvenv.cfg and site-packages, so the link is not the running interpreter.
    The same holds for an in-tree link named after another tool, which would
    start the interpreter with that tool's arguments. The interpreter's own path
    is exempt, and so is a sibling name of it: a link beside ``sys.executable``
    that is the same file (``python3`` next to the ``python`` ASH runs from, in
    the tree's own venv when ASH is installed there) reads the same pyvenv.cfg,
    so it IS the running interpreter under another name, and refusing it read a
    tool that is already running as MISSING. A link in another directory, such
    as another venv's link to the base interpreter, stays refused, and so does
    a tool installed beside the interpreter inside a scanned tree.
    """
    if not sys.executable:
        return False
    own = _own_path(sys.executable)
    path = _own_path(candidate)
    if path == own:
        return True
    if os.path.dirname(path) != os.path.dirname(own):
        return False
    try:
        return os.path.samefile(path, own)
    except OSError:
        return False


def _containing_tree(candidate: str, roots: Sequence[str]) -> Optional[str]:
    for root in roots:
        if is_inside_tree(candidate, root):
            return root
    return None


def _first_usable(
    command: str,
    candidates: Iterator[str],
    scope: Optional[_TreeScope],
    sandbox: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """The first candidate outside the scan's trees, or inside one when allowed.

    Returns the chosen path, or None, and the in-tree file refused on the way when
    nothing was chosen. A refusal followed by a usable candidate is logged once
    but not recorded: the tool is not missing.
    """
    if scope is None:
        first = next(candidates, None)
        return first, None
    allowed = scope.allow and (not sandbox or SANDBOX_PROGRAMS_FOLLOW_OPT_IN)
    refused: Optional[str] = None
    for candidate in candidates:
        root = _containing_tree(candidate, scope.roots)
        if root is None or _is_running_interpreter(candidate):
            return candidate, None
        if allowed:
            _warn_once(
                scope,
                ("allowed", command, candidate),
                f"Running {command} from inside the scanned tree {root}: {candidate}. "
                f"In-tree tools are allowed by {ALLOW_IN_TREE_TOOLS_ENV} or "
                f"{ALLOW_IN_TREE_TOOLS_FLAG}.",
            )
            return candidate, None
        _warn_once(
            scope,
            ("refused", command, candidate),
            f"Not running {command} from inside the scanned tree {root}: {candidate}. "
            f"To use it, {_remedy(sandbox)}.",
        )
        if refused is None:
            refused = candidate
    return None, refused


def _warn_once(scope: _TreeScope, key: tuple, message: str) -> None:
    if key in scope.warned:
        return
    scope.warned.add(key)
    ASH_LOGGER.warning(message, extra=NO_MARKUP)


def _executable_candidates(command: str) -> Iterator[str]:
    """Every file ``find_executable`` may answer for ``command``, in its order.

    The first is the answer ``find_executable`` has always given; the rest are
    reached only when an earlier one is refused for being inside the scanned tree.
    Nothing is found through the working directory.
    """
    for name in _executable_candidate_names(command):
        if os.path.dirname(name):
            found = _which_outside_working_directory(name)
            if found:
                yield found
            continue
        # shutil.which first, as find_executable always has. When it finds nothing
        # no PATH entry holds the name, so the entries are searched one by one
        # only after a hit: one through the working directory, which is skipped,
        # or one that may be refused for being inside the scanned tree.
        first = shutil.which(name)
        if first is not None:
            if _is_anchored(first):
                yield first
            for entry in _absolute_path_entries():
                found = shutil.which(os.path.join(entry, name))
                if found and found != first:
                    yield found
        # Anchored only: a relative ASH_BIN_PATH would be read against the cwd.
        for directory in path_independent_dirs():
            if not _is_anchored(str(directory)):
                continue
            poss = directory.joinpath(name)
            ASH_LOGGER.debug(f"Checking for executable: {poss}", extra=NO_MARKUP)
            if _is_executable_file(str(poss)):
                yield poss.as_posix()


def _lookup(command: str, sandbox: bool = False) -> Optional[str]:
    """find_executable's search under the active scan, cached by what it depends on.

    PATH and ASH_BIN_PATH are part of the key, and a remembered path is used only
    while it is still an executable file: deleted, or without its execute bit, it
    is searched for again.
    """
    scope = _TREE_SCOPE.get()
    key = (
        command,
        sandbox,
        tree_scope_key(),
        # None when PATH is unset, which shutil.which reads as the system's
        # default directories; an empty PATH names none. The two must not share
        # a cache entry.
        os.environ.get("PATH"),
        os.environ.get("ASH_BIN_PATH", ""),
    )
    cached = _find_executable_cache.get(key)
    if cached is not None:
        if cached[0] is None or not _is_executable_file(cached[0]):
            # A miss is searched for again on every call, so a tool installed
            # after one missed is found by the next; a remembered path is used
            # only while it is still an executable file.
            cached = None
    if cached is None:
        with _find_executable_lock:
            generation = _find_executable_generation
        try:
            cached = _first_usable(
                command, _executable_candidates(command), scope, sandbox
            )
        except Exception as e:
            ASH_LOGGER.error(e, extra=NO_MARKUP)
            cached = (None, None)
        # Remembered only if no clear ran while the search was under way: a
        # search that began before an install found what was there before it,
        # and the clear after the install is what makes the next lookup search
        # again. A miss is not remembered (it is searched for again on every
        # call), and the cache is bounded, oldest entries first.
        with _find_executable_lock:
            if generation == _find_executable_generation and cached[0] is not None:
                while len(_find_executable_cache) >= _FIND_EXECUTABLE_CACHE_LIMIT:
                    _find_executable_cache.pop(next(iter(_find_executable_cache)))
                _find_executable_cache[key] = cached
    found, refused = cached
    if refused is not None and scope is not None:
        # Recorded on this scan even when the answer came from the cache, so a
        # later scan of the same tree sees why the tool is missing.
        scope.refusals.setdefault(command, refused)
        scope.events.append(command)
    elif found is not None and scope is not None:
        # A usable copy found now: an earlier refusal of this command is no
        # longer why the tool is missing, since it is not. Left in place, the
        # incomplete-scan message named a tool that did run as one not run.
        scope.refusals.pop(command, None)
    return found


def in_tree_refusals() -> Dict[str, str]:
    """The active scan's refused tools: command -> the in-tree file not run."""
    scope = _TREE_SCOPE.get()
    return dict(scope.refusals) if scope is not None else {}


def in_tree_remedy() -> str:
    """What to do about a refused tool, naming the opt-in only where it applies."""
    return _remedy(sandbox=False)


@contextmanager
def recording_in_tree_refusals() -> Iterator[List[str]]:
    """Collect the refusal reasons of lookups made while the block runs.

    For a caller that wants the reason a check failed, such as the scan phase
    recording why a scanner is MISSING, whatever lookups the check made.
    """
    scope = _TREE_SCOPE.get()
    start = len(scope.events) if scope is not None else 0
    recorded: List[str] = []
    try:
        yield recorded
    finally:
        if scope is not None:
            for command in dict.fromkeys(scope.events[start:]):
                reason = in_tree_refusal(command)
                if reason is not None:
                    recorded.append(reason)


#: How long an interrupted child (a container runtime, the Nix shell) gets to stop
#: on its own before it is killed.
INTERRUPT_GRACE_SECONDS = 5

#: The slices that grace is waited out in, on both arms. On Windows Popen.wait
#: is a single WaitForSingleObject, which a Ctrl-C does not end, so a second
#: Ctrl-C would land only once the whole grace had passed; between two slices it
#: lands at once. The POSIX wait slices for its own reason: each pass observes
#: the exit without reaping, so the die-now record is discarded before the reap.
INTERRUPT_WAIT_SLICE_SECONDS = 0.25

#: How long :func:`discard_tool_pid_before_reap` polls for a child's exit on a
#: build without ``os.waitid``, for a child that was just sent a kill
#: (``just_killed``, the default). A child still alive after this is past
#: anything a kill leaves behind, so the record is dropped rather than the
#: caller left waiting. A healthy child waited on to its end is not bounded.
_REAP_POLL_BOUND_SECONDS = 5.0


def _has_a_console() -> bool:
    """Whether this process is attached to a Windows console.

    GetConsoleProcessList lists the processes attached to this process's console:
    "If the return value is zero, the function has failed, because every console has
    at least one process associated with it."
    (https://learn.microsoft.com/windows/console/getconsoleprocesslist) A buffer of
    one is enough, since with more processes attached it returns how many there are.
    GetConsoleWindow is not used: it answers whether the console has a window, and it
    need not have one: a process started with CREATE_NO_WINDOW can be attached to a
    console with no window, and a Ctrl-C sent to that console reaches its children.
    """
    try:
        import ctypes

        processes = (ctypes.c_ulong * 1)()
        attached = ctypes.windll.kernel32.GetConsoleProcessList(processes, 1)  # type: ignore[attr-defined]
        return attached != 0
    except (ImportError, AttributeError, OSError):
        # No ctypes (a Python built without _ctypes) or no Windows API: no console
        # that could have passed the Ctrl-C on.
        return False


def _child_got_the_terminals_interrupt() -> bool:
    """Whether a Ctrl-C typed at the terminal also reached the child this started.

    On POSIX the child runs in this process's group. When that group is the
    terminal's foreground group, the terminal sent SIGINT to every process in it,
    the child included.

    On Windows the child is started without CREATE_NEW_PROCESS_GROUP, so it shares
    this process's console, and "By default, these signals are passed to all console
    processes that are attached to the console."
    (https://learn.microsoft.com/windows/console/ctrl-c-and-ctrl-break-signals)
    With a console, then, the child has the Ctrl-C already. Terminating it at once
    cut short its own handling: with `docker run --rm` attached, that can leave the
    container running after ASH exits.
    """
    if os.name == "nt":
        return _has_a_console()
    # Whichever standard stream is the terminal: ``ash scan < inputs`` has its
    # input redirected and its output still at the terminal, and asked of the
    # input alone the probe read "no terminal" and sent the typed Ctrl-C a
    # second time.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            return os.tcgetpgrp(stream.fileno()) == os.getpgrp()
        except (AttributeError, OSError, ValueError):
            continue
    # No terminal: CI, a pipe.
    return False


class HeldInterrupt:
    """Holds a Ctrl-C while a child is started, until the caller has the child.

    A KeyboardInterrupt raised inside Popen, after the child exists and before Popen
    returns it, left the caller nothing to stop: ASH exited 130 at once, and a
    container runtime ran on, given neither its grace nor a kill. Inside this block
    SIGINT is only recorded. The caller calls :meth:`release` once it holds the
    process, inside the try that stops it: that puts the previous handler back and
    hands it a Ctrl-C that came, so Python's own handler raises KeyboardInterrupt,
    handled as one during the wait, and a handler that does something else does
    that. Leaving the block puts the handler back in any case, and hands it a
    Ctrl-C that came while the child failed to start: a KeyboardInterrupt it raises
    replaces that failure. Once the block is left, a Ctrl-C goes to the previous
    handler even where putting it back failed.

    Only a Python handler is held. SIGINT ignored (a script run as ``cmd &``
    starts that way, and its children inherit it), at its default, or set outside
    Python is left as it is: a recording handler in its place would be reset at
    exec, so a child started inside the block would stop ignoring SIGINT, and a
    SIGINT would raise KeyboardInterrupt where it is meant to be ignored. Only the
    main thread can set a signal handler, so elsewhere nothing is held either. The
    signal mask is not touched: a child inherits the mask, but not a handler,
    which exec resets.
    """

    def __init__(self) -> None:
        self._previous: Any = None
        self._held = False
        # Each Ctrl-C held, as Python delivered it: its number (an int) and frame.
        self._pending: List[Tuple[int, Any]] = []
        self._left = False

    def __enter__(self) -> Self:
        if threading.current_thread() is threading.main_thread() and callable(
            signal.getsignal(signal.SIGINT)
        ):
            self._previous = signal.signal(signal.SIGINT, self._record)
            self._held = True
        return self

    def _record(self, signum: int, frame: Any) -> None:
        if self._left:
            # Still installed after the block, because putting the previous
            # handler back failed: a Ctrl-C now is not the block's to hold.
            self._previous(signum, frame)
            return
        self._pending.append((signum, frame))

    def _restore(self) -> None:
        if self._held:
            signal.signal(signal.SIGINT, self._previous)
            # Only once it is back: a failure above leaves it held, so leaving the
            # block tries again rather than leaving every later Ctrl-C recorded.
            self._held = False

    def _hand_over(self) -> None:
        """Give each held Ctrl-C to the handler it was held from, as Python would
        have: once each, with the number and frame it came with. One that raises,
        as Python's own handler does, ends the hand-over, as it ends the run."""
        pending, self._pending = self._pending, []
        for signum, frame in pending:
            self._previous(signum, frame)

    def release(self) -> None:
        """Put the previous handler back, and hand it a Ctrl-C that was held.

        The hold is given up even when putting the handler back fails: each held
        Ctrl-C still goes to the previous handler, what it raises chained from
        the failure, and the recording handler, left installed, passes each
        later Ctrl-C to the previous one, as it does once a block is left. The
        ``__exit__`` that follows, where the ``with`` form is left, tries the
        restore again and hands over what is still held."""
        try:
            self._restore()
        except BaseException as restore_error:
            self._left = True
            # The hold is given up even now: each held Ctrl-C goes to the
            # previous handler, which does not have to be installed to be
            # called. One that raises, as Python's own does, replaces the
            # restore failure, chained from it.
            try:
                self._hand_over()
            except BaseException as handed_over:
                raise handed_over from restore_error
            raise
        self._hand_over()

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self._left = True
        self._restore()
        if exc_type is KeyboardInterrupt:
            return
        try:
            self._hand_over()
        except KeyboardInterrupt as interrupt:
            raise interrupt from exc


def discard_tool_pid_once_exited(process: subprocess.Popen) -> bool:
    """Forget a recorded launcher child the moment its exit is OBSERVED,
    before anything reaps it. Answers whether the child has ended.

    The die-now mirror holds plain pids (core/cancellation._TOOL_PIDS), and a
    reaped pid can be reused at once, so the discard must come between the
    child's end and the reap: discarded after, the die-now window aims a
    SIGKILL at whatever process holds the pid next. ``os.waitid`` with
    ``WNOWAIT`` reads the exit and leaves the child reapable, so the caller's
    own poll or wait still reaps it. A child this process cannot ``waitid``
    (already reaped elsewhere) has nothing left for the record to name, so
    the record is dropped. On a build without ``waitid`` the record is
    dropped once ``poll`` says the child ended: on Windows no die-now
    handler installs, so nothing reads the record; on a POSIX build without
    it (CPython leaves ``waitid`` out on macOS) the handlers do install, and
    ``poll`` reaps before the discard, so a pid reused inside that one step
    stays aimed at until the discard lands -- the narrow window the
    ``waitid`` arm exists to close. A no-op for a child that was never
    recorded.
    """
    if process.returncode is not None:
        discard_tool_pid(process.pid)
        return True
    if not hasattr(os, "waitid"):
        if process.poll() is None:
            return False
        discard_tool_pid(process.pid)
        return True
    try:
        waited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except OSError:
        discard_tool_pid(process.pid)
        return True
    if waited is None:
        return False
    discard_tool_pid(process.pid)
    return True


def discard_tool_pid_before_reap(
    process: subprocess.Popen, *, just_killed: bool = True
) -> None:
    """Wait for the child's exit WITHOUT reaping it, then forget its record.

    The blocking form of :func:`discard_tool_pid_once_exited`, for the arms
    that know the child is ending (a kill was just sent, or the caller wants
    to block until the end): ``waitid`` with ``WNOWAIT`` and no ``WNOHANG``
    sleeps until the exit and leaves the child reapable, so the caller's
    ``wait`` right after this still reaps it, and the record never outlives
    the reap.

    On a build without ``waitid`` (CPython leaves it out on macOS, and
    Windows has none) the exit is polled for in slices with the record still
    registered, and the record is discarded only once the poll sees the exit.
    ``poll`` reaps, so on those builds the discard follows the reap by one
    step, as in :func:`discard_tool_pid_once_exited`; what the poll closes is
    the longer window in which the child was alive and its record already
    gone, out of reach of a concurrent die-now sweep.

    ``just_killed`` says which of the two callers this is. For a child that
    was just sent a kill the poll is bounded by ``_REAP_POLL_BOUND_SECONDS``:
    one still alive after that survived the kill, and a die-now sweep can do
    nothing more to it. For a healthy child the caller wants to block on until
    its end (``just_killed=False``) there is no bound, because dropping the
    record while the child lives leaves it out of reach of the sweep for the
    rest of its run.
    """
    if process.returncode is None:
        deadline = time.monotonic() + _REAP_POLL_BOUND_SECONDS if just_killed else None
        if hasattr(os, "waitid"):
            # Observed in slices, with the bound the just-killed arm promises:
            # a blocking waitid on a child in uninterruptible sleep held the
            # caller for as long as the child chose to stay.
            while True:
                try:
                    waited = os.waitid(
                        os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                    )
                except OSError:
                    break
                if waited is not None:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
                time.sleep(INTERRUPT_WAIT_SLICE_SECONDS)
        else:
            while process.poll() is None and (
                deadline is None or time.monotonic() < deadline
            ):
                time.sleep(INTERRUPT_WAIT_SLICE_SECONDS)
    discard_tool_pid(process.pid)


def stop_after_interrupt(
    process: "subprocess.Popen[Any]",
    grace: float = INTERRUPT_GRACE_SECONDS,
    *,
    child_got_the_interrupt: Optional[bool] = None,
) -> bool:
    """Pass the operator's interrupt on to *process* and give it *grace* to stop.

    For a child that stops cleanly on Ctrl-C itself: a container runtime, which
    hands it to the container, or the Nix shell, which is the inner ASH. An
    interrupt sent to this process alone (kill -INT, a CI job's cancel) has not
    reached the child, so it is sent on; one typed at the terminal has, and is not
    sent twice, which would cut short the child's own clean-up. On Windows the
    console sends a Ctrl-C to the child too, and a process with no console cannot
    pass one on, so its child is ended at once instead. A child still running after
    the grace is killed, and so is one when the operator presses Ctrl-C again while
    waiting: on Windows within one slice of the wait. The caller re-raises the
    interrupt.

    Returns whether the child is stopped as far as this process can tell: True
    when it exited within the grace, or outlived it and the kill was accepted;
    False when the kill was refused (EPERM, a setuid program the tool became), so
    the child may still run and a caller raising a cancel can say so, as
    _run_cancellable's cancel does. A second Ctrl-C while waiting raises its
    KeyboardInterrupt instead of returning; a kill refused there is logged.

    ``child_got_the_interrupt`` says whether the child already has the operator's
    interrupt. The default, None, asks the terminal, which is right for a
    KeyboardInterrupt arm and only there. A stop triggered by the scan's cancel
    event -- the SIGTERM handler sets it, and the signal was delivered to this
    process alone -- must pass False: the child has received nothing, and at a
    terminal the probe would wrongly skip the send, leaving the child its full
    grace for no reason and the runtime no chance at a clean stop.

    With no terminal there is no telling a SIGINT sent to the whole process group
    (``kill -INT -<pgid>``) from one sent to this process alone, so after a group
    SIGINT the child gets it twice. A child that reads a second Ctrl-C as "stop now"
    stops then without the rest of its own clean-up.
    """
    if child_got_the_interrupt is None:
        child_got_the_interrupt = _child_got_the_terminals_interrupt()
    # The exit is observed, and the record discarded, before any signal:
    # send_signal and kill poll first, which reaps a child that has exited,
    # and a record discarded after that reap could name a reused pid. The
    # signal is still sent: on a child that has exited it does nothing.
    if not child_got_the_interrupt:
        discard_tool_pid_once_exited(process)
        try:
            if os.name == "nt":
                process.terminate()
            else:
                process.send_signal(signal.SIGINT)
        except OSError:
            pass  # it has already exited
    try:
        _wait_out(process, grace)
    except KeyboardInterrupt:
        discard_tool_pid_once_exited(process)
        if _kill_unless_refused(process):
            # Observed, discarded, then reaped: the die-now record must not
            # outlive the reap (discard_tool_pid_before_reap). The reap is
            # bounded: a child SIGKILL did not end, in uninterruptible sleep
            # say, is not waited for without end (_wait_after_kill).
            discard_tool_pid_before_reap(process)
            _wait_after_kill(process)
        raise
    except Exception:
        discard_tool_pid_once_exited(process)
        if not _kill_unless_refused(process):
            return False
        discard_tool_pid_before_reap(process)
        _wait_after_kill(process)
    return True


def _kill_unless_refused(process: "subprocess.Popen[Any]") -> bool:
    """Kill *process*; False, logged, when the kernel refuses the signal.

    ``kill`` raises PermissionError on a child this process may not signal,
    such as a setuid program the tool became. Raised from a stop arm it
    replaced the KeyboardInterrupt or the cancel the caller re-raises with an
    OSError, and a child the kernel would not kill is not waited for either.
    The callers of stop_after_interrupt record their child by pid
    (record_tool_pid), and the discard that follows a kill runs only on an
    accepted one, so a refused kill leaves that pid recorded for the SIGTERM
    handler's die-now kill, which tries it again.
    """
    try:
        process.kill()
    except OSError as error:
        ASH_LOGGER.warning(
            f"Could not kill pid {process.pid}: {error}", extra=NO_MARKUP
        )
        return False
    return True


def _wait_out(process: "subprocess.Popen[Any]", grace: float) -> None:
    """Wait up to *grace* for *process*, raising TimeoutExpired if it outlives it.

    Both arms wait the grace out in slices of INTERRUPT_WAIT_SLICE_SECONDS. On
    POSIX each pass OBSERVES the exit without reaping, so the die-now record is
    discarded before the reaping wait, and a signal interrupts the sleep, so a
    second Ctrl-C lands within one slice. On Windows the wait is one
    WaitForSingleObject, which a Ctrl-C does not end (CPython's
    subprocess.Popen._wait), so the slices are what let a second Ctrl-C land
    between two of them.
    """
    if os.name != "nt":
        # Sliced like the Windows arm, but for a different reason: the exit
        # is OBSERVED (waitid WNOWAIT) and the die-now record discarded
        # before the reaping wait, so the record never outlives the reap
        # (discard_tool_pid_once_exited). A signal still interrupts the
        # sleep, so a second Ctrl-C lands within one slice.
        deadline = time.monotonic() + grace
        while not discard_tool_pid_once_exited(process):
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(
                    getattr(process, "args", "the child"), grace
                )
            time.sleep(
                min(INTERRUPT_WAIT_SLICE_SECONDS, max(0.0, deadline - time.monotonic()))
            )
        process.wait(timeout=grace)
        return
    slices = max(1, round(grace / INTERRUPT_WAIT_SLICE_SECONDS))
    for _ in range(slices):
        try:
            process.wait(timeout=INTERRUPT_WAIT_SLICE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            continue
    raise subprocess.TimeoutExpired(getattr(process, "args", "the child"), grace)


def find_executable(command: str) -> Optional[str]:
    """Find the full path to an executable.

    Nothing is found through the working directory, which is usually the
    repository being scanned (see :func:`_which_outside_working_directory`), and
    while a scan is in progress a copy inside the scanned tree is refused unless
    the operator allowed it (see the section comment above).

    The directories searched after PATH (:func:`path_independent_dirs`) count only
    when they are anchored: a relative ASH_BIN_PATH names a directory under the
    working directory, which is usually the repository being scanned, so a
    repository that committed ``bin/grype`` had it run as grype under
    ``ASH_BIN_PATH=bin``. And only an executable file there counts, as on PATH: a
    file without the execute bit, or a directory, of the tool's name is not the tool.

    Only a found path is remembered, for the PATH and ASH_BIN_PATH it was found
    under, so after either changes the next call searches again. An unset PATH,
    which ``shutil.which`` reads as the system's default directories, is told apart
    from an empty one, which names none. It is given again only while it is still
    an executable file: deleted, or without its execute bit, it is searched for
    again. A miss is searched for again on every call, so a tool installed after
    one is found by the next.

    Args:
        command: The command to find

    Returns:
        The full path to the executable, or None if not found
    """
    return _lookup(command)


def lookup_for_scan(
    command: str, root: "str | os.PathLike[str]"
) -> Tuple[Optional[str], Optional[str]]:
    """``find_executable`` with ``root`` treated as a scanned tree, and the reason.

    For callers that know their tree, such as a converter run on its own or the
    cdk-nag worker process. Returns the path, or None, and when None because an
    in-tree copy was refused, the text that says so.
    """
    with scanning_tree(root):
        found = find_executable(command)
        return found, (None if found else in_tree_refusal(command))


def find_executable_for_scan(
    command: str, root: "str | os.PathLike[str]"
) -> Optional[str]:
    """:func:`lookup_for_scan` without the reason.

    Returns:
        An absolute path, or None. A caller given None treats the tool as
        unavailable and starts nothing.
    """
    return lookup_for_scan(command, root)[0]


def find_trusted_executable(command: str) -> Optional[str]:
    """Find a program the scanner sandbox itself runs: bwrap, firejail, readlink.

    :func:`find_executable`, with the opt-in applying only if
    :data:`SANDBOX_PROGRAMS_FOLLOW_OPT_IN` says so.
    """
    return _lookup(command, sandbox=True)


def _without_in_tree_path_entries(
    env: Dict[str, str], scope: _TreeScope
) -> Dict[str, str]:
    """``env`` with the scan's trees, and entries not anchored, taken off PATH.

    A child looks programs up by name itself: a ``#!/usr/bin/env node`` shebang, a
    binstub, a scanner starting git, jsii starting node. Without this it would find
    the tree's copies that ASH's own lookup refused. When no entry is left, PATH is
    :func:`_default_search_path`: an empty PATH is read as the working directory.
    Also carries the scan's decision on the opt-in, so a child ASH (the cdk-nag
    worker, a container, a nix shell) makes the same one.
    """
    env = dict(env)
    if scope.allow:
        env[ALLOW_IN_TREE_TOOLS_ENV] = "1"
        return env
    env.pop(ALLOW_IN_TREE_TOOLS_ENV, None)
    path_value = env.get("PATH")
    if path_value:
        kept = [
            entry
            for entry in path_value.split(os.pathsep)
            if entry
            and _is_anchored(entry)
            and _containing_tree(entry, scope.roots) is None
        ]
        env["PATH"] = os.pathsep.join(kept) if kept else _default_search_path()
    return env


def child_environ(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The environment to start a child with: see :func:`_spawn_env`."""
    return _spawn_env(env)


def started_from_working_directory(
    name: str,
    cwd: "str | os.PathLike[str] | None" = None,
    env: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """The file the OS would start for the bare ``name`` through a working directory.

    Two searches look there. Windows ``CreateProcess`` tries ASH's working directory
    before PATH. And on every platform a PATH entry that is not anchored (an empty
    entry, ``.``, ``bin``) names a directory under one: ASH's on Windows, and on
    POSIX the child's, ``cwd``, because the search runs after the child changes
    directory. ASH usually runs from the repository it scans, and a scanner's
    ``cwd`` is often the tree itself.

    Returns:
        The file, or None when neither search would find one.
    """
    if os.path.dirname(name):
        return None
    windows = platform.system().lower() == "windows"
    path_value = (
        env.get("PATH", os.defpath)
        if env is not None
        else os.environ.get("PATH", os.defpath)
    )
    directories = [
        entry for entry in path_value.split(os.pathsep) if not _is_anchored(entry)
    ]
    if windows:
        directories.insert(0, os.curdir)
    base = os.getcwd() if windows or cwd is None else os.fspath(cwd)
    names = _executable_candidate_names(name)
    if windows:
        names.append(f"{name}.com")
    for directory in directories:
        for candidate in names:
            path = os.path.join(base, directory, candidate)
            if os.path.isfile(path):
                return path
    return None


def names_a_location(value: str) -> bool:
    """Whether *value* spells a filesystem location (holds a path separator) rather
    than a bare command name that PATH resolves. ``/`` is a separator on every
    platform node runs on; ``os.sep`` and ``os.altsep`` cover the host's own.

    One definition for the cdk-nag scanner's dependency check and the cdk-nag
    wrapper, which read ``JSII_NODE`` by the same test and must not drift apart.
    """
    separators = {"/", os.sep, os.altsep} - {None}
    return bool(value) and any(separator in value for separator in separators)


#: The suffixes the operating system starts by running cmd.exe on the file. Which
#: suffixes the lookup tries is decided where the candidate names are built.
_BATCH_SUFFIXES = (".bat", ".cmd")

#: What cmd.exe acts on outside double quotes: its operators, its escape character and
#: the parentheses, which close or open the block that holds ``%*`` in a batch wrapper.
_CMD_CHARACTERS = "<>|&^()"

#: Appended to the refusal of a caret: ``pkg@^1.0.0`` is npm's default version range,
#: and an argument with a space is quoted by ``list2cmdline`` and passed as it is.
_VERSION_RANGE_ADVICE = (
    "; a version range can be written without ^, as 1.x or as >=1.0.0 <2.0.0, "
    "which has a space and is passed as it is"
)


def _starts_through_cmd_exe(program: str) -> bool:
    """Whether the operating system starts ``program`` by running cmd.exe on it."""
    return platform.system().lower() == "windows" and str(program).lower().endswith(
        _BATCH_SUFFIXES
    )


def _text_of_argument(argument: Any) -> Optional[str]:
    """The text ``subprocess`` writes for ``argument``, or None when it is not text.

    A str, bytes or path-like element is decoded as ``subprocess`` decodes it. Any
    other element stays for ``Popen`` to report.
    """
    if not isinstance(argument, (str, bytes, os.PathLike)):
        return None
    try:
        return os.fsdecode(argument)
    except (TypeError, ValueError):
        return None


def _why_cmd_exe_reads_it_differently(text: str, percent_signs: int) -> Optional[str]:
    """Why cmd.exe would not read ``text`` as written, or None when it would.

    ``percent_signs`` is how many the whole command line holds. ``list2cmdline`` puts
    ``text`` in double quotes when it is empty or holds a space or tab. Inside the
    quotes cmd.exe reads ``< > | & ^ ( )`` as plain text, in the first read and in the
    batch file's second read of ``%*``. Written bare, each of them acts (a ``)`` closes
    a parenthesized block that holds ``%*``). A caret before an operator
    would protect it in the first read only, so nothing is written: ``text`` is passed
    as it is or not at all. The reason for a caret carries the way to write a version
    range, because npm's default range, ``^1.0.0``, is an argument with no space.

    A double quote has no escape cmd.exe reads in a line written by
    ``list2cmdline`` (it writes ``\\"``), and a line break ends the line. A percent
    sign starts ``%name%`` wherever it stands, double quotes included, and the name
    may run across arguments; a lone one names nothing.
    """
    if '"' in text or "\r" in text or "\n" in text:
        return "a double quote or a line break"
    if "%" in text and percent_signs > 1:
        return "a percent sign that could pair with another"
    quoted = not text or " " in text or "\t" in text
    if not quoted and any(char in text for char in _CMD_CHARACTERS):
        reason = "a character cmd.exe acts on, with no double quotes around it"
        return reason + _VERSION_RANGE_ADVICE if "^" in text else reason
    return None


def _refusal_for_cmd_exe(args: List[Any]) -> Optional[OSError]:
    """The refusal for ``args`` when cmd.exe would read one of them differently.

    ``args[0]`` is the batch file, read like any other element, and nothing in
    ``args`` is rewritten. The error names the program and the position, never the
    argument: its text can be a value the operator keeps private.
    """
    texts = [_text_of_argument(argument) for argument in args]
    percent_signs = sum(text.count("%") for text in texts if text is not None)
    for index, text in enumerate(texts):
        if text is None:
            continue
        reason = _why_cmd_exe_reads_it_differently(text, percent_signs)
        if reason is not None:
            subject = "the program" if index == 0 else f"argument {index}"
            return OSError(
                errno.EINVAL,
                f"{subject} cannot be passed to a batch program: cmd.exe would read "
                f"it differently ({reason})",
                args[0],
            )
    return None


def _resolve_for_spawn(
    args: List[str],
    cwd: "str | os.PathLike[str] | None" = None,
    env: Optional[Dict[str, str]] = None,
) -> Optional[OSError]:
    """Point ``args[0]`` at the file :func:`find_executable` finds for it.

    When that file is a batch file on Windows, the arguments are checked for cmd.exe
    (see the module docstring), once, here, so every helper that starts a process
    applies the same rule. Only ``args[0]`` is ever rewritten. An argument cmd.exe
    would read differently is returned as an ``OSError`` with ``errno.EINVAL``.

    Returned, for the caller to raise where it reports a command that could not
    start, as the ``FileNotFoundError`` ``subprocess`` raises for a missing
    program, when the program would otherwise come from the working directory or
    the scanned tree:

    * a path with a directory part that is not anchored, such as ``./tool``;
    * any name, bare or a full path, whose lookup refused an in-tree copy and found
      nothing else, because the operating system would start that copy;
    * a bare name it did not find that the operating system would start from a
      working directory (:func:`started_from_working_directory`);
    * on Windows, any bare name it did not find: ``CreateProcess`` has search
      locations of its own that ASH's lookup does not check.

    Any other name it does not find is passed on as it was, for ``subprocess`` to
    start or fail on.
    """
    name = os.fspath(args[0]) if isinstance(args[0], os.PathLike) else args[0]
    if os.path.dirname(name) and not _is_anchored(name):
        return FileNotFoundError(
            errno.ENOENT,
            f"{name} is a path relative to the working directory, which is not run",
            name,
        )
    # The child's own PATH first, when the caller gave one that differs from
    # ASH's: a tool's bin directory put first there names the copy the child
    # would run, which ASH's PATH may shadow with another copy, and an in-tree
    # copy refused on that PATH is a refusal to report, not a miss to fall
    # through.
    found, child_refused = _found_on_the_childs_path(name, env)
    if found is None:
        found = find_executable(name)
    if found:
        args[0] = found
        if _starts_through_cmd_exe(found):
            return _refusal_for_cmd_exe(args)
        return None
    refusal = in_tree_refusal(name)
    if refusal is None and child_refused is not None:
        refusal = (
            f"{name} resolves on the child's PATH to {child_refused}, inside the "
            "scanned tree, which is not run"
        )
    if refusal is not None:
        return FileNotFoundError(errno.ENOENT, refusal, name)
    if os.path.dirname(name):
        return None
    local = started_from_working_directory(name, cwd, env)
    if local is not None:
        return FileNotFoundError(
            errno.ENOENT,
            f"{name} is not on PATH, and the copy found through the working "
            f"directory, {local}, is not run",
            name,
        )
    if platform.system().lower() == "windows" and _refuse_unresolved_on_windows:
        return FileNotFoundError(errno.ENOENT, f"{name} was not found on PATH", name)
    return None


def _found_on_the_childs_path(
    name: str, env: Optional[Dict[str, str]]
) -> Tuple[Optional[str], Optional[str]]:
    """The program as the CHILD's PATH names it, when the caller gave one, and
    the in-tree copy that PATH named and the scan refused when nothing was chosen.

    ``find_executable`` searches ASH's own PATH. A caller that hands the child
    an environment of its own (a tool's bin directory put first) had argv[0]
    resolved against ASH's PATH, or refused as not found, while the child's own
    search would have found it. The child's anchored entries are searched the
    way ASH's are, with the scan's in-tree refusal applied (``_first_usable``),
    and before ASH's PATH, which may shadow the child's copy with another.
    ``(None, None)`` when the caller gave no PATH of its own, or when it names
    nothing; ``(None, refused)`` when its only copies were inside the scanned
    tree, for the caller to report as the refusal it is.
    """
    if env is None or os.path.dirname(name):
        return None, None
    path_value = env.get("PATH")
    if not path_value or path_value == os.environ.get("PATH"):
        return None, None
    entries = [
        entry for entry in path_value.split(os.pathsep) if entry and _is_anchored(entry)
    ]
    if not entries:
        return None, None

    def candidates() -> Iterator[str]:
        for candidate in _executable_candidate_names(name):
            for entry in entries:
                found = shutil.which(os.path.join(entry, candidate))
                if found:
                    yield found

    return _first_usable(name, candidates(), _TREE_SCOPE.get())


#: Whether a bare name ASH's lookup cannot resolve is refused on Windows instead of
#: handed to CreateProcess, whose own search includes directories ASH does not check.
_refuse_unresolved_on_windows = True


def resolve_command(
    args: List[str],
    cwd: "str | os.PathLike[str] | None" = None,
    env: Optional[Dict[str, str]] = None,
) -> List[str]:
    """A copy of ``args`` with its program resolved as the spawn helpers resolve it.

    For a caller that starts the process itself. When the program is a batch file on
    Windows the arguments have been checked for cmd.exe (see the module docstring),
    and the copy goes to ``subprocess`` as it is. A string is the program's name,
    as the spawn helpers read one (``_argv_list``); ``list()`` of it made it its
    characters.

    Raises:
        FileNotFoundError: the program would come from the working directory (see
            :func:`_resolve_for_spawn`), the error ``subprocess`` raises for a
            program that is not installed.
        OSError: an argument to a batch program is one cmd.exe would read
            differently (``errno.EINVAL``).
    """
    resolved = _argv_list(args)
    if resolved:
        refused = _resolve_for_spawn(resolved, cwd, env)
        if refused is not None:
            raise refused
    return resolved


def _prepare_spawn(
    args: Union[List[str], str],
    env: Optional[Dict[str, str]],
    cwd: Optional[Union[str, Path]],
    shell: bool,
) -> "Optional[SpawnPlan]":
    """The scanner sandbox's rewrite of this spawn, or None when none applies.

    Every helper in this module calls this immediately before starting a process, which
    makes it the one place a scanner subprocess is sandboxed (see
    ``utils/sandbox/scope.py``). Outside a scanner's sandbox scope it returns None and
    the spawn is exactly what it was.
    """
    from automated_security_helper.utils.sandbox.scope import (
        SandboxUnavailable,
        active_scope,
        prepare_spawn,
    )

    scope = active_scope()
    if scope is None:
        return None
    if shell or isinstance(args, str):
        # No builtin scanner spawns through a shell. Refused rather than wrapped as
        # `sh -c`, so that a string command cannot reach the sandbox unparsed.
        # Counted as the scope's other refusals are (scope.prepare_spawn), so a
        # converter's row reports this one too.
        refusal = SandboxUnavailable(
            "a scanner tried to start a shell command, which the sandbox does not wrap"
        )
        scope.refused_spawns += 1
        scope.last_refusal = str(refusal)
        raise refusal
    return prepare_spawn(args, env, cwd)


class _StartedChild:
    """A spawn's record of the child its runner started.

    run_command, run_command_with_output_handling and spawn_run each hold one
    (``recording()``) around their own runner call and nothing else. The runner
    records its child right after Popen returns (_note_start). When the call
    raises, a record without a child is a start that never happened (127,
    ``spawn_failed``), and one with a child is a failure after the start
    (``post_run_error``). Nothing is read from tracebacks, frames or names, so a
    wrapper or a decorator around the runner changes nothing. A runner that other
    code calls, such as a step of the sandbox's plan before the spawn, runs
    outside the hold and records nothing.

    ``stopped`` is set when waiting on the child failed while it still ran, and
    the runner stopped it: the code it then has is ASH's signal, not the tool's.
    ``stdout`` and ``stderr`` are what the child had written by then.
    """

    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen] = None
        self.stopped = False
        #: A stop ASH sent was refused by the kernel (EPERM) while the child,
        #: or anything in its group, still ran (_note_stop_refused polls at the
        #: refusal, before the pipes close). The tool did not finish on its own
        #: after that: closing the pipes can end the child before the response
        #: is built, so a later poll cannot tell this ending apart from a stop
        #: that worked, and a group member can outlive an exited leader.
        self.stop_refused = False
        self.stdout: Any = None
        self.stderr: Any = None
        #: Made under a ``watched_launch`` scope (_tell_watches). Only such a
        #: record may answer for the launch when an exception carries it: a
        #: helper spawn's record would otherwise stand in for a launch that
        #: never started.
        self.watched_launch = False

    @contextlib.contextmanager
    def recording(self) -> Iterator["_StartedChild"]:
        """Hold this record for the runner called inside the block."""
        token = _STARTED_CHILD.set(self)
        try:
            yield self
        finally:
            _STARTED_CHILD.reset(token)

    def exit_code(self) -> Optional[int]:
        """The tool's own exit code, or None when ASH stopped it while it ran,
        or when a stop was refused while it or its group still ran.

        A refused stop leaves part of the tool possibly running, so there is no
        code to report even when the group's leader exited on its own: the
        leader's code beside a reason saying the tool may still be running read
        as a run that finished (``error_after``'s contract, and the same answer
        a could-not-stop timeout gives)."""
        if self.stopped or self.stop_refused or self.process is None:
            return None
        code = self.process.returncode
        return code if isinstance(code, int) else None

    def not_stopped(self) -> Optional[str]:
        """What to say of a child a stop ASH sent did not end; None for one that
        ended. A stop refused while the child still ran counts whatever a poll
        now says: the child never finished on its own, even when closing the
        pipes ended it meanwhile."""
        if self.process is None:
            return None
        if not self.stop_refused:
            try:
                if _has_exited(self.process):
                    return None
            except OSError:
                return None
        return f"{COULD_NOT_STOP_MARKER} {self.process.pid}), {COULD_NOT_STOP_SUFFIX}"

    def not_stopped_pid(self) -> Optional[int]:
        """The pid of this spawn's recorded child, for the carrier's companion
        field (``could_not_stop_pid``), or None for a spawn that recorded none.
        Read only where ``not_stopped()`` answered: the number rides as data, so
        a reason whose text is lost can still name the process ASH left running.
        """
        return self.process.pid if self.process is not None else None

    def error_after(self, error: BaseException, not_stopped: Optional[str]) -> str:
        """The error of a failure after the start, saying so when ASH stopped the
        tool, or could not: it never finished on its own, so it has no exit code
        to report.

        ``not_stopped`` is the caller's single read of ``not_stopped()`` for this
        failure. The caller decides the recorded flag from the same read, so the
        reason's words and the state cannot describe two different children: a
        child that ignored the stop and exited between two polls used to leave a
        reason saying it may still be running beside a flag saying the stop
        worked.
        """
        if not_stopped is not None:
            return f"{not_stopped}, after: {error}"
        if self.exit_code() is None:
            return f"ASH stopped the tool after: {error}"
        return str(error)


def _has_exited(process: subprocess.Popen) -> bool:
    """Whether the child has ended, read so that another thread's reap cannot
    make a dead child read as running.

    The poll is asked first, once, and its answer stands when it says the child
    ended, or when it raises (a caller's handler reads that raise as the
    handling's own failure). ``Popen.poll`` answers from ``returncode`` alone
    when another thread holds the reaping lock (the registry sweep's own poll,
    _forget_exited_groups), so a child that thread was reaping read as still
    running, and a stop that worked was flagged as one ASH could not perform.
    A poll that says "running" is therefore checked against the kernel with
    ``waitid`` and ``WNOWAIT`` where the build has it, which neither reaps nor
    waits for the lock. A pid the kernel does not know as this process's child
    (``ChildProcessError``: reaped by the other thread, or a recorded child
    that was never spawned) answers with ``returncode``, which the reaper set
    if it finished; the kernel is never asked to decide for a pid that is not
    ours. Without ``waitid`` the poll is the answer.
    """
    # No ``returncode`` shortcut ahead of the poll: ``Popen.poll`` answers a
    # set ``returncode`` from memory, so the shortcut saves nothing for a real
    # child, and it would hide the raise of a poll whose child already carries
    # a code, which the handlers below read as their own failure.
    if process.poll() is not None:
        return True
    if os.name != "nt" and hasattr(os, "waitid"):
        try:
            waited = os.waitid(
                os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
            )
        except ChildProcessError:
            return process.returncode is not None
        except (OSError, TypeError, ValueError, OverflowError):
            return False
        if waited is not None:
            return True
    return process.returncode is not None


def _text_of(error: BaseException) -> str:
    """``str(error)`` as a plain str, or the error's type, named, when its text
    cannot be formatted: an answer built for a handler that raised must not
    raise on the error that handler raised. A __str__ may return a str subclass,
    whose own formatting can raise in the message built from it, so the text is
    copied into a plain str here."""
    try:
        return str.__str__(str(error))
    except Exception:  # noqa: BLE001 -- an error whose __str__ raises
        return f"{type(error).__name__} (its text could not be formatted)"


def _carried_failure(
    error: BaseException, handled: Optional[BaseException] = None
) -> Optional[str]:
    """The text of the failure *error*'s handler was handling, for the
    reason's lead, or None when nothing should lead.

    ``raise ... from None`` is the explicit disavowal and the only chain shape
    that overrides what the caller had in hand: the env-blind refusals rely on
    a disavowed failure, which can quote an environment-read value, staying
    out of every reason. Otherwise ``handled`` wins when the caller passes it
    -- the failure it caught itself, which a handler's own nested try/except
    would hide from the one-level ``__context__`` read. A ``from cause`` on
    the raise does not beat it: that raise can come from a helper frames below
    the handler, and its ``from`` describes the helper's own chain, never a
    decision about the failure the caller caught -- a value a led failure can
    quote is the printers' job to redact. A helper's ``from None`` is honored
    even so, and the asymmetry is deliberate: ``from cause`` adds a fact about
    the helper's own chain, while ``from None`` removes the chain -- in this
    codebase it is the env-blind refusals' idiom, written exactly because the
    raiser knows some link of its chain can quote an environment-read value
    and this walk cannot tell which link that is, so the removal has to hold
    wherever the raise sits, at the cost of sometimes losing a benign lead.
    The named cause leads only when the caller holds nothing, then the
    context. A lead whose text is empty or already inside the error's own text
    (a translated error that quotes its cause) adds nothing and is skipped.
    """
    if error.__cause__ is None and error.__suppress_context__:
        return None
    carried = handled if handled is not None else error.__cause__
    if carried is None and not error.__suppress_context__:
        carried = error.__context__
    if carried is None or carried is error:
        return None
    if isinstance(carried, subprocess.CalledProcessError):
        # The raw subprocess errors quote the full argv in their str, and an
        # argument can carry an environment-read value: their text never
        # leads a reason, but their data still does, as a fixed argv-free
        # lead. Of the builders of these responses only the timeout path
        # sets ``timed_out``, and the recorded returncode is the launch's
        # own, so dropping the lead entirely lost the one fact that explains
        # the record.
        text = f"the command exited {carried.returncode}"
    elif isinstance(carried, subprocess.TimeoutExpired):
        # No limit in the lead: the limit itself can be an environment-read
        # value (the reason texts elsewhere mask it through _timeout_token
        # with the caller's values), and this walk holds no values to redact
        # one with.
        text = "the command timed out"
    else:
        text = _text_of(carried)
    if not text or text in _text_of(error):
        return None
    return text


#: The record of the spawn whose runner call is under way in this context.
_STARTED_CHILD: "contextvars.ContextVar[Optional[_StartedChild]]" = (
    contextvars.ContextVar("ash_started_child", default=None)
)


def _note_start(process: subprocess.Popen) -> Optional[_StartedChild]:
    """Record ``process`` as the child of the spawn whose record is held, if any.

    Each runner calls this right after Popen returns. The first child recorded is
    the tool's; a later one in the same call is not taken. Returns the record when
    it took this child, for _note_failed_wait.
    """
    started = _STARTED_CHILD.get()
    if started is None or started.process is not None:
        return None
    started.process = process
    _tell_watches(started)
    return started


def _tell_watches(started: "_StartedChild") -> None:
    """Tell every held watch of this record, once each: the first start a watch
    sees is the one it answers for. One registration for _note_start and
    _claim_started, so a raise while noting the start cannot blind a watch.

    Only a spawn inside a ``watched_launch`` scope tells: a watch answers for
    THE LAUNCH, and the layer that makes the launch holds that scope around its
    own spawn alone, so a helper the same layer runs first -- an availability
    probe, a version read, an install -- can never stand in for a launch that
    then never started."""
    if not _WATCHED_LAUNCH.get():
        return
    # Marked whether or not a watch is held: failure_after_the_start's
    # carried-record fallback takes only a record made under this scope.
    started.watched_launch = True
    for watch in _START_WATCHES.get():
        if watch.started is None:
            watch.started = started


#: Whether the spawn under way is the launch a held watch answers for.
_WATCHED_LAUNCH: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
    "ash_watched_launch", default=False
)


@contextlib.contextmanager
def watched_launch() -> Iterator[None]:
    """Mark the spawns in this block as the launch for any held StartWatch.

    Held by the layer that makes the launch (the uv tool runner), around only
    the call that launches the tool, never around its helpers."""
    token = _WATCHED_LAUNCH.set(True)
    try:
        yield
    finally:
        _WATCHED_LAUNCH.reset(token)


def _claim_started(process: subprocess.Popen) -> Optional["_StartedChild"]:
    """The spawn's held record with ``process`` attached, for a runner whose own
    note of the start raised: the child started when Popen returned, whatever
    noting it managed. None when no record is held, or when the record already
    holds another spawn's child. The held watches are told too, since the note
    that raised may not have reached them."""
    started = _STARTED_CHILD.get()
    if started is None:
        return None
    if started.process is None:
        started.process = process
        _tell_watches(started)
        return started
    if started.process is process:
        _tell_watches(started)
        return started
    return None


class StartWatch:
    """Whether the launch inside a block started its child.

    For a caller that launches through a layer that can raise after the start,
    such as the uv tool runner: an exception from that layer then can't say
    whether the tool ran. Held with ``watching()`` around the layer's call, it
    is told by the launch's own record (_StartedChild) when the launch's runner
    starts its child -- only a spawn inside the launching layer's
    ``watched_launch`` scope tells (_tell_watches), so a helper that layer runs
    first (an availability probe, an install) never reads as the launch. A
    runner that other code calls outside a spawn's record, such as a step of
    the sandbox's plan, tells it nothing either.
    """

    def __init__(self) -> None:
        self.started: Optional[_StartedChild] = None

    @contextlib.contextmanager
    def watching(self) -> Iterator["StartWatch"]:
        """Hold this watch for the spawns inside the block."""
        token = _START_WATCHES.set((*_START_WATCHES.get(), self))
        try:
            yield self
        finally:
            _START_WATCHES.reset(token)

    def failure_after_the_start(
        self, error: BaseException, stdout_preference: str = "write"
    ) -> Optional[Dict[str, Any]]:
        """The response for ``error`` when the launch started its child, or None.

        It is a failure after the start: ``post_run_error`` with the child's own
        exit code, or None for a child ASH stopped while it ran, as
        run_command_with_output_handling answers a failure while waiting. It
        carries what the record holds of the tool's output: a completed run's
        streams, or what a failed wait had read -- the stderr always, as for a
        failure after the run, and the stdout body only when
        ``stdout_preference`` returns it (``return`` or ``both``), the bound the
        runner's own responses honor. A record the error itself carries
        (spawn_run attaches its call's record to every exception it raises)
        answers when the watch holds none: the exception's own record is
        authoritative for the spawn it came from.
        """
        started = self.started
        if started is None:
            carried = getattr(error, _STARTED_CHILD_ATTRIBUTE, None)
            if (
                isinstance(carried, _StartedChild)
                and carried.process is not None
                # Only a record made under watched_launch: a helper spawn (an
                # availability probe, a version read, an install) carries its
                # own record on what it raises, and that run is not the launch.
                and carried.watched_launch
            ):
                started = carried
        if started is None:
            return None
        # One read decides the reason's words and the flag together.
        not_stopped = started.not_stopped()
        reason = started.error_after(error, not_stopped)
        carried = _carried_failure(error)
        if carried is not None:
            # The handler raised while handling an earlier failure: the reason
            # leads with that failure, then the handler's own error, so the
            # record names what broke the wait, not only what broke its
            # handler. _carried_failure says which failure that is, and when
            # nothing should lead at all.
            reason = f"{carried}, then: {reason}"
        flags, reason = _signaled_failure(
            started.exit_code(),
            "the tool",
            reason,
            log_the_death=True,
            after_a_failed_wait=True,
        )
        response: Dict[str, Any] = {
            "returncode": started.exit_code(),
            "error": reason,
            "post_run_error": True,
            "spawn_failed": False,
            **flags,
        }
        if not_stopped is not None:
            response["could_not_stop"] = True
            response["could_not_stop_pid"] = started.not_stopped_pid()
        if started.stdout and stdout_preference in ("return", "both"):
            response["stdout"] = started.stdout
        if started.stderr is not None:
            response["stderr"] = started.stderr
        return response


#: The watches held in this context, innermost last.
_START_WATCHES: "contextvars.ContextVar[Tuple[StartWatch, ...]]" = (
    contextvars.ContextVar("ash_start_watches", default=())
)


def _output_after_failure(process: subprocess.Popen) -> Tuple[Any, Any]:
    """What the child wrote before a failure while ASH waited on it.

    Read once the child was stopped, for at most _REAP_SECONDS. communicate()
    keeps what its earlier calls read, so this returns that with whatever was
    left in the pipes. A read that a process still holding the pipes keeps open
    returns what it got, decoded in a text-mode run as communicate would have
    (its TimeoutExpired carries bytes); one that fails returns nothing, since
    the failure being reported is the wait's, not this read's.
    """
    if process.stdout is None and process.stderr is None:
        return None, None
    try:
        return process.communicate(timeout=_REAP_SECONDS)
    except subprocess.TimeoutExpired as late:
        if getattr(process, "text_mode", False):
            return _decoded(late.output, process), _decoded(late.stderr, process)
        return late.output, late.stderr
    except Exception:
        return None, None


def _decoded(captured: Any, process: subprocess.Popen) -> Any:
    """Captured bytes as text, with replacement; anything else as it is.

    The encoding is the one *process*'s own stream wrappers carry, which is
    what communicate's successful decode would have used: a child Popen opened
    with a caller's encoding reads back in that encoding, not a pinned UTF-8.
    UTF-8 when no piped stream names one."""
    if not isinstance(captured, bytes):
        return captured
    encoding = getattr(process.stdout, "encoding", None) or getattr(
        process.stderr, "encoding", None
    )
    # The error handler the stream wrappers carry is the one communicate's own
    # decode used. "strict" (TextIOWrapper's default when the caller named none)
    # is not kept: a late read that raised UnicodeDecodeError would replace the
    # wait's failure, which is what this read reports, with its own.
    errors = getattr(process.stdout, "errors", None) or getattr(
        process.stderr, "errors", None
    )
    if errors in (None, "strict"):
        errors = "replace"
    return _as_text_mode_reads(captured, encoding or "utf-8", errors)


def _late_decoded(
    captured: Any, encoding: Optional[str], errors: str = "replace"
) -> Any:
    """Partial bytes a failed wait carried, decoded as the finished run's
    streams would have been: the caller's encoding, or when the caller named
    none the locale encoding Popen's text mode resolves to (under UTF-8 mode
    the locale read answers utf-8, keeping the two in step), and the caller's
    error handler (every runner's default is replace). A decode pinned to
    UTF-8 disagreed with the finished run on a non-UTF-8 locale.
    TimeoutExpired carries the partial output undecoded, text mode or not.
    "strict" is not kept, as _decoded does not keep it: this read runs inside
    the timeout's handler, and a UnicodeDecodeError raised there, for a partial
    read that ended in the middle of a character, would replace the timeout
    the caller is owed."""
    if not isinstance(captured, bytes):
        return captured
    if errors in (None, "strict"):
        errors = "replace"
    return _as_text_mode_reads(
        captured, encoding or locale.getpreferredencoding(False), errors
    )


def _as_text_mode_reads(captured: bytes, encoding: str, errors: str = "replace") -> str:
    """*captured* as Popen's text mode would have read it: decoded with the
    run's error handler, then with universal newlines (``\\r\\n`` and a lone
    ``\\r`` become ``\\n``), the translation communicate's own text-mode decode
    applies. A late or partial read decoded without it kept the ``\\r`` a
    finished run would have dropped, so the same bytes read differently by the
    way the wait ended."""
    return (
        captured.decode(encoding, errors=errors)
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )


def _note_failed_wait(
    started: Optional[_StartedChild],
    process: subprocess.Popen,
    was_running: bool,
    error: BaseException,
) -> None:
    """Record how waiting on the recorded child ended in ``error``, once the runner
    has stopped it: whether it still ran (``was_running``, so ASH stopped it), and
    for an ordinary exception what it had written. An interrupt is handed on at
    once, as subprocess.run hands it on."""
    if started is None:
        return
    started.stopped = was_running
    if isinstance(error, Exception):
        started.stdout, started.stderr = _output_after_failure(process)


def _pipes_for(kwargs: Dict[str, Any], input_data: Any, capture_output: bool) -> None:
    """Set the pipes ``input`` and ``capture_output`` ask for, as subprocess.run
    does, with its ValueErrors when a stream they set is also given.

    Without ``input`` the child's standard input is ``subprocess.DEVNULL`` unless
    the caller passes a ``stdin`` other than None (an explicit ``stdin=None`` also
    gets DEVNULL): ASH's own standard input is the MCP client's channel under
    ``ash mcp``, and a terminal under the CLI, and neither belongs to the tool.
    A caller that does want the child to read ASH's input says so with
    ``stdin=sys.stdin`` or ``stdin=0``. Every runner built on ASH's Popen (_run_plain, _run_stoppable,
    _run_cancellable) sets its pipes here, so this is the one place the spawn
    helpers and spawn_run get it.
    """
    if input_data is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used.")
        kwargs["stdin"] = subprocess.PIPE
    else:
        # An explicit ``stdin=None`` means "inherit" to Popen; it gets DEVNULL too.
        if kwargs.get("stdin") is None:
            kwargs["stdin"] = subprocess.DEVNULL
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError(
                "stdout and stderr arguments may not be used with capture_output."
            )
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE


def _run_plain(
    *popenargs: Any,
    capture_output: bool = False,
    timeout: Optional[float] = None,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """``subprocess.run``, built on ASH's own Popen and communicate.

    The runner of a spawn outside a sandbox and outside a cancel scope (_runner).
    It does what subprocess.run does, case by case: ``input`` (taken from kwargs,
    since the name is a builtin's) and ``capture_output`` set the pipes; a timeout
    kills the child and every process it started (with a timeout the child leads
    a process group of its own, _start_in_own_group, stopped with _stop_tree),
    reaps it and raises the TimeoutExpired communicate raised, with the output
    read so far; any other error, KeyboardInterrupt included, kills the child
    (its group, when it leads one) the same way and is raised as it is;
    ``check`` raises CalledProcessError. The pipes are closed and the child is
    waited for on the way out, as ``with Popen`` does, but for at most
    _REAP_SECONDS (_reap): a child the kill did not end, in uninterruptible
    sleep say, is left running and named, never waited for without end. What it
    adds is the record of its child right after Popen returns (_note_start), and
    for a failure while waiting, whether the child still ran and what it had
    written (_note_failed_wait). Called with no record held, it is
    subprocess.run with that bound.
    """
    input_data = kwargs.pop("input", None)
    _pipes_for(kwargs, input_data, capture_output)
    # With a timeout the child leads a process group of its own, as every
    # unsandboxed spawn in a cancel scope does, so the kill at the timeout
    # reaches what it started: a tool run through uv is uv's child, and killing
    # uv alone left the tool running while the TimeoutExpired said the stop had
    # worked. Without a timeout the child stays in ASH's own session and group,
    # as subprocess.run leaves it: a child in a session of its own has no
    # controlling terminal (a prompt through /dev/tty, as git, ssh or sudo
    # make one, fails), gets no SIGHUP, SIGTSTP or SIGQUIT from the terminal,
    # and is missed by a group-wide kill from outside, and a spawn with no bound
    # to enforce has nothing to gain for that. A group this runner makes is
    # registered as a cancellable spawn's is, so the server's last stop and the
    # SIGTERM handler's die-now kill reach it when ASH ends without unwinding;
    # _reap forgets it.
    if timeout is not None:
        _start_in_own_group(kwargs)
    # Whether the child leads a group this runner can treat as its own: read
    # from the flag as it goes to Popen, not from the timeout. On POSIX
    # _start_in_own_group only sets a default, so a caller's explicit
    # start_new_session=False stands and the child then shares ASH's group,
    # timeout or not; registering its pid as a group, or signalling the group
    # its pid names, would reach a stranger's group that reused the id. A
    # caller's own True counts the same as this runner's. On Windows the flag
    # is a creation flag that is always ORed in, so the timeout is the answer.
    if os.name == "nt":
        own_group = timeout is not None
    else:
        own_group = bool(kwargs.get("start_new_session"))
    # A Ctrl-C while the child is being started is held until the process is in
    # hand (HeldInterrupt), as _run_stoppable and _run_cancellable hold theirs:
    # a KeyboardInterrupt raised inside Popen, after the child exists and
    # before Popen returns it, left this runner no process to stop, and a child
    # that leads a session of its own (the timeout case above) never had the
    # terminal's Ctrl-C, so it ran on, orphaned. Released inside the try that
    # stops the child, once the start is noted and registered; leaving the
    # block puts the previous handler back in any case and hands it a Ctrl-C
    # that was held.
    with HeldInterrupt() as held:
        process = subprocess.Popen(*popenargs, **kwargs)  # nosec B603 - callers pass list argv
        started: Optional[_StartedChild] = None
        try:
            try:
                # Inside this handling: the child started when Popen returned,
                # so a raise while noting or registering the start is a failure
                # after it, and the child is stopped like any other.
                started = _note_start(process)
                if own_group:
                    _register_group(process)
                # A Ctrl-C held while the child was started is raised here,
                # after the start is noted, inside the try that stops it.
                held.release()
                stdout, stderr = process.communicate(input_data, timeout=timeout)
            except subprocess.TimeoutExpired as expired:
                # SIGKILL at once, as subprocess.run kills its child at once: to
                # the whole group where the child leads one, to the child alone
                # where a caller kept it in ASH's group; a refused stop is
                # logged and recorded (_stop_child). The record says ASH stopped
                # it, so its signal is never read as the tool's exit code.
                if started is not None:
                    started.stopped = True
                stop = (
                    _stop_tree if own_group or _leads_its_own_group(process) else _kill
                )
                _stop_child(_argv_of(process), process, stop, 0.0, None)
                # On POSIX communicate already put what it read in the
                # exception; Windows reads the pipes in threads joined at the
                # timeout, so what they read is collected after the kill.
                expired.stdout, expired.stderr = _output_after_stop(process, expired)
                raise
            except BaseException as error:
                if started is None:
                    started = _claim_started(process)
                was_running = process.poll() is None
                # The whole group where the child leads one (this runner's own,
                # or a caller's start_new_session), as _run_cancellable chooses;
                # a child in ASH's own group is killed alone, as subprocess.run
                # does.
                stop = (
                    _stop_tree if own_group or _leads_its_own_group(process) else _kill
                )
                _stop_child(_argv_of(process), process, stop, 0.0, None)
                _note_failed_wait(started, process, was_running, error)
                raise
            # communicate() waited for the child, so this returns its code at
            # once.
            retcode = process.wait()
            if check and retcode:
                raise subprocess.CalledProcessError(
                    retcode, process.args, output=stdout, stderr=stderr
                )
        finally:
            _reap(_argv_of(process), process)
    return subprocess.CompletedProcess(process.args, retcode, stdout, stderr)


#: The caller's environment values (the scan config's) while its spawn runs,
#: for the lines the stop paths log and the could-not-stop records they build.
#: A context variable, like the spawn's _STARTED_CHILD: the runner interface
#: is subprocess.run-shaped, and the values are a reporting input of the whole
#: spawn, not an argument of the child, so they ride beside the call instead
#: of threading through every stop helper's signature. Outside any spawn the
#: default is empty, and the record-only union _logged_without applies still
#: covers a sandboxed or uv run's values.
_SPAWN_VALUES: contextvars.ContextVar[Tuple[str, ...]] = contextvars.ContextVar(
    "ash_spawn_values", default=()
)

#: The subset of the spawn's values whose variable NAMES are secret-shaped
#: (core/constants.py's is_secret_shaped_environment_name; the set is wider
#: than the five forms the config allowlist test bars). A streamed
#: report may print a short ordinary value as a bare word; a secret-named
#: value never takes that exemption, whatever its length.
_SPAWN_STRICT_VALUES: contextvars.ContextVar[Tuple[str, ...]] = contextvars.ContextVar(
    "ash_spawn_strict_values", default=()
)

#: Whether the spawn's streamed output is the scan's own report, whose bare
#: words keep the loosened band (run_ash_container._streamed_line). Default
#: False: every other stream (the image build) keeps the strict band.
_SPAWN_SCAN_REPORT: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "ash_spawn_scan_report", default=False
)


@contextlib.contextmanager
def _spawn_values(
    values: Tuple[str, ...],
    strict: Tuple[str, ...] = (),
    scan_report: bool = False,
) -> Iterator[None]:
    """Carry the caller's values across its spawn, for the stop paths' lines.

    ``strict`` is the secret-named subset of ``values``: the streamed report's
    bare-word exemption never applies to it (``_SPAWN_STRICT_VALUES``).
    ``scan_report`` marks the spawn whose streamed output is the scan's own
    report (``_SPAWN_SCAN_REPORT``); every other stream keeps the strict band.
    """
    token = _SPAWN_VALUES.set(values)
    strict_token = _SPAWN_STRICT_VALUES.set(strict)
    report_token = _SPAWN_SCAN_REPORT.set(scan_report)
    try:
        yield
    finally:
        _SPAWN_SCAN_REPORT.reset(report_token)
        _SPAWN_STRICT_VALUES.reset(strict_token)
        _SPAWN_VALUES.reset(token)


def _shown_tool(args: List[Any], values: Tuple[str, ...]) -> str:
    """argv0 as a record or a cancel's text may name it.

    The shown argv, so a --config-overrides value never rides it, and then
    the caller's environment values hidden, so a value inside the tool's own
    path (an option's directory, say) never does either. ``shown_arguments``
    rewrites option values only, and argv0 passes through it as it is, which
    is why the shown form alone was not enough.
    """
    from automated_security_helper.utils.error_text import text_without_values

    return text_without_values(str(shown_arguments(list(args))[0]), values)


def _argv_of(process: subprocess.Popen) -> List[Any]:
    """The child's command as a list, for naming it in a log line."""
    args = process.args
    return list(args) if isinstance(args, (list, tuple)) else [args]


def _send_stop(process: subprocess.Popen, stop: Callable[[], None]) -> bool:
    """Send ``stop``, the child's terminate or kill; False if the kernel refused it.

    A refusal (EPERM, for a setuid program the tool started, say) is logged and
    raises nothing: the timeout or the failed wait being handled stays the one
    reported, and for a child still running at the refusal the result says ASH
    could not stop it (_StartedChild.not_stopped), recorded on the spawn's
    record so a child that the pipe close ends meanwhile still reads as one ASH
    could not stop. A refusal about a child that already exited marks nothing
    (_note_stop_refused) unless the group its pid names still exists: a child
    that finished on its own with its group gone left nothing the stop was
    needed for, while a surviving group member keeps the mark.
    """
    try:
        stop()
    except OSError as error:
        _note_stop_refused(process)
        ASH_LOGGER.warning(
            _logged_without(
                f"Could not stop {_argv_of(process)[0]} (pid {process.pid}): {error}",
                _SPAWN_VALUES.get(),
            ),
            extra=NO_MARKUP,
        )
        return False
    return True


def _note_stop_refused(process: subprocess.Popen) -> None:
    """Mark the spawn's record when the kernel refused a stop while the child,
    or anything in its group, still ran, so the response is graded by the stop
    attempt rather than a later poll.

    Checked here, at the refusal, where an exit the poll sees can only be the
    child's own ending or a stop that worked: the pipes close later, in _reap,
    so the pipe-close ending the mark exists for cannot have happened yet. The
    leader's exit alone is not the stop having worked: _stop_tree signals the
    group even then, and a surviving member the server may not signal (EPERM)
    can still write into the output directory, so the mark is skipped only when
    the group is gone as well. The group read is by the group id, the leader's
    pid; for the tree stops that produce this case the pid IS a group id, and
    POSIX keeps a pid from reuse while it names a live group. For a child that
    led no group the read can, in principle, see an unrelated group that reused
    the reaped pid in the instants between the poll and the probe; that false
    mark errs toward reporting a stop as failed, never the other way. A group
    this check cannot even probe (_group_exists reads EPERM as existing) is
    precisely one ASH could not stop. The pid in the reason doubles as the
    group id for a tree stop. On Windows no group is recorded and taskkill
    stops the tree, so the leader's poll is the whole answer."""
    started = _STARTED_CHILD.get()
    if started is None or started.process is not process:
        return
    try:
        # Through _group_survives: as PID 1 a group left with nothing but the
        # tool's unreaped children is a tool that is gone, not a survivor.
        if _has_exited(process):
            # Reaped here, once its exit is known: an exited leader not yet
            # reaped is a zombie, and a zombie leader alone keeps its group id
            # alive, so the group probe below read a tool that had ended before
            # the stop as one the stop could not end, and its exit code was lost
            # to the refusal. The poll of an ended child takes nothing a later
            # reader would miss: Popen keeps the code it reaps.
            process.poll()
            if os.name == "nt" or not _group_survives(process.pid):
                return
    except OSError:
        return
    started.stop_refused = True


#: How long a sandboxed process gets to stop after SIGTERM on a timeout before it is
#: killed outright.
SANDBOX_STOP_GRACE_SECONDS = 10.0


def _run_stoppable(args: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """``subprocess.run`` that stops a timed-out process with SIGTERM first.

    subprocess.run kills a timed-out child with SIGKILL, which the Landlock
    wrapper cannot catch; it would then never end the processes its scanner left
    running. Sending SIGTERM lets the wrapper kill its whole tree. SIGKILL follows
    if it has not exited within SANDBOX_STOP_GRACE_SECONDS. Raises the
    TimeoutExpired communicate raised, as subprocess.run does, with the output
    read before and after the stop. Used for sandboxed spawns only. It takes
    subprocess.run's arguments, ``input`` and ``capture_output`` included, records
    its child, and bounds every wait after a stop, as _run_plain does.
    """
    timeout = kwargs.pop("timeout", None)
    check = kwargs.pop("check", False)
    input_data = kwargs.pop("input", None)
    _pipes_for(kwargs, input_data, kwargs.pop("capture_output", False))
    # A Ctrl-C while the child is being started is held until the process is in
    # hand (HeldInterrupt): the sandbox wrapper calls setsid, so the child
    # leads a session of its own and the terminal's Ctrl-C never reaches it,
    # and a KeyboardInterrupt raised inside Popen left this runner no process
    # to stop. Released inside the try that stops the child, once the start is
    # noted, as _run_cancellable releases its hold; leaving the block puts the
    # previous handler back in any case and hands it a Ctrl-C that was held.
    with HeldInterrupt() as held:
        process = subprocess.Popen(args, **kwargs)  # nosec B603 - sandbox-built argv
        started: Optional[_StartedChild] = None
        try:
            try:
                # Inside this handling, as in _run_plain: a raise while noting
                # the start is a failure after it.
                started = _note_start(process)
                # A Ctrl-C held while the child was started is raised here,
                # after the start is noted, inside the try that stops it.
                held.release()
                stdout, stderr = process.communicate(input_data, timeout=timeout)
            except subprocess.TimeoutExpired as expired:
                stdout, stderr = expired.output, expired.stderr
                # The child was running at the timeout, and ASH stops it: the
                # record says so, so a later reading of the record never takes
                # ASH's own signal for the tool's exit code.
                if started is not None:
                    started.stopped = True
                # A SIGTERM the kernel refused has no grace to wait out.
                if _send_stop(process, process.terminate):
                    try:
                        stdout, stderr = process.communicate(
                            timeout=SANDBOX_STOP_GRACE_SECONDS
                        )
                    except subprocess.TimeoutExpired as second:
                        stdout = second.output or stdout
                        stderr = second.stderr or stderr
                        # A bounded wait, not communicate(): a process the
                        # scanner left holding the pipes would keep
                        # communicate() reading until it chose to exit, and the
                        # timeout would stop being one.
                        if _send_stop(process, process.kill):
                            _wait_after_kill(process)
                    except BaseException:
                        # A Ctrl-C during the grace: the escalation still
                        # happens, so the child is not left SIGTERMed only, and
                        # the interrupt goes on as it would have.
                        if _send_stop(process, process.kill):
                            _wait_after_kill(process)
                        raise
                expired.stdout, expired.stderr = stdout, stderr
                raise
            except BaseException as error:
                if started is None:
                    started = _claim_started(process)
                was_running = process.poll() is None
                if _send_stop(process, process.terminate):
                    try:
                        process.wait(timeout=SANDBOX_STOP_GRACE_SECONDS)
                    except subprocess.TimeoutExpired:
                        _send_stop(process, process.kill)
                _note_failed_wait(started, process, was_running, error)
                raise
        finally:
            _reap(args, process)
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


#: How often a child is checked for its scan having been cancelled. Short enough
#: that a prompt stop (PROMPT_STOP_GRACE_SECONDS) fits in the two seconds an MCP
#: client gives a server it is shutting down; a check is one select() call.
CANCEL_POLL_SECONDS = 0.25

#: The grace after SIGTERM when the scan must stop promptly
#: (core/cancellation.CancelEvent.stop_promptly): the process is going away, and
#: an MCP client that closed the connection kills it two seconds later.
PROMPT_STOP_GRACE_SECONDS = 0.5


def _stop_grace(cancel_event: threading.Event) -> float:
    """The grace a child of a cancelled scan gets after SIGTERM before SIGKILL."""
    if getattr(cancel_event, "stop_promptly", False):
        return min(PROMPT_STOP_GRACE_SECONDS, SANDBOX_STOP_GRACE_SECONDS)
    return SANDBOX_STOP_GRACE_SECONDS


#: How often a stop waiting out its grace looks whether the child has gone.
_GRACE_POLL_SECONDS = 0.05


def _wait_out_grace(
    process: subprocess.Popen,
    pgid: Optional[int],
    grace: float,
    prompt: Optional[threading.Event] = None,
) -> None:
    """Wait until the child, and with ``pgid`` its process group, is gone, or the grace ends.

    ``prompt`` is the scan's CancelEvent.prompt. Once it is set the grace still to
    run is cut to PROMPT_STOP_GRACE_SECONDS: when it is already set as the wait
    begins, because a timeout passes the full grace whatever the prompt says, and
    when it is set after, because the wait blocks on that event rather than
    sleeping, so a SIGTERM that reaches the server in the middle of a stop a cancel
    began is seen at once.

    The group is read through _group_survives: when this process is PID 1, the
    exited children of a stopped tool fall to it as zombies nobody else reaps,
    and a group made only of those kept the wait going for the whole grace.
    """
    deadline = time.monotonic() + grace
    shortened = prompt is None
    # Inside stop_grace_in_progress: a first Ctrl-C during this wait latches the
    # registered scans' cancel and does not interrupt the wait, so the SIGKILL
    # that follows the grace is still sent (a SIGTERM-ignoring tool would
    # otherwise outlive the interrupted stop). The context's own docstring names
    # this wait as the one it exists for; it had no caller until now.
    with stop_grace_in_progress():
        while process.poll() is None or (pgid is not None and _group_survives(pgid)):
            now = time.monotonic()
            if not shortened and prompt is not None and prompt.is_set():
                shortened = True
                deadline = min(deadline, now + PROMPT_STOP_GRACE_SECONDS)
            if now >= deadline:
                return
            step = min(_GRACE_POLL_SECONDS, deadline - now)
            if shortened or prompt is None:
                time.sleep(step)
            else:
                prompt.wait(step)


#: How long a cancellable spawn waits, once the child has been stopped or has
#: finished, for it to have exited before returning without it. A child the stop
#: could not signal (killpg's EPERM) does not exit; the call returns, logs it,
#: and leaves it registered for kill_running_groups.
_REAP_SECONDS = 2.0


def _wait_after_kill(process: subprocess.Popen) -> None:
    """Wait for a SIGKILLed child, at most _REAP_SECONDS.

    One that SIGKILL did not end, in uninterruptible sleep say, is not waited for
    without a bound: the spawn's _reap logs it and leaves it recorded.
    """
    try:
        process.wait(timeout=_REAP_SECONDS)
    except subprocess.TimeoutExpired:
        pass


def _stop(
    process: subprocess.Popen,
    grace: Optional[float] = None,
    prompt: Optional[threading.Event] = None,
) -> None:
    """SIGTERM, then SIGKILL if it has not exited within the grace period.

    The sandbox grace period unless the caller names one; ``prompt`` cuts it short
    as for _wait_out_grace.
    """
    process.terminate()
    try:
        _wait_out_grace(
            process,
            None,
            SANDBOX_STOP_GRACE_SECONDS if grace is None else grace,
            prompt,
        )
    except BaseException:
        # A Ctrl-C during the grace: the SIGKILL still follows, so the child is
        # not left SIGTERMed only while the interrupt goes on. A kill the kernel
        # refuses (EPERM on a child that switched user) must not replace the
        # interrupt being raised with an OSError the caller reads as a failure;
        # it is what _stop_child's refusal path does for the ordinary stop: the
        # spawn's record is marked (the response is graded by the refused stop,
        # not a later poll) and the refusal is logged at WARNING.
        try:
            if process.poll() is None:
                process.kill()
        except OSError as error:
            _note_stop_refused(process)
            ASH_LOGGER.warning(
                _logged_without(
                    f"Could not stop {_argv_of(process)[0]} (pid {process.pid}) "
                    f"after an interrupt: {error}",
                    _SPAWN_VALUES.get(),
                ),
                extra=NO_MARKUP,
            )
        raise
    if process.poll() is None:
        process.kill()
        _wait_after_kill(process)


#: How long _stop_tree waits for a SIGKILLed group to be gone. Short: a zombie
#: whose new parent has not reaped it yet keeps the group in existence, and
#: nothing in a killed group runs again either way.
_KILLED_GROUP_SETTLE_SECONDS = 0.25


def _start_in_own_group(kwargs: Dict[str, Any]) -> None:
    """Have Popen start the child as the leader of a process group of its own.

    So that _stop_tree can reach every process the child starts. On POSIX a new
    session (setsid), which is also a new group; on Windows a new process group,
    which taskkill /T walks.
    """
    if os.name == "nt":
        flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | flag
    else:
        kwargs.setdefault("start_new_session", True)


def _plan_popen_kwargs(plan: "Optional[SpawnPlan]") -> Dict[str, Any]:
    """The Popen keyword arguments a sandbox plan asks for beyond argv and env.

    ``start_new_session=True`` when the plan says so (SpawnPlan.start_new_session):
    the child leads a session of its own where the wrapper does not call setsid
    itself, so the stop paths' group signals reach what the tool starts. Empty for
    every other plan and for no plan, so such a spawn is passed exactly what it
    was. Where the runner sets the flag itself (_start_in_own_group), the plan's
    True is the same value. Read with a default, as the other reads of a plan
    here go: a plan that does not carry the field (one built before it existed,
    or a stand-in that only runs a cleanup) asks for nothing, instead of the
    spawn failing before the child exists and the run being reported as a tool
    that never started.
    """
    if plan is not None and getattr(plan, "start_new_session", False):
        return {"start_new_session": True}
    return {}


def _signal_group(pgid: int, signum: int) -> bool:
    """Send signum to the process group; False when the group has no process left."""
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        return False
    return True


def _windows_system_directory() -> Optional[str]:
    """The Windows system directory: GetSystemDirectoryW, else %SystemRoot%\\System32.

    None when neither gives an absolute path. Read from the OS rather than from the
    search path, which on Windows starts in the current directory.
    """
    try:
        import ctypes
    except ImportError:
        # A Python built without _ctypes: the environment's answer stands alone,
        # where the import used to raise past the stop and leave the child alive.
        ctypes = None  # type: ignore[assignment]

    windll = getattr(ctypes, "windll", None)
    if windll is not None:
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
            if 0 < length < len(buffer) and ntpath.isabs(buffer.value):
                return buffer.value
        except (AttributeError, OSError):
            pass
    root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
    if root and ntpath.isabs(root):
        return ntpath.join(root, "System32")
    return None


def _taskkill_path() -> Optional[str]:
    """taskkill.exe by its absolute path in the system directory, or None."""
    system = _windows_system_directory()
    return ntpath.join(system, "taskkill.exe") if system else None


def _stop_tree(
    process: subprocess.Popen,
    grace: float,
    prompt: Optional[threading.Event] = None,
) -> None:
    """Stop a child started by _start_in_own_group and every process it started.

    SIGTERM to the group, then SIGKILL to whatever is left of it once the child has
    exited and the group is empty, or after ``grace`` seconds, cut short once
    ``prompt`` is set (_wait_out_grace). Signalled even when the child itself has
    already exited: what it started may still be running, and holding its output
    pipe. ``grace`` 0 is SIGKILL at once, as subprocess.run does on a timeout.

    On Windows, ``taskkill /T /F`` ends the child's tree. It is run by its absolute
    path in the system directory, never by a bare name: the search path starts in
    the current directory, the scanned repository, where a taskkill.exe of its own
    would run with the server's rights. With no system directory to find it in,
    the child alone is killed.

    On POSIX a child that leads no group, one _leads_its_own_group could not ask
    about, is stopped by its pid alone, as _stop does: signalling only a group
    that does not exist left it running.
    """
    if os.name == "nt":
        taskkill = _taskkill_path()
        if taskkill is None:
            ASH_LOGGER.warning(
                "Found no Windows system directory to run taskkill from; killing "
                f"pid {process.pid} alone, so processes it started may keep running"
            )
        else:
            try:
                subprocess.run(  # nosec B603 - absolute path in the system directory
                    [taskkill, "/T", "/F", "/PID", str(process.pid)],
                    capture_output=True,
                    check=False,
                    timeout=max(grace, 5.0),
                )
            except (OSError, subprocess.SubprocessError):
                pass
        if process.poll() is None:
            process.kill()
        _wait_after_kill(process)
        return
    pgid = process.pid
    # The exit status already read, never poll(): a poll here would reap a
    # leader whose exit was not yet observed, and the group its pid names
    # would then read as a stranger's below while its orphans still run. Read
    # with a default, as the other reads of a child's state here go through
    # poll and wait: a stand-in child need not carry the attribute.
    if getattr(process, "returncode", None) is not None and _pid_names_a_live_process(
        pgid
    ):
        # The child was reaped, and a live process holds its pid. POSIX keeps a
        # pid from reuse only while it names a live group, so the child's own
        # group (its orphans) was gone before that process got the id, and the
        # group the id names now is a stranger's. An own_group spawn reaches
        # here with the child reaped when the wait ended after communicate
        # returned; signalling the group then would have hit whoever took the
        # id next. Nothing of ours is left to stop.
        return
    # Every group read here goes through _group_survives: as PID 1 this process
    # holds the exited members of the group as zombies nobody else reaps, and a
    # group left with nothing but those is a tool that is gone, not one to
    # signal, wait out or record as a survivor.
    if not _group_survives(pgid):
        if process.poll() is None:
            _stop(process, grace, prompt)
        return
    if grace > 0:
        if not _signal_group(pgid, signal.SIGTERM):
            # The group vanished between the read above and this signal: the
            # leader was reaped earlier and its last member just went. The
            # kernel has released the id, and a new process group can hold
            # it, so falling through to the SIGKILL below would aim it at
            # whoever got the id next, and the survivor check would read
            # that stranger's id as a stop that failed. With the child
            # reaped, nothing of ours is left to kill or to read, so stop
            # here. A child not reaped keeps the id ours (a zombie leader
            # holds its group), so that case falls through to the kill.
            if process.poll() is not None:
                return
        else:
            try:
                _wait_out_grace(process, pgid, grace, prompt)
            except BaseException:
                # A Ctrl-C during the grace: the group is still SIGKILLed, so
                # the tool is not left SIGTERMed only while the interrupt goes
                # on. The group id is still the child's: the leader is not
                # reaped before the wait returns. A refused kill (EPERM on a
                # member the server may not signal) is marked and logged, not
                # raised: the interrupt is what the caller handles, not an
                # OSError in its place, and the record says the stop was
                # refused, as _stop_child says for the ordinary stop.
                try:
                    _signal_group(pgid, signal.SIGKILL)
                except OSError as error:
                    _note_stop_refused(process)
                    ASH_LOGGER.warning(
                        _logged_without(
                            f"Could not stop {_argv_of(process)[0]} (process group "
                            f"{pgid}) after an interrupt: {error}",
                            _SPAWN_VALUES.get(),
                        ),
                        extra=NO_MARKUP,
                    )
                raise
            if process.poll() is not None and not _group_survives(pgid):
                # The wait reaps the leader and can end with the group
                # observed empty; the kernel has then released the id, and
                # a new process group can hold it, so the final SIGKILL
                # would be aimed at whoever got the id next, and the
                # survivor check below would be reading a stranger's id as
                # a stop that failed. Nothing of ours is left to kill or to
                # read, so stop here. A group that dies between this read
                # and the kill below is a syscall-width window this process
                # cannot close.
                return
    if _signal_group(pgid, signal.SIGKILL):
        # A killed process is gone only once the kernel has torn it down. Waited
        # for, briefly, so that a caller that goes on to put the previous results
        # back is not racing a process that is still writing. A zombie whose new
        # parent has not reaped it yet still counts, hence the bound.
        settled = time.monotonic() + _KILLED_GROUP_SETTLE_SECONDS
        while time.monotonic() < settled and _group_survives(pgid):
            time.sleep(0.02)
    _wait_after_kill(process)
    # The kernel reports a group kill as a success when it signalled ANY member,
    # so a member ASH may not signal (a setuid program the tool started, say)
    # can survive with no EPERM raised, and only the refusal route above would
    # have marked it. The leader is reaped by now and the settle has passed, so
    # a group that still exists after one more settle is a survivor: recorded as
    # a stop that failed, the way a refused stop records one, so the run never
    # reads as a plain timeout while part of the tool may still be writing.
    # Read through _group_survives: when this process is its container's init,
    # the killed descendants fall to it as zombies that nobody else reaps, and
    # a group made only of those is a tool that is gone, not one that survived.
    if _group_survives(pgid):
        settled = time.monotonic() + _KILLED_GROUP_SETTLE_SECONDS
        while time.monotonic() < settled and _group_survives(pgid):
            time.sleep(0.02)
        if _group_survives(pgid):
            _note_stop_refused(process)


#: The children of cancellable spawns not yet reaped, by pid, each the leader of
#: its process group. POSIX only: on Windows nothing is recorded, a stopped
#: scan's tree is ended with taskkill (_stop_tree), and the server has no SIGTERM
#: path that would call kill_running_groups. For kill_running_groups.
_RUNNING_GROUPS: Dict[int, subprocess.Popen] = {}
_RUNNING_GROUPS_LOCK = threading.Lock()

#: Set by kill_running_groups, the server's last step before it exits, and never
#: cleared: a cancellable spawn that has not started its child by then does not
#: start it (_begin_spawn), and one whose child started but was not recorded yet
#: kills the child itself (_record_spawn).
_STOPPING = False

#: Cancellable spawns past _begin_spawn whose child is not recorded yet: between
#: the check and Popen returning, and from there to _record_spawn. Changed under
#: _RUNNING_GROUPS_LOCK; kill_running_groups waits for it to reach 0.
_SPAWNS_STARTING = 0

#: The pids the server's stop signalled (_kill_group, through kill_running_groups
#: or _record_spawn), for _stopped_by_the_server: a child in this set that then
#: exited was ended by the server whatever code it died with, since a wrapper
#: turns the SIGTERM a groupless child is sent first into the end of its own
#: tree and exits with a code of its own. The stop is one-way, so the set only
#: grows, by at most the number of recorded groups; a pid is never reused by a
#: spawn the server admits after its stop began (_begin_spawn refuses them).
_SERVER_KILLED: set = set()

#: How long kill_running_groups waits for the spawns already starting to record
#: their child. Popen returns in milliseconds; this allows for a busy host. A
#: spawn still starting after it kills its child itself once it records it.
#: Known limit: a spawn whose Popen takes longer than this while the server
#: exits can leave its child running, since the process is gone before the
#: spawn records it.
_SPAWN_SETTLE_SECONDS = 2.0

#: How long kill_running_groups waits for _RUNNING_GROUPS_LOCK before reading the
#: recorded groups without it. Every holder keeps it for a few dict operations;
#: the bound is for a kill that runs in a signal handler on a thread that holds
#: it, which would otherwise wait for itself.
_LOCK_WAIT_SECONDS = 1.0


def _forget_exited_groups() -> None:
    """Drop the children whose process group is empty. Called with
    _RUNNING_GROUPS_LOCK held.

    poll() reaps the child; once reaped a pid may be reused, so a child must not
    stay recorded past that point -- in the SIGTERM handler's group mirror too,
    or the die-now kill would aim at whatever holds the group id next. A reaped
    leader whose group still has members is kept: a sandbox wrapper exits while
    the tool it started runs on, and the group id is the only handle a later
    kill has on those processes. The kernel keeps a group id in use while any
    member holds it, so the entry goes when the group does. A group this process
    may no longer signal (EPERM: a member now runs as another user) still exists,
    so its entry is kept rather than letting the probe raise out of a spawn. When
    this process is PID 1 the orphans it inherited are reaped first, so a group
    left with nothing but zombies reads as gone. A reaped leader's pid that some
    live process holds again has been reused: the group that answers may be a
    stranger's, so the entry is dropped, or the die-now kill would aim at
    whatever holds the group id next. No process holding the pid means the
    surviving group can only be the leader's own orphans.
    """
    for pid, process in list(_RUNNING_GROUPS.items()):
        if process.poll() is None:
            continue
        if (
            os.name != "nt"
            and not _pid_names_a_live_process(pid)
            and _group_survives(pid)
        ):
            continue
        del _RUNNING_GROUPS[pid]
        discard_tool_group(pid)


def _register_group(process: subprocess.Popen) -> None:
    # Windows records nothing: see _RUNNING_GROUPS.
    if os.name == "nt":
        return
    with _RUNNING_GROUPS_LOCK:
        _forget_exited_groups()
        _RUNNING_GROUPS[process.pid] = process
        # Mirrored for the SIGTERM handler's die-now kill, which cannot take
        # this registry's lock (core/cancellation._TOOL_GROUPS).
        record_tool_group(process.pid)


def _begin_spawn(args: List[str]) -> None:
    """Count a cancellable spawn as starting, or refuse it once the server stops.

    Before Popen, so that kill_running_groups, which waits for every spawn it
    counts, cannot run between this child starting and being recorded and
    leave it running after the server has exited.
    """
    global _SPAWNS_STARTING
    with _RUNNING_GROUPS_LOCK:
        if _STOPPING:
            raise ScanCancelled(
                "the server is stopping, so "
                f"{_shown_tool(args, _SPAWN_VALUES.get())} was not started"
            )
        _SPAWNS_STARTING += 1


def _end_spawn() -> None:
    """A spawn counted by _begin_spawn whose Popen raised: it started nothing."""
    global _SPAWNS_STARTING
    with _RUNNING_GROUPS_LOCK:
        _SPAWNS_STARTING -= 1


class _SpawnRecord(enum.Enum):
    """How _record_spawn left the child it recorded.

    Truthy only for GOES_ON, the one ending the spawn carries on from, so a
    caller reading the return as a bool (``if _record_spawn(process)``) still
    reads "the spawn goes on". The two stop endings are told apart for the
    cancel's wording: a kill the kernel refused did not stop the tool.
    """

    GOES_ON = "goes on"
    KILLED = "killed at the server's stop"
    KILL_REFUSED = "kill refused at the server's stop"

    def __bool__(self) -> bool:
        return self is _SpawnRecord.GOES_ON


def _record_spawn(process: subprocess.Popen) -> _SpawnRecord:
    """Record the child of a spawn counted by _begin_spawn, and say whether the
    spawn goes on or the server's stop ended it.

    Recorded and uncounted in one step, so kill_running_groups, once it has seen
    no spawn starting, finds this child recorded. If the server began stopping
    after _begin_spawn, the child is killed here too: kill_running_groups may
    have given up waiting for it, and a child recorded after its snapshot would
    outlive the server.

    It never raises its own count back at the caller: a kill the kernel refuses
    (EPERM, as the stops meet it in _stop_child) is handled here as _stop_child
    handles one -- logged, and the spawn's record marked as a stop that failed
    (_note_stop_refused) -- and KILL_REFUSED is returned, so the spawn still
    ends as a ScanCancelled, one saying the tool could not be stopped. The child
    stays recorded, and kill_running_groups tries it again with its own
    handling. With no raise possible past the decrement, the caller's
    spent-count flag set just before this call tells the failure handling
    whether the count was given up, and the one window left -- an exception
    delivered at the call itself -- can only leave the count held, never give
    it up twice.
    """
    global _SPAWNS_STARTING
    with _RUNNING_GROUPS_LOCK:
        _SPAWNS_STARTING -= 1
        # Windows records nothing: see _RUNNING_GROUPS.
        if os.name != "nt":
            _forget_exited_groups()
            _RUNNING_GROUPS[process.pid] = process
            # Mirrored for the SIGTERM handler's die-now kill, as in
            # _register_group.
            record_tool_group(process.pid)
        stopping = _STOPPING
    if not stopping:
        return _SpawnRecord.GOES_ON
    try:
        _kill_group(process)
    except OSError as error:
        _note_stop_refused(process)
        ASH_LOGGER.warning(
            _logged_without(
                f"Could not kill {_argv_of(process)[0]} (pid {process.pid}) "
                f"while the server stops: {error}",
                _SPAWN_VALUES.get(),
            ),
            extra=NO_MARKUP,
        )
        return _SpawnRecord.KILL_REFUSED
    return _SpawnRecord.KILLED


def _server_stopping() -> bool:
    """Whether the server's last stop (kill_running_groups) has begun."""
    with _RUNNING_GROUPS_LOCK:
        return _STOPPING


def _kill_group(process: subprocess.Popen) -> bool:
    """SIGKILL the child's process group, or the child when it leads none.

    True when something was signalled. On Windows, the child alone.

    A child already reaped is signalled only while its pid still names its own
    group: reaped, the pid can be another process's, and the group id another
    group's. The kernel keeps a pid from reuse while it names a live group, so
    a reaped leader whose group survives (a sandbox wrapper's) is still ours;
    a reaped leader whose pid names a live PROCESS is a stranger's, and
    nothing of ours is left to kill. A child that leads no group (a sandbox
    wrapper before its setsid, a Landlock wrapper, whose scanner it forked into
    a session of its own) is sent SIGTERM first, which such a wrapper turns
    into the end of its tree, and SIGKILL after a short settle; killed
    outright, the wrapper died and the scanner it started ran on. Every pid
    signalled here is recorded in _SERVER_KILLED, so _stopped_by_the_server
    reads the child's ending as the server's whatever code the wrapper exits
    with.
    """
    if os.name == "nt":
        if process.poll() is None:
            process.kill()
            _SERVER_KILLED.add(process.pid)
            return True
        return False
    if process.returncode is not None:
        if _pid_names_a_live_process(process.pid):
            return False
        # A reaped leader's group of nothing but zombies (this process as PID 1)
        # is gone, not a group to signal: _group_survives reaps them first.
        if not _group_survives(process.pid):
            return False
    if _leads_its_own_group(process) or process.returncode is not None:
        if _signal_group(process.pid, signal.SIGKILL):
            _SERVER_KILLED.add(process.pid)
            return True
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=_KILLED_GROUP_SETTLE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
        _SERVER_KILLED.add(process.pid)
        return True
    return False


def _unregister_group(process: subprocess.Popen) -> None:
    """Forget ``process``, and only it.

    By identity, not by pid alone: once it is reaped its pid can be reused, and
    recorded for a new child before this runs, and popping by pid dropped that
    child's entry.
    """
    with _RUNNING_GROUPS_LOCK:
        if _RUNNING_GROUPS.get(process.pid) is process:
            del _RUNNING_GROUPS[process.pid]
            discard_tool_group(process.pid)


def kill_running_groups() -> int:
    """SIGKILL the process group of every cancellable spawn still running.

    For the MCP server's last step before it exits (cli/mcp_server): a scanner's
    tool leads a session of its own, so the server's exit does not end it, and a
    scan still stopping when the server stops waiting for it would leave its tool
    running after the server has gone. Also reaches a child a stop could not
    signal, if the kernel lets this signal through. Returns how many groups were
    signalled. POSIX only; on Windows nothing is recorded.

    A group is signalled while it is still recorded: an unreaped child's pid is
    not reused, so its group id names its group and no other, and a reaped
    leader's group is recorded only while no process holds its pid again, so the
    id can only name the leader's own orphans (see _forget_exited_groups).

    A spawn that starts its child while this runs is not missed. _STOPPING is set
    first, so a spawn that has not started its child yet does not start it, and
    this waits, up to _SPAWN_SETTLE_SECONDS, for the spawns already starting to
    record theirs; one that records after that kills its child itself, so a child
    started just before the stop and recorded just after it is killed too.
    """
    global _STOPPING
    # A plain store: a spawn reads it under the lock, after this store.
    _STOPPING = True
    settled = time.monotonic() + _SPAWN_SETTLE_SECONDS
    while _SPAWNS_STARTING > 0 and time.monotonic() < settled:
        time.sleep(0.01)
    if _RUNNING_GROUPS_LOCK.acquire(timeout=_LOCK_WAIT_SECONDS):
        try:
            _forget_exited_groups()
            processes = list(_RUNNING_GROUPS.values())
        finally:
            _RUNNING_GROUPS_LOCK.release()
    else:
        processes = list(_RUNNING_GROUPS.values())
    signalled = []
    for process in processes:
        try:
            # _kill_group reads whether the child was reaped meanwhile (by
            # another thread's sweep, or this lock-timeout fallback skipping
            # the sweep) and signals no group id a reaped pid no longer names.
            if _kill_group(process):
                signalled.append(process.pid)
        except OSError as error:
            ASH_LOGGER.warning(
                f"Could not kill process group {process.pid}: {error}",
                extra=NO_MARKUP,
            )
    settled = time.monotonic() + _KILLED_GROUP_SETTLE_SECONDS
    while time.monotonic() < settled and any(
        _group_survives(pgid) for pgid in signalled
    ):
        time.sleep(0.02)
    return len(signalled)


def _group_exists(pgid: int) -> bool:
    try:
        return _signal_group(pgid, 0)
    except OSError:
        return True


def _pid_names_a_live_process(pid: int) -> bool:
    """Whether some process, zombie included, holds *pid* now. POSIX only.

    ``kill(pid, 0)`` fails with ESRCH only when no process has the pid; a
    refusal (EPERM) means one does, another user's. For a child this process
    has reaped, True means the pid has been reused.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _this_process_is_init() -> bool:
    """True when this process is PID 1: the reaper of every orphan on the host.

    ASH is PID 1 when it is the entrypoint of its own container image.
    """
    return os.name != "nt" and os.getpid() == 1


def _zombie_orphans_of_group(pgid: int) -> List[int]:
    """The exited, unreaped children of this process in group *pgid*, from /proc.

    Read from each ``/proc/<pid>/stat``: the state letter, the parent and the
    group come right after the command name, which can hold spaces and
    parentheses, so the fields are taken from after its closing parenthesis.
    Empty where there is no /proc to read.

    The leader itself, the child whose pid is the group id, is never listed: it
    is a Popen's child, and a waitpid here would take its exit status from under
    that Popen, whose next poll would then read ECHILD as a clean exit (code 0)
    for a tool that was killed. Only the orphans the group's members left to
    this process are reaped here.
    """
    me = os.getpid()
    zombies: List[int] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return zombies
    for entry in entries:
        if not entry.isdigit() or int(entry) == pgid:
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as stat:
                fields = stat.read().rpartition(b")")[2].split()
        except OSError:
            continue
        if len(fields) < 3 or fields[0] != b"Z":
            continue
        try:
            if int(fields[1]) == me and int(fields[2]) == pgid:
                zombies.append(int(entry))
        except ValueError:
            continue
    return zombies


def _group_survives(pgid: int) -> bool:
    """_group_exists, once the orphans this process inherited as init are reaped.

    ``killpg(pgid, 0)`` succeeds while any member exists, a zombie included. A
    killed tool's children are re-parented to PID 1, and when that is ASH (its
    own container's init) nothing reaps them, so the group of a tool that is
    gone kept existing and every stop of a tool that had children was recorded
    as one ASH could not stop. Only this process's own exited children in the
    group are waited for, each by its pid, and never the leader (its pid is the
    group id, and its status is its Popen's to read), so no spawn's exit status
    is taken from under its Popen.
    """
    if _this_process_is_init():
        for pid in _zombie_orphans_of_group(pgid):
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
    return _group_exists(pgid)


#: How often _wait_for_group_before_cleanup reads the group again.
_GROUP_WAIT_POLL_SECONDS = 0.05


def _wait_for_group_before_cleanup(process: Any) -> None:
    """Wait, bounded, for the child's process group to end before a plan's cleanup.

    A sandbox plan's cleanup starts with ``sweep_writable``, which removes what a
    scanner left under its writable roots. A wrapper that execs the tool with no
    reaper (the sandbox-exec setsid wrapper) can leave a grandchild running after
    the child itself has exited, and the sweep then runs while that grandchild
    still writes. When the child was started as the leader of its own group, the
    group is read with the file's own :func:`_group_survives` every
    ``_GROUP_WAIT_POLL_SECONDS`` until it is gone or
    ``_KILLED_GROUP_SETTLE_SECONDS`` has passed. Nothing is signalled: a group
    still there at the bound is logged at DEBUG and the cleanup runs as before.
    A child that was not a group leader has no group under its pid, so the first
    read returns False and nothing waits; ``None`` (no child started) and
    Windows, where there are no process groups, return at once.
    """
    if process is None or os.name == "nt":
        return
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        return
    deadline = time.monotonic() + _KILLED_GROUP_SETTLE_SECONDS
    while _group_survives(pid):
        if time.monotonic() >= deadline:
            ASH_LOGGER.debug(
                f"Process group {pid} still has a member after "
                f"{_KILLED_GROUP_SETTLE_SECONDS}s; the sandbox cleanup runs now"
            )
            return
        time.sleep(_GROUP_WAIT_POLL_SECONDS)


def _kill(
    process: subprocess.Popen,
    grace: Optional[float] = None,
    prompt: Optional[threading.Event] = None,
) -> None:
    """SIGKILL at once, as subprocess.run does on a timeout; _reap waits for it."""
    process.kill()


def _stop_child(
    args: List[str],
    process: subprocess.Popen,
    stop: Any,
    grace: Optional[float],
    prompt: Optional[threading.Event],
) -> None:
    """Run one of the stops, and log rather than raise when the kernel refuses it.

    killpg raises PermissionError on a group that holds a process the server may
    not signal, such as a setuid program the tool started. Raised, it replaced
    the TimeoutExpired or ScanCancelled the caller handles with an OSError that
    reached the scanner as an unexplained failure.
    """
    try:
        stop(process, grace, prompt)
    except OSError as error:
        _note_stop_refused(process)
        ASH_LOGGER.warning(
            _logged_without(
                f"Could not stop {args[0]} (pid {process.pid}): {error}",
                _SPAWN_VALUES.get(),
            ),
            extra=NO_MARKUP,
        )


def _reap(args: List[str], process: subprocess.Popen) -> None:
    """What ``with Popen`` does on the way out, with the wait bounded.

    Closes the pipes and waits up to _REAP_SECONDS for the child. One still
    running then is one a stop could not signal: logged, and left recorded for
    kill_running_groups, instead of the call waiting for as long as it runs.
    """
    for stream in (process.stdout, process.stderr, process.stdin):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    try:
        process.wait(timeout=_REAP_SECONDS)
    except subprocess.TimeoutExpired:
        ASH_LOGGER.warning(
            _logged_without(
                f"Could not stop {args[0]} (pid {process.pid}): still running "
                f"{_REAP_SECONDS:g}s after it was stopped; returning without it",
                _SPAWN_VALUES.get(),
            ),
            extra=NO_MARKUP,
        )
        return
    _unregister_group(process)


def _leads_its_own_group(process: subprocess.Popen) -> bool:
    """Whether a stop should signal the group the child's pid names. POSIX only.

    Asked at stop time, not at start: a sandbox wrapper calls setsid once it
    runs, so it may not lead one yet right after Popen.

    False for a child already reaped: its pid may be another process's by now,
    a group leader's even, and getpgid would answer for that one. True, with a
    warning, when getpgid fails on a child not yet reaped. Taken as False, that
    failure left what a wrapper that had called setsid started running after
    its stop. The unreaped child still holds its pid, so a group carrying that
    pid can only be one the child made, and _stop_tree stops the child by its
    pid alone when there is none.
    """
    if os.name == "nt" or process.returncode is not None:
        return False
    try:
        return os.getpgid(process.pid) == process.pid
    except OSError as error:
        ASH_LOGGER.warning(
            f"Could not tell whether pid {process.pid} leads a process group of "
            f"its own ({error}); stopping the group its pid names as well, if "
            f"there is one",
            extra=NO_MARKUP,
        )
        return True


def _output_after_stop(
    process: subprocess.Popen, expired: subprocess.TimeoutExpired
) -> Tuple[Any, Any]:
    """The output a timed-out child wrote, read once more after its stop on Windows.

    On POSIX the TimeoutExpired of a communicate that ran out carries what was
    read so far (None when nothing was), and that is returned, as subprocess.run
    does: reading again would wait on a process the stop missed that still holds
    the pipes. On Windows it carries nothing, so the pipes are read after the
    stop, as subprocess.run does there, for at most _REAP_SECONDS.
    """
    if os.name != "nt" or expired.output is not None or expired.stderr is not None:
        return expired.output, expired.stderr
    if process.stdout is None and process.stderr is None:
        return None, None
    try:
        return process.communicate(timeout=_REAP_SECONDS)
    except subprocess.TimeoutExpired as late:
        return late.output, late.stderr
    except (OSError, ValueError):
        return None, None


def _run_cancellable(
    args: List[str],
    *,
    cancel_event: threading.Event,
    graceful_timeout: bool,
    own_group: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """``subprocess.run`` that also stops the child when its scan is cancelled.

    Used only inside a scan's ``cancel_scope`` (see core/cancellation.py), for
    every spawn :func:`_run_plain` or :func:`_run_stoppable` would otherwise make.
    It waits on the child in slices of CANCEL_POLL_SECONDS and, once the event is
    set, stops it with SIGTERM and then SIGKILL and raises ScanCancelled.
    Everything else is ``subprocess.run``'s: the return value, ``check``, and
    ``TimeoutExpired`` at the timeout, with the child stopped the way the runner
    it replaces stops it (``graceful_timeout``: SIGTERM first, as
    :func:`_run_stoppable` does for a sandboxed spawn; otherwise SIGKILL, as
    :func:`_run_plain` does).

    With ``own_group`` (every unsandboxed spawn in a cancel scope) the child
    leads a process group of its own, and a cancel or a timeout stops the whole
    group (:func:`_stop_tree`): a scanner's tool that starts processes of its own
    would otherwise leave them running after the cancel. A sandboxed spawn is not put in
    a group here, because its wrapper calls setsid itself. Its stop still reaches
    the whole group once the child leads one (:func:`_leads_its_own_group`).
    sandbox-exec's wrapper on macOS execs the tool after setsid, so nothing is
    left to end the tool's children, and stopping the pid alone would leave them
    running. The Landlock wrapper ends its own tree on SIGTERM either way.

    Retrying ``communicate`` after its own timeout loses no output; the input is
    handed to the first call only, as ``communicate`` requires, and the later
    calls write what is left of it. ``input`` and ``capture_output`` set the
    pipes as subprocess.run sets them, and the child is recorded as _run_plain
    records it.
    """
    timeout = kwargs.pop("timeout", None)
    check = kwargs.pop("check", False)
    pending_input = kwargs.pop("input", None)
    _pipes_for(kwargs, pending_input, kwargs.pop("capture_output", False))
    if own_group:
        _start_in_own_group(kwargs)
    prompt = getattr(cancel_event, "prompt", None)
    deadline = None if timeout is None else time.monotonic() + timeout
    # Set once the child has been stopped, so whatever ends the wait stops it at
    # most once. The timeout stopped it and then raised into the handler below,
    # which stopped it again: on a group a zombie kept alive, that second stop
    # sent SIGTERM and waited out the whole grace period, and the timeout ran
    # that much past its bound.
    stopped = False
    # Not ``with Popen``: its exit waits for the child without a bound, and a
    # child the kernel would not let the stop signal (EPERM) kept the call, and
    # the scan, waiting for as long as the child chose to run (_reap).
    started: Optional[_StartedChild] = None
    # Whether _begin_spawn's count has been given up, so the handler below gives
    # it up exactly once. Set just before the _record_spawn call, which never
    # raises past its decrement (a refused kill is handled inside it), so a
    # synchronous raise can never land between the flag and the decrement. The
    # one window left is an asynchronous exception delivered at the call itself:
    # the flag is already set, the decrement never ran, and the count stays held
    # (+1), which costs a later kill_running_groups its spawn settle wait and
    # nothing worse. The flag the other way around would give the count up twice
    # on that window, and a negative count can end the settle wait while another
    # spawn is still starting. A test's stand-in for _record_spawn that raises
    # reads as a raise in that window, by design.
    count_spent = False
    # A Ctrl-C while the child is being started is held until the process is in
    # hand, and released inside the try that stops the child, once the child is
    # recorded, as run_ash_container and run_ash_nix release their own holds
    # (HeldInterrupt). A KeyboardInterrupt raised inside Popen, after the child
    # exists and before Popen returns it, left this runner no process to stop,
    # and a child that leads a session of its own never had the terminal's
    # Ctrl-C. Leaving the block puts the previous handler back in any case -- a
    # Popen failure, or a server-stop raise below, each before the release --
    # and hands it a Ctrl-C that was held, raised in place of that failure
    # (HeldInterrupt.__exit__); it does so even where putting the handler back
    # failed once, so no later Ctrl-C is quietly recorded on a hold nothing
    # reads again.
    with HeldInterrupt() as held:
        # Counted before the child starts and recorded once it has, so a server
        # stopping in between still kills it (kill_running_groups).
        _begin_spawn(args)
        try:
            process = subprocess.Popen(args, **kwargs)  # nosec B603 - callers pass list argv
        except BaseException:
            _end_spawn()
            raise
        try:
            try:
                # Inside the try: the child has started, so a failure noting or
                # recording it is one after the start, and the child is stopped
                # like any other.
                started = _note_start(process)
                count_spent = True
                spawn_recorded = _record_spawn(process)
                if spawn_recorded is _SpawnRecord.KILL_REFUSED:
                    # The server is stopping, and the kernel refused
                    # _record_spawn's kill: the tool may still run, so the
                    # cancel says so, and carries the tool and pid as data the
                    # way the stop path's cancel does (below) -- the exit line
                    # names survivors from the field, never from the text. The
                    # tool through _shown_tool, record and text both: argv0 can
                    # hold the caller's environment value, and shown_arguments
                    # alone passes argv0 through.
                    stopped = True
                    tool = _shown_tool(args, _SPAWN_VALUES.get())
                    event = current_cancel_event()
                    if isinstance(event, CancelEvent):
                        event.note_could_not_stop(tool, process.pid)
                    raise ScanCancelled(
                        "the server is stopping; "
                        + could_not_stop_sentence(f"{tool} (pid {process.pid})"),
                        could_not_stop=((tool, process.pid),),
                    )
                if not spawn_recorded:
                    # The server is stopping, and _record_spawn killed the child.
                    stopped = True
                    raise ScanCancelled(
                        "the server is stopping, so "
                        f"{_shown_tool(args, _SPAWN_VALUES.get())} was stopped"
                    )
                # A Ctrl-C held while the child was started is raised here,
                # after the child is noted and recorded, inside the try that
                # stops it, as one that came during the wait is. The server-stop
                # raises above sit before this release, so a Ctrl-C held across
                # them is handed over as the block is left.
                held.release()
                while True:
                    wait = CANCEL_POLL_SECONDS
                    if deadline is not None:
                        wait = max(0.0, min(wait, deadline - time.monotonic()))
                    try:
                        stdout, stderr = process.communicate(
                            pending_input, timeout=wait
                        )
                        break
                    except subprocess.TimeoutExpired as expired:
                        pending_input = None
                        if cancel_event.is_set():
                            raise ScanCancelled(
                                "the scan was cancelled while "
                                f"{_shown_tool(args, _SPAWN_VALUES.get())} was running"
                            ) from None
                        if deadline is not None and time.monotonic() >= deadline:
                            # Marked before the stop, not after: a stop that fails
                            # must not be tried again below with the full cancel
                            # grace. The record says so too: the child was
                            # running at the timeout and ASH stops it, so a
                            # later reading of the record never takes ASH's own
                            # signal for the tool's exit code.
                            stopped = True
                            if started is not None:
                                started.stopped = True
                            if own_group or _leads_its_own_group(process):
                                grace = (
                                    SANDBOX_STOP_GRACE_SECONDS
                                    if graceful_timeout
                                    else 0.0
                                )
                                _stop_child(args, process, _stop_tree, grace, prompt)
                            elif graceful_timeout:
                                _stop_child(args, process, _stop, None, prompt)
                            else:
                                _stop_child(args, process, _kill, None, prompt)
                            output, errors = _output_after_stop(process, expired)
                            raise subprocess.TimeoutExpired(
                                args, timeout, output=output, stderr=errors
                            ) from None
            except BaseException as error:
                # ScanCancelled above, or anything else that ends the wait: the
                # child must not outlive it, as subprocess.run guarantees too,
                # and with its own group nothing it started may either. The
                # timeout's stop above raised TimeoutExpired, which callers
                # report as a timeout.
                if not count_spent:
                    # _record_spawn never took the count, so _begin_spawn's
                    # count is still held for a spawn that is not settling:
                    # without this, every later kill_running_groups waits the
                    # full spawn settle on it.
                    _end_spawn()
                if stopped:
                    raise
                if started is None:
                    started = _claim_started(process)
                # The group is asked about before the poll below, which would
                # reap a child that has exited: a sandbox wrapper's group
                # outlives it, and _leads_its_own_group answers False for a
                # reaped child.
                whole_group = own_group or _leads_its_own_group(process)
                was_running = process.poll() is None
                if whole_group:
                    _stop_child(
                        args, process, _stop_tree, _stop_grace(cancel_event), prompt
                    )
                elif was_running:
                    _stop_child(args, process, _stop, _stop_grace(cancel_event), prompt)
                _note_failed_wait(started, process, was_running, error)
                if isinstance(error, ScanCancelled):
                    # One read decides, as _StartedChild.not_stopped's contract
                    # says: a stop refused while the child or its group still ran
                    # counts whatever a poll now says, so a leader the pipe close
                    # ended meanwhile still reads as one ASH could not stop.
                    not_ended = (
                        started.not_stopped() is not None
                        if started is not None
                        else process.poll() is None
                    )
                    if not_ended:
                        # The stop did not end it: the cancel stays a cancel,
                        # says so, and carries the tool and pid as data. The
                        # record also goes on the scan's event chain, so a later
                        # raise_if_cancelled -- the cancel that usually reaches
                        # the CLI -- names it too. The tool through _shown_tool,
                        # record and text both: the shown argv alone rewrites
                        # only option values, and argv0 itself can hold the
                        # caller's environment value.
                        tool = _shown_tool(args, _SPAWN_VALUES.get())
                        event = current_cancel_event()
                        if isinstance(event, CancelEvent):
                            event.note_could_not_stop(tool, process.pid)
                        raise ScanCancelled(
                            f"{error}; "
                            + could_not_stop_sentence(f"{tool} (pid {process.pid})"),
                            could_not_stop=getattr(error, "could_not_stop", ())
                            + ((tool, process.pid),),
                        ) from error
                raise
            if _stopped_by_the_server(process.returncode, process):
                # The wait ended because the server's last stop
                # (kill_running_groups) signalled the child, or a signal of
                # the stop's kind killed it while the stop ran: ASH's own stop,
                # so the scan ends as a cancel, as a child killed by
                # _record_spawn does. Returned normally, the code would read as
                # the tool's own ending.
                raise ScanCancelled(
                    "the server is stopping, so "
                    f"{_shown_tool(args, _SPAWN_VALUES.get())} was stopped"
                )
        finally:
            _reap(args, process)
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


#: The signals the server's last stop sends (kill_running_groups' SIGKILL, and
#: the SIGTERM _kill_group sends a groupless child first), as negative codes.
_SERVER_STOP_RETURNCODES = frozenset(
    -number
    for number in (getattr(signal, "SIGKILL", None), getattr(signal, "SIGTERM", None))
    if number is not None
)


def _stopped_by_the_server(
    returncode: Any, process: Optional[subprocess.Popen] = None
) -> bool:
    """Whether the child's ending is the server's own stop, and nothing else.

    A child the server's stop signalled (``_kill_group``, recorded in
    _SERVER_KILLED) was ended by it whatever code it died with: a wrapper that
    turns the SIGTERM a groupless child is sent first into the end of its tree
    exits with a code of its own (143, or the scanner's) within the settle, and
    read by the signal number alone that ending was a normal run returned while
    the server stopped. For a child the stop did not signal, or when no process
    is given, only a SIGKILL or SIGTERM death while the server stops is ASH's: a
    tool that died of a SIGSEGV, or that the operator killed with another
    signal, in those same seconds is not a stop ASH performed, and reporting it
    as one hid the tool's own ending.
    """
    if not _server_stopping():
        return False
    if process is not None and process.pid in _SERVER_KILLED:
        return True
    return is_exit_code(returncode) and returncode in _SERVER_STOP_RETURNCODES


def _runner(sandboxed: bool) -> Any:
    """The ``subprocess.run``-shaped callable a spawn should use.

    Inside a scan's cancel scope, :func:`_run_cancellable`, so a cancel stops the
    child. Otherwise :func:`_run_stoppable` for a sandboxed spawn, and
    :func:`_run_plain` for the rest. Each records the child it starts in the
    spawn's _StartedChild. ``_run_plain`` is looked up here at each call, as a
    module global, so a test that stands in for it is the runner a spawn gets.
    """
    cancel_event = current_cancel_event()
    if cancel_event is not None:

        def run_cancellable(
            args: List[str], **kwargs: Any
        ) -> subprocess.CompletedProcess:
            return _run_cancellable(
                args,
                cancel_event=cancel_event,
                graceful_timeout=sandboxed,
                own_group=not sandboxed,
                **kwargs,
            )

        return run_cancellable
    return _run_stoppable if sandboxed else _run_plain


#: The attribute spawn_run sets on every exception it raises: that call's
#: _StartedChild, for spawn_run_failure_after_the_start.
_STARTED_CHILD_ATTRIBUTE = "_ash_started_child"


def _run_recording_the_start(
    runner: Any, args: List[str], kwargs: Dict[str, Any], started: "_StartedChild"
) -> subprocess.CompletedProcess:
    """spawn_run's runner call, with the call's record held around it alone."""
    with started.recording():
        return runner(args, **kwargs)  # nosec B603 - callers pass list argv


def spawn_run(args: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """``subprocess.run`` through the scanner sandbox choke point.

    Same arguments, same return value, same exceptions as ``subprocess.run``, for the
    call sites that rely on its exact semantics (``check=True`` raising,
    ``TimeoutExpired`` propagating) and so cannot move to :func:`run_command`.
    The program is resolved first, and refused where :func:`_resolve_for_spawn`
    refuses it, raising the ``FileNotFoundError`` ``subprocess.run`` would, or an
    ``OSError`` (``errno.EINVAL``) for an argument to a batch program that cmd.exe
    would read differently.

    Inside a cancelled scan it raises ScanCancelled instead of starting the child,
    and stops a running one; see :func:`_runner`. Only its runner call is
    recorded, so a child a step of the sandbox's plan runs is not the tool's.

    An exception it raises is raised as it is, carrying this call's record, so a
    caller can tell a failure after the child started from one before it
    (spawn_run_failure_after_the_start). Every exception gets this call's record,
    one with no child when nothing started, so an exception instance raised
    again after an earlier run never brings that run's start back.

    Standard input is ``subprocess.DEVNULL`` unless the caller passes ``input`` or a
    ``stdin`` other than None (_pipes_for): ASH's own standard input is the MCP
    client's channel under ``ash mcp``, and a terminal under the CLI, and neither
    belongs to the tool. This differs from ``subprocess.run``, where ``stdin=None``
    means the child inherits the parent's input: here an explicit ``stdin=None``
    also gets DEVNULL, and a caller that wants the child on ASH's input passes
    ``stdin=sys.stdin`` or ``stdin=0``.
    """
    if args and not kwargs.get("shell", False):
        # A string is the program's name, as subprocess.run reads it without a
        # shell; list() turned it into its characters.
        args = _argv_list(args)
        refused = _resolve_for_spawn(args, kwargs.get("cwd"), kwargs.get("env"))
        if refused is not None:
            raise refused
    started = _StartedChild()
    try:
        raise_if_cancelled()
        plan = _prepare_spawn(
            args, kwargs.get("env"), kwargs.get("cwd"), bool(kwargs.get("shell", False))
        )
        if plan is None:
            kwargs["env"] = _spawn_env(kwargs.get("env"))
            return _run_recording_the_start(
                _runner(sandboxed=False), args, kwargs, started
            )
        kwargs["env"] = _spawn_env(plan.env)
        kwargs.update(_plan_popen_kwargs(plan))
        try:
            return _run_recording_the_start(
                _runner(sandboxed=True), plan.argv, kwargs, started
            )
        finally:
            _wait_for_group_before_cleanup(started.process)
            plan.run_cleanup()
    except BaseException as error:
        try:
            setattr(error, _STARTED_CHILD_ATTRIBUTE, started)
        except Exception:
            # An exception whose type refuses attributes, a frozen one: it is
            # raised as it is, the runner's own error, and since the record
            # cannot ride it the caller reads the spawn as one that never
            # started.
            pass
        raise


def spawn_run_failure_after_the_start(
    args: Any, error: BaseException
) -> Optional[PostRunErrorProcess]:
    """For a caller of spawn_run: the result for ``error``, when it came after the
    child spawn_run started, or None when the child never started.

    Read from the record spawn_run's runner call made of its child, which the
    error carries. The result keeps the child's exit code, with what it had
    written; for a tool ASH stopped while it ran, no code, and an error that
    says so.
    """
    started = getattr(error, _STARTED_CHILD_ATTRIBUTE, None)
    if not isinstance(started, _StartedChild) or started.process is None:
        return None
    # One read decides the reason's words and the flag together.
    not_stopped = started.not_stopped()
    reason = started.error_after(error, not_stopped)
    flags, reason = _signaled_failure(
        started.exit_code(),
        "the tool",
        reason,
        log_the_death=True,
        after_a_failed_wait=True,
    )
    after = PostRunErrorProcess(
        args=args,
        returncode=started.exit_code(),
        stdout=started.stdout or "",
        stderr=started.stderr or "",
        error=reason,
        **flags,
    )
    if not_stopped is not None:
        after.could_not_stop = True
        after.could_not_stop_pid = started.not_stopped_pid()
    return after


def run_ended_with_the_server(
    args: List[str], **kwargs: Any
) -> subprocess.CompletedProcess:
    """``subprocess.run`` for a child ASH runs for itself that can run for a while.

    For ASH's own helpers, such as nbconvert or a git clone, not a scanner's tool:
    nothing is sandboxed. The child leads a process group of its own, recorded
    until it is reaped, so a stopping MCP server ends it with its scanners' tools
    (kill_running_groups), and once the server is stopping none starts. Through
    plain ``subprocess.run`` it ran in the server's own group, unrecorded, and
    outlived a server that stopped meanwhile. Inside a scan's cancel scope a
    cancel stops it too. Same arguments, return value and exceptions as
    ``subprocess.run``, ScanCancelled aside. The program is resolved first, and
    refused where :func:`_resolve_for_spawn` refuses it, raising the
    ``FileNotFoundError`` ``subprocess.run`` would, or an ``OSError``
    (``errno.EINVAL``) for an argument to a batch program that cmd.exe would read
    differently. The child's environment is built as every other spawn's is
    (:func:`_spawn_env`).

    A short probe with its own timeout (a ``--version``, a bounded git query)
    does not need this: it ends on its own soon after the server.
    """
    raise_if_cancelled()
    cancel_event = current_cancel_event()
    if args and not kwargs.get("shell", False):
        # A copy, with a string read as the program's name (_argv_list): list()
        # of a string made it its characters, the bug the other helpers fixed.
        args = _argv_list(args)
        refused = _resolve_for_spawn(args, kwargs.get("cwd"), kwargs.get("env"))
        if refused is not None:
            raise refused
    kwargs["env"] = _spawn_env(kwargs.get("env"))
    return _run_cancellable(
        args,
        # Outside a scan nothing cancels it; the server's stop still ends it.
        cancel_event=cancel_event if cancel_event is not None else threading.Event(),
        graceful_timeout=False,
        own_group=True,
        **kwargs,
    )


#: The option whose values a shown command line writes as their keys.
def _argv_list(args: Any) -> Any:
    """``args`` as a list of its own, for the program to be resolved in.

    A list or a tuple is copied, so the caller's sequence is left as it was (and
    a tuple, which cannot take the resolved program, no longer raises TypeError
    outside the spawn's handling). A string without a shell is the program's
    name, as subprocess reads it, so it becomes a one-element list; ``list()``
    turned it into its characters and ran the wrong command. Anything else is
    passed on for subprocess to accept or refuse.
    """
    if isinstance(args, (str, bytes, os.PathLike)):
        return [args]
    if isinstance(args, (list, tuple)):
        return list(args)
    return args


def _resolved_or_refused(
    args: Any,
    cwd: "str | os.PathLike[str] | None",
    env: Optional[Dict[str, str]],
    shell: bool,
) -> Optional[BaseException]:
    """``_resolve_for_spawn`` as the spawn helpers call it: the refusal to raise
    inside the spawn's own try, or None.

    An exception the resolution itself raises (``os.getcwd`` on a deleted
    working directory, a lookup that fails) is returned the same way, so the
    helper reports a command that could not start instead of raising past the
    result it promises.
    """
    if not args or shell:
        return None
    try:
        return _resolve_for_spawn(args, cwd, env)
    except Exception as error:  # noqa: BLE001 -- reported as the spawn's failure
        return error


_CONFIG_OVERRIDES_OPTION = "--config-overrides"


def _override_by_key(override: str) -> str:
    key, separator, _ = override.partition("=")
    return f"{key}=<value>" if separator else override


def shown_arguments(args: List[Any]) -> List[Any]:
    """``args`` as a log line or a debug echo shows a command: every
    --config-overrides value written as its key, ``key=<value>``, and every other
    argument as it is.

    An override's value can be a credential, and container and Nix mode pass
    the user's --config-overrides on to the ASH they start. Both forms are
    shown by key: ``--config-overrides key=value`` and
    ``--config-overrides=key=value``. The command that runs is not changed. An
    argument that is not a string is kept as it is: a caller that joins the line
    makes it a string first, or the join raises TypeError for it.
    """
    shown: List[Any] = []
    follows_option = False
    for arg in args:
        if not isinstance(arg, str):
            shown.append(arg)
            follows_option = False
        elif follows_option:
            shown.append(_override_by_key(arg))
            follows_option = False
        elif arg == _CONFIG_OVERRIDES_OPTION:
            shown.append(arg)
            follows_option = True
        elif arg.startswith(_CONFIG_OVERRIDES_OPTION + "="):
            override = arg[len(_CONFIG_OVERRIDES_OPTION) + 1 :]
            shown.append(f"{_CONFIG_OVERRIDES_OPTION}={_override_by_key(override)}")
        else:
            shown.append(arg)
    return shown


def _timeout_token(timeout: Any, values: Tuple[str, ...] = ()) -> str:
    """A timeout's limit as its own quoted token, ``'60' s``.

    Printed through the one formatter every timeout message uses
    (error_text.timeout_limit_token), with the caller's environment values (the
    scan config's, for a scanner's run): a limit one of them types to names the
    option instead of printing a number. The runner logs this text itself, and
    no log handler redacts, so the plugin's own redaction of the errors it keeps
    does not reach that line. The uv runner's timeout texts use it too.
    """
    from automated_security_helper.utils.error_text import timeout_limit_token

    return timeout_limit_token(timeout, values)


def _logged_without(text: str, values: Tuple[str, ...]) -> str:
    """A line the runner logs itself, without the caller's environment values.

    For a uv run the line also hides the run's plugin inputs with the full
    uv layer, WHATEVER the sandbox mode: the sandbox scope carries them when
    one is active, and the dispatch's record-only context
    (sandbox.scope.uv_record_inputs) carries the same set under the default
    mode "off" -- these records quote the command line, and a glued or
    pinned spec hidden on the report lines must not print here. For any
    other tool this is the plain value layer (and with no values the text
    comes back unchanged, so the plain case costs nothing).

    This decorates a log line, and some call sites run outside any try (the
    "Running command:" line comes before the spawn), so a raise here would
    stop the run itself. A raising shower gets a placeholder: the line is
    lost, never the run -- and never the raw text, whose command line is
    exactly what the shower was hiding.
    """
    from automated_security_helper.utils.sandbox.scope import scope_shown_text

    try:
        return scope_shown_text(text, values)
    except Exception:  # noqa: BLE001 -- a raising shower loses the line, not the run
        return "(this line could not be shown)"


def run_command(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
    shell: bool = False,
    log_level: int = logging.INFO,
    timeout: Optional[float] = None,
    encoding: Optional[str] = None,
    errors: str = "replace",
    values: Iterable[str] = (),
) -> subprocess.CompletedProcess:
    """Run a command and return the completed process.

    Args:
        args: Command arguments as a list
        cwd: Working directory for the command
        env: Environment variables for the command
        capture_output: Whether to capture stdout and stderr
        text: Whether to decode stdout and stderr as text
        check: Whether to raise an exception if the command fails
        shell: Whether to run the command in a shell
        log_level: Log level for command execution
        timeout: Timeout for the command in seconds
        values: The caller's environment values, which the timeout text
            prints its limit with and every line this runner logs is redacted
            of. ASH's own callers have none to give; this is a public helper,
            and a plugin can call it with its config's. A scanner's run goes
            through run_command_with_output_handling, which takes them too.

    Returns:
        The completed process

    Raises:
        subprocess.CalledProcessError: If check=True and the command fails
        subprocess.TimeoutExpired: If the command times out
        PostRunError: If check=True and ASH failed after the command started
    """
    # Copy args to avoid mutating the caller's list. A string without a shell is
    # the program's name (_argv_list); with a shell it goes to the shell as it is.
    args = _argv_list(args) if not shell or not isinstance(args, str) else args

    # Resolve the full path to the executable if possible. A refusal, or a
    # failure of the resolution itself, is raised in the try below, so it is
    # reported as a command that could not start.
    refused = _resolved_or_refused(args, cwd, env, shell)

    # Log the command being executed
    # str() each argument: a Path or an int in the list made the join raise
    # TypeError here, before the spawn's own handlers could report anything.
    # shown_arguments writes each --config-overrides value as its key.
    cmd_str = (
        " ".join(map(str, shown_arguments(args)))
        if isinstance(args, list)
        else str(args)
    )
    # Every line this runner logs itself is redacted with the caller's values:
    # the command can carry a value the config read from the environment (an
    # option's path), and so can what the child wrote to stderr. What it
    # returns stays as it is; the caller redacts where it keeps it. Through
    # the normalizer, so one string given on its own is one value.
    values = value_tuple(values)
    ASH_LOGGER.log(
        log_level,
        _logged_without(f"Running command: {cmd_str}", values),
        extra=NO_MARKUP,
    )

    # Set encoding for Windows compatibility. In bytes mode (text=False) no
    # encoding and no error handler are passed: either one switches Popen to
    # text mode, so a caller that asked for bytes got str.
    if not text:
        encoding, errors = None, None  # type: ignore[assignment]
    elif encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    # A cancelled scan starts no more children. Outside the try below, whose
    # handlers would otherwise turn the cancel into a failed command.
    raise_if_cancelled()

    sandbox_plan = None
    # The run, once the runner returned it: what fails after that, such as the
    # log of its result, is a failure after the tool exited, with its exit code.
    ran: Optional[subprocess.CompletedProcess] = None
    # The runner's record of the child it started, held around its call alone.
    started = _StartedChild()
    try:
        if refused is not None:
            raise refused
        sandbox_plan = _prepare_spawn(args, env, cwd, shell)
        if sandbox_plan is not None:
            args, env = sandbox_plan.argv, sandbox_plan.env
        # A sandboxed spawn is stopped with SIGTERM on a timeout; see _run_stoppable.
        runner = _runner(sandboxed=sandbox_plan is not None)
        # The values ride the spawn (_SPAWN_VALUES): the lines the stop paths
        # log and the could-not-stop records they build are redacted with them,
        # as this runner's own lines are.
        with started.recording(), _spawn_values(values):
            result = runner(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
                args,
                cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
                env=_spawn_env(env),
                capture_output=capture_output,
                text=text,
                check=check,
                shell=shell,
                timeout=timeout,
                encoding=encoding,
                errors=errors,
                **_plan_popen_kwargs(sandbox_plan),
            )
        ran = result

        death = signal_death(result.returncode, cmd_str)
        if death is not None:
            # A signal ASH did not send ended it, as in
            # run_command_with_output_handling.
            number, ended = death
            # Built before the death is logged: a failure building the result
            # reaches the handler below, whose failure line carries the death,
            # so the death is still logged once.
            signaled = SignaledProcess(
                args=result.args,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                error=ended,
                signal=number,
            )
            ASH_LOGGER.error(
                shown_on_one_line(_logged_without(ended, values)), extra=NO_MARKUP
            )
            return signaled

        # Log command result. A caller that asked for its command to be logged
        # below INFO (a sweep's rm of a container that may be gone) gets the
        # failure line at that level too; every other caller keeps WARNING.
        if result.returncode == 0:
            ASH_LOGGER.debug(f"Command succeeded with return code {result.returncode}")
        else:
            failure_line = f"Command failed with return code {result.returncode}"
            if log_level < logging.INFO:
                ASH_LOGGER.log(log_level, failure_line)
            else:
                # Through ``warning`` itself, the method a caller that watches
                # this line patches or counts, never through ``log``.
                ASH_LOGGER.warning(failure_line)
            # Built only when the record would be EMITTED: .debug() is gated
            # by the logger's level (isEnabledFor), and the record then has
            # to reach a handler whose level admits it (utils.log.delivers,
            # as _pre_scan guards its dumps). The redaction walks the whole
            # stderr of every failed command, and the CLI's logger sits at
            # TRACE with its file handlers at INFO, so isEnabledFor(DEBUG)
            # alone was always true there and the work ran for records every
            # handler then dropped; delivers alone would build the record a
            # raised logger level never emits.
            if (
                result.stderr
                and ASH_LOGGER.isEnabledFor(logging.DEBUG)
                and delivers(ASH_LOGGER, logging.DEBUG)
            ):
                ASH_LOGGER.debug(
                    _logged_without(f"Command stderr: {result.stderr}", values),
                    extra=NO_MARKUP,
                )

        return result
    except subprocess.CalledProcessError as e:
        ASH_LOGGER.error(
            _logged_without(
                f"Command failed with return code {e.returncode}: {cmd_str}", values
            ),
            extra=NO_MARKUP,
        )
        if (
            e.stderr
            and ASH_LOGGER.isEnabledFor(logging.DEBUG)
            and delivers(ASH_LOGGER, logging.DEBUG)
        ):
            ASH_LOGGER.debug(
                _logged_without(f"Command stderr: {e.stderr}", values),
                extra=NO_MARKUP,
            )
        if check:
            raise
        return subprocess.CompletedProcess(
            args=e.cmd,
            returncode=e.returncode,
            stdout=e.output or "",
            stderr=e.stderr or "",
        )
    except subprocess.TimeoutExpired as e:
        timed_out = (
            f"Command timed out after {_timeout_token(timeout, values)}: {cmd_str}"
        )
        # As in run_command_with_output_handling: a child the stop did not end
        # has no code, and the reason names it.
        not_stopped = started.not_stopped()
        if not_stopped is not None:
            timed_out = f"{timed_out}. {not_stopped}"
        ASH_LOGGER.error(_logged_without(timed_out, values), extra=NO_MARKUP)
        if check:
            raise
        # TimeoutExpired carries what communicate had read undecoded, text mode
        # or not, so a tool that wrote before the timeout handed a text-mode
        # caller bytes; decoded as the finished run's streams would have been.
        partial_stdout, partial_stderr = e.stdout, e.stderr
        if text:
            partial_stdout = _late_decoded(partial_stdout, encoding, errors)
            partial_stderr = _late_decoded(partial_stderr, encoding, errors)
        # -1 rather than TIMEOUT_RETURNCODE because callers and tests already pin
        # it; the type carries the timeout so nothing has to infer it from the code.
        timed_out_result = TimedOutProcess(
            args=e.cmd,
            returncode=-1 if not_stopped is None else None,
            stdout=partial_stdout or "",
            stderr=partial_stderr
            or f"Command timed out after {_timeout_token(e.timeout, values)}",
            error=timed_out,
        )
        if not_stopped is not None:
            timed_out_result.could_not_stop = True
            timed_out_result.could_not_stop_pid = started.not_stopped_pid()
        return timed_out_result
    except Exception as e:
        if ran is not None:
            # The tool exited, and ASH failed after it. Its exit code and output
            # are kept, with the error, as for a failure while waiting on it.
            flags, reason = _signaled_failure(
                ran.returncode, cmd_str, str(e), log_the_death=False
            )
            failure = f"ASH could not record the output of {cmd_str}: {reason}"
            ASH_LOGGER.error(
                shown_on_one_line(_logged_without(failure, values)), extra=NO_MARKUP
            )
            if check:
                raise PostRunError(
                    ran.args,
                    ran.returncode,
                    reason,
                    ran.stdout,
                    ran.stderr,
                    **flags,
                ) from e
            return PostRunErrorProcess(
                args=ran.args,
                returncode=ran.returncode,
                stdout=ran.stdout,
                stderr=ran.stderr,
                error=reason,
                **flags,
            )
        if started.process is not None:
            # The runner recorded its child, and waiting on it raised: reading
            # its output, or stopping it. A child that had exited keeps its own
            # exit code, as run_command_with_output_handling keeps it, with the
            # error and what it wrote; 127 would say it never ran. One still
            # running was stopped by ASH, whose signal is not the tool's code:
            # None, and an error that says so.
            # One read decides the reason's words and the flag together.
            not_stopped = started.not_stopped()
            error = started.error_after(e, not_stopped)
            flags, error = _signaled_failure(
                started.exit_code(),
                cmd_str,
                error,
                log_the_death=False,
                after_a_failed_wait=True,
            )
            failure = f"ASH could not record the output of {cmd_str}: {error}"
            ASH_LOGGER.error(
                shown_on_one_line(_logged_without(failure, values)), extra=NO_MARKUP
            )
            if check:
                # Raised, as check asks, with the flag and ASH's reason, and only
                # a code the tool gave.
                raise PostRunError(
                    args,
                    started.exit_code(),
                    error,
                    started.stdout or "",
                    started.stderr or "",
                    **flags,
                ) from e
            post_run_result = PostRunErrorProcess(
                args=args,
                returncode=started.exit_code(),
                stdout=started.stdout or "",
                stderr=started.stderr or "",
                error=error,
                **flags,
            )
            if not_stopped is not None:
                post_run_result.could_not_stop = True
                post_run_result.could_not_stop_pid = started.not_stopped_pid()
            return post_run_result
        # An OSError from the OS, or anything else the try raised before the
        # child started: it came from preparing or starting the spawn, so the
        # command never ran. Not returncode 1, which reads as "ran and failed" and
        # is an accepted exit code for most scanners.
        message = spawn_failure_message(cmd_str, e)
        ASH_LOGGER.error(
            shown_on_one_line(_logged_without(message, values)), extra=NO_MARKUP
        )
        if check:
            raise
        return SpawnFailedProcess(
            args=args,
            returncode=SPAWN_FAILURE_RETURNCODE,
            stdout="",
            stderr=message,
            error=str(e),
        )
    finally:
        if sandbox_plan is not None:
            sandbox_plan.run_cleanup()


def _write_stream_log(
    results_dir: Optional[Union[str, Path]],
    class_name: Optional[str],
    stream_name: str,
    preference: str,
    text: str,
) -> None:
    """Write one captured stream to ``<results_dir>/<class_name>.<stream>.log``.

    An empty stream truncates the log an earlier run left at the name, and
    creates none: the file read back as this run's output used to be the
    previous command's in the same results directory.
    """
    if results_dir is None or preference not in ["write", "both"]:
        return
    from automated_security_helper.utils.sandbox.scope import active_scope

    results_dir_path = Path(results_dir)
    filename = f"{class_name}.{stream_name}.log" if class_name else f"{stream_name}.log"
    path = results_dir_path.joinpath(filename)
    if not text:
        if path.is_symlink() or not path.is_file():
            return
    else:
        results_dir_path.mkdir(parents=True, exist_ok=True)
    # Not a plain open(): a sandboxed scanner can leave a symlink at this name, and
    # ASH is not sandboxed. See utils/sandbox/fs_guard.py. Under a sandbox the
    # scope's results directory is named as the root: the spawn released its own
    # registrations in its cleanup, before this write, and a process the scanner
    # left running can make a link after the cleanup's sweep.
    scope_results = getattr(active_scope(), "results_dir", None)
    root = None
    if scope_results is not None:
        scope_root = Path(os.path.abspath(scope_results))
        if scope_root in Path(os.path.abspath(path)).parents:
            root = scope_root
    with open_for_write(
        path, encoding="utf-8", errors="replace", root=root
    ) as log_file:
        log_file.write(text)


def _write_stream_logs(
    sandbox_plan: Optional["SpawnPlan"],
    results_dir: Optional[Union[str, Path]],
    class_name: Optional[str],
    streams: Iterable[Tuple[str, str, Optional[str]]],
) -> List[str]:
    """Write each captured stream to its log, after the sandbox's cleanup.

    ``streams`` is (name, preference, text) triples; empty texts are skipped.
    The sandbox's cleanup runs first because its FIRST step is sweep_writable
    over the policy's writable dirs (inserted by scope.prepare_spawn), which
    removes a link a scanner left at a log's name before ASH writes there;
    open_for_write below the registered root is the second defense, for a
    link made after the sweep and for writes with no plan (see
    utils/sandbox/fs_guard.py). The plan's rmtree of its own private
    directories, one of which sits in the results directory, follows in the
    same cleanup. The plan runs each cleanup step once, so a repeat
    elsewhere stays a no-op. Returns
    one clause per write that failed ("ASH could not write its X log: ..."),
    for the caller's reason: the run keeps its own verdict and is not run
    again. Four callers go through here -- the timeout path, both failed-wait
    builders, and the completed-run path; drift between their hand-rolled
    copies is how the failed-wait writes lost the stderr log and the cleanup
    the other paths had. The completed-run path passes no plan (its cleanup
    already ran) and raises its clauses as one OSError into the outer
    post-run handler, which puts them in the response's reason. Only
    ``_spawn_failure_response`` stays separate: no child ever ran, its
    message is its own composition, and a failed write only rates a debug
    line.
    """
    clauses: List[str] = []
    # An empty stream is still written: _write_stream_log truncates the log a
    # previous run left at the name (and creates none), so the stale text is
    # not read back as this run's.
    todo = [
        (name, pref, text or "")
        for name, pref, text in streams
        if pref in ("write", "both")
    ]
    if todo and sandbox_plan is not None:
        sandbox_plan.run_cleanup()
    for stream_name, preference, text in todo:
        try:
            _write_stream_log(results_dir, class_name, stream_name, preference, text)
        except Exception as log_error:
            clauses.append(f"ASH could not write its {stream_name} log: {log_error}")
    return clauses


def _spawn_failure_response(
    cmd_str: str,
    exc: BaseException,
    results_dir: Optional[Union[str, Path]],
    class_name: Optional[str],
    stderr_preference: str,
    values: Tuple[str, ...] = (),
) -> Dict[str, Any]:
    """The ``run_command_with_output_handling`` result for a command that never ran.

    There is no tool output, so the reason is the whole stderr. It is written to
    the stderr log as a completed run's would be, because scanners default to
    "write" and read that file to explain a failure. The line logged here is
    redacted with ``values``, the caller's environment values; the returned
    reason stays as it is.
    """
    message = spawn_failure_message(cmd_str, exc)
    ASH_LOGGER.error(
        shown_on_one_line(_logged_without(message, values)), extra=NO_MARKUP
    )
    try:
        _write_stream_log(results_dir, class_name, "stderr", stderr_preference, message)
    except OSError as log_error:
        ASH_LOGGER.debug(f"Could not write the stderr log: {log_error}")
    return {
        "error": str(exc),
        "returncode": SPAWN_FAILURE_RETURNCODE,
        "spawn_failed": True,
        "stderr": message,
    }


def run_command_with_output_handling(
    command: List[str],
    results_dir: Optional[Union[str, Path]] = None,
    stdout_preference: Literal["return", "write", "both", "none"] = "write",
    stderr_preference: Literal["return", "write", "both", "none"] = "write",
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
    class_name: str = None,
    encoding: Optional[str] = None,
    errors: str = "replace",
    timeout: Optional[float] = None,
    values: Iterable[str] = (),
) -> Dict[str, Any]:
    """Run a subprocess with the given command and handle output according to preferences.

    Args:
        command: Command to run as a list of arguments
        results_dir: Directory to write output files to
        stdout_preference: How to handle stdout ("return", "write", "both", or "none")
        stderr_preference: How to handle stderr ("return", "write", "both", or "none")
        cwd: Working directory for the command
        env: Environment variables for the command
        shell: Whether to run the command in a shell
        class_name: Optional class name for log file naming
        timeout: Seconds to allow the command before it is killed. None leaves it
            unbounded, which is the previous behaviour and the default so that
            existing callers are unchanged.
        values: The caller's environment values (the scan config's), which
            the timeout text prints its limit with and its log line is
            redacted of.

    Returns:
        Dictionary with stdout, stderr, and returncode if requested. A timed-out
        command returns returncode 124 (matching coreutils ``timeout(1)``) and
        ``timed_out: True``, so callers can tell it from the generic failure path.
        A command that never started (the OS refused it, or preparing or starting
        the spawn raised) returns returncode 127 and ``spawn_failed: True``, with
        the reason on one line as its stderr. A command that ran, when ASH then
        failed (writing its stream logs, for one), keeps its own returncode, with
        ``post_run_error: True`` and the error, and returns the tool's stderr
        whatever ``stderr_preference`` asked for. When waiting on a command that
        still ran failed, ASH stopped it: returncode is None, with
        ``post_run_error``, and the error reads "ASH stopped the tool after:
        <error>". A command the stop did not end, after a timeout or such a
        failure, keeps that flag with returncode None, and its error says ASH
        could not stop the tool, which may still be running, with its pid.
    """
    # The resolved program replaces the first element, so it is resolved in a copy:
    # the caller's list is left as it was, as in spawn_run, and a list passed again
    # is resolved again from the name. A tuple is copied too, and a string
    # without a shell is the program's name (_argv_list).
    if not shell or not isinstance(command, str):
        command = _argv_list(command)
    # Resolve the full path to the executable if possible. A refusal, or a
    # failure of the resolution itself, is raised in the spawn's try below, so
    # it is reported as a command that could not start.
    refused = _resolved_or_refused(command, cwd, env, shell)

    # Log the command being executed
    # Shown as in run_command: the join ran before the spawn's try.
    cmd_str = (
        " ".join(map(str, shown_arguments(command)))
        if isinstance(command, list)
        else str(command)
    )
    # As in run_command: every line logged here is redacted with the caller's
    # values, and what is returned stays as it is.
    values = value_tuple(values)
    ASH_LOGGER.verbose(_logged_without(f"Running: {cmd_str}", values), extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    # As in run_command: a cancelled scan starts no more children.
    raise_if_cancelled()

    sandbox_plan = None
    # The run, once it returned, and the response built from it so far: the
    # handler below keeps the tool's own exit code when ASH fails after the run.
    ran: Optional[subprocess.CompletedProcess] = None
    response: Dict[str, Any] = {}
    # The runner's record of the child it started, held around its call alone.
    started = _StartedChild()
    #: The wait's own failure, held for the outer handler: a raise from inside
    #: the except below lands there, and its __context__ can point at an inner
    #: handled error rather than this one.
    wait_error: Optional[BaseException] = None
    try:
        try:
            # Inside the spawn's own try: a sandbox that cannot be provided raises
            # SandboxUnavailable, an OSError, which is reported like any command
            # that could not start, and never falls through to an unsandboxed run.
            # A program refused by _resolve_for_spawn is reported the same way.
            if refused is not None:
                raise refused
            spawn_command, spawn_env = command, env
            sandbox_plan = _prepare_spawn(command, env, cwd, shell)
            if sandbox_plan is not None:
                spawn_command, spawn_env = sandbox_plan.argv, sandbox_plan.env
            # A sandboxed spawn is stopped with SIGTERM on a timeout; see
            # _run_stoppable.
            runner = _runner(sandboxed=sandbox_plan is not None)
            # The values ride the spawn (_SPAWN_VALUES), as in run_command, so
            # the stop paths' lines and records are redacted with them too.
            with started.recording(), _spawn_values(values):
                result = runner(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
                    spawn_command,
                    capture_output=True,
                    text=True,
                    shell=shell,
                    check=False,
                    cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
                    env=_spawn_env(spawn_env),
                    encoding=encoding,
                    errors=errors,
                    timeout=timeout,
                    **_plan_popen_kwargs(sandbox_plan),
                )
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            wait_error = e
            if started.process is not None:
                # The runner recorded its child, and waiting on it raised: reading
                # its output, or stopping it. A failure after the start, with the
                # child's own exit code, or None for a child ASH stopped while it
                # ran, whose signal is not the tool's. The stderr read before the
                # failure is returned whatever stderr_preference asked for, as for
                # a failure after the run.
                # One read decides the reason's words and the flag together.
                not_stopped = started.not_stopped()
                error = started.error_after(e, not_stopped)
                # Written where a completed run's and a timeout's output go:
                # what the tool printed before the wait broke is usually the
                # only clue to why it failed, scanners default to "write", and
                # they read <class>.stderr.log to explain a failure.
                for clause in _write_stream_logs(
                    sandbox_plan,
                    results_dir,
                    class_name,
                    (
                        ("stdout", stdout_preference, started.stdout),
                        ("stderr", stderr_preference, started.stderr),
                    ),
                ):
                    error = f"{error}; {clause}"
                flags, error = _signaled_failure(
                    started.exit_code(),
                    cmd_str,
                    error,
                    log_the_death=False,
                    after_a_failed_wait=True,
                )
                failure = f"ASH could not record the output of {cmd_str}: {error}"
                ASH_LOGGER.error(
                    shown_on_one_line(_logged_without(failure, values)),
                    extra=NO_MARKUP,
                )
                waited: Dict[str, Any] = {
                    "returncode": started.exit_code(),
                    "error": error,
                    "post_run_error": True,
                    "spawn_failed": False,
                    **flags,
                }
                if not_stopped is not None:
                    waited["could_not_stop"] = True
                    waited["could_not_stop_pid"] = started.not_stopped_pid()
                if started.stdout and stdout_preference in ("return", "both"):
                    waited["stdout"] = started.stdout
                # A read stderr is carried even when it is empty, as the
                # fallback and the watch carry it: one bound for one field.
                if started.stderr is not None:
                    waited["stderr"] = started.stderr
                return waited
            # Caught here, around the spawn alone, so an OSError from writing the
            # stream logs below is not reported as a command that never ran. Any
            # other exception here, not only an OSError, means the command never
            # ran: a ValueError for an argument holding a null byte, a sandbox plan
            # that could not be built, a runner that failed before it started
            # anything.
            return _spawn_failure_response(
                cmd_str, e, results_dir, class_name, stderr_preference, values
            )
        ran = result
        # The record keeps the completed run's output: a failure after this call
        # has returned, the uv runner's conversion of its response say, still
        # carries what the tool wrote (StartWatch.failure_after_the_start). The
        # stderr always; the stdout body only when the preference returns it,
        # since under "write" it went to the results file and the caller asked
        # to keep it on disk, the bound this call's own responses honor.
        if stdout_preference in ("return", "both"):
            started.stdout = result.stdout
        started.stderr = result.stderr

        # Before ASH writes the stream logs: the cleanup's first step is
        # sweep_writable (inserted by scope.prepare_spawn), which removes a
        # link a scanner left at a log's name; open_for_write below the
        # registered root is the second defense (see _write_stream_logs).
        # The plan's private directories go in the same cleanup.
        if sandbox_plan is not None:
            _wait_for_group_before_cleanup(started.process)
            sandbox_plan.run_cleanup()

        # Use the actual returncode from the result
        returncode = result.returncode

        response = {"returncode": returncode}
        # A signal ASH did not send ended the tool: its negative code is kept, and
        # the flag and reason say so, since no exit code describes it.
        death = signal_death(returncode, cmd_str)
        if death is not None:
            number, ended = death
            ASH_LOGGER.error(
                shown_on_one_line(_logged_without(ended, values)), extra=NO_MARKUP
            )
            response.update({"signaled": True, "signal": number, "error": ended})

        # The response fields first: the preference's "return" half did not
        # fail when the disk write did. Then the SHARED writer, so a stdout
        # log that cannot be written does not cost the stderr log and every
        # failed write gets the same clause the failed-wait and timeout paths
        # give it -- a hand-rolled copy of that loop is how those paths'
        # wordings drifted apart before (_write_stream_logs' docstring). The
        # cleanup already ran above, so no plan is passed.
        streams = (
            ("stdout", stdout_preference, result.stdout),
            ("stderr", stderr_preference, result.stderr),
        )
        for stream_name, preference, text in streams:
            if text and preference in ["return", "both"]:
                response[stream_name] = text
        write_clauses = _write_stream_logs(None, results_dir, class_name, streams)
        if write_clauses:
            # Raised into the outer post-run handler, which turns it into the
            # response's reason, after both writes were attempted. The
            # original exceptions live only in the clauses' text; there is no
            # single live exception to chain `from` here.
            raise OSError("; ".join(write_clauses))

        return response

    except subprocess.TimeoutExpired as e:
        # The runner has already stopped the child by the time this is raised,
        # which is the point: without the stop the tool would keep running after
        # ASH stopped waiting for it.
        #
        # Handled ahead of the generic branch below so a timeout is reported as
        # such. That branch returns returncode 1 for everything, which cannot be
        # told apart from a tool that simply exited 1.
        #
        # No cleanup call here: _write_stream_logs below runs the sandbox's
        # cleanup before it writes, and the function's finally covers the
        # no-output case -- one cleanup call per path.
        error_msg = (
            f"Command timed out after {_timeout_token(timeout, values)}: {cmd_str}"
        )
        # A child the stop did not end has no code, the tool's or ASH's: the
        # timeout stays the flag, and the reason names the child.
        not_stopped = started.not_stopped()
        if not_stopped is not None:
            error_msg = f"{error_msg}. {not_stopped}"
        partial = {}
        for stream_name in ("stdout", "stderr"):
            captured = getattr(e, stream_name, None)
            if not captured:
                continue
            # Decoded as the finished run's streams are (_late_decoded): the
            # caller's encoding, or the locale encoding text mode resolves to
            # when the caller named none, and the caller's error handler.
            partial[stream_name] = _late_decoded(captured, encoding, errors)
        # Written where a completed run's output goes. What a tool printed
        # before it was killed is usually the only clue to why it hung, and
        # returning it was not enough: scanners default to "write", so the
        # partial stderr reached no file and no log.
        for clause in _write_stream_logs(
            sandbox_plan,
            results_dir,
            class_name,
            (
                ("stdout", stdout_preference, partial.get("stdout")),
                ("stderr", stderr_preference, partial.get("stderr")),
            ),
        ):
            error_msg = f"{error_msg}; {clause}"
        # NO_MARKUP rather than escaping error_msg: it is also returned to the
        # caller below and lands in the scanner's stderr, which must stay verbatim.
        # The returned text is redacted where the caller keeps it; this line is
        # logged here, so it is redacted here.
        ASH_LOGGER.error(
            shown_on_one_line(_logged_without(error_msg, values)), extra=NO_MARKUP
        )
        return {
            "error": error_msg,
            "returncode": TIMEOUT_RETURNCODE if not_stopped is None else None,
            "timed_out": True,
            # The recorded state, read with .get wherever the response travels:
            # the fact never rides in the reason's text, and the pid rides as
            # data beside it.
            **(
                {
                    "could_not_stop": True,
                    "could_not_stop_pid": started.not_stopped_pid(),
                }
                if not_stopped is not None
                else {}
            ),
            "stderr": f"{partial.get('stderr', '')}\n{error_msg}".strip(),
            # The partial stdout reached the stream log above when the
            # preference writes it ("write" or "both", _write_stream_log's own
            # gate); the response carries the body only when the preference
            # returns it, the bound every other builder honors.
            **(
                {"stdout": partial["stdout"]}
                if "stdout" in partial and stdout_preference in ("return", "both")
                else {}
            ),
        }

    except Exception as e:
        if ran is None:
            # Reached only when the spawn's own handler raised: there is no run
            # yet, and that handler's own answer never came back.
            if started.process is not None:
                # The runner had recorded its child, so the failure came after
                # the start: a post-run error with the child's own code (None
                # for one ASH stopped, or whose stop was refused), never 127
                # "the command never ran". The answer is the one that handler
                # would have given (StartWatch.failure_after_the_start's): a
                # refused stop's could_not_stop and pid, and what the record
                # holds of the tool's output. The error's text and the child's
                # poll are each read under a guard, since either can be what
                # made that handler raise.
                described = _text_of(e)
                try:
                    not_stopped = started.not_stopped()
                except Exception:  # noqa: BLE001 -- a poll that raises again
                    not_stopped = None
                if not_stopped is not None:
                    described = f"{not_stopped}, after: {described}"
                elif started.exit_code() is None:
                    described = f"ASH stopped the tool after: {described}"
                carried = _carried_failure(e, handled=wait_error)
                if carried is not None:
                    # The handler raised while handling the wait's own failure:
                    # the text leads with that failure, then the handler's
                    # crash, composed OUTERMOST so the order matches
                    # failure_after_the_start's reason exactly. wait_error is
                    # the failure that handler caught, read as a local because
                    # the handler's own nested try/except can make the raise's
                    # __context__ an inner error instead.
                    described = f"{carried}, then: {described}"
                # The same destination the first handler's answer gives them:
                # the wait's partial reads go to the stream logs under the
                # caller's preferences, whichever handler ends up answering.
                for clause in _write_stream_logs(
                    sandbox_plan,
                    results_dir,
                    class_name,
                    (
                        ("stdout", stdout_preference, started.stdout),
                        ("stderr", stderr_preference, started.stderr),
                    ),
                ):
                    described = f"{described}; {clause}"
                flags, error = _signaled_failure(
                    started.exit_code(),
                    cmd_str,
                    described,
                    log_the_death=False,
                    after_a_failed_wait=True,
                )
                failure = f"ASH could not record the output of {cmd_str}: {error}"
                ASH_LOGGER.error(
                    shown_on_one_line(_logged_without(failure, values)),
                    extra=NO_MARKUP,
                )
                answer: Dict[str, Any] = {
                    "returncode": started.exit_code(),
                    "error": error,
                    "post_run_error": True,
                    "spawn_failed": False,
                    **flags,
                }
                if not_stopped is not None:
                    answer["could_not_stop"] = True
                    answer["could_not_stop_pid"] = started.not_stopped_pid()
                # The stdout body only when the preference returns it, the
                # bound every other builder of this response honors; the
                # stderr always, as for a failure after the run.
                if started.stdout and stdout_preference in ("return", "both"):
                    answer["stdout"] = started.stdout
                if started.stderr is not None:
                    answer["stderr"] = started.stderr
                return answer
            return _spawn_failure_response(
                cmd_str, e, results_dir, class_name, stderr_preference, values
            )
        # The tool ran and exited, and ASH then failed: writing its stream logs, for
        # one. Its own exit code is kept, with post_run_error and the error. 127
        # would say it never started, and 1 reads as "ran and found issues" to most
        # scanners, so ASH's own failure would pass for a finding or a clean run.
        earlier = response.get("error")
        error_text = f"{earlier}; {e}" if earlier else str(e)
        # The response built so far carries the signal flags once the run was
        # read; a failure before that (the sandbox's cleanup, say) left it
        # empty, and the kept code still names the tool's own ending. Recomputing
        # over a response that already carries them would report the ending twice.
        late_flags: Dict[str, Any] = {}
        if "signaled" not in response:
            late_flags, error_text = _signaled_failure(
                ran.returncode, cmd_str, error_text, log_the_death=False
            )
        # One log record: with the death when it was read here, since no other
        # record carries it then; otherwise ASH's own failure alone, since the
        # ending was already reported where the response was built.
        message = f"ASH could not record the output of {cmd_str}: " + (
            error_text if late_flags else str(e)
        )
        ASH_LOGGER.error(
            shown_on_one_line(_logged_without(message, values)), extra=NO_MARKUP
        )
        post_run: Dict[str, Any] = {
            **late_flags,
            **response,
            "returncode": ran.returncode,
            "error": error_text,
            "post_run_error": True,
            "spawn_failed": False,
        }
        # The tool's stderr, whatever stderr_preference asked for: its log may be
        # what could not be written, and the tool's diagnostics are what explain
        # ASH's own failure. As the tool wrote it, as a returned stderr always is.
        if ran.stderr:
            post_run["stderr"] = ran.stderr
        return post_run
    finally:
        if sandbox_plan is not None:
            sandbox_plan.run_cleanup()


def run_command_get_output(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
    check: bool = False,
) -> Tuple[int, str, str]:
    """Run a command and return the exit code, stdout, and stderr.

    Args:
        args: Command arguments as a list
        cwd: Working directory for the command
        env: Environment variables for the command
        shell: Whether to run the command in a shell
        check: Whether to raise an exception if the command fails

    Returns:
        Tuple of (exit_code, stdout, stderr)

    Raises:
        subprocess.CalledProcessError: If check=True and the command fails
    """
    result = run_command(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
        args=args,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=check,
        shell=shell,
    )

    return result.returncode, result.stdout, result.stderr


def run_command_stream_output(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
    encoding: Optional[str] = None,
    errors: str = "replace",
) -> int:
    """Run a command and stream its output to the console.

    Args:
        args: Command arguments as a list
        cwd: Working directory for the command
        env: Environment variables for the command
        shell: Whether to run the command in a shell

    Returns:
        The exit code of the command: 127 when it could not be started;
        ``UNRECORDED_RUN_RETURNCODE`` (255) when it started and ASH then failed
        relaying its output, waiting on it, or stopping it afterwards, which is
        logged on one line; and otherwise the tool's own, also when closing the
        pipe its output was read from then fails, which is logged on one line
        too. A bare exit code has no
        flag to tell ASH's failure from the tool's, so a caller that needs one
        uses ``run_command_with_output_handling``, whose response sets
        ``post_run_error`` and keeps the tool's code.

    Raises:
        ScanCancelled: the scan was cancelled before the tool started, or while
        it ran. In the second case the tool is stopped first, SIGTERM and then
        SIGKILL after the cancel's grace, the whole process group when the tool
        leads one; a tool that is silent when the cancel comes is stopped all
        the same, by a watcher that reads the cancel every CANCEL_POLL_SECONDS.
    """
    # The resolved program replaces the first element, so it is resolved in a copy:
    # the caller's list is left as it was, as in spawn_run, and a list passed again
    # is resolved again from the name. A tuple is copied too, and a string
    # without a shell is the program's name (_argv_list).
    if not shell or not isinstance(args, str):
        args = _argv_list(args)
    # Resolve the full path to the executable if possible. A refusal, or a
    # failure of the resolution itself, is raised in the try below, so it is
    # reported as a command that could not start.
    refused = _resolved_or_refused(args, cwd, env, shell)

    # Log the command being executed
    # str() each argument: a Path or an int in the list made the join raise
    # TypeError here, before the spawn's own handlers could report anything.
    # shown_arguments writes each --config-overrides value as its key.
    cmd_str = (
        " ".join(map(str, shown_arguments(args)))
        if isinstance(args, list)
        else str(args)
    )
    ASH_LOGGER.info(f"Running command: {cmd_str}", extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    # A cancelled scan starts no more children, as in run_command. Outside the
    # try below, whose handler would report the cancel as a failed start.
    raise_if_cancelled()
    cancel_event = current_cancel_event()

    sandbox_plan = None
    # Bound before the spawn: the finally below reads it, and a plan prepared
    # before a Popen that raised leaves no child to wait for.
    process: Optional[subprocess.Popen] = None
    try:
        try:
            # Inside the spawn's own try, as in run_command_with_output_handling: a
            # program refused by _resolve_for_spawn is reported like any command that
            # could not start.
            if refused is not None:
                raise refused
            sandbox_plan = _prepare_spawn(args, env, cwd, shell)
            if sandbox_plan is not None:
                args, env = sandbox_plan.argv, sandbox_plan.env
            process = subprocess.Popen(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
                args,
                cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
                env=_spawn_env(env),
                # Not ASH's own standard input; see _pipes_for.
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=shell,
                encoding=encoding,
                errors=errors,
                **_plan_popen_kwargs(sandbox_plan),
            )
        except Exception as e:
            # Around the spawn alone, as in run_command_with_output_handling: an
            # OSError from the OS, or anything raised preparing or starting it,
            # means the command never ran.
            message = spawn_failure_message(cmd_str, e)
            ASH_LOGGER.error(shown_on_one_line(message), extra=NO_MARKUP)
            return SPAWN_FAILURE_RETURNCODE

        # The tool started: a failure from here on is ASH's own, relaying its
        # output, waiting on it, or stopping it afterwards. Any of them returns
        # UNRECORDED_RUN_RETURNCODE, never the tool's code: a 0 kept after a
        # failed stop would read as a clean run.
        failed = False
        # The scan's cancel ends the run while the tool runs, not only between
        # its output lines: read between lines alone, a tool that printed nothing
        # more held a cancelled scan at the wait below for as long as it chose to
        # run. A watcher in the scan's own context (ash_thread carries its
        # cancellation scope and its log scope) reads the cancel every
        # CANCEL_POLL_SECONDS and stops the child, the whole group when the child
        # leads one, as the cancellable runner does; the line loop reads it too,
        # and the lock makes the two readers one stop. The stop ends the child's
        # output, so the loop and the wait below return, and the cancel is raised
        # from this thread.
        stop_once = threading.Lock()
        prompt = getattr(cancel_event, "prompt", None)
        watcher: Optional[threading.Thread] = None

        def stop_on_cancel() -> bool:
            """Stop the child once; False when the other reader is stopping it."""
            if not stop_once.acquire(blocking=False):
                return False
            stop = _stop_tree if _leads_its_own_group(process) else _stop
            _stop_child(args, process, stop, _stop_grace(cancel_event), prompt)
            return True

        def wait_for_the_watchers_stop() -> None:
            """A stop the watcher began runs to its end before this thread goes
            on: its SIGTERM grace, then its SIGKILL. Raising the cancel while the
            watcher still waits out the grace put the finally's kill in front of
            that grace (a tool that printed one more line after the SIGTERM lost
            the grace it was given). Bounded by the grace and two reaps."""
            if watcher is not None and watcher.is_alive():
                watcher.join(timeout=_stop_grace(cancel_event) + 2 * _REAP_SECONDS)

        watcher_done = threading.Event()

        def watch_for_the_cancel() -> None:
            while not watcher_done.wait(CANCEL_POLL_SECONDS):
                if cancel_event.is_set():
                    stop_on_cancel()
                    return

        try:
            # Started inside the try: a thread that cannot start raises, and the
            # finally below then still kills and reaps the child.
            if cancel_event is not None:
                watcher = ash_thread(
                    watch_for_the_cancel, name="ash-stream-cancel-watch", daemon=True
                )
                watcher.start()
            # Stream output, shown: it is the tool's, and quotes what it scanned.
            for line in process.stdout:
                print(shown_not_obeyed(line.rstrip()))
                if cancel_event is not None and cancel_event.is_set():
                    if not stop_on_cancel():
                        wait_for_the_watchers_stop()
                    raise_if_cancelled()

            # Wait for process to complete
            process.wait()
            # A cancel the watcher answered while the tool was silent: the child
            # was stopped, and the cancel is raised here, in the caller's thread.
            # A child that ended on its own keeps its code even in a scan since
            # cancelled, as the cancellable runner keeps a completed result.
            if stop_once.locked():
                raise_if_cancelled()
        except ScanCancelled:
            raise
        except Exception as e:
            failed = True
            _log_unrecorded_run(cmd_str, e)
        finally:
            watcher_done.set()
            try:
                # A stop the watcher is still waiting out keeps its grace: the
                # kill below comes after it, not in front of it. The wait sits
                # in a try of its own so that a second interrupt landing during
                # it (a Ctrl-C while the first stop's grace runs) still reaches
                # the kill, the reap and the close below; the first interrupt
                # alone leaves the grace whole.
                if stop_once.locked():
                    wait_for_the_watchers_stop()
            finally:
                try:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                except Exception as e:
                    failed = True
                    _log_unrecorded_run(cmd_str, e)
                    # The kill can be delivered and then raise, so the child
                    # may be dead but unreaped, and a run that returns without
                    # reaping it leaves a zombie no caller can act on. A
                    # bounded wait reaps a dead child; one a failed stop left
                    # running is logged, on one line, and the code stays
                    # UNRECORDED_RUN_RETURNCODE either way.
                    try:
                        process.wait(timeout=0.5)
                    except Exception as reap_error:
                        ASH_LOGGER.error(
                            shown_on_one_line(
                                f"Ran {cmd_str}, and the tool (pid {process.pid}) "
                                f"was not reaped after a failed stop: {reap_error}"
                            ),
                            extra=NO_MARKUP,
                        )
                # After the kill above: a watcher still inside a stop's grace
                # returns once the child is gone. Bounded, as the reap is; a
                # daemon thread left past the bound holds nothing of the run.
                # Only a thread that is running is joined: one whose start()
                # raised was built but never started, and a join on it would
                # raise here, in front of the close and the code.
                if watcher is not None and watcher.is_alive():
                    watcher.join(timeout=_REAP_SECONDS)
                # The read end of the child's output, which nothing else
                # closes. A close that fails loses no output, so it does not
                # change the code; it is logged on one line.
                close = getattr(process.stdout, "close", None)
                if close is not None:
                    try:
                        close()
                    except Exception as e:
                        ASH_LOGGER.error(
                            shown_on_one_line(
                                f"Ran {cmd_str}, and closing its output pipe "
                                f"failed: {e}"
                            ),
                            extra=NO_MARKUP,
                        )
        code = process.returncode
        if failed or not isinstance(code, int):
            return UNRECORDED_RUN_RETURNCODE
        return code
    finally:
        if sandbox_plan is not None:
            _wait_for_group_before_cleanup(process)
            sandbox_plan.run_cleanup()


def _log_unrecorded_run(cmd_str: str, error: BaseException) -> None:
    """Log, on one line with markup off, a failure of ASH's after a streamed tool
    started."""
    ASH_LOGGER.error(
        shown_on_one_line(f"ASH could not record the output of {cmd_str}: {error}"),
        extra=NO_MARKUP,
    )


def get_host_uid() -> int:
    """Get the current user's UID.

    Returns:
        The UID of the current user
    """
    try:
        result = run_command(["id", "-u"], capture_output=True, text=True, check=True)
        return int(result.stdout.strip())
    except Exception as e:
        ASH_LOGGER.error(f"Error getting host UID: {e}", extra=NO_MARKUP)
        ASH_LOGGER.warning(
            "Falling back to default UID 1000 (command 'id -u' unavailable on this platform)"
        )
        return 1000  # Default UID as fallback


def get_host_gid() -> int:
    """Get the current user's GID.

    Returns:
        The GID of the current user
    """
    try:
        result = run_command(["id", "-g"], capture_output=True, text=True, check=True)
        return int(result.stdout.strip())
    except Exception as e:
        ASH_LOGGER.error(f"Error getting host GID: {e}", extra=NO_MARKUP)
        ASH_LOGGER.warning(
            "Falling back to default GID 1000 (command 'id -g' unavailable on this platform)"
        )
        return 1000  # Default GID as fallback


def create_completed_process(
    args: List[str], returncode: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    """Create a CompletedProcess object with the given attributes.

    Args:
        args: Command arguments
        returncode: Return code
        stdout: Standard output
        stderr: Standard error

    Returns:
        A CompletedProcess object
    """
    return subprocess.CompletedProcess(
        args=args, returncode=returncode, stdout=stdout, stderr=stderr
    )


def raise_called_process_error(
    returncode: int, cmd: List[str], output: str = None, stderr: str = None
) -> None:
    """Raise a CalledProcessError with the given attributes.

    Args:
        returncode: Return code
        cmd: Command arguments
        output: Standard output
        stderr: Standard error

    Raises:
        subprocess.CalledProcessError: Always raised with the given attributes
    """
    raise subprocess.CalledProcessError(
        returncode=returncode, cmd=cmd, output=output, stderr=stderr
    )


def create_process_with_pipes(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    text: bool = True,
    shell: bool = False,
    stderr_to_stdout: bool = False,
    encoding: Optional[str] = None,
    errors: str = "replace",
) -> subprocess.Popen:
    """Create a process with pipes for stdout and stderr.

    Args:
        args: Command arguments
        cwd: Working directory
        env: Environment variables
        text: Whether to decode stdout and stderr as text
        shell: Whether to run the command in a shell
        stderr_to_stdout: Whether to redirect stderr to stdout

    Returns:
        A Popen object with pipes for stdout and stderr
    """
    # The resolved program replaces the first element, so it is resolved in a copy:
    # the caller's list is left as it was, as in spawn_run, and a list passed again
    # is resolved again from the name. A tuple is copied too, and a string
    # without a shell is the program's name (_argv_list).
    if not shell or not isinstance(args, str):
        args = _argv_list(args)
    # Resolve the full path to the executable if possible. A refusal, or a
    # failure of the resolution itself, is raised in the try below, which logs
    # and re-raises it as it does a failed Popen.
    refused = _resolved_or_refused(args, cwd, env, shell)

    # Log the command being executed
    # str() each argument: a Path or an int in the list made the join raise
    # TypeError here, before the spawn's own handlers could report anything.
    # shown_arguments writes each --config-overrides value as its key, and
    # the spawn's carried environment values are hidden too: a mount's source
    # or destination in this argv can hold a value the operator's chain read
    # from the environment, and shown_arguments passes mounts through.
    cmd_str = (
        " ".join(map(str, shown_arguments(args)))
        if isinstance(args, list)
        else str(args)
    )
    ASH_LOGGER.verbose(
        _logged_without(f"Creating process with pipes: {cmd_str}", _SPAWN_VALUES.get()),
        extra=NO_MARKUP,
    )

    stderr = subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE

    # Set encoding for Windows compatibility. In bytes mode no encoding and no
    # error handler are passed: either one switches Popen to text mode.
    if not text:
        encoding, errors = None, None  # type: ignore[assignment]
    elif encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    sandbox_plan = None
    try:
        if refused is not None:
            raise refused
        sandbox_plan = _prepare_spawn(args, env, cwd, shell)
        if sandbox_plan is not None:
            args, env = sandbox_plan.argv, sandbox_plan.env
        process = subprocess.Popen(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            args,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=_spawn_env(env),
            # Not ASH's own standard input; see _pipes_for. The caller gets no
            # stdin pipe to write to.
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=text,
            shell=shell,
            encoding=encoding,
            errors=errors,
            **_plan_popen_kwargs(sandbox_plan),
        )
        if sandbox_plan is not None:
            # The caller owns the process, so the plan's temporary files go when it
            # does; off the finalizer's own thread, see _run_cleanup_off_the_finalizer.
            weakref.finalize(process, _run_cleanup_off_the_finalizer, sandbox_plan)
        return process
    except Exception as e:
        if sandbox_plan is not None:
            # No process owns the plan: its writable-root registrations and its
            # private temporary directory would otherwise outlive this call.
            sandbox_plan.run_cleanup()
        # Redacted of the spawn's values and kept to one line, as the start
        # line above is: the error quotes the argv.
        ASH_LOGGER.error(
            shown_on_one_line(
                _logged_without(
                    f"Error creating process with pipes: {e}", _SPAWN_VALUES.get()
                )
            ),
            extra=NO_MARKUP,
        )
        raise


def _run_cleanup_off_the_finalizer(plan: "SpawnPlan") -> None:
    """Run *plan*'s cleanup from a Popen's finalizer without this thread's locks.

    The cleanup releases the registration of the spawn's writable roots
    (fs_guard.release_writable_root), which takes the registry's lock, and that
    lock is not re-entrant. A garbage-collection finalizer runs inside whatever
    allocation triggered the collection, which can be one this thread made
    while holding that lock inside the registry: the release then waited on the
    very thread it ran in. So the cleanup runs on a thread of its own, which
    waits for the lock like any other caller. With the collector disabled
    (weakref.finalize's own exit pass runs that way, with no registry call in
    progress) no finalizer can interrupt an allocation, and the cleanup runs
    inline so the temporary files are gone before the interpreter is. A thread
    that cannot be started (Thread.start raises RuntimeError) runs the cleanup
    inline once the interpreter is shutting down: once the interpreter is
    finalizing (the flag that makes Thread.start refuse, set by CPython's order
    after threading's shutdown and the atexit pass), or when the main thread is
    no longer alive (threading's shutdown has run). The second case covers a
    start that fails during the atexit pass for another reason: a callback
    registered with atexit DURING its pass never runs (the pass iterates the
    count it read at entry), so a finalizer firing inside another atexit
    callback with the collector on has nothing to leave the cleanup to but
    itself; no registry call of this thread can be in progress then.
    Thread.start raises the same error mid-run when the process is out of
    threads or memory, and inline there is the self-deadlock the thread exists
    to avoid, so the cleanup is left to the exit pass instead (atexit, which
    runs on the main thread with no registry call in progress), and logged.
    """
    if not gc.isenabled():
        plan.run_cleanup()
        return
    # Through the factory, so the cleanup's lines belong to the run that made
    # the plan (its log scope rides the copied context), not to no run.
    worker = ash_thread(plan.run_cleanup, name="ash-sandbox-plan-cleanup", daemon=False)
    try:
        worker.start()
    except RuntimeError as error:
        if sys.is_finalizing() or not threading.main_thread().is_alive():
            plan.run_cleanup()
            return
        atexit.register(plan.run_cleanup)
        ASH_LOGGER.debug(
            f"Could not start a thread for a sandbox plan's cleanup ({error}); "
            f"it runs at exit instead",
            extra=NO_MARKUP,
        )
