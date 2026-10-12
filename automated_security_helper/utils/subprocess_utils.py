"""Centralized subprocess execution utilities for ASH."""

import contextvars
import errno
import logging
import os
import platform
import shutil
import subprocess  # nosec B404 - suprocess module required for the nature of this package to orchestrate SAST/SCA/IAC/SBOM scanners
import sys
import weakref
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from automated_security_helper.core.constants import ASH_BIN_PATH
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.offline_tool_env import offline_tool_environment
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.scanned_tree import is_inside_tree

if TYPE_CHECKING:
    from automated_security_helper.utils.sandbox.backends import SpawnPlan


# (command, sandbox, tree scope key) -> (path or None, refused in-tree file or None)
_find_executable_cache: Dict[
    Tuple[str, bool, Tuple[Tuple[str, ...], bool]], Tuple[Optional[str], Optional[str]]
] = {}


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
    """
    env = env if env is not None else snapshot_environ()
    offline = offline_tool_environment()
    if offline:
        env = {**env, **offline}
    scope = _TREE_SCOPE.get()
    if scope is not None:
        env = _without_in_tree_path_entries(env, scope)
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
    type callers already check for.
    """

    timed_out = True


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
    when a caller (``UVToolRunner.run_tool``) converts that dict back.
    """

    spawn_failed = True


def spawn_failure_message(cmd_str: str, exc: OSError) -> str:
    """The stderr text for a command that never ran."""
    return (
        f"Could not start {cmd_str}: {exc}. The command never ran "
        f"(exit code {SPAWN_FAILURE_RETURNCODE})."
    )


def clear_find_executable_cache() -> None:
    """Clear the find_executable lookup cache.

    Call this after installing a new tool so subsequent lookups can
    discover the newly available binary.
    """
    _find_executable_cache.clear()


def _bin_path() -> Path:
    """The ASH bin directory, resolved when asked rather than at import time.

    ``core.constants.ASH_BIN_PATH`` is computed the first time that module is
    imported. ``ash dependencies install --bin-path X`` sets ASH_BIN_PATH in the
    environment after that has already happened, so a lookup against the constant
    searched the default directory and reported a tool ASH had just installed into
    X as absent.

    The module-level constant remains the fallback, so tests that patch
    ``subprocess_utils.ASH_BIN_PATH`` keep working.

    Absolute: a tool found here is run by scanners whose working directory is the
    scanned tree, where a relative ``bin/grype`` would name the repository's file.
    """
    from_env = os.environ.get("ASH_BIN_PATH")
    return Path(from_env).absolute() if from_env else ASH_BIN_PATH


def path_independent_dirs() -> List[Path]:
    """The directories ``find_executable`` searches whatever PATH says, in order.

    These are the fallbacks after ``shutil.which``: ASH's bin directory, then
    /usr/local/bin except on Windows. A tool in one of them is found by every
    later lookup in any environment, which is not true of a tool found only
    through PATH -- a different shell, a CI job or a cron entry may not have the
    same PATH. ``download_utils.find_verified_pinned_executable`` relies on that
    difference, so the list lives here, where ``find_executable`` reads it too,
    rather than being restated there.
    """
    dirs = [_bin_path()]
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


def _is_running_interpreter(candidate: str) -> bool:
    """The Python running ASH: already started, so refusing it protects nothing."""
    try:
        return os.path.samefile(candidate, sys.executable)
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
            if poss.exists():
                yield poss.as_posix()


def _lookup(command: str, sandbox: bool = False) -> Optional[str]:
    """find_executable's search under the active scan, cached by what it depends on."""
    scope = _TREE_SCOPE.get()
    key = (command, sandbox, tree_scope_key())
    cached = _find_executable_cache.get(key)
    if cached is None:
        try:
            cached = _first_usable(
                command, _executable_candidates(command), scope, sandbox
            )
        except Exception as e:
            ASH_LOGGER.error(e, extra=NO_MARKUP)
            cached = (None, None)
        _find_executable_cache[key] = cached
    found, refused = cached
    if refused is not None and scope is not None:
        # Recorded on this scan even when the answer came from the cache, so a
        # later scan of the same tree sees why the tool is missing.
        scope.refusals.setdefault(command, refused)
        scope.events.append(command)
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


def find_executable(command: str) -> Optional[str]:
    """Find the full path to an executable.

    Nothing is found through the working directory, which is usually the
    repository being scanned (see :func:`_which_outside_working_directory`), and
    while a scan is in progress a copy inside the scanned tree is refused unless
    the operator allowed it (see the section comment above).

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
    the tree's copies that ASH's own lookup refused. Also carries the scan's
    decision on the opt-in, so a child ASH (the cdk-nag worker, a container, a nix
    shell) makes the same one.
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
        env["PATH"] = os.pathsep.join(kept)
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


def _resolve_for_spawn(
    args: List[str],
    cwd: "str | os.PathLike[str] | None" = None,
    env: Optional[Dict[str, str]] = None,
) -> Optional[FileNotFoundError]:
    """Point ``args[0]`` at the file :func:`find_executable` finds for it.

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
    name = args[0]
    if os.path.dirname(name) and not _is_anchored(name):
        return FileNotFoundError(
            errno.ENOENT,
            f"{name} is a path relative to the working directory, which is not run",
            name,
        )
    found = find_executable(name)
    if found:
        args[0] = found
        return None
    refusal = in_tree_refusal(name)
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


#: Whether a bare name ASH's lookup cannot resolve is refused on Windows instead of
#: handed to CreateProcess, whose own search includes directories ASH does not check.
_refuse_unresolved_on_windows = True


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

    if active_scope() is None:
        return None
    if shell or isinstance(args, str):
        # No builtin scanner spawns through a shell. Refused rather than wrapped as
        # `sh -c`, so that a string command cannot reach the sandbox unparsed.
        raise SandboxUnavailable(
            "a scanner tried to start a shell command, which the sandbox does not wrap"
        )
    return prepare_spawn(args, env, cwd)


#: How long a sandboxed process gets to stop after SIGTERM on a timeout before it is
#: killed outright.
SANDBOX_STOP_GRACE_SECONDS = 10.0


def _run_stoppable(args: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """``subprocess.run`` that stops a timed-out process with SIGTERM first.

    subprocess.run kills a timed-out child with SIGKILL, which the Landlock
    wrapper cannot catch; it would then never end the processes its scanner left
    running. Sending SIGTERM lets the wrapper kill its whole tree. SIGKILL follows
    if it has not exited within SANDBOX_STOP_GRACE_SECONDS. Raises TimeoutExpired
    the way subprocess.run does. Used for sandboxed spawns only.
    """
    timeout = kwargs.pop("timeout", None)
    check = kwargs.pop("check", False)
    input_data = kwargs.pop("input", None)
    if kwargs.pop("capture_output", False):
        if "stdout" in kwargs or "stderr" in kwargs:
            raise ValueError(
                "stdout and stderr arguments may not be used with capture_output."
            )
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    with subprocess.Popen(args, **kwargs) as process:  # nosec B603 - sandbox-built argv
        try:
            stdout, stderr = process.communicate(input_data, timeout=timeout)
        except subprocess.TimeoutExpired as first:
            stdout, stderr = first.output, first.stderr
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=SANDBOX_STOP_GRACE_SECONDS)
            except subprocess.TimeoutExpired as second:
                stdout = second.output or stdout
                stderr = second.stderr or stderr
                process.kill()
                # wait(), not communicate(): a process the scanner left holding the
                # pipes would keep communicate() reading until it chose to exit, and
                # the timeout would stop being one. subprocess.run waits the same
                # way after its kill.
                process.wait()
            raise subprocess.TimeoutExpired(
                args, timeout, output=stdout, stderr=stderr
            ) from None
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=SANDBOX_STOP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
            raise
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


def spawn_run(args: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """``subprocess.run`` through the scanner sandbox choke point.

    Same arguments, same return value, same exceptions as ``subprocess.run``, for the
    call sites that rely on its exact semantics (``check=True`` raising,
    ``TimeoutExpired`` propagating) and so cannot move to :func:`run_command`.
    The program is resolved first, and refused where :func:`_resolve_for_spawn`
    refuses it, raising the ``FileNotFoundError`` ``subprocess.run`` would.
    """
    if args and not kwargs.get("shell", False):
        args = list(args)
        refused = _resolve_for_spawn(args, kwargs.get("cwd"), kwargs.get("env"))
        if refused is not None:
            raise refused
    plan = _prepare_spawn(
        args, kwargs.get("env"), kwargs.get("cwd"), bool(kwargs.get("shell", False))
    )
    if plan is None:
        kwargs["env"] = _spawn_env(kwargs.get("env"))
        return subprocess.run(args, **kwargs)  # nosec B603 - callers pass list argv
    kwargs["env"] = _spawn_env(plan.env)
    try:
        return _run_stoppable(plan.argv, **kwargs)
    finally:
        plan.run_cleanup()


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

    Returns:
        The completed process

    Raises:
        subprocess.CalledProcessError: If check=True and the command fails
        subprocess.TimeoutExpired: If the command times out
    """
    # Copy args to avoid mutating the caller's list
    args = list(args)

    # Resolve the full path to the executable if possible. A refusal is raised in
    # the try below, so it is reported as a command that could not start.
    refused = _resolve_for_spawn(args, cwd, env) if args and not shell else None

    # Log the command being executed
    cmd_str = " ".join(args) if isinstance(args, list) else args
    ASH_LOGGER.log(log_level, f"Running command: {cmd_str}", extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    sandbox_plan = None
    try:
        if refused is not None:
            raise refused
        sandbox_plan = _prepare_spawn(args, env, cwd, shell)
        if sandbox_plan is not None:
            args, env = sandbox_plan.argv, sandbox_plan.env
        # A sandboxed spawn is stopped with SIGTERM on a timeout; see _run_stoppable.
        runner = _run_stoppable if sandbox_plan is not None else subprocess.run
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
        )

        # Log command result
        if result.returncode == 0:
            ASH_LOGGER.debug(f"Command succeeded with return code {result.returncode}")
        else:
            ASH_LOGGER.warning(f"Command failed with return code {result.returncode}")
            if result.stderr:
                ASH_LOGGER.debug(f"Command stderr: {result.stderr}", extra=NO_MARKUP)

        return result
    except subprocess.CalledProcessError as e:
        ASH_LOGGER.error(
            f"Command failed with return code {e.returncode}: {cmd_str}",
            extra=NO_MARKUP,
        )
        if e.stderr:
            ASH_LOGGER.debug(f"Command stderr: {e.stderr}", extra=NO_MARKUP)
        if check:
            raise
        return subprocess.CompletedProcess(
            args=e.cmd,
            returncode=e.returncode,
            stdout=e.output or "",
            stderr=e.stderr or "",
        )
    except subprocess.TimeoutExpired as e:
        ASH_LOGGER.error(
            f"Command timed out after {timeout} seconds: {cmd_str}", extra=NO_MARKUP
        )
        if check:
            raise
        # -1 rather than TIMEOUT_RETURNCODE because callers and tests already pin
        # it; the type carries the timeout so nothing has to infer it from the code.
        return TimedOutProcess(
            args=e.cmd,
            returncode=-1,
            stdout=e.stdout or "",
            stderr=e.stderr or f"Command timed out after {e.timeout}s",
        )
    except OSError as e:
        # Ahead of the generic branch, whose returncode 1 reads as "ran and
        # failed" and is an accepted exit code for most scanners.
        error_msg = spawn_failure_message(cmd_str, e)
        ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
        if check:
            raise
        return SpawnFailedProcess(
            args=args,
            returncode=SPAWN_FAILURE_RETURNCODE,
            stdout="",
            stderr=error_msg,
        )
    except Exception as e:
        ASH_LOGGER.error(f"Error running command {cmd_str}: {e}", extra=NO_MARKUP)
        if check:
            raise
        # Not 1, which most scanners accept: see SPAWN_FAILURE_RETURNCODE.
        return subprocess.CompletedProcess(
            args=args,
            returncode=SPAWN_FAILURE_RETURNCODE,
            stdout="",
            stderr=f"Error: {str(e)}",
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
    """Write one captured stream to ``<results_dir>/<class_name>.<stream>.log``."""
    if results_dir is None or preference not in ["write", "both"]:
        return
    results_dir_path = Path(results_dir)
    results_dir_path.mkdir(parents=True, exist_ok=True)
    filename = f"{class_name}.{stream_name}.log" if class_name else f"{stream_name}.log"
    # Not a plain open(): a sandboxed scanner can leave a symlink at this name, and
    # ASH is not sandboxed. See utils/sandbox/fs_guard.py.
    with open_for_write(
        results_dir_path.joinpath(filename), encoding="utf-8", errors="replace"
    ) as log_file:
        log_file.write(text)


def _spawn_failure_response(
    cmd_str: str,
    exc: OSError,
    results_dir: Optional[Union[str, Path]],
    class_name: Optional[str],
    stderr_preference: str,
) -> Dict[str, Any]:
    """The ``run_command_with_output_handling`` result for a command that never ran.

    There is no tool output, so the reason is the whole stderr. It is written to
    the stderr log as a completed run's would be, because scanners default to
    "write" and read that file to explain a failure.
    """
    error_msg = spawn_failure_message(cmd_str, exc)
    ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
    try:
        _write_stream_log(
            results_dir, class_name, "stderr", stderr_preference, error_msg
        )
    except OSError as log_error:
        ASH_LOGGER.debug(f"Could not write the stderr log: {log_error}")
    return {
        "error": str(exc),
        "returncode": SPAWN_FAILURE_RETURNCODE,
        "spawn_failed": True,
        "stderr": error_msg,
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

    Returns:
        Dictionary with stdout, stderr, and returncode if requested. A timed-out
        command returns returncode 124 (matching coreutils ``timeout(1)``) and
        ``timed_out: True``, so callers can tell it from the generic failure path.
        A command the OS could not start returns returncode 127 and
        ``spawn_failed: True``, with the reason as its stderr.
    """
    # Resolve the full path to the executable if possible. A refusal is raised in
    # the spawn's try below, so it is reported as a command that could not start.
    refused = _resolve_for_spawn(command, cwd, env) if command and not shell else None

    # Log the command being executed
    cmd_str = " ".join(command) if isinstance(command, list) else command
    ASH_LOGGER.verbose(f"Running: {cmd_str}", extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    sandbox_plan = None
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
            runner = _run_stoppable if sandbox_plan is not None else subprocess.run
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
            )
        except OSError as e:
            # Caught here, around the spawn alone, so an OSError from writing the
            # stream logs below is not reported as a command that never ran.
            return _spawn_failure_response(
                cmd_str, e, results_dir, class_name, stderr_preference
            )

        # Before ASH writes the stream logs into the scanner's results directory:
        # the sandbox's cleanup removes any link the scanner left there.
        if sandbox_plan is not None:
            sandbox_plan.run_cleanup()

        # Use the actual returncode from the result
        returncode = result.returncode

        response = {"returncode": returncode}

        for stream_name, preference, text in (
            ("stdout", stdout_preference, result.stdout),
            ("stderr", stderr_preference, result.stderr),
        ):
            if not text:
                continue
            _write_stream_log(results_dir, class_name, stream_name, preference, text)
            if preference in ["return", "both"]:
                response[stream_name] = text

        return response

    except subprocess.TimeoutExpired as e:
        # subprocess.run has already killed the child by the time this is raised,
        # which is the point: without the kill the tool would keep running after
        # ASH stopped waiting for it.
        #
        # Handled ahead of the generic branch below so a timeout is reported as
        # such. That branch returns returncode 1 for everything, which cannot be
        # told apart from a tool that simply exited 1.
        if sandbox_plan is not None:
            sandbox_plan.run_cleanup()
        error_msg = f"Command timed out after {timeout}s: {cmd_str}"
        # NO_MARKUP rather than escaping error_msg: it is also returned to the
        # caller below and lands in the scanner's stderr, which must stay verbatim.
        ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
        partial = {}
        for stream_name, preference in (
            ("stdout", stdout_preference),
            ("stderr", stderr_preference),
        ):
            captured = getattr(e, stream_name, None)
            if not captured:
                continue
            if isinstance(captured, bytes):
                captured = captured.decode("utf-8", errors="replace")
            partial[stream_name] = captured
            # Written where a completed run's output goes. What a tool printed
            # before it was killed is usually the only clue to why it hung, and
            # returning it was not enough: scanners default to "write", so the
            # partial stderr reached no file and no log.
            _write_stream_log(
                results_dir, class_name, stream_name, preference, captured
            )
        return {
            "error": error_msg,
            "returncode": TIMEOUT_RETURNCODE,
            "timed_out": True,
            "stderr": f"{partial.get('stderr', '')}\n{error_msg}".strip(),
            **{k: v for k, v in partial.items() if k == "stdout"},
        }

    except Exception as e:
        error_msg = f"Error running {cmd_str}: {e}"
        ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
        # Not 1, which most scanners accept: see SPAWN_FAILURE_RETURNCODE.
        return {
            "error": str(e),
            "returncode": SPAWN_FAILURE_RETURNCODE,
            "stderr": error_msg,
        }
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
        The exit code of the command
    """
    # Resolve the full path to the executable if possible. A refusal is raised in
    # the try below, so it is reported as a command that could not start.
    refused = _resolve_for_spawn(args, cwd, env) if args and not shell else None

    # Log the command being executed
    cmd_str = " ".join(args) if isinstance(args, list) else args
    ASH_LOGGER.info(f"Running command: {cmd_str}", extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
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
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=shell,
            encoding=encoding,
            errors=errors,
        )

        try:
            # Stream output
            for line in process.stdout:
                print(line.rstrip())

            # Wait for process to complete
            process.wait()
            return process.returncode
        except Exception as e:
            # The tool is stopped below; what it did is unknown. Not 1, which most
            # scanners accept: see SPAWN_FAILURE_RETURNCODE.
            ASH_LOGGER.error(f"Error running command {cmd_str}: {e}", extra=NO_MARKUP)
            return SPAWN_FAILURE_RETURNCODE
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    except OSError as e:
        ASH_LOGGER.error(spawn_failure_message(cmd_str, e), extra=NO_MARKUP)
        return SPAWN_FAILURE_RETURNCODE
    except Exception as e:
        ASH_LOGGER.error(f"Error running command {cmd_str}: {e}")
        return SPAWN_FAILURE_RETURNCODE
    finally:
        if sandbox_plan is not None:
            sandbox_plan.run_cleanup()


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
    # Resolve the full path to the executable if possible. A refusal is raised in
    # the try below, which logs and re-raises it as it does a failed Popen.
    refused = _resolve_for_spawn(args, cwd, env) if args and not shell else None

    # Log the command being executed
    cmd_str = " ".join(args) if isinstance(args, list) else args
    ASH_LOGGER.verbose(f"Creating process with pipes: {cmd_str}", extra=NO_MARKUP)

    stderr = subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

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
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=text,
            shell=shell,
            encoding=encoding,
            errors=errors,
        )
        if sandbox_plan is not None:
            # The caller owns the process, so the plan's temporary files go when it does.
            weakref.finalize(process, sandbox_plan.run_cleanup)
        return process
    except Exception as e:
        ASH_LOGGER.error(f"Error creating process with pipes: {e}", extra=NO_MARKUP)
        raise
