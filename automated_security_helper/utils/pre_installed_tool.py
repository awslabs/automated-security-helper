# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check whether an executable found on PATH satisfies the requirement a scan needs.

Why this exists
---------------
bandit, checkov and semgrep run through ``uv tool run --from <requirement>``.
When ``uv tool list`` cannot see the tool but an executable of the same name is
on PATH, the scanners logged "Using pre-installed <tool> at <path>" and then
ran through uv anyway. Under ``ASH_OFFLINE`` that is ``uv tool run --offline
--from 'bandit[sarif,toml]>=1.7.8,<2.0.0'``, which has to resolve the
requirement from uv's cache. A container whose tools were installed under one
``$HOME`` and that runs under another sees an empty tool dir and an empty cache,
so the resolve fails and the scanner reports ERROR with uv's resolver output
(issue #520). The binary on PATH was never run.

The fix is to run the binary on PATH when it provably satisfies the requirement,
and to say exactly what is missing when it does not. "Provably" is the point of
this module: a binary named ``bandit`` is not evidence that bandit's SARIF
formatter is installed, because that needs the ``sarif`` extra.

How the check works
-------------------
1. ``<executable> --version`` must exit 0. That proves the binary runs, and it
   is also the first import of the tool from that environment, done once and
   serially, before parallel scans can race to build stevedore's per-user
   entry-point cache (see ``UVToolRunner.get_tool_version``).
2. The executable's Python environment is located: the interpreter its ``#!``
   line names (a console script's own environment), else, for a script another
   interpreter runs or a Windows launcher, a ``python`` next to the resolved
   executable (a venv's ``bin``/``Scripts`` directory, which is where a
   ``uv tool`` symlink leads). A native binary with neither has no environment.
   A program packaged by nixpkgs is neither: see "Nix-wrapped programs" below.
3. ``uv pip install --dry-run --offline --no-cache --no-config --python <env>
   <requirement>`` decides. uv evaluates extras, environment markers and the
   version constraint the same way the scan's ``uv tool run`` would, and with no
   cache and no network it can only answer "Would make no changes" when that
   environment already satisfies the requirement. Nothing is installed. Under
   ``--sandbox`` the dry run is granted that interpreter's environment the way a
   spawn's own program is (``sandbox.scope.also_runs``); uv's own directory alone
   does not hold it.

Rejected alternatives: reading ``importlib.metadata`` in the tool's interpreter
needs marker evaluation (bandit's ``toml`` extra is ``tomli; python_version <
"3.11"``), and ``packaging`` is not guaranteed in a tool venv or a direct
dependency of ASH. Parsing ``bandit -h`` for a ``sarif`` formatter works for one
scanner and none of the others.

Nix-wrapped programs
--------------------
nixpkgs does not install a Python application into a venv. ``bin/<tool>`` is a
bash script from ``makeWrapper`` ending in ``exec -a "$0" ".../.<tool>-wrapped"``,
and that file has a bare interpreter's shebang followed by a line that calls
``site.addsitedir`` once per store path in the tool's closure. There is no
``python`` beside the executable and the interpreter's own site-packages is
empty, so step 2 found nothing and every flake-supplied Python scanner was
``unverifiable``. Callers then kept ``uv tool run --offline``, which ran a PyPI
build instead of the pinned one and only worked when an earlier online probe
had happened to fill uv's cache. On a slow runner the probe timed out halfway
and checkov failed with ``Failed to download numpy``.

For these programs the closure is read from the wrapper itself. Each
``*.dist-info/METADATA`` on its ``addsitedir`` list is copied into a scratch
directory and the dry run is given ``--target <that directory>``, so uv judges
exactly the distributions the program imports, with markers evaluated against
the program's own interpreter. Only METADATA is copied: uv ignores a symlinked
``.dist-info`` directory, and nothing else in it bears on resolution.

Verdicts
--------
``satisfied``: run the executable directly.
``unsatisfied``: it runs, but its environment does not satisfy the requirement;
``detail`` names the missing extras or the version mismatch.
``unverifiable``: no Python environment could be located (a native binary;
a Windows launcher takes the interpreter beside it), uv is absent, or uv
failed for a reason other than resolution. Callers keep their previous behavior for this verdict rather than
guessing in either direction.
"""

from __future__ import annotations

import os
import time
import re
import shutil
import subprocess
import tempfile
import threading
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal, Optional, Sequence, Tuple, Union
from automated_security_helper.utils.error_text import ESCAPE_CODES
from automated_security_helper.utils.output_excerpt import head_and_tail
from automated_security_helper.utils.process_env import environ_for_parsed_output

from automated_security_helper.utils.subprocess_utils import find_executable, spawn_run

Status = Literal["satisfied", "unsatisfied", "unverifiable"]

# A cold import of checkov or semgrep takes seconds; this bounds a hung one.
_VERSION_PROBE_TIMEOUT = 120
_UV_DRY_RUN_TIMEOUT = 60

# uv's wording when a requirement cannot be met. Anything else from a failed
# dry run (bad interpreter path, unreadable environment) is not evidence about
# the requirement, so it yields "unverifiable" instead of "unsatisfied".
_UV_UNSATISFIABLE_MARKERS = (
    "No solution found when resolving",
    "not found in the cache",
    "network was disabled",
)

_INTERPRETER_NAMES = ("python", "python3", "python.exe")

# The two lines nixpkgs generates for a wrapped Python program. makeWrapper ends
# bin/<tool> with the first; wrapPythonPrograms writes the second into the
# wrapped script, right after the shebang (or a coding comment).
_NIX_EXEC_LINE = re.compile(r'^exec -a "\$0" "([^"]+)"', re.MULTILINE)
_NIX_SITEDIR_LIST = re.compile(r"site\.addsitedir\(p, k\), \[([^\]]*)\]")
_QUOTED = re.compile(r"'([^']+)'")
#: Strips escape codes from tool output; public, so other modules read a
#: tool's lines through the same expression rather than keeping copies. The
#: shared pattern (error_text.ESCAPE_CODES): every complete CSI or OSC
#: sequence, not only color. A color-only copy here repeated the cause-match
#: defect the uv mixin's offline explainer fixed -- a non-color code (an
#: erase-line \x1b[2K) inside uv's "No solution found when resolving" phrase
#: turned _dry_run's "unsatisfied" into "unverifiable" -- and a code one side
#: strips and another keeps re-joins a split value in clear.
ANSI_ESCAPE = ESCAPE_CODES
_ANSI_ESCAPE = ANSI_ESCAPE
# A makeWrapper script is a few kB; the addsitedir line of a large closure is
# tens of kB. Neither file needs to be read past this.
_WRAPPER_READ_LIMIT = 1 << 20
# How many ``exec -a "$0"`` hops find_nix_python_environment follows before it
# gives up: a wrapper of a wrapper of a wrapper is the deepest shape seen, and a
# bound keeps two scripts that exec each other from being followed forever.
_NIX_MAX_EXEC_HOPS = 4


@dataclass(frozen=True)
class PreInstalledToolVerdict:
    status: Status
    executable: str
    requirement: Optional[str]
    detail: str
    missing_extras: Tuple[str, ...] = field(default_factory=tuple)
    # True when the executable is a nixpkgs-wrapped Python program, whatever
    # the status. Callers use it to refuse a uv substitute for a pinned tool.
    from_nix: bool = False
    # The first line of the executable's own ``--version`` answer, as uv's
    # version probe reads a tool's, or None when the probe did not run or
    # answered nothing. A caller that runs this copy reports this version.
    version: Optional[str] = None
    # One line about the verdict for callers whose messages reach the results
    # (the jupyter converter's recorded reason): no path, no excerpt of a
    # tool's own output, and no constraint text, since a constraint can be
    # read from the environment. Empty for a satisfied verdict. ``detail``
    # keeps the full story for the log.
    summary: str = ""


#: How long a memoized verdict answers for its copy. The key carries the
#: executable's own mtime, which does not move when the ENVIRONMENT around it
#: does (a package installed into the venv that provides it), and the memo is
#: never cleared in production: an in-process MCP server kept a stale verdict
#: for as long as it lived. A scan's repeated checks of one copy fall well
#: inside this; a later scan in a long-lived process probes again.
_VERDICT_MEMO_SECONDS = 600.0

#: key -> (verdict, the monotonic time it was stored). The key is the copy's
#: resolved path and mtime, the requirement, the caller's values and the uv
#: that judged (or "" when none did).
_verdict_cache: Dict[
    Tuple[str, int, str, Tuple[str, ...], str], Tuple[PreInstalledToolVerdict, float]
] = {}
_verdict_cache_lock = threading.Lock()


def reset_pre_installed_tool_cache() -> None:
    """Forget memoized verdicts (tests, or after installing a tool mid-process)."""
    with _verdict_cache_lock:
        _verdict_cache.clear()


def validate_version_constraint(value: Optional[str]) -> Optional[str]:
    """``value`` as a PEP 440 specifier set, or None or empty; ValueError otherwise.

    A scanner's ``tool_version`` is appended to its package name and handed to
    ``uv tool install``, ``uv tool run --from`` or ``pip install``, so whatever it
    holds decides what gets installed. It is meant to hold ``>=1.2,<2``. A value
    such as ``" @ file:///repo/pkg"`` or ``"[extra] @ https://..."`` would instead
    install a package from a path or URL, and building that package runs its code.
    A config file in the scanned repository can set the option, so the check
    applies wherever the value came from.

    Parsing is ``packaging.specifiers.SpecifierSet``, which refuses ``@``, ``[``,
    ``;`` and anything else that is not a specifier. Two things it accepts are
    refused here as well. ``===`` takes an arbitrary string (``===1.0@file:///x``
    parses), so every clause's version must be a real PEP 440 version, with
    ``.*`` allowed only where PEP 440 allows it. And the result is rebuilt clause by
    clause, so no whitespace or newline from the input reaches the requirement.

    Returns:
        None for None, an empty string for a blank one (no constraint either
        way), otherwise the clauses in the order written, joined by commas, each
        in canonical form (``>= 1.2`` becomes ``>=1.2``).
    """
    if value is None:
        return None
    if not value.strip():
        return ""
    from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
    from packaging.version import InvalidVersion, Version

    message = (
        f"{value!r} is not a version constraint; use PEP 440 specifiers such as "
        "'>=1.2.0,<2.0.0' or '==1.4.1'"
    )
    try:
        SpecifierSet(value)
    except InvalidSpecifier:
        raise ValueError(message) from None
    clauses: List[str] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            specifier = Specifier(part)
            version = specifier.version
            if specifier.operator in ("==", "!=") and version.endswith(".*"):
                version = version[: -len(".*")]
            Version(version)
        except (InvalidSpecifier, InvalidVersion):
            raise ValueError(message) from None
        clauses.append(str(specifier))
    if not clauses:
        raise ValueError(message)
    return ",".join(clauses)


def build_requirement(
    package: str, extras: Sequence[str] | None, version_constraint: str | None
) -> str:
    """The requirement string, built the way ``UVToolRunner.run_tool`` builds ``--from``."""
    base = f"{package}[{','.join(extras)}]" if extras else package
    return f"{base}{version_constraint}" if version_constraint else base


def find_tool_interpreter(executable: str) -> Optional[str]:
    """The Python interpreter whose environment provides ``executable``, if any.

    A console script names its interpreter on its ``#!`` line, and that is the
    environment that provides it. A script another interpreter runs (a shell
    wrapper a package installed into a venv's ``bin``) is provided by the
    environment beside it, so the interpreter in its directory is read, as it is
    for a Windows launcher (an ``.exe`` entry point, whose shebang is embedded
    past the file's start). A native binary with no ``#!`` line and no ``.exe``
    suffix has no interpreter: it used to be judged against whatever python sat
    in its directory, an unrelated environment, and read as unsatisfied.
    """
    resolved = Path(os.path.realpath(executable))
    try:
        with open(resolved, "rb") as handle:
            first_line = handle.readline(1024)
    except OSError:
        return None
    if first_line.startswith(b"#!"):
        parts = first_line[2:].decode("utf-8", errors="replace").split()
        if not parts:
            return None
        interpreter = parts[0]
        if Path(interpreter).name == "env" and len(parts) > 1:
            interpreter = find_executable(parts[1]) or ""
        if "python" in Path(interpreter).name.lower():
            return interpreter if Path(interpreter).is_file() else None
        # Another interpreter's script: the environment beside it, below.
    elif os.name != "nt" and resolved.suffix.lower() != ".exe":
        return None
    for name in _INTERPRETER_NAMES:
        candidate = resolved.parent / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _in_user_site(executable: str) -> bool:
    """Whether ``executable`` sits in the user scripts directory (``pip install
    --user``), the one place a console script's shebang interpreter does not
    describe the environment that provides it."""
    import sysconfig

    try:
        # The platform's own user scheme: "<os.name>_user" is posix_user on
        # every POSIX platform, but a macOS framework build (python.org,
        # Homebrew) installs user scripts under osx_framework_user, below
        # ~/Library/Python, and a copy there was judged against the system
        # interpreter's environment.
        scripts = sysconfig.get_path("scripts", sysconfig.get_preferred_scheme("user"))
    except (KeyError, ValueError):
        return False
    if not scripts:
        return False
    try:
        return Path(os.path.realpath(executable)).parent == Path(
            os.path.realpath(scripts)
        )
    except (OSError, ValueError):
        return False


def _read_head(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            return handle.read(_WRAPPER_READ_LIMIT).decode("utf-8", errors="replace")
    except OSError:
        return None


def _python_shebang(text: str) -> Optional[str]:
    first_line = text.split("\n", 1)[0]
    if not first_line.startswith("#!"):
        return None
    parts = first_line[2:].split()
    if not parts or "python" not in Path(parts[0]).name.lower():
        return None
    return parts[0] if Path(parts[0]).is_file() else None


def find_nix_python_environment(
    executable: str,
) -> Optional[Tuple[str, Tuple[str, ...]]]:
    """``(interpreter, site_dirs)`` for a nixpkgs-wrapped Python program, else None.

    Accepts both shapes nixpkgs produces: the makeWrapper script that execs
    ``.<tool>-wrapped``, and a wrapped script installed directly as ``bin/<tool>``
    (no makeWrapper arguments). See "Nix-wrapped programs" in the module docstring.
    """
    resolved = Path(os.path.realpath(executable))
    text = _read_head(resolved)
    if text is None:
        return None

    # A program can be wrapped more than once (a makeWrapper around a
    # makeWrapper, as a flake that adds an environment variable to a packaged
    # tool produces): each hop's script execs the next. Only one hop used to be
    # followed, so a twice-wrapped tool was "unverifiable", and offline a Nix
    # tool that cannot be verified is refused.
    hops = 0
    while _python_shebang(text) is None:
        match = _NIX_EXEC_LINE.search(text)
        if match is None or hops >= _NIX_MAX_EXEC_HOPS:
            return None
        text = _read_head(Path(os.path.realpath(match.group(1))))
        if text is None:
            return None
        hops += 1

    interpreter = _python_shebang(text)
    sitedirs = _NIX_SITEDIR_LIST.search(text)
    if interpreter is None or sitedirs is None:
        return None
    site_dirs = tuple(_QUOTED.findall(sitedirs.group(1)))
    return (interpreter, site_dirs) if site_dirs else None


def _stage_nix_metadata(site_dirs: Sequence[str], target: Path) -> int:
    """Copy each distribution's METADATA from ``site_dirs`` into ``target``.

    A distribution seen earlier on the list is skipped, so ``sys.path`` order
    decides, as it does for the program's own imports. Seen means the same
    distribution NAME (PEP 503 normalized): two versions of one distribution on
    the list, or two spellings of its name, are one import, and staging both
    gave uv two candidates for one requirement. Returns the number staged.
    """
    staged = 0
    seen: set = set()
    for site_dir in site_dirs:
        try:
            entries = sorted(Path(site_dir).glob("*.dist-info"))
        except OSError:
            continue
        for dist_info in entries:
            metadata = dist_info / "METADATA"
            destination = target / dist_info.name
            if destination.exists() or not metadata.is_file():
                continue
            name = _distribution_name(dist_info, metadata)
            if name in seen:
                continue
            destination.mkdir()
            shutil.copyfile(metadata, destination / "METADATA")
            seen.add(name)
            staged += 1
    return staged


def _distribution_name(dist_info: Path, metadata: Path) -> str:
    """The PEP 503 name of the distribution ``dist_info`` describes.

    Read from METADATA's ``Name`` header, where the name is spelled whole. The
    directory's stem is the fallback for a METADATA with no such header: its
    name part is cut from the version at the first ``-``, which misreads a
    name that carries one itself (``foo-bar-2.0.dist-info`` read as ``foo``),
    so a second version of a distribution under that spelling was staged as
    another distribution beside the first.
    """
    from packaging.utils import canonicalize_name

    try:
        with metadata.open("rb") as handle:
            for raw in handle:
                line = raw.decode("utf-8", "replace")
                if not line.strip():
                    break
                if line[:5].lower() == "name:":
                    return canonicalize_name(line[5:].strip())
    except OSError:
        pass
    stem = dist_info.name[: -len(".dist-info")]
    return canonicalize_name(stem.split("-", 1)[0])


@dataclass(frozen=True)
class _ProbeFailure:
    """A probe that could not run, with the spawn's own error.

    The verdict's detail carries ``error``: "could not execute" alone read the
    same for a too-long argument list, a busy text file, an exhausted file table
    and an out-of-memory spawn, and the operator could not tell which.
    """

    error: str


#: What ``_run`` and ``_probe`` answer: the probe's result, a failure to run it
#: (with the cause), or None from an older stub that knows only "did not run".
_ProbeAnswer = Union[subprocess.CompletedProcess, _ProbeFailure, None]


def _did_not_run(answer: _ProbeAnswer) -> bool:
    return answer is None or isinstance(answer, _ProbeFailure)


def _probe_cause(answer: _ProbeAnswer) -> str:
    """The failure's own words after the caller's sentence, or nothing."""
    if isinstance(answer, _ProbeFailure) and answer.error:
        return f": {answer.error}"
    return ""


def _run(command: List[str], timeout: int) -> _ProbeAnswer:
    """Run one probe in an empty directory; a ``_ProbeFailure`` when it could not run.

    ASH is usually started in the repository it scans, and a tool reads modules
    and configuration from where it starts, so a probe does not start there.
    Under a scanner sandbox the plan gives the probe its own directory, and none
    is made here.

    Raises:
        SandboxUnavailable: The active scanner sandbox scope refused the spawn. The
            probe never ran, which says nothing about the tool, so it is raised to
            ``verify_pre_installed_tool`` rather than read as a tool that does not
            run.
    """
    from automated_security_helper.utils.sandbox.policy import SandboxUnavailable
    from automated_security_helper.utils.sandbox.scope import active_scope

    if active_scope() is not None:
        return _probe(command, timeout, None)
    try:
        with tempfile.TemporaryDirectory(prefix="ash-probe-cwd-") as empty:
            return _probe(command, timeout, empty)
    except SandboxUnavailable:
        raise
    except OSError as error:
        # No empty directory to start it in: it is not started from anywhere else.
        return _ProbeFailure(
            f"no empty directory to start it in ({type(error).__name__}: {error})"
        )


def _probe(command: List[str], timeout: int, cwd: Optional[str]) -> _ProbeAnswer:
    """``command`` run with its output read, from ``cwd`` when there is one.

    ``command``'s output is read here, so it runs without the caller's display
    variables (``environ_for_parsed_output``). Only a given ``cwd`` is passed on,
    so a call without one reaches the spawn with the arguments it always had.
    """
    from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

    where = {} if cwd is None else {"cwd": cwd}
    try:
        return spawn_run(  # nosec B603 - list args; executable resolved from PATH by the caller
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=environ_for_parsed_output(),
            **where,
        )
    except SandboxUnavailable:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        # The error's own words ride to the verdict: a timeout, E2BIG, ETXTBSY,
        # EMFILE and ENOMEM used to read alike as "could not execute".
        return _ProbeFailure(f"{type(error).__name__}: {error}")


#: uv's warning for an extra the installed package does not declare, as a
#: substring of its flowed output: "The package `bandit==1.7.0` does not have an
#: extra named `sarif`".
_UV_UNKNOWN_EXTRA_MARKER = "does not have an extra named"
#: The same warning with the backticked package fragment captured whole: uv
#: prints it for every package in the resolution, so the check has to tell the
#: requested package's missing extra from a transitive dependency's. The fragment
#: is read by ``_names_in_fragment``, not by a fixed ``name==version`` shape, so a
#: spelling with another operator, an ``@ url`` or a ``name-version`` join still
#: names its package.
_UV_UNKNOWN_EXTRA_PATTERN = r"The package `([^`]+)` " + _UV_UNKNOWN_EXTRA_MARKER
#: A distribution name, as PEP 503 spells it, at the head of a fragment.
_NAME_HEAD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _names_in_fragment(fragment: str) -> frozenset:
    """The canonical package names uv's backticked fragment can be naming.

    ``bandit==1.7.0``, ``bandit>=1.7``, ``bandit @ file:///x`` and ``bandit[sarif]``
    parse as requirements and name ``bandit``. A ``name-version`` join (``bandit-1.7.0``)
    parses too, as the name ``bandit-1.7.0``, so the head before a ``-<digit>`` is
    offered as well; and a fragment the parser refuses falls back to its leading
    name-shaped run. Empty when nothing in the fragment reads as a name.
    """
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name

    names = set()
    try:
        names.add(canonicalize_name(Requirement(fragment).name))
    except (InvalidRequirement, ValueError):
        pass
    head = _NAME_HEAD.match(fragment)
    if head is not None:
        names.add(canonicalize_name(head.group(0)))
        joined = re.match(r"(.+?)-\d", head.group(0))
        if joined is not None:
            names.add(canonicalize_name(joined.group(1)))
    return frozenset(names)


def _requested_package_lacks_an_extra(requirement: str, flowed: str) -> bool:
    """Whether uv's unknown-extra warning in ``flowed`` names the package that
    ``requirement`` asks for.

    uv prints the warning for every package in the resolution, a transitive
    dependency included (one asking for ``urllib3[secure]`` with urllib3 2.x
    installed), and such a copy is satisfied all the same: only the requested
    package's own missing extra means the copy never provides what the extra
    brings. The bare marker matched any package's warning, so a satisfied copy
    read as unsatisfied and, offline, was refused in favor of ``uv tool run
    --offline``, the fallback this module exists to prevent.

    Fail-closed on wording drift: when the marker is present but no backticked
    fragment reads as a package (uv changed the line's shape), the answer is the
    bare marker's, unsatisfied, never "satisfied" by a pattern that saw nothing.
    """
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name

    if _UV_UNKNOWN_EXTRA_MARKER not in flowed:
        return False
    try:
        requested = canonicalize_name(Requirement(requirement).name)
    except (InvalidRequirement, ValueError):
        # Not a requirement the parser reads (a URL, a path): the marker's own
        # reading, as before.
        return True
    named = [
        _names_in_fragment(match.group(1))
        for match in re.finditer(_UV_UNKNOWN_EXTRA_PATTERN, flowed)
    ]
    readable = [names for names in named if names]
    if not readable:
        return True
    return any(requested in names for names in readable)


def _dry_run(
    uv: str,
    interpreter: str,
    requirement: str,
    target: Optional[str] = None,
    no_deps: bool = False,
) -> Tuple[Status, str]:
    command = [
        uv,
        "pip",
        "install",
        "--dry-run",
        "--offline",
        "--no-cache",
        "--no-config",
        # A tool installed into a system interpreter marked EXTERNALLY-MANAGED
        # (PEP 668: Debian's and Fedora's python3) is refused by uv before it
        # resolves anything, so such a copy could never verify. The dry run
        # changes nothing, so the refusal protects nothing here; the flag lets
        # the resolve run, and the verdict still comes from what resolves.
        "--break-system-packages",
        "--python",
        interpreter,
    ]
    if target is not None:
        command += ["--target", target]
    if no_deps:
        command.append("--no-deps")
    from automated_security_helper.utils.sandbox.scope import (
        also_runs,
        reads_directory,
    )

    # uv runs the interpreter to inspect it, so under --sandbox the spawn needs the
    # interpreter's environment as well as uv's own directory. With --target it
    # reads what is installed in that directory, the staged Nix metadata under
    # TMPDIR, which neither grant reaches: that one directory is granted too.
    with ExitStack() as grants:
        grants.enter_context(also_runs(interpreter))
        if target is not None:
            try:
                grants.enter_context(reads_directory(target))
            except ValueError as refusal:
                # The staging directory resolves to one the sandbox never grants
                # (TMPDIR is a home directory, so the directory sits directly in
                # it). The check cannot run under the sandbox: it answers
                # "unverifiable", as a staging that could not be done does, not
                # with an exception out of the scanner's dependency check.
                reason = (
                    f"could not grant uv its staging directory to check "
                    f"{requirement!r}: {refusal}"
                )
                return "unverifiable", reason
        result = _run(command + [requirement], _UV_DRY_RUN_TIMEOUT)
    if _did_not_run(result):
        return (
            "unverifiable",
            f"could not run uv to check {requirement!r}{_probe_cause(result)}",
        )
    # uv colors its output into a pipe when FORCE_COLOR or CLICOLOR_FORCE is
    # set, and a terminal-aware uv can also write non-color codes: the escapes
    # would otherwise land in the reason a user reads, and a non-color code
    # inside a marker phrase would defeat the cause match below (the shared
    # pattern strips every complete CSI or OSC sequence, see ANSI_ESCAPE).
    # NOT stripped: the detail is redacted downstream (the unverifiable arm,
    # _first_cause), and a whole-text strip here eats the last character of a
    # value that ends uv's text -- a form feed, say -- so no whole spelling
    # matches and the fragment prints. The strip belongs after the redaction.
    output = _ANSI_ESCAPE.sub("", f"{result.stdout or ''}\n{result.stderr or ''}")
    # Matched with every run of whitespace as one space, so a message wrapped
    # across lines still matches.
    flowed = " ".join(output.split())
    if _requested_package_lacks_an_extra(requirement, flowed):
        # The installed version declares no extra of a requested name (it
        # predates the extra): uv warns, installs nothing for it and reports
        # no changes, so the "satisfied" reading below would run a copy that
        # never provides what the extra brings. Matched for the requested
        # package alone: the same warning about a transitive dependency's
        # extra says nothing about this copy.
        return "unsatisfied", output
    if result.returncode == 0 and "Would make no changes" in flowed:
        return "satisfied", ""
    if result.returncode == 0 or any(m in flowed for m in _UV_UNSATISFIABLE_MARKERS):
        return "unsatisfied", output
    return "unverifiable", output


# uv's tree glyphs, taken only as a line PREFIX; trailing whitespace is
# stripped separately. A prefix run must be followed by whitespace or the
# line's end, so a redacted placeholder, or a word that merely starts with
# "-", keeps itself whole. The strip runs AFTER the redaction (see
# ``_first_cause``), so there is no value left for it to respell.
_TREE_GLYPH_PREFIX = re.compile(r"^\s*(?:[╰─▶`|>\-]+(?:\s+|$))?")


def _first_cause(
    output: str, values: Sequence[str], requirement: str, package: str
) -> str:
    """uv's first "Because ..." clause, unwrapped, or its first line.

    The text is REDACTED before it is unwrapped: uv wraps long clauses at the
    terminal's width, so an env-read value can span the wrap, and flowing the
    raw lines into one text first (every line break becomes a space) rewrites
    the value's spelling before any redaction layer can match it whole. The
    layer is the uv one ``_verify``'s own probe excerpt uses, with the probe's
    plugin-built input, so a respelled env-read version is hidden here too.
    That layer runs on the RAW text, nothing stripped first: a both-edges
    glyph strip before it ate a value's own edge character ("-" starts or
    ends base64url tokens) at a line edge, and ``splitlines`` dropped a
    value's trailing FF the same way, so the whole-spelling match missed.
    The layer itself normalizes each value's whitespace respelling back to
    the value's own spelling (uv wraps a clause at a SPACE with an indented
    continuation) and then decides what to hide under its own rules (the
    under-floor pass-through included).

    Only after the redaction are uv's tree glyphs removed, and only as a
    line PREFIX plus trailing whitespace: a both-edges strip at this point
    ate the closing ">" of a line-ending "<argument N not shown>"
    placeholder.
    """
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        output, values, plugin_inputs=(requirement,), tool_name=package, limit=None
    )
    stripped = "\n".join(
        _TREE_GLYPH_PREFIX.sub("", line).rstrip() for line in shown.splitlines()
    )
    text = " ".join(stripped.split())
    match = re.search(r"Because (.+?)(?:, we can conclude|\.\s|$)", text)
    if match:
        return "because " + match.group(1).strip()
    lines = [line for line in stripped.splitlines() if line.strip()]
    return lines[0].strip() if lines else "uv reported it unsatisfiable"


def verify_pre_installed_tool(
    executable: str,
    package: str,
    extras: Sequence[str] | None = None,
    version_constraint: str | None = None,
    uv_executable: str | None = None,
    values: Sequence[str] = (),
) -> PreInstalledToolVerdict:
    """Decide whether ``executable`` satisfies ``package[extras]version_constraint``.

    Memoized per (resolved path, file mtime, requirement, values, uv path) for
    ``_VERDICT_MEMO_SECONDS``: scanners call their dependency check several
    times per run, and the ``--version`` probe of a large tool takes seconds. ``values`` is the caller's env-read
    set: the probe's stderr excerpt is redacted with it BEFORE it is cut, so
    a cut cannot split a value and leave a fragment the downstream
    whole-spelling redaction misses; it is part of the memo key because the
    cached detail embeds the redaction. A check the scanner sandbox refused is
    ``unverifiable`` with the refusal as its detail, and is not memoized: it
    never ran, and a later check in another scope may.

    Checks of one copy that run at the same time share one probe: the others wait
    on a per-key lock and answer from the memo the first probe leaves. A check the
    sandbox refused leaves nothing in the memo, so the next one probes for itself.
    """
    from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

    # Normalized ONCE: the memo key and _verify both read it, and a second
    # tuple() of a generator argument is empty -- the key then recorded the
    # values while the probe excerpt was cached unredacted under it.
    values = tuple(values)
    try:
        canonical = validate_version_constraint(version_constraint)
    except ValueError as error:
        # Never handed to the dry run below: uv resolves whatever the requirement
        # names, and a path or URL would be built to read its metadata.
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            None,
            str(error),
            summary="the version constraint is not a valid PEP 440 specifier",
        )
    # The validated form, not the raw value: the validator accepts a constraint
    # it has to normalize (an empty clause from a trailing comma, spaces inside
    # a clause), and the raw spelling then reached uv malformed.
    version_constraint = canonical or None
    requirement = build_requirement(package, extras, version_constraint)
    resolved = os.path.realpath(executable)
    try:
        mtime = os.stat(resolved).st_mtime_ns
    except OSError:
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            requirement,
            f"{executable} does not exist",
            summary="the copy does not exist",
        )

    # The uv that judges is part of the question: a verdict made with one uv
    # (or with none, "unverifiable") was served to a caller passing another.
    if uv_executable is None:
        from automated_security_helper.utils.uv_tool_runner import find_uv_or_none

        uv_executable = find_uv_or_none()

    key = (resolved, mtime, requirement, tuple(values), uv_executable or "")
    answered = _answer_without_a_probe(key)
    if answered is not None:
        return answered

    # One probe per key at a time. Checks of one copy that arrive together (the
    # project instances of one scanner in a workspace scan) would each start their
    # own probe, up to _VERSION_PROBE_TIMEOUT long, and the memo is written only
    # when a probe ends. They park here instead, and read the memo again once the
    # first probe has stored its answer. The lock's key is the hash of the memo
    # key, so no env-read value is spelled in it; the "verdict::" prefix keeps it
    # apart from the runner's own "version::" and "command::" probe locks, which
    # are plain non-reentrant locks in the same table.
    from automated_security_helper.utils.uv_tool_runner import (
        _get_or_create_probe_lock,
        _probe_lock_held,
        _uv_tool_runner_cache_lock,
    )

    # The table wants the runner's coarse lock for the get-or-create, and the probe
    # lock must stay bound to a local until it is acquired (STRONG-REF CONTRACT,
    # _get_or_create_probe_lock). The coarse lock is not held across the probe.
    with _uv_tool_runner_cache_lock:
        probe_lock = _get_or_create_probe_lock(f"verdict::{hash(key)}")
    with _probe_lock_held(probe_lock):
        answered = _answer_without_a_probe(key)
        if answered is not None:
            return answered
        try:
            verdict = _verify(
                executable,
                package,
                list(extras or []),
                version_constraint,
                requirement,
                uv_executable,
                tuple(values),
            )
        except SandboxUnavailable as refusal:
            return PreInstalledToolVerdict(
                "unverifiable",
                executable,
                requirement,
                f"the scanner sandbox refused the check: {refusal}",
                # The field contract reserves an empty summary for a satisfied
                # verdict; a caller recording the summary (the jupyter
                # converter's reason) named no cause for this one.
                summary="the scanner sandbox refused the check",
            )

        with _verdict_cache_lock:
            _verdict_cache[key] = (verdict, time.monotonic())
        return verdict


def _answer_without_a_probe(
    key: Tuple[str, int, str, Tuple[str, ...], str],
) -> Optional[PreInstalledToolVerdict]:
    """The memoized verdict for ``key``, or None when the copy has to be probed:
    nothing remembered, or a verdict older than ``_VERDICT_MEMO_SECONDS``."""
    with _verdict_cache_lock:
        remembered = _verdict_cache.get(key)
        if remembered is None:
            return None
        verdict, stored_at = remembered
        if time.monotonic() - stored_at > _VERDICT_MEMO_SECONDS:
            _verdict_cache.pop(key, None)
            return None
        return verdict


def _verify(
    executable: str,
    package: str,
    extras: List[str],
    version_constraint: Optional[str],
    requirement: str,
    uv_executable: Optional[str],
    values: Tuple[str, ...] = (),
) -> PreInstalledToolVerdict:
    probe = _run([executable, "--version"], _VERSION_PROBE_TIMEOUT)
    if _did_not_run(probe):
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            requirement,
            f"could not execute {executable}{_probe_cause(probe)}",
            summary="the copy could not be executed",
        )
    if probe.returncode != 0:
        from automated_security_helper.utils.uv_tool_runner import shown_uv_output

        # REDACTED BEFORE the excerpt is cut: a cut can split a quoted
        # env-read value, and the downstream whole-spelling redaction cannot
        # match the fragment. With the uv input layer: the probed copy is a
        # uv-managed tool's, and it can print an env-read version in another
        # spelling ("9.9.9-RC777" as "9.9.9rc777") that the neutral layer's
        # as-written match misses; the requirement is the probe's
        # plugin-built input. For a non-uv copy the extra forms only hide
        # more -- the accepted cost of one layer for every verdict.
        # Stripped only AFTER the redaction: a whole-text strip first eats
        # the last character of a value ending the probe's text (a form
        # feed, say), and the fragment then misses the whole-spelling match.
        excerpt = head_and_tail(
            shown_uv_output(
                probe.stderr or probe.stdout or "",
                values,
                plugin_inputs=(requirement,),
                tool_name=package,
                limit=None,
            ).strip(),
            500,
        )
        return PreInstalledToolVerdict(
            "unsatisfied",
            executable,
            requirement,
            f"`{executable} --version` exited {probe.returncode}: {excerpt}",
            summary=f"its --version probe exited {probe.returncode}",
        )
    # The copy's own version: the answer's first non-blank line, as uv's probe
    # reads one. Redacted whole BEFORE that cut, through the same uv layer the
    # failed probe's excerpt gets: the probed copy can be a uv-managed tool's,
    # and --version output is exactly where it prints an env-read version in
    # another spelling ("9.9.9-RC777" as "9.9.9rc777") that the neutral
    # as-written match misses. An env-read value holding a line break would
    # also leave its first half in the carried version otherwise.
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown_answer = shown_uv_output(
        probe.stdout or "",
        values,
        plugin_inputs=(requirement,),
        tool_name=package,
        limit=None,
    )
    version = next(
        (line.strip() for line in shown_answer.splitlines() if line.strip()),
        None,
    )

    if uv_executable is None:
        # The uv installed with ASH first, then PATH; see find_uv_or_none.
        # Reached only by a caller that did not resolve uv itself: the
        # memoizing caller (verify_pre_installed_tool) resolves it before
        # building its key and passes it here, so the key and the judgment
        # there share one uv.
        from automated_security_helper.utils.uv_tool_runner import find_uv_or_none

        uv_executable = find_uv_or_none()
    uv = uv_executable

    nix_environment = find_nix_python_environment(executable)
    if nix_environment is not None:
        if uv is None:
            return PreInstalledToolVerdict(
                "unverifiable",
                executable,
                requirement,
                "no uv was found beside ASH's interpreter or on PATH",
                from_nix=True,
                version=version,
                summary="no uv was found beside ASH's interpreter or on PATH",
            )
        nix_interpreter, site_dirs = nix_environment
        from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

        try:
            with tempfile.TemporaryDirectory(prefix="ash-nix-metadata-") as target:
                if _stage_nix_metadata(site_dirs, Path(target)) == 0:
                    return PreInstalledToolVerdict(
                        "unverifiable",
                        executable,
                        requirement,
                        f"{executable} is a Nix-wrapped Python program, but no "
                        "distribution metadata was found on its site-packages paths",
                        from_nix=True,
                        version=version,
                        summary="it is a Nix-wrapped Python program with no "
                        "distribution metadata on its site-packages paths",
                    )
                return _judge(
                    executable,
                    package,
                    extras,
                    version_constraint,
                    requirement,
                    uv,
                    nix_interpreter,
                    target,
                    f"its Nix environment ({nix_interpreter}, {len(site_dirs)} store paths)",
                    version,
                    values=values,
                )
        except SandboxUnavailable:
            # The scope's refusal, handled by verify_pre_installed_tool.
            raise
        except OSError as error:
            # The staging (the temporary directory, a mkdir, a copy of one
            # METADATA) could not be done: a verdict, not an exception out of
            # the scanner's dependency check.
            return PreInstalledToolVerdict(
                "unverifiable",
                executable,
                requirement,
                f"{executable} is a Nix-wrapped Python program whose distribution "
                f"metadata could not be staged for uv: {error}",
                from_nix=True,
                version=version,
                summary="its Nix environment's distribution metadata could not "
                "be staged for uv",
            )

    interpreter = find_tool_interpreter(executable)
    if interpreter is None:
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            requirement,
            f"could not locate the Python environment that provides {executable}",
            version=version,
            summary="no Python environment could be located for the copy",
        )

    if _in_user_site(executable):
        # ``pip install --user`` puts the script in the user scripts directory
        # and its packages in the user site, which the interpreter's shebang
        # does not name and uv's dry run does not inspect: it judges the
        # interpreter's own environment, where the package is absent, so such a
        # copy read as unsatisfied and, offline, was refused. It cannot be
        # judged from here, which is what "unverifiable" says.
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            requirement,
            f"{executable} is installed in the user site (pip install --user), "
            "whose packages uv's dry run of the interpreter's own environment "
            "does not inspect",
            version=version,
            summary="the copy is installed in the user site, which cannot be inspected",
        )

    if uv is None:
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            requirement,
            "no uv was found beside ASH's interpreter or on PATH",
            version=version,
            summary="no uv was found beside ASH's interpreter or on PATH",
        )

    return _judge(
        executable,
        package,
        extras,
        version_constraint,
        requirement,
        uv,
        interpreter,
        None,
        f"its environment ({interpreter})",
        version,
        values=values,
    )


def _judge(
    executable: str,
    package: str,
    extras: List[str],
    version_constraint: Optional[str],
    requirement: str,
    uv: str,
    interpreter: str,
    target: Optional[str],
    environment: str,
    version: Optional[str] = None,
    *,
    values: Sequence[str],
) -> PreInstalledToolVerdict:
    from_nix = target is not None  # --target is only ever a staged Nix closure
    status, output = _dry_run(uv, interpreter, requirement, target)
    if status != "unsatisfied":
        # The unverifiable arm's detail is uv's own output, never routed
        # through the cause extraction, and it reaches the dependency reason
        # and the through-uv log line. It takes the same uv redaction layer
        # (which normalizes uv's wrap) before it is returned: the memo's
        # contract that the cached detail embeds the redaction covers this
        # arm too. The satisfied arm's output is empty, so this is free there.
        from automated_security_helper.utils.uv_tool_runner import shown_uv_output

        return PreInstalledToolVerdict(
            status,
            executable,
            requirement,
            # Stripped only AFTER the redaction: _dry_run keeps its text's
            # edges so a value ending the text still matches whole.
            shown_uv_output(
                output, values, plugin_inputs=(requirement,), tool_name=package
            ).strip(),
            from_nix=from_nix,
            version=version,
            summary=(
                ""
                if status == "satisfied"
                else "uv could not verify the requirement in its environment"
            ),
        )

    # Name the cause. One probe per extra, plus one for the bare package with the
    # constraint, only on this failure path. The constraint probe is --no-deps:
    # it asks about the package's own version, and with dependencies included a
    # gap further down the tree would be misreported as a version mismatch.
    # The extras are probed only when the bare package resolves: each extra's
    # probe resolves the whole tree, so a dependency the environment lacks (or
    # the package's own absence) read as every requested extra missing, and the
    # real cause, the resolver's own, was suppressed below.
    package_resolves = not extras or (
        _dry_run(uv, interpreter, package, target)[0] != "unsatisfied"
    )
    missing = (
        tuple(
            extra
            for extra in extras
            if _dry_run(
                uv, interpreter, build_requirement(package, [extra], None), target
            )[0]
            == "unsatisfied"
        )
        if package_resolves
        else ()
    )
    reasons = []
    # The summary's parallel parts name no constraint text and no path. They
    # do name the missing extras: those are the caller's own requirement's
    # words, which the reason that carries the summary already shows, and a
    # refusal that says only "missing extra" tells the reader nothing the
    # remedy does not have to repeat.
    summary_parts = []
    if missing:
        named_missing = (
            f"missing extra{'s' if len(missing) > 1 else ''}: {', '.join(missing)}"
        )
        reasons.append(named_missing)
        summary_parts.append(named_missing)
    if (
        version_constraint
        and _dry_run(
            uv,
            interpreter,
            build_requirement(package, None, version_constraint),
            target,
            no_deps=True,
        )[0]
        == "unsatisfied"
    ):
        reasons.append(f"installed {package} does not satisfy {version_constraint!r}")
        summary_parts.append(
            "the installed package does not satisfy the version constraint"
        )
    if not reasons:
        reasons.append(_first_cause(output, values, requirement, package))
        summary_parts.append("the requirement does not resolve in its environment")
    return PreInstalledToolVerdict(
        "unsatisfied",
        executable,
        requirement,
        f"{environment} does not satisfy {requirement!r}: " + "; ".join(reasons),
        missing,
        from_nix=from_nix,
        version=version,
        summary="; ".join(summary_parts),
    )
