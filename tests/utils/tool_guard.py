"""Recording stand-ins for scanner tools, placed first on PATH, and a spawn recorder.

A unit test that reaches a real scanner tool depends on the host it runs on: whether
semgrep or checkov is installed, whether ``uv tool run`` can reach PyPI, and what the
tool writes under HOME (``~/.config/.semgrep``, ``~/.cache/checkov``). A stand-in
records the arguments it was started with and exits 1, so a test can assert that
nothing started a tool, and a test that starts one fails on the host it runs on
instead of downloading something there.

One call is answered instead: the tool locator's version probe, ``[<the stand-in's
own path>, "--version"]``, which it makes once per binary before running the tool.
The stand-in prints ``<tool> <version>`` (``STAND_IN_VERSIONS``) and exits 0, and
the call is listed in ``ToolGuard.probes``, not as a start. A second probe of the
same path in one test, a ``--version`` by bare name, or ``--version`` with anything
after it is a start.

Two layers, because each misses what the other catches:

- Stand-ins: ASH resolves tools by name through ``shutil.which``
  (``utils/subprocess_utils.find_executable``), so a stand-in first on PATH answers
  for each name in ``GUARDED_TOOLS``. That lookup is cached per process, so the
  caches are cleared when the guard goes in and again when it comes out: a cached
  real path would bypass the guard, and a cached stand-in would leak into the next
  test. On Windows the lookup tries ``<name>.exe`` over the whole PATH before
  ``<name>.bat``, so a host ``.exe`` later on PATH would win; the guard makes a
  guarded name resolve to its stand-in there. uv is looked up in the copy installed
  with ASH before PATH (``uv_tool_runner.bundled_uv_executable``), so while uv is
  guarded that lookup answers nothing and PATH's stand-in is found.
- A spawn recorder: an audit hook (``sys.addaudithook``) sees every process start in
  this interpreter, so a tool started by an absolute path, under a name not on the
  list, or by a bare name Windows resolves to an ``.exe`` is recorded too. A bare
  name is looked up on the PATH the child is given, and a start that reached a
  stand-in but left no line in its log is recorded as well. ``ToolGuard.started``
  lists both.

``ToolGuard.started`` is every start but ASH's workers and the real git, the file git
resolves to on PATH when the guard goes in (``runs_git``). ``ToolGuard.tool_starts``
is the part of it that ran a guarded tool or asked a stand-in to run one, which is what
tests/unit/conftest.py fails a unit test on. A start that reached no stand-in is one of
those when the file it runs is a guarded tool outside the test's own directories
(``own_directories``), judged by its name and by the name of the file it links to, so
``/usr/local/bin/ferret-scan`` and a uv found on a PATH that skips the stand-ins count
and a test's fake ``uv`` under tmp_path does not; and when it is a Python running a
guarded tool's module (``GUARDED_MODULES``), as ``python -m uv`` does.

Child processes are not audited, so a start of this interpreter is recorded unless it
is one of ASH's two worker children (``_is_an_ash_worker``): ``python -m uv``, ``-m
pip`` or a ``-c`` child can start a tool by its own path. A start through ASH's Landlock wrapper
is judged by the command after its ``--``, a start through ``env`` by the command it
runs (``_through_env``), and a fork is recorded, because what the forked child
starts is recorded only in the child. Some routes raise no process event at all:
multiprocessing's spawn and forkserver starts, recorded by wrapping
``multiprocessing.util.spawnv_passfds``; a process a running forkserver forks,
recorded by wrapping ``multiprocessing.forkserver.connect_to_new_process``; a direct
``_posixsubprocess.fork_exec``, recorded by wrapping it; and a C library's
``system()``, ``exec*()``, ``clone`` or ``wordexp()`` (``C_PROCESS_FUNCTIONS``)
called through ctypes, recorded when it is looked up.

Not seen, so not recorded: a C function pointer, or a ``fork_exec``, looked up before
the guard went in; a function called through cffi, whose lookups raise no event; a
start in a forked or forkserver child, and what a started process starts in turn,
except a bare tool name it looks up on the PATH it inherited, which reaches a
stand-in; a launcher other than ``env`` (``nice``, ``timeout``, ``xargs`` and the
like) running a tool by its path; and ``<interpreter> -m uv`` through a link whose
name does not start with ``python``. git is let through by the file it runs
(``runs_git``) in ``ToolGuard.started``; only ``popen_runs_only_git`` also reads
what git's configuration tells it to run.

Audit hooks cannot be removed, so the hook is installed once per process and records
only while a guard is installed (``monkeypatch`` restores the "none" state).
"""

from __future__ import annotations

import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path

from automated_security_helper.utils.tool_downloads import (
    CFN_NAG_GEM_VERSION,
    TOOL_VERSIONS,
)

#: The tools ASH's built-in scanners, converters and their version probes start by name.
GUARDED_TOOLS = (
    "uv",
    "uvx",
    "bandit",
    "checkov",
    "detect-secrets",
    "semgrep",
    "opengrep",
    "grype",
    "syft",
    "trivy",
    "npm",
    "yarn",
    "pnpm",
    "node",
    "cfn_nag_scan",
    "gem",
    "jupyter",
    "jupyter-nbconvert",
    "ferret-scan",
    "snyk",
)

#: What a stand-in prints for a version probe, ``<tool> <version>``. A pinned tool
#: prints its pin (``tool_downloads.TOOL_VERSIONS``, read here so it moves with the
#: pins; cfn-nag's gem version for cfn_nag_scan). A tool with no pin prints a version
#: inside the tool locator's default range for it (``_default_constraint``, which
#: reads ``tool_downloads.TOOL_VERSION_CONSTRAINTS``): ferret-scan ">=2.4.5,<2.6.0",
#: node ">=18.0.0". The rest have no default range, so any version is used.
STAND_IN_VERSIONS: dict[str, str] = {
    **{name: version.removeprefix("v") for name, version in TOOL_VERSIONS.items()},
    "uvx": TOOL_VERSIONS["uv"],
    "cfn_nag_scan": CFN_NAG_GEM_VERSION,
    "ferret-scan": "2.5.0",
    "node": "20.0.0",
    "snyk": "1.1300.0",
}

#: The version a guarded tool with no entry above prints.
UNRANGED_VERSION = "1.0.0"


def stand_in_version(name: str) -> str:
    """The version the stand-in for *name* prints when probed."""
    return STAND_IN_VERSIONS.get(name, UNRANGED_VERSION)


def real_git() -> str | None:
    """The real path of the git on this process's PATH, normalized, or None.

    ASH's scan set asks git which files a tree tracks, so a guarded test may start
    git: this git, and nothing else named git (``runs_git``).
    """
    found = shutil.which("git")
    return os.path.normcase(os.path.realpath(found)) if found else None


#: The module ASH's detect-secrets scan runs in, as ``python -m`` (its scanner's
#: ``_worker_command``).
DETECT_SECRETS_WORKER = "automated_security_helper.utils.detect_secrets_worker"

#: The guarded tools a Python runs as ``python -m <module>``, by the module's top-level
#: package: ``python -m uv`` finds uv's binary and runs it, and the Python tools run
#: from their packages.
GUARDED_MODULES = {
    "uv": "uv",
    "bandit": "bandit",
    "checkov": "checkov",
    "detect_secrets": "detect-secrets",
    "semgrep": "semgrep",
    "nbconvert": "jupyter-nbconvert",
    "jupyter": "jupyter",
}

_WINDOWS_SUFFIXES = (".exe", ".bat", ".cmd", ".com")


def _on_windows() -> bool:
    # The same test ASH's lookup uses (subprocess_utils._executable_candidate_names),
    # so a test that reports Windows to it gets the Windows stand-ins too.
    return platform.system().lower() == "windows"


def _as_text(value: object) -> str:
    return os.fsdecode(value) if isinstance(value, bytes) else str(value)


def _search_path(env: object) -> str:
    """The PATH a bare program name is looked up on when a child is started with *env*.

    On POSIX, subprocess looks the name up on the PATH of the environment it gives
    the child (``os.get_exec_path(env)``, ``os.defpath`` when that has no PATH);
    CreateProcess on Windows searches this process's own PATH.
    """
    if _on_windows() or not isinstance(env, Mapping):
        env = None
    return os.pathsep.join(os.get_exec_path(env))


def _is_an_ash_worker(args: Sequence[str]) -> bool:
    """*args*, the arguments after this interpreter, start one of ASH's worker children.

    The detect-secrets scan (``python -m`` ``DETECT_SECRETS_WORKER``) and the cdk-nag
    evaluation, whose ``-c`` code has to be cdk_nag_worker's own bootstrap.
    """
    from automated_security_helper.utils.cdk_nag_worker import _CHILD_BOOTSTRAP

    return list(args[:2]) in (["-m", DETECT_SECRETS_WORKER], ["-c", _CHILD_BOOTSTRAP])


def _inside_the_landlock_wrapper(args: Sequence[str]) -> list[str] | None:
    """The command ASH's Landlock wrapper would run, read as landlock_exec.main reads it.

    *args* are the arguments after this interpreter. None when they are not the
    wrapper running a command (the ``--abi`` probe runs none).
    """
    from automated_security_helper.utils.sandbox.backends import LANDLOCK_EXEC

    if list(args[:2]) != ["-I", str(LANDLOCK_EXEC)]:
        return None
    wrapper_args = list(args[2:])
    if (
        wrapper_args[:1] in (["--socket-filter"], ["--policy"])
        and len(wrapper_args) >= 4
        and wrapper_args[2] == "--"
    ):
        return wrapper_args[3:]
    return None


def _the_start_to_judge(program: str, argv: object) -> tuple[str, object] | None:
    """The program and arguments a start runs: None for one of ASH's worker children,
    the wrapped command for ASH's Landlock wrapper, otherwise the start itself."""
    if program != sys.executable or not isinstance(argv, (list, tuple)):
        return program, argv
    args = [_as_text(a) for a in argv[1:]]
    if _is_an_ash_worker(args):
        return None
    wrapped = _inside_the_landlock_wrapper(args)
    if wrapped:
        return _the_start_to_judge(wrapped[0], wrapped)
    return program, argv


#: coreutils env's options that take a value, short and long.
_ENV_SHORT_OPTIONS_WITH_A_VALUE = frozenset("aCSu")
_ENV_LONG_OPTIONS_WITH_A_VALUE = frozenset(
    {"--argv0", "--chdir", "--split-string", "--unset"}
)


def _through_env(
    program: str, argv: object, search_path: str, cwd: str | None
) -> tuple[str, object, str, str | None]:
    """The start ``env [option...] [NAME=VALUE...] command [arg...]`` makes, or the start.

    Read as coreutils' env reads its arguments: ``-i`` clears the environment, so the
    command is looked up on the C library's default path; a ``PATH=`` assignment is
    the PATH the command is looked up on; ``-C`` changes directory first, and ``-S``
    splits a string into arguments. Short options cluster as getopt reads them
    (``-iS 'tool arg'``, ``-iu NAME``), and one that takes a value takes the rest of
    its word or the next one. ``env`` with no command prints the environment and
    starts nothing. Other launchers (``nice``, ``timeout``, ``nohup``, ``setsid``,
    ``xargs``, ``sudo``) are not looked through.
    """
    if Path(program).name != "env" or not isinstance(argv, list):
        return program, argv, search_path, cwd
    args = [_as_text(a) for a in argv[1:]]
    cleared, path_given = False, None
    index = 0

    def take(option: str, value: str) -> None:
        nonlocal cwd
        if option in ("C", "--chdir"):
            cwd = os.path.join(cwd or os.getcwd(), value)
        elif option in ("S", "--split-string"):
            args[index:index] = shlex.split(value)

    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if arg in ("-", "--ignore-environment"):
            cleared = True
            index += 1
        elif arg.startswith("--"):
            name, equals, value = arg.partition("=")
            index += 1
            if name in _ENV_LONG_OPTIONS_WITH_A_VALUE:
                if not equals:
                    value = args[index] if index < len(args) else ""
                    index += 1
                take(name, value)
        elif arg.startswith("-") and len(arg) > 1:
            index += 1
            for position, flag in enumerate(arg[1:], start=2):
                if flag == "i":
                    cleared = True
                elif flag in _ENV_SHORT_OPTIONS_WITH_A_VALUE:
                    value = arg[position:]
                    if not value:
                        value = args[index] if index < len(args) else ""
                        index += 1
                    take(flag, value)
                    break
        else:
            break
    while index < len(args) and "=" in args[index][1:]:
        name, _, value = args[index].partition("=")
        if name == "PATH":
            path_given = value
        index += 1
    if index >= len(args):
        return program, argv, search_path, cwd
    if path_given is not None:
        search_path = path_given
    elif cleared:
        search_path = os.defpath
    return _through_env(args[index], args[index:], search_path, cwd)


def _shown(argv: object) -> str:
    if isinstance(argv, (list, tuple)):
        return " ".join(_as_text(a) for a in argv)
    return _as_text(argv)


def _without_windows_suffix(name: str) -> str:
    for suffix in _WINDOWS_SUFFIXES:
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    return name


def _module_run_by(argv: object) -> str | None:
    """The module a Python command line runs with ``-m``, or None.

    Read as the interpreter reads its options: ``-I -m uv``, ``-Im uv`` and ``-muv``
    all run uv, and ``-c``, a script or ``-`` ends the options with no module. Of
    the options before those, ``-W``, ``-X`` and ``--check-hash-based-pycs`` take a
    value.
    """
    if not isinstance(argv, (list, tuple)):
        return None
    args = [_as_text(a) for a in argv[1:]]
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--check-hash-based-pycs":
            index += 1
            continue
        if arg.startswith("--"):
            continue
        if not arg.startswith("-") or arg == "-":
            return None
        cluster = arg[1:]
        for position, flag in enumerate(cluster):
            rest = cluster[position + 1 :]
            if flag == "m":
                if rest:
                    return rest
                return args[index] if index < len(args) else None
            if flag == "c":
                return None
            if flag in "WX":
                if not rest:
                    index += 1
                break
    return None


def _resolved(program: str, search_path: str, cwd: str | None) -> str | None:
    """The file a start of *program* runs, found as the child finds it, or None.

    A program with a directory part (``./uv`` has one) is that path, taken from the
    child's working directory *cwd*, as subprocess takes it. A bare name is the first
    match on *search_path*, whose relative entries are taken from *cwd* too.
    CreateProcess on Windows appends .exe only, so there a bare name never resolves
    to a .bat.
    """
    base = cwd or os.getcwd()
    if os.path.dirname(program):
        return os.path.join(base, program)
    if _on_windows() and not program.lower().endswith(_WINDOWS_SUFFIXES):
        program = f"{program}.exe"
    entries = [
        os.path.join(base, entry) for entry in search_path.split(os.pathsep) if entry
    ]
    return shutil.which(program, path=os.pathsep.join(entries))


def runs_git(program: str, search_path: str, cwd: str | None, git: str | None) -> bool:
    """Whether a start of *program* runs *git*, a path ``real_git`` returned.

    Judged by the file the start resolves to (``_resolved``), followed through
    links. By its name alone, a link named git to another program, or another git
    first on the child's PATH, would pass.
    """
    if git is None:
        return False
    found = _resolved(program, search_path, cwd)
    return found is not None and os.path.normcase(os.path.realpath(found)) == git


def popen_runs_only_git(
    git: str | None, args: object, *, executable=None, shell=False, env=None, cwd=None
) -> bool:
    """Whether ``subprocess.Popen(args, ...)`` starts *git* and nothing else.

    An argument list whose program resolves to *git* (``runs_git``), on the PATH of
    the child's environment, from its working directory. Not a shell, whose command
    line can start anything after its git, and not ``executable=``, which runs
    another program under git's name. And a git that no configuration or variable
    it reads tells to run a program (``why_git_may_run_a_program``).
    """
    if shell or executable is not None:
        return False
    if not isinstance(args, (list, tuple)) or not args:
        return False
    cwd = _working_directory(cwd)
    if not runs_git(_as_text(args[0]), _search_path(env), cwd, git):
        return False
    return why_git_may_run_a_program(args, env, cwd) is None


#: Environment variables that name a program for git to run (git(1)): git's own,
#: and the editors and askpass program it falls back to (``git commit`` and ``git
#: config --edit`` run EDITOR or VISUAL when no git setting names an editor).
GIT_PROGRAM_VARIABLES = (
    "EDITOR",
    "GIT_ASKPASS",
    "GIT_EDITOR",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "GIT_PROXY_COMMAND",
    "GIT_SEQUENCE_EDITOR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_ASKPASS",
    "VISUAL",
)

#: Configuration that names a program for git to run (git-config(1)), by section
#: and variable name, whatever the subsection: ``diff.<driver>.textconv`` is
#: ("diff", "textconv"). Values that are only true or false are judged apart
#: (``_git_setting_runs_a_program``).
_GIT_PROGRAM_SETTINGS = frozenset(
    {
        ("browser", "cmd"),
        ("browser", "path"),
        ("core", "alternaterefscommand"),
        ("core", "askpass"),
        ("core", "editor"),
        ("core", "gitproxy"),
        ("core", "pager"),
        ("core", "sshcommand"),
        ("credential", "helper"),
        ("diff", "command"),
        ("diff", "external"),
        ("diff", "textconv"),
        ("difftool", "cmd"),
        ("difftool", "path"),
        ("filter", "clean"),
        ("filter", "process"),
        ("filter", "smudge"),
        ("gpg", "program"),
        ("imap", "tunnel"),
        ("include", "path"),
        ("includeif", "path"),
        ("man", "cmd"),
        ("man", "path"),
        ("merge", "driver"),
        ("mergetool", "cmd"),
        ("mergetool", "path"),
        ("remote", "receivepack"),
        ("remote", "uploadpack"),
        ("sendemail", "sendmailcmd"),
        ("sendemail", "smtpserver"),
        ("sequence", "editor"),
        ("uploadpack", "packobjectshook"),
        ("web", "browser"),
    }
)

#: Settings that run gpg when true.
_GIT_SIGNING_SETTINGS = frozenset(
    {
        "commit.gpgsign",
        "log.showsignature",
        "merge.verifysignatures",
        "push.gpgsign",
        "tag.gpgsign",
    }
)

_GIT_FALSE = frozenset({"false", "no", "off", "0", ""})

#: git commands that read the repository and write neither its index nor its refs,
#: so no hook runs for them. Any other command can (post-index-change and
#: reference-transaction run for an index or ref git writes along the way).
_GIT_COMMANDS_WITHOUT_HOOKS = frozenset(
    {
        "cat-file",
        "check-attr",
        "check-ignore",
        "config",
        "describe",
        "for-each-ref",
        "init",
        "log",
        "ls-files",
        "ls-tree",
        "merge-base",
        "name-rev",
        "rev-list",
        "rev-parse",
        "show",
        "show-ref",
        "var",
    }
)


def _git_setting_runs_a_program(key: str, value: str | None) -> bool:
    """Whether git setting *key* = *value* (None: given without a value, so true)
    tells git to run a program. ``include.path`` counts: what it includes is not
    read here."""
    key = key.lower()
    section, _, rest = key.partition(".")
    name = rest.rsplit(".", 1)[-1]
    text = (value or "").strip()
    if section == "alias" or (section, name) == ("submodule", "update"):
        return text.startswith("!")
    if key == "core.fsmonitor" or key in _GIT_SIGNING_SETTINGS:
        return value is None or text.lower() not in _GIT_FALSE
    if key == "core.hookspath":
        return text != os.devnull
    if section == "pager":
        return text.lower() not in _GIT_FALSE | {"true", "yes", "on", "1"}
    return (section, name) in _GIT_PROGRAM_SETTINGS and text != ""


def _git_key(key: str) -> str:
    """*key* as git compares it: section and variable names fold to lower case, and
    a subsection keeps its case (``diff.Foo.textconv`` is not ``diff.foo.textconv``)."""
    section, dot, rest = key.partition(".")
    subsection, dot2, name = rest.rpartition(".")
    if not dot2:
        return f"{section.lower()}{dot}{rest.lower()}"
    return f"{section.lower()}.{subsection}.{name.lower()}"


#: The characters git's config parser takes as space (its sane_ctype isspace).
_GIT_SPACE = " \t\r\n"
#: The escapes git takes in a config value; any other is a line it refuses.
_GIT_ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "\\": "\\", '"': '"'}


def _git_key_char(c: str) -> bool:
    return c.isascii() and (c.isalnum() or c == "-")


def _git_line_end(text: str, i: int) -> int:
    """Where the line holding *text[i]* ends: just past its newline."""
    end = text.find("\n", i)
    return len(text) if end == -1 else end + 1


def _git_section_header(text: str, i: int) -> tuple[str | None, int]:
    """The section a header names, read from just past its ``[`` as git's
    get_base_var does, and where reading goes on; None for a header git refuses."""
    n = len(text)
    name = ""
    while True:
        if i >= n:
            return None, i
        c = text[i]
        i += 1
        if c == "]":
            return (name or None), i
        if c in _GIT_SPACE:
            break
        if not (_git_key_char(c) or c == "."):
            return None, i - 1
        # The old [section.subsection] folds its subsection to lower case too.
        name += c.lower()
    # [section "Subsection"]: the subsection keeps its case.
    while c in _GIT_SPACE:
        if c == "\n" or i >= n:
            return None, i - 1
        c = text[i]
        i += 1
    if c != '"':
        return None, i - 1
    subsection = ""
    while True:
        if i >= n:
            return None, i
        c = text[i]
        i += 1
        if c == "\n":
            return None, i - 1
        if c == '"':
            break
        if c == "\\":
            if i >= n or text[i] == "\n":
                return None, i
            c = text[i]
            i += 1
        subsection += c
    if i < n and text[i] == "]":
        return f"{name}.{subsection}", i + 1
    return None, i


def _git_value(text: str, i: int) -> tuple[str | None, int]:
    """The value that starts at *text[i]*, just past its ``=``, read as git's
    parse_value reads it, and where reading goes on; None for one git refuses.

    Space outside quotes is dropped at either end and kept as it is inside (git
    2.50; older versions write each as a space); a ``#`` or ``;`` outside quotes
    starts a comment to the end of the line; a backslash escapes, and at the end
    of a line continues the value on the next one. A backslash inside a comment
    continues nothing.
    """
    n = len(text)
    value = ""
    quoted = in_comment = False
    spaces = ""
    while True:
        if i >= n:
            return (None if quoted else value), n
        c = text[i]
        i += 1
        if c == "\n":
            return (None, i - 1) if quoted else (value, i)
        if in_comment:
            continue
        if c in _GIT_SPACE and not quoted:
            if value:
                spaces += c
            continue
        if c in "#;" and not quoted:
            in_comment = True
            continue
        value += spaces
        spaces = ""
        if c == "\\":
            escaped = text[i] if i < n else "\n"
            i += 1
            if escaped == "\n":
                continue
            if escaped not in _GIT_ESCAPES:
                return None, i - 1
            value += _GIT_ESCAPES[escaped]
        elif c == '"':
            quoted = not quoted
        else:
            value += c


def _git_file_text(path: Path, encoding: str = "utf-8") -> str:
    """The text of a file git reads, decoded from its bytes.

    ``Path.read_text`` reads with universal newlines, so a lone CR ended a line
    there, while git ends a line only at LF: a CR inside a quoted config value, or
    in the path a ``.git`` file or ``commondir`` names, is one character to git.
    ``read_text`` takes no ``newline`` argument before Python 3.13."""
    return path.read_bytes().decode(encoding, errors="replace")


def _git_config_file_settings(path: Path) -> list[tuple[str, str | None]]:
    """The settings in git config file *path*: (``section[.subsection].name``, value),
    each key as :func:`_git_key` gives it, read as git's own config parser reads them.

    That is section headers (``[section "Subsection"]``, and the old
    ``[section.subsection]``, whose subsection git folds to lower case), a name
    given alone (None: true) or with ``=`` and a value (``_git_value``), comments,
    and a leading byte order mark. Only LF ends a line, so a lone CR is space
    outside quotes and a character inside them (``_git_file_text``). git stops at a
    line it refuses; here that line is skipped and reading goes on, so at least
    every setting git reads is read.
    """
    try:
        text = _git_file_text(path, "utf-8-sig")
    except OSError:
        return []
    text = text.replace("\r\n", "\n")
    settings: list[tuple[str, str | None]] = []
    section = ""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in _GIT_SPACE:
            i += 1
            continue
        if c in "#;":
            i = _git_line_end(text, i)
            continue
        if c == "[":
            header, i = _git_section_header(text, i + 1)
            if header is None:
                i = _git_line_end(text, i)
            else:
                section = header
            continue
        if not (c.isascii() and c.isalpha()):
            i = _git_line_end(text, i)
            continue
        start = i
        while i < n and _git_key_char(text[i]):
            i += 1
        key = f"{section}.{text[start:i].lower()}" if section else text[start:i].lower()
        while i < n and text[i] in " \t":
            i += 1
        if i >= n or text[i] == "\n":
            settings.append((key, None))
            i += 1
            continue
        if text[i] != "=":
            i = _git_line_end(text, i)
            continue
        value, i = _git_value(text, i + 1)
        if value is None:
            i = _git_line_end(text, i)
            continue
        settings.append((key, value))
    return settings


def _git_path_file_text(path: Path) -> str:
    """The text of a file git reads one path from, a ``.git`` file or ``commondir``,
    as git reads it: only the CRs and LFs that end it are dropped, so a path ending
    in a space keeps the space (git 2.50.1 resolves such a directory as named)."""
    return _git_file_text(path).rstrip("\r\n")


def _git_dir_found_from(start: str, env: Mapping[str, str]) -> Path | None:
    """The git directory git finds from *start*: ``.git`` there or in a parent, below
    the first of ``GIT_CEILING_DIRECTORIES`` on the way up.

    A ``.git`` file names it after ``gitdir: ``, taken as written. git refuses a
    ``.git`` file without that prefix and runs nothing, so such a file is passed over.
    """
    ceilings = {
        os.path.normcase(os.path.abspath(entry))
        for entry in env.get("GIT_CEILING_DIRECTORIES", "").split(os.pathsep)
        if entry
    }
    current = Path(os.path.abspath(start))
    while True:
        dot_git = current / ".git"
        if dot_git.is_dir():
            return dot_git
        if dot_git.is_file():
            pointer = _git_path_file_text(dot_git)
            if pointer.startswith("gitdir: "):
                return (current / pointer[len("gitdir: ") :]).resolve()
        parent = current.parent
        if parent == current or os.path.normcase(str(parent)) in ceilings:
            return None
        current = parent


def why_git_may_run_a_program(
    args: Sequence[object], env: object, cwd: str | None
) -> str | None:
    """Why a start of git with *args* may run a program other than git, or None.

    git runs what its configuration and variables name: a ``!`` alias, an fsmonitor,
    hooks, a pager, an external diff (``_GIT_PROGRAM_SETTINGS``,
    ``GIT_PROGRAM_VARIABLES``). Measured, the real git ran a hook with ``-c alias``,
    ``-c core.fsmonitor``, ``--exec-path``, an ``env=`` setting ``GIT_CONFIG_*`` or
    ``GIT_EXTERNAL_DIFF``, and a ``cwd=`` in a repository whose own config set an
    fsmonitor. Read here: ``-c`` and ``--config-env``, ``--exec-path``, the
    variables, the settings ``GIT_CONFIG_COUNT`` and ``GIT_CONFIG_PARAMETERS``
    carry, the global config files, and the config files and hooks of the
    repository git finds from its working directory (``-C`` and ``--git-dir``
    taken; hooks only for a command that can run one, not those in
    ``_GIT_COMMANDS_WITHOUT_HOOKS``). ``git --version`` and ``git help`` read none
    of the files. A setting given on the command line is read in place of the files'.
    The system config's path is compiled into git, so it has to be off
    (``GIT_CONFIG_NOSYSTEM``). Not read: what an ``include.path`` includes (the
    setting itself counts), and a ``git-<name>`` program on PATH that git runs for a
    subcommand it does not have.
    """
    environ: Mapping[str, str] = env if isinstance(env, Mapping) else os.environ
    words = [_as_text(a) for a in args[1:]]
    command_line: dict[str, str | None] = {}
    start = cwd or os.getcwd()
    git_dir: Path | None = None
    index = 0
    while index < len(words) and words[index].startswith("-"):
        word = words[index]
        value = words[index + 1] if index + 1 < len(words) else ""
        if word.startswith("--exec-path"):
            return f"git {word}, which chooses the programs git runs"
        if word in ("-c", "--config-env") or word.startswith("--config-env="):
            setting = (
                word.split("=", 1)[1] if word.startswith("--config-env=") else value
            )
            key, equals, given = setting.partition("=")
            if word != "-c":
                given = environ.get(given, "")
            command_line[_git_key(key)] = given if equals else None
            index += 1 if word.startswith("--config-env=") else 2
            continue
        if word == "-C":
            start = os.path.join(start, value)
            index += 2
            continue
        if word.startswith("--git-dir="):
            git_dir = Path(start, word.split("=", 1)[1])
        elif word in ("--git-dir", "--work-tree", "--namespace"):
            if word == "--git-dir":
                git_dir = Path(start, value)
            index += 2
            continue
        index += 1
    for name in GIT_PROGRAM_VARIABLES:
        if environ.get(name):
            return f"{name} is set"
    settings = list(command_line.items())
    count = environ.get("GIT_CONFIG_COUNT", "")
    for number in range(int(count) if count.isdigit() else 0):
        key = environ.get(f"GIT_CONFIG_KEY_{number}", "")
        settings.append((key, environ.get(f"GIT_CONFIG_VALUE_{number}", "")))
    for key, given in re.findall(
        r"'([^']*)'(?:='([^']*)')?", environ.get("GIT_CONFIG_PARAMETERS", "")
    ):
        settings.append((key, given))
    for key, given in settings:
        if _git_setting_runs_a_program(key, given):
            return f"git setting {key} names a program for git to run"
    command = words[index] if index < len(words) else "version"
    if command in ("version", "help"):
        # Printed with no repository and no configuration read.
        return None
    if not environ.get("GIT_CONFIG_NOSYSTEM"):
        return "git reads the system config (GIT_CONFIG_NOSYSTEM is not set)"
    if environ.get("GIT_CONFIG_SYSTEM"):
        return "git reads the system config GIT_CONFIG_SYSTEM names"
    files: list[Path] = []
    if environ.get("GIT_CONFIG_GLOBAL") is not None:
        files.append(Path(environ["GIT_CONFIG_GLOBAL"]))
    else:
        home = environ.get("HOME", "")
        config_home = environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        files += [Path(config_home, "git", "config"), Path(home, ".gitconfig")]
    # --git-dir on the command line wins over GIT_DIR, as git takes it.
    if git_dir is None and environ.get("GIT_DIR"):
        git_dir = Path(start, environ["GIT_DIR"])
    if git_dir is None:
        git_dir = _git_dir_found_from(start, environ)
    hooks: Path | None = None
    if git_dir is not None:
        common = git_dir
        commondir = git_dir / "commondir"
        if environ.get("GIT_COMMON_DIR"):
            common = Path(start, environ["GIT_COMMON_DIR"])
        elif commondir.is_file():
            common = git_dir / _git_path_file_text(commondir)
        files += [common / "config", git_dir / "config.worktree"]
        hooks = common / "hooks"
    for path in files:
        for key, given in _git_config_file_settings(path):
            if key in command_line:
                continue
            if _git_setting_runs_a_program(key, given):
                return f"{path} sets {key}, which names a program for git to run"
    runs_no_hooks = command in _GIT_COMMANDS_WITHOUT_HOOKS or (
        command == "worktree" and words[index + 1 : index + 2] == ["list"]
    )
    if (
        hooks is not None
        and not runs_no_hooks
        and command_line.get("core.hookspath") != os.devnull
    ):
        if hooks.is_dir() and any(
            hook.is_file() and not hook.name.endswith(".sample")
            for hook in hooks.iterdir()
        ):
            return f"the repository has hooks in {hooks}"
    return None


def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives on Windows
        return False


def reset_tool_lookup_caches() -> None:
    """Forget every executable path and probe answer ASH cached in this process."""
    from automated_security_helper.utils import subprocess_utils, uv_tool_runner
    from automated_security_helper.utils.pre_installed_tool import (
        reset_pre_installed_tool_cache,
    )

    uv_tool_runner._reset_uv_tool_runner_caches()
    uv_tool_runner.reset_uv_tool_runner()
    subprocess_utils.clear_find_executable_cache()
    reset_pre_installed_tool_cache()


def stub_tool_probes(monkeypatch) -> None:
    """Answer the probes ASH runs while building and validating scanners, without a process.

    Each one starts a tool to ask a question the tests in question do not ask:
    ``uv --version`` (``UVToolRunner.uv_availability``, from building a uv-run
    scanner), ``uv tool run <tool> --version`` (``get_uv_tool_command``), ``<tool>
    --version`` for a pre-installed tool (``pre_installed_tool._run``) and
    ``opengrep --version`` (``OpengrepScanner._get_opengrep_version``). Each answers
    as it does on a host without the tool: uv absent, the pre-installed tool not
    executable, no opengrep version.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
    )
    from automated_security_helper.utils import pre_installed_tool, uv_tool_runner

    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "uv_availability", lambda self: (False, None)
    )
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
    monkeypatch.setattr(pre_installed_tool, "_run", lambda command, timeout: None)
    monkeypatch.setattr(OpengrepScanner, "_get_opengrep_version", lambda self: None)


#: Python source a child process that runs ASH executes first, to answer the probes
#: ``stub_tool_probes`` answers, the same way. A child is not audited, and it finds the
#: uv installed with ASH beside its interpreter whatever PATH it is given, so a child
#: ``ash scan`` ran that uv, and the tools it starts, for real. It has to be source
#: rather than a call: a child started with ``-I`` cannot import the tests.
CHILD_TOOL_PROBE_STUBS = """\
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner as _StubbedOpengrepScanner,
)
from automated_security_helper.utils import pre_installed_tool as _stubbed_pre_installed
from automated_security_helper.utils import uv_tool_runner as _stubbed_uv_tool_runner

_stubbed_uv_tool_runner.UVToolRunner.uv_availability = lambda self: (False, None)
_stubbed_uv_tool_runner.find_uv_or_none = lambda: None
_stubbed_pre_installed._run = lambda command, timeout: None
_StubbedOpengrepScanner._get_opengrep_version = lambda self: None
"""


class ToolGuard:
    """The stand-ins' directory and what was started while the guard was in."""

    def __init__(
        self,
        directory: Path,
        names: Sequence[str] = GUARDED_TOOLS,
        own_directories: Sequence[Path] = (),
        basetemp: Path | None = None,
    ) -> None:
        self.directory = directory
        self.names = frozenset(os.path.normcase(name) for name in names)
        #: pytest's base temp directory, for the HOME rule (_hold_to_the_home_rule).
        self.basetemp = basetemp
        #: Why each start the HOME rule refused was refused, kept for a teardown check:
        #: code that swallows the refusal does not hide it.
        self.home_refusals: list[str] = []
        #: Per thread, the (program, argv) one armed fork_exec skip stands
        #: for (_arm_fork_exec_skip). Keyed by thread so another thread's
        #: call cannot spend an arm, and interleaved Popens keep their own.
        self._fork_exec_arms: dict[int, tuple] = {}
        #: The git a guarded test may start, found before the stand-ins go on PATH.
        self.git = real_git()
        #: Where a test keeps programs of its own (tmp_path, the temp directory): a
        #: guarded name started from in one of them is the test's fake, not the tool.
        #: Each is kept as given and resolved, normalized for comparison.
        self._own_roots = tuple(
            {
                os.path.normcase(form)
                for root in own_directories
                for form in (os.path.abspath(root), os.path.realpath(root))
            }
        )
        self.log = directory / "started.log"
        #: Where a POSIX stand-in writes the path it was run by for a lone
        #: ``--version``. The Windows stand-in reads no argument, so it writes every
        #: call to ``log``.
        self.probe_log = directory / "probes.log"
        #: (program, argv, the PATH a bare program name is looked up on, the child's
        #: working directory), or (None, the whole line, "", None) for a start no argv
        #: describes, such as a fork.
        self._spawned: list[tuple[str | None, object, str, str | None]] = []
        #: What install_tool_guard wrote to each stand-in, by file name.
        self._stand_in_bytes: dict[str, bytes] = {}

    def _is_a_stand_in(self, path: Path) -> bool:
        """Whether *path* is still the stand-in the guard wrote there: not a link, and
        its bytes. A test that put a host tool in its place, as a link or a copy,
        ran that tool."""
        written = self._stand_in_bytes.get(path.name)
        if written is None or path.is_symlink():
            return False
        try:
            return path.read_bytes() == written
        except OSError:
            return False

    def _record_spawn(
        self,
        program: str | None,
        argv: object,
        search_path: str,
        cwd: str | None = None,
    ) -> None:
        entry = (program, argv, search_path, cwd)
        # subprocess reports one start twice when it uses posix_spawn (both
        # subprocess.Popen and os.posix_spawn).
        if not self._spawned or self._spawned[-1][:2] != entry[:2]:
            self._spawned.append(entry)

    def _arm_fork_exec_skip(self, program: str, argv: object) -> None:
        """One fork_exec skip, armed by a Popen AUDIT EVENT on this thread,
        carrying the start it stands for.

        Armed on every Popen event - a deduplicated repeat too, whose own
        fork_exec still follows - and never by any other record: arming on
        every appended record let the wrapper's own record of a held direct
        call, or any other recorded start, license a skip for the next
        matching direct call. Keyed by thread, since Popen's own fork_exec
        follows its audit event on the same thread: another thread's call
        cannot spend this arm, and interleaved Popens each keep their own."""
        self._fork_exec_arms[threading.get_ident()] = (program, argv)

    def _consume_fork_exec_arm(self):
        """The (program, argv) this thread's arm stands for, or None; asking
        spends it either way."""
        return self._fork_exec_arms.pop(threading.get_ident(), None)

    def _popens_own_fork_exec(
        self, argv_text: list[str], candidates: list[str], record: tuple
    ) -> bool:
        """Whether a ``fork_exec`` call is ``subprocess.Popen``'s own, for
        *record*, the (program, argv) whose Popen audit event armed the skip.

        Popen's audit event fires before its fork_exec, so that call carries
        the armed record's argv, and every executable candidate runs that
        record's program: the program itself, or a PATH directory's join with
        its name (fork_exec runs the first candidate that executes). Proven
        so, recording the call again would misname the start as the first
        candidate - the first PATH entry's join, a file that mostly does not
        exist - and count it twice. Anything short of the proof is recorded
        as before: a direct fork_exec that matches no armed record stays a
        start, so the unrecognized case still records rather than passing
        silently.
        """
        if not candidates or not argv_text:
            return False
        program, last_argv = record
        if program is None or not isinstance(last_argv, (list, tuple)):
            return False
        if [_as_text(a) for a in last_argv] != argv_text:
            return False
        name = os.path.basename(program)
        if not name:
            return False
        return all(
            candidate == program
            or _without_windows_suffix(os.path.basename(candidate))
            == _without_windows_suffix(name)
            for candidate in candidates
        )

    def _stand_in_reached(
        self, program: str, search_path: str, cwd: str | None
    ) -> Path | None:
        """The stand-in a start of *program* runs, or None if it runs none."""
        found = _resolved(program, search_path, cwd)
        if found is None or Path(found).parent != self.directory:
            return None
        return Path(found)

    def _is_own(self, path: str) -> bool:
        target = os.path.normcase(path)
        return any(_is_within(target, root) for root in self._own_roots)

    def _runs_a_guarded_tool(
        self, program: str, argv: object, search_path: str, cwd: str | None
    ) -> bool:
        """Whether a start that reached no stand-in runs one of the guarded tools.

        It does when the file it runs is a guarded tool outside the test's own
        directories, by that file's name or by the name of the file it links to: a
        test's fake ``uv`` under tmp_path is not one, and neither is a link there named
        ``uv`` to ``true``, while a link named anything to a real uv is. It does too
        when it is a Python running a guarded tool's module (``GUARDED_MODULES``).
        A program that does not exist ran nothing.
        """
        name = os.path.normcase(_without_windows_suffix(Path(program).name))
        if name.startswith("python"):
            module = _module_run_by(argv)
            if module is not None:
                return GUARDED_MODULES.get(module.split(".")[0], "") in self.names
        found = _resolved(program, search_path, cwd)
        if found is None or not os.path.exists(found):
            return False
        for path in (os.path.abspath(found), os.path.realpath(found)):
            base = os.path.normcase(_without_windows_suffix(Path(path).name))
            if base in self.names and not self._is_own(path):
                return True
        return False

    @staticmethod
    def _as_logged(name: str, argv: object) -> str:
        """The line a stand-in named *name* writes to ``log`` when started with *argv*."""
        if _on_windows() or not isinstance(argv, (list, tuple)):
            return name
        return " ".join([name, *(_as_text(a) for a in argv[1:])]).strip()

    @staticmethod
    def _is_a_version_call(argv: object) -> bool:
        return isinstance(argv, (list, tuple)) and [_as_text(a) for a in argv[1:]] == [
            "--version"
        ]

    @staticmethod
    def _read_lines(path: Path) -> list[str]:
        if not path.exists():
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
        return [line.strip() for line in text.splitlines() if line.strip()]

    def _sort(self) -> tuple[list[str], list[str], list[str]]:
        """(probes, starts, tool starts): every call this guard saw, sorted."""
        logged = self._read_lines(self.log)
        probe_paths = self._read_lines(self.probe_log)
        unmatched_logged = Counter(logged)
        unmatched_probes = Counter(probe_paths)
        # Windows: lines in `log` that were probes, so they are not starts.
        probes_in_log: Counter[str] = Counter()
        probed: set[str] = set()
        probes: list[str] = []
        extra: list[str] = []
        #: The lines of ``extra`` that ran a guarded tool or asked a stand-in to.
        tool_extra: list[str] = []
        for program, argv, search_path, cwd in self._spawned:
            if program is None:
                # A start no argv describes: argv holds its whole line.
                extra.append(str(argv))
                continue
            judged = _the_start_to_judge(program, argv)
            if judged is None:
                continue
            program, argv, search_path, cwd = _through_env(*judged, search_path, cwd)
            if runs_git(program, search_path, cwd, self.git):
                continue
            stand_in = self._stand_in_reached(program, search_path, cwd)
            if stand_in is None:
                line = f"{_shown(argv)} (not through a stand-in)"
                extra.append(line)
                if self._runs_a_guarded_tool(program, argv, search_path, cwd):
                    tool_extra.append(line)
                continue
            name = _without_windows_suffix(stand_in.name)
            if self._is_a_version_call(argv):
                # A probe is one a stand-in answered: the stand-in the guard wrote
                # (by name and by its bytes, read now), and the line it writes for
                # the call. Any other file in the directory, or a host tool linked
                # or copied there, writes no line, and a lone --version to it ran
                # it; a line a child's own probe of the stand-in left does not
                # answer for a tool put in the stand-in's place since. A tool put
                # there and taken away again before this is read is not seen.
                answered = False
                if os.path.normcase(name) in self.names and self._is_a_stand_in(
                    stand_in
                ):
                    if _on_windows():
                        if unmatched_logged[name] > 0:
                            unmatched_logged[name] -= 1
                            probes_in_log[name] += 1
                            answered = True
                    elif unmatched_probes[str(stand_in)] > 0:
                        unmatched_probes[str(stand_in)] -= 1
                        answered = True
                if not answered:
                    line = f"{_shown(argv)} (a --version call no stand-in answered)"
                    extra.append(line)
                    tool_extra.append(line)
                    continue
                if not Path(program).is_absolute():
                    extra.append(
                        f"{_shown(argv)} (a --version call not by the stand-in's own path)"
                    )
                elif str(stand_in) in probed:
                    extra.append(f"{_shown(argv)} (a second --version probe)")
                else:
                    probed.add(str(stand_in))
                    probes.append(f"{name} --version")
                continue
            line = self._as_logged(name, argv)
            if unmatched_logged[line] > 0:
                unmatched_logged[line] -= 1
            else:
                line = f"{_shown(argv)} (through a stand-in that recorded nothing)"
                extra.append(line)
                tool_extra.append(line)
        # Probes no audited start accounts for: made by a child process.
        for path in probe_paths:
            if unmatched_probes[path] == 0:
                continue
            unmatched_probes[path] -= 1
            if path in probed:
                extra.append(f"{path} --version (a second --version probe)")
            else:
                probed.add(path)
                probes.append(f"{_without_windows_suffix(Path(path).name)} --version")
        starts: list[str] = []
        for line in logged:
            if probes_in_log[line] > 0:
                probes_in_log[line] -= 1
                continue
            starts.append(line)
        return probes, starts + extra, starts + tool_extra

    @property
    def started(self) -> list[str]:
        """One line per start: the tool's name, then its arguments.

        A stand-in's own record, then every other process start the audit hook saw,
        except one of ASH's worker children, the real git (``runs_git``), a version
        probe (``probes``), or one that went through a stand-in and has its line in
        the stand-in's record. A start through a stand-in that left no line is listed
        too, and so is a second probe of one path or a ``--version`` by bare name.
        """
        return self._sort()[1]

    @property
    def tool_starts(self) -> list[str]:
        """The lines of ``started`` that ran a guarded tool, or asked a stand-in to.

        Every call a stand-in recorded, which is every call but a lone ``--version``;
        a start that reached a stand-in and left no record; and a start that reached
        no stand-in but runs a guarded tool all the same (``_runs_a_guarded_tool``):
        by a path, found on a PATH that skips the stand-ins, or as ``python -m``.
        Not listed, because no real tool ran: a ``--version`` a stand-in answered, a
        guarded name from the test's own directories, any other program, and a fork
        or C library lookup, whose own starts are not seen.
        """
        return self._sort()[2]

    @property
    def probes(self) -> list[str]:
        """``<tool> --version`` for each stand-in probed by its own path, once."""
        return self._sort()[0]


#: The guard the audit hook records into, if any. Set by install_tool_guard through
#: monkeypatch, so it is back to None when the test ends.
_ACTIVE: ToolGuard | None = None
_HOOK_INSTALLED = False

#: C library functions that start a process, or a child that can start one, without
#: an audit event of their own. Looking one up through ctypes raises
#: ``ctypes.dlsym``, so that is recorded. ``syscall`` is here for
#: ``syscall(SYS_clone)``, and ``wordexp`` because it runs a shell for ``$(...)``.
C_PROCESS_FUNCTIONS = frozenset(
    {
        "system",
        "popen",
        "fork",
        "vfork",
        "_Fork",
        "clone",
        "clone3",
        "syscall",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fexecve",
        "posix_spawn",
        "posix_spawnp",
        "pidfd_spawn",
        "pidfd_spawnp",
        "wordexp",
    }
)


#: The audit events _audit reads. Every other event (each open, import and listdir
#: among them) returns at the first check, since a guard is in for every unit test.
_RECORDED_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.posix_spawn",
        "os.exec",
        "os.spawn",
        "os.system",
        "os.fork",
        "os.forkpty",
        "ctypes.dlsym",
        "ctypes.dlsym/handle",
    }
)


def _hold_to_the_home_rule(
    guard: ToolGuard,
    what: str,
    args: object,
    env: object = None,
    cwd: object = None,
    *,
    shell: bool = False,
    executable: object = None,
) -> None:
    """Refuse a start that breaks the HOME rule, before it happens.

    The rule is tests/conftest.py's, which applies it at subprocess.Popen
    (``home_rule_refusal``, through tests/utils/home_rule.py): a Python or ASH child
    whose HOME is the developer's or none, or a tool installer aimed there. These
    starts never reach Popen, so the recorder asks it. ``args``, ``env``, ``cwd``,
    ``shell`` and ``executable`` are as Popen takes them. A refusal fails the test where
    the start is, with ``pytest.fail``, which ``except Exception`` does not catch, and
    is kept in ``guard.home_refusals`` for the unit tests' teardown check. A start the
    rule cannot read is refused too.
    """
    from tests.utils.home_rule import home_rule_refusal

    try:
        refusal = home_rule_refusal(
            args,
            env,
            cwd,
            basetemp=guard.basetemp,
            shell=shell,
            executable=executable,
        )
    except Exception as error:  # what the rule cannot read is not let through
        refusal = f"the HOME rule could not read it ({type(error).__name__}: {error})"
    if refusal is None:
        return
    guard.home_refusals.append(f"{what}: {refusal}")
    import pytest

    pytest.fail(f"{what} breaks the HOME rule: {refusal}", pytrace=False)


#: What a child of this interpreter runs, as the HOME rule reads it: a fork, or a
#: process a C function looked up through ctypes starts, has this process's
#: environment whatever it then runs.
_THIS_INTERPRETER = [sys.executable]


def _audit(event: str, args: tuple) -> None:
    if event not in _RECORDED_EVENTS:
        return
    guard = _ACTIVE
    if guard is None:
        return
    # The HOME rule first: a start it refuses does not happen, so it is not recorded.
    # Popen's own starts are held to it by tests/conftest.py.
    if event in ("os.posix_spawn", "os.exec"):
        _hold_to_the_home_rule(
            guard, f"{event} {_shown(args[1])}", args[1], args[2], executable=args[0]
        )
    elif event == "os.spawn":
        _hold_to_the_home_rule(
            guard, f"{event} {_shown(args[2])}", args[2], args[3], executable=args[1]
        )
    elif event == "os.system":
        _hold_to_the_home_rule(
            guard, f"{event} {_as_text(args[0])!r}", args[0], shell=True
        )
    elif event in ("os.fork", "os.forkpty"):
        _hold_to_the_home_rule(
            guard, f"{event}() (the child is this interpreter)", _THIS_INTERPRETER
        )
    elif event in ("ctypes.dlsym", "ctypes.dlsym/handle"):
        name = _as_text(args[1])
        if name in C_PROCESS_FUNCTIONS:
            _hold_to_the_home_rule(
                guard,
                f"{event} {name}() (what it starts has this process's environment)",
                _THIS_INTERPRETER,
            )
    try:
        env: object = None
        cwd: object = None
        if event == "subprocess.Popen":
            executable, argv, cwd, env = args[0], args[1], args[2], args[3]
            if executable is not None:
                program = executable
            elif isinstance(argv, (list, tuple)) and argv:
                program = argv[0]
            else:
                program = argv
        elif event in ("os.posix_spawn", "os.exec"):
            program, argv, env = args[0], args[1], args[2]
        elif event == "os.spawn":
            program, argv, env = args[1], args[2], args[3]
        elif event == "os.system":
            program = argv = args[0]
        elif event in ("os.fork", "os.forkpty"):
            guard._record_spawn(
                None, f"{event}() (a forked child, whose starts are not recorded)", ""
            )
            return
        elif event in ("ctypes.dlsym", "ctypes.dlsym/handle"):
            name = _as_text(args[1])
            if name in C_PROCESS_FUNCTIONS:
                guard._record_spawn(
                    None,
                    f"ctypes {name}() (looked up from a C library; what it starts "
                    "is not recorded)",
                    "",
                )
            return
        else:
            return
        try:
            search_path = _search_path(env)
        except Exception:
            # Unknown: an empty PATH finds nothing, so a bare name is recorded.
            search_path = ""
        if isinstance(argv, (list, tuple)):
            argv = list(argv)
        guard._record_spawn(
            _as_text(program), argv, search_path, _working_directory(cwd)
        )
        if event == "subprocess.Popen":
            # Popen's own fork_exec follows this event on this thread even
            # when the record above was deduplicated, so the skip is armed on
            # every Popen event, and only here.
            guard._arm_fork_exec_skip(_as_text(program), argv)
    except Exception:  # an audit hook that raises would break the spawn itself
        return


def _working_directory(cwd: object) -> str | None:
    """The directory a child starts in: *cwd*, given to Popen, or this process's own.

    Read when the child starts, since a test can change directory before the guard
    sorts its starts. None when this process's directory is gone.
    """
    if isinstance(cwd, (str, bytes, os.PathLike)):
        return os.path.abspath(os.fsdecode(cwd))
    try:
        return os.getcwd()
    except OSError:
        return None


def _install_audit_hook() -> None:
    global _HOOK_INSTALLED
    if not _HOOK_INSTALLED:
        sys.addaudithook(_audit)
        _HOOK_INSTALLED = True


def run_own_directories(basetemp: Path, session_dir: str | None = None) -> list[Path]:
    """Where a test's own programs are, for ``install_tool_guard``'s *own_directories*.

    pytest's base temp directory, where tmp_path and the rest are, and the session
    temp directory, which tempfile uses (*session_dir*, by default
    ``tempfile.gettempdir()``), less any of them that the HOME rule does not count as
    the run's own (tests/utils/home_rule.py): one inside the developer's ~/.ash, where
    the default bin directory and the receipts are, or one that holds their home. So
    what the run's own directories leave out has one definition, the HOME rule's.

    The HOME rule counts more as the run's own: the temp directories the run started
    with and pytest's temp root, which are /tmp on a usual run. They are not the
    developer's, so for it they are rightly exempt. They are not the test's either: a
    test makes its programs under basetemp or the session directory, never in the
    shared root, so the tool guard leaves them out, and a guarded tool found there by
    its path is the host's and a tool start. Taking them would have let every guarded
    tool under /tmp through.
    """
    from tests.utils.home_rule import inside_the_runs_own_directories

    session = Path(session_dir if session_dir is not None else tempfile.gettempdir())
    return [
        root
        for root in (Path(basetemp), session)
        if inside_the_runs_own_directories(root, basetemp)
    ]


def install_tool_guard(
    monkeypatch,
    directory: Path,
    names=GUARDED_TOOLS,
    own_directories: Sequence[Path] = (),
    basetemp: Path | None = None,
) -> ToolGuard:
    """Put a recording stand-in for each of *names* first on PATH and record spawns.

    *own_directories* are where the test keeps programs of its own, so a guarded name
    started from inside one is not a tool start (``ToolGuard.tool_starts``).
    The starts the recorder sees that skip subprocess.Popen are held to the HOME rule
    (``_hold_to_the_home_rule``), with *basetemp*, pytest's base temp directory, one
    of the run's own directories; refused, they are in ``ToolGuard.home_refusals``.
    The caller resets the caches again on teardown (``reset_tool_lookup_caches``);
    ``monkeypatch`` restores PATH, the Windows lookup and the spawn recorder.
    """
    from automated_security_helper.utils import subprocess_utils
    from tests.utils.home_rule import loaded_conftest

    # The rule is tests/conftest.py's; without it the recorder could not apply it,
    # and the guard does not go in without its HOME check.
    loaded_conftest()
    directory.mkdir(parents=True, exist_ok=True)
    guard = ToolGuard(directory, names, own_directories, basetemp)
    for name in names:
        if _on_windows():
            # Only the name is recorded: "%*" in a .bat line is parsed by cmd, so an
            # argument holding & | or > would run as a command. A "%" in the log
            # path is doubled for the same parser.
            # For the same reason it cannot tell a version probe from any other
            # call: it prints the version every time (the locator ignores the exit
            # code), and ToolGuard sorts the probe out from the audited argv.
            stand_in = directory / f"{name}.bat"
            log = str(guard.log).replace("%", "%%")
            stand_in.write_text(
                f'@echo {name}>> "{log}"\r\n'
                f"@echo {name} {stand_in_version(name)}\r\n"
                "@exit /b 1\r\n",
                encoding="utf-8",
            )
        else:
            stand_in = directory / name
            answer = shlex.quote(f"{name} {stand_in_version(name)}")
            stand_in.write_text(
                "#!/bin/sh\n"
                'if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then\n'
                f"  printf '%s\\n' \"$0\" >> {shlex.quote(str(guard.probe_log))}\n"
                f"  printf '%s\\n' {answer}\n"
                "  exit 0\n"
                "fi\n"
                f"printf '%s\\n' \"{name} $*\" >> {shlex.quote(str(guard.log))}\n"
                "exit 1\n",
                encoding="utf-8",
            )
        stand_in.chmod(0o755)
        guard._stand_in_bytes[stand_in.name] = stand_in.read_bytes()
    if _on_windows():
        guarded = set(names)
        real_candidates = subprocess_utils._executable_candidate_names

        def _guard_first(command: str) -> list[str]:
            if command in guarded:
                return [f"{command}.bat"]
            return real_candidates(command)

        monkeypatch.setattr(
            subprocess_utils, "_executable_candidate_names", _guard_first
        )
    if "uv" in names:
        # find_uv_or_none asks for the uv installed with ASH before it searches
        # PATH, so that copy would answer ahead of the stand-in.
        from automated_security_helper.utils import uv_tool_runner

        monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", lambda: None)
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ.get('PATH', '')}")
    _record_multiprocessing_spawns(monkeypatch, guard)
    _record_fork_execs(monkeypatch, guard)
    _record_forkserver_starts(monkeypatch, guard)
    reset_tool_lookup_caches()
    _install_audit_hook()
    monkeypatch.setattr(sys.modules[__name__], "_ACTIVE", guard)
    return guard


def _record_multiprocessing_spawns(monkeypatch, guard: ToolGuard) -> None:
    """Record the starts multiprocessing makes through spawnv_passfds.

    Its spawn and forkserver start methods, and its resource tracker, start this
    interpreter through _posixsubprocess.fork_exec, which raises no audit event.
    They all call ``multiprocessing.util.spawnv_passfds`` by attribute, so the
    wrapper sees each one.
    """
    from multiprocessing import util

    spawn = util.spawnv_passfds

    def recording(path, args, passfds):
        # Started with this process's environment.
        _hold_to_the_home_rule(
            guard,
            f"multiprocessing spawnv_passfds {_shown(list(args))}",
            list(args),
            executable=path,
        )
        guard._record_spawn(
            _as_text(path), list(args), _search_path(None), _working_directory(None)
        )
        return spawn(path, args, passfds)

    monkeypatch.setattr(util, "spawnv_passfds", recording)


def _environment_of(env_list: object) -> Mapping[str, str] | None:
    """The mapping of ``fork_exec``'s ``KEY=VALUE`` list, or None for "inherited"."""
    if not isinstance(env_list, (list, tuple)):
        return None
    pairs = (_as_text(item).partition("=") for item in env_list)
    return {key: value for key, _, value in pairs}


def _record_fork_execs(monkeypatch, guard: ToolGuard) -> None:
    """Record a start made through ``_posixsubprocess.fork_exec`` by attribute.

    It raises no audit event. On interpreters whose ``subprocess.Popen`` bound
    ``fork_exec`` when subprocess was imported, Popen's own starts do not come
    through here; on ones whose Popen calls ``_posixsubprocess.fork_exec`` by
    attribute (Python 3.10), they do, right after Popen's own audit event
    recorded them, so the wrapper skips the call it can prove is that same
    start (``ToolGuard._popens_own_fork_exec``) instead of recording it a
    second time under the first PATH candidate's path - a file that mostly
    does not exist, which misnamed the start and double-counted every start a
    stand-in answered. A test's direct call is recorded, as are
    multiprocessing's ``spawnv_passfds`` starts (recorded once: the same start
    twice in a row is one). A ``fork_exec`` a module bound before the guard
    went in is not seen.
    """
    try:
        import _posixsubprocess
    except ImportError:  # Windows has no fork_exec
        return
    fork_exec = _posixsubprocess.fork_exec
    # Popen's own starts reach this wrapper only where subprocess did not
    # bind fork_exec at import; everywhere else a call seen here is a start
    # of its own, however closely it repeats a recorded one.
    popen_calls_by_attribute = not hasattr(subprocess, "_fork_exec")
    if popen_calls_by_attribute:
        # A Popen whose own fork_exec never comes - the posix_spawn route
        # (close_fds=False with an absolute executable), or an env error
        # raised before any start - would leave its thread's arm set, and
        # thread idents are reused after a join, so a later call could spend
        # a dead thread's arm. The arm's life is therefore bounded to the
        # Popen call that set it: the audit event fires inside
        # _execute_child, and this finally pops whatever that call left
        # behind on its thread.
        execute_child = subprocess.Popen._execute_child

        def arm_bounded_execute_child(*args, **kwargs):
            try:
                return execute_child(*args, **kwargs)
            finally:
                guard._fork_exec_arms.pop(threading.get_ident(), None)

        monkeypatch.setattr(
            subprocess.Popen, "_execute_child", arm_bounded_execute_child
        )

    def recording(*args, **kwargs):
        argv, executables, cwd, env_list = args[0], args[1], args[4], args[5]
        try:
            armed = guard._consume_fork_exec_arm() if popen_calls_by_attribute else None
            if armed is not None and guard._popens_own_fork_exec(
                [_as_text(a) for a in argv],
                [_as_text(c) for c in executables]
                if isinstance(executables, (list, tuple))
                else [],
                armed,
            ):
                # Popen already recorded this start (its audit event fires
                # before its fork_exec on this thread, and arms exactly one
                # skip carrying it) and conftest already held it to the HOME
                # rule at Popen.
                return fork_exec(*args, **kwargs)
        except Exception:  # never break the start itself
            pass
        program = executables[0] if executables else argv[0]
        # env_list None: the child gets this process's environment.
        _hold_to_the_home_rule(
            guard,
            f"_posixsubprocess.fork_exec {_shown([_as_text(a) for a in argv])}",
            [_as_text(a) for a in argv],
            _environment_of(env_list),
            None if cwd is None else _as_text(cwd),
            executable=_as_text(program),
        )
        try:
            guard._record_spawn(
                _as_text(program),
                [_as_text(a) for a in argv],
                _search_path(_environment_of(env_list)),
                _working_directory(cwd),
            )
        except Exception:  # never break the start itself
            pass
        return fork_exec(*args, **kwargs)

    monkeypatch.setattr(_posixsubprocess, "fork_exec", recording)


def _record_forkserver_starts(monkeypatch, guard: ToolGuard) -> None:
    """Record each process a running forkserver is asked to fork.

    The forkserver's own start goes through ``spawnv_passfds``; once it runs, each
    new process (``Process.start`` with the forkserver method, a
    ``ProcessPoolExecutor`` worker on it, the default on Python 3.14) is a fork of
    the server, asked for over a socket with no event in this process. What that
    child starts is recorded nowhere. The HOME rule is applied to the server's own
    start, whose environment each child it forks has, not to each child.
    """
    try:
        from multiprocessing import forkserver
    except ImportError:
        return
    connect = forkserver.connect_to_new_process

    def recording(fds):
        guard._record_spawn(
            None,
            "multiprocessing forkserver start (a child the forkserver forks, "
            "whose starts are not recorded)",
            "",
        )
        return connect(fds)

    monkeypatch.setattr(forkserver, "connect_to_new_process", recording)


def real_tools_opt_out_refusal(
    reason: str | None, module_name: str, allowed_modules: frozenset[str]
) -> str | None:
    """Why a ``runs_real_tools`` mark may not drop the tool guard, or None.

    Only a listed module may opt out (*module_name* is its path as the list names
    it), and only with its reason, so a new test cannot drop the guard by adding the
    mark.
    """
    if module_name not in allowed_modules:
        return (
            f"{module_name} is marked runs_real_tools, and is not one of the modules "
            f"allowed to run real tools here: {sorted(allowed_modules)}"
        )
    if not reason or not reason.strip():
        return f"{module_name} is marked runs_real_tools without a reason="
    return None


def files_left_in(home: Path) -> list[str]:
    """Every file under *home*, relative and in sorted order; directories are not listed."""
    return sorted(
        path.relative_to(home).as_posix()
        for path in Path(home).rglob("*")
        if not path.is_dir()
    )


#: What ASH itself keeps under HOME, relative to it, that a test may leave: install
#: receipts, the MCP server's session configs in ``.cache/ash-mcp``, and the records of
#: the containers a container-mode run started (``.ash/state/containers``, which a
#: cancelled run leaves for the next start's sweep). A test's own
#: HOME is where ASH is meant to write those. Not the rest of ``.ash``: the default
#: bin directory is under the test's own directories, so a tool copied into
#: ``.ash/bin`` ran as the test's own and, allowed here, was never seen.
ASH_HOME_STATE = (".ash/install-receipts", ".cache/ash-mcp", ".ash/state/containers")


def tool_files_left_in(home: Path) -> list[str]:
    """``files_left_in(home)`` without ASH's own state (``ASH_HOME_STATE``).

    What is left is a tool's: semgrep's ``.semgrep``, checkov's ``.cache/checkov``,
    uv's tool directory and cache, written by a tool a test started, in this process
    or in a child.
    """
    return [
        name
        for name in files_left_in(home)
        if not any(name.startswith(f"{state}/") for state in ASH_HOME_STATE)
    ]
