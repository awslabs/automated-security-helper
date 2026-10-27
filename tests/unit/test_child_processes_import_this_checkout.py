# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A test that starts a child Python running ASH points it at this checkout.

A child started as ``sys.executable`` imports ``automated_security_helper`` from
wherever the interpreter's installed copy points, unless the test says otherwise.
For an editable install that is the tree it was installed from, which need not be
the checkout under test: a venv shared between worktrees ran another tree's code
in such a child, and the test passed or failed on that code. ``-I`` and ``-E``
children ignore ``PYTHONPATH`` too.

So every child launch in tests/ is denied unless it is routed or allowlisted here:

- a ``-c`` (or ``-`` on stdin) child whose code imports ASH runs that code through
  ``importing_this_checkout`` (tests/utils/helpers.py), which puts this checkout
  first on ``sys.path`` and exits 86 if ASH still comes from elsewhere;
- a ``-m automated_security_helper...`` child, a ``-m pytest`` child (the tests
  it runs import ASH), a script child, or the ``ash`` console script is started
  with ``env=checkout_env(...)``, which puts this checkout first on
  ``PYTHONPATH``, and without ``-I`` or ``-E``, which would ignore it; an isolated
  module child runs ``module_from_this_checkout(module)`` as ``-c`` code instead;
- a ``-c`` child whose code is known and imports nothing from ASH needs nothing;
- anything the scan cannot read (code built at run time, a script path), and the
  starts no env can be given to (pytester's ``runpytest_subprocess``, a
  multiprocessing ``spawn`` or ``forkserver`` child), is listed in ALLOWED with the
  reason it needs no routing. An entry names one launch site: the file, the
  function the call is in, the kind and place of the launch there, and the call
  that takes the command line, with whether it is given a working directory. Each
  call a command line is given to is judged by itself.

The interpreter is ``sys.executable`` or ``sys._base_executable``, however sys or
the name is imported, or ``shutil.which("python...")``; a console script is one of
the CLI's (``pyproject.toml``'s ``[project.scripts]``) found beside the interpreter
or under sys's prefixes. The scan reads, with either as the program:

- each list or tuple, a ``+`` sum of them, and what is appended to it after it is
  assigned (``+=``, ``.append``, ``.extend``), directly, through a name, through
  ``*`` a name or a function of the same file, or as what such a function
  returns, given to a call by position or by keyword, or assigned, renamed and
  then given;
- a call given the program by itself and its arguments one by one (``os.execl``,
  ``os.spawnl``, asyncio's ``create_subprocess_exec``, pexpect, sh, pytester's
  ``run``, a helper of the suite), and plumbum's ``local[python][...]``;
- a string command line (an f-string or a ``+`` sum) given to ``os.system``,
  ``os.popen``, a subprocess call or ``create_subprocess_shell``, or split with
  shlex;
- the env such a call is given: through a name, a function, a conditional, or a
  ``functools.partial`` and each of its runs, and not routed once its PYTHONPATH
  is set, dropped or replaced (a value keeping the old PYTHONPATH adds entries;
  what an added entry holds is not read), whether through its own name, another
  name bound to it, or a function of the same file it is given to. A key is read
  when it is written out (not an f-string), or is the name of a ``for`` that does
  not bind it again, over written-out names or over the names a comprehension
  keeps by a plain ``startswith`` of written-out prefixes (a child pytest dropping
  this session's ``PYTEST_*``); any other key may be PYTHONPATH. Given to a call
  the scan cannot read, other than a launch given it as ``env=`` or a call that
  only reads or copies it, it is not routed.

A ``-c`` or ``-m`` with nothing after it, and an interpreter given no script (which
reads its code from standard input), count as code or a module it cannot read.
A bare interpreter command line with nothing to read is a value, not a start,
only when every call it is given to is known to take it as one (_VALUE_TAKERS):
a finished run's record (a CompletedProcess subclass takes ``args`` beside
``returncode``), an expected argv the suite's checker is handed, a read or a
copy. Anything else keeps the launch -- an explicit ``-``, an ``input=`` or
``stdin=`` keyword, and every callee not on that closed list, because a
launcher the scan does not know by name starts it on the suite's own standard
input. What it does not read: a command line built in another file and only run here, and a bare
``"ash"`` left to a PATH lookup. In this suite a bare ``"ash"`` list is an expected
command line or a parser's input, and the ones started are the home guard's refusal
cases in tests/unit/test_conftest_helpers.py, which start nothing.

Known limits. These start ASH unrouted and are not found; each is a plant in
tests/test_data/child_launch_shapes/known_limits.py.txt, whose cell goes red when
the scan learns it:

- the interpreter given as ``os.path.realpath`` or ``Path.resolve`` of
  sys.executable, through a conditional or an ``or``, as ``"python3"`` by name, or
  as ``executable=sys.executable`` beside another program name;
- a module run by ``-m coverage run -m ...`` or ``-m cProfile -m ...``: only the
  module right after ``-m`` is read;
- a command line held in an attribute (``self.cmd``), a dict, a parametrize list,
  a ``.copy()``, or a name unpacked from a tuple;
- ``sh -c`` or ``bash -c`` given an f-string or a joined list;
- ``-c`` code that imports a module of the suite that imports ASH, or names ASH in
  two parts;
- a ``%`` mapping (``%(name)s``), and a ``str.format`` or ``%`` template held in a
  name (a written-out template is read);
- pytester's ``runpytest_subprocess`` through an alias;
- a multiprocessing context chosen through a name or by keyword, and a pool on the
  default context, whose children are given sys.path and so import this checkout.

And the other way: an env given to ``os.execve`` by position is not read, so a
routed one is reported.
"""

from __future__ import annotations

import ast
import collections
import dataclasses
import functools
import re
import shlex
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Counter, Dict, FrozenSet, Iterator, List, Optional, Set, Tuple

import pytest

from tests.utils.helpers import iter_repo_files

if sys.version_info >= (3, 11):  # pragma: no cover - depends on the interpreter
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS = REPO_ROOT / "tests"
ASH = "automated_security_helper"
ROUTED = "<routed>"
ISOLATING_FLAGS = {"-I", "-E"}
#: The CLI's console scripts, each of which imports ASH from the installed copy.
CONSOLE_SCRIPTS = frozenset(
    tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]["scripts"]
)


def _a_console_script_name(text: str) -> bool:
    """``ash``, ``ashv3.exe`` or ``ash{}`` (an f-string's hole): a console script's
    name, with or without a suffix."""
    return any(
        text == name or text.startswith((f"{name}.", f"{name}{{"))
        for name in CONSOLE_SCRIPTS
    )


_BARE_INTERPRETER = (
    "-I -S on automated_security_helper/assets/install-pinned-tool.py, which loads "
    "the checkout's tool_downloads.py by file path from beside itself; a bare "
    "interpreter is what the test is about"
)
_STANDARD_LIBRARY_GROUP_REPORT = (
    "_group_report() is standard-library code that writes whether the child leads "
    "its process group; it imports nothing from ASH"
)
_AUDIT_EVENT_ONLY = (
    "_popen_event() hands the argv to the tool guard's audit hook as "
    "subprocess.Popen would; no process starts"
)
_SELECTION_TOOL = (
    "a test-selection tool a developer runs from the repository root "
    "(tests/unit/test_test_selection_tool_location.py checks it runs this "
    "interpreter's pytest, with subprocess.run faked): `-m pytest` puts that "
    "working directory, the checkout, first on sys.path"
)
_PYTEST_ON_THIS_CHECKOUT = (
    "pytester's runpytest_subprocess takes no env; the test first puts this "
    "checkout first on PYTHONPATH with monkeypatch.setenv, so the child pytest, "
    "started without -I, imports ASH from it"
)
_FRESH_INTERPRETER = (
    "a multiprocessing child in a new interpreter: multiprocessing hands it the "
    "parent's sys.path, so it imports ASH from where this test process does, this "
    "checkout"
)

#: "<path below the repository>::<function>::<kind>#<place>@<call>" (Launch.key) ->
#: why that one launch needs no routing. Each entry allows one launch site; a launch
#: the function gains, of the same kind or another, the same command line given to
#: another call, or the call given a working directory, has a key of its own and
#: fails.
ALLOWED: Dict[str, str] = {
    "tests/test_data/sandbox_escape/escape_ash_plugins/__init__.py"
    "::SandboxEscapeScanner.scan::unread-script#1@_run_subprocess": (
        "runs the probe the sandbox test names, escape_probe.py or "
        "macos_services_probe.py, which import the standard library only"
    ),
    "tests/test_data/sigterm_stop/sigterm_ash_plugins/__init__.py"
    "::SigtermStopScanner.scan::unread-script#1@_run_subprocess": (
        "runs the blocker the SIGTERM test names, blocker.py, which imports "
        "the standard library only and sleeps until the stop path kills it"
    ),
    "tests/unit/assets/test_install_pinned_tool.py"
    "::TestTheScriptRunsWithNothingInstalled.test_help_works_under_a_bare_interpreter"
    "::isolated-script#1@run": (_BARE_INTERPRETER),
    "tests/unit/assets/test_install_pinned_tool.py"
    "::TestTheScriptRunsWithNothingInstalled"
    ".test_resolving_a_pin_needs_no_third_party_import::unread-code#1@run": (
        "-I -S code that loads install-pinned-tool.py from the checkout with "
        "spec_from_file_location, with no package import"
    ),
    "tests/unit/assets/test_install_pinned_tool.py"
    "::TestLicensesOnly.test_the_mode_works_under_a_bare_interpreter"
    "::isolated-script#1@run": (_BARE_INTERPRETER),
    "tests/unit/assets/test_install_pinned_tool.py"
    "::TestUvToolPins.test_the_mode_prints_them_under_a_bare_interpreter"
    "::isolated-script#1@run": (_BARE_INTERPRETER),
    "tests/unit/cli/mcp/test_mcp_resource_limits.py"
    "::_child_process_scans._ChildProcessScan.execute_scan::unread-code#1@run_command": (
        "the child is _child() or _slow_to_stop(), standard-library code that "
        "records its pid and sleeps; it imports nothing from ASH"
    ),
    "tests/unit/cli/test_genai_guide_ships_with_install.py"
    "::_run_from_wheel::code#1@run+cwd": (
        "imports ASH from the built wheel on PYTHONPATH on purpose, and asserts "
        "automated_security_helper.__file__ is in it; the checkout must not come first"
    ),
    "tests/unit/cli/test_usage_error_exit_code.py"
    "::_start_with_forkserver::fresh-interpreter#1@get_context": (
        f"{_FRESH_INTERPRETER}; its target is os.getpid"
    ),
    "tests/unit/config/test_a_suppression_reason_read_from_the_environment_is_not_written.py"
    "::test_the_recorder_records_a_path_like_start::code#1@run": (
        "-c code built from _RECORDER, which imports only os, sys and subprocess and "
        "refuses every start but ASH's own detect-secrets worker, plus a path-like "
        "Popen of /bin/true that the recorder refuses; it imports nothing from ASH"
    ),
    "tests/unit/deploy/test_deploy_s3_sync_moto_server.py"
    "::run_helper::unread-script#1@run": (
        "runs the deploy S3 sync helper (the Terraform module's ash_s3_sync.py or "
        "the CDK buildspec's heredoc), which imports boto3, not ASH"
    ),
    "tests/unit/models/test_flat_vulnerability_ids_are_per_location.py"
    "::test_an_additional_report_id_is_the_same_in_every_process"
    "::fresh-interpreter#1@get_context": (
        f"{_FRESH_INTERPRETER}; the spawn Pool's children run "
        "_additional_report_id from this test module"
    ),
    "tests/snapshot/test_snapshot_plugin_registry.py"
    "::test_a_module_an_earlier_test_imported_loads_again"
    "::pytester-subprocess#1@runpytest_subprocess": (_PYTEST_ON_THIS_CHECKOUT),
    "tests/unit/cli/mcp/test_list_scanners_import_order.py"
    "::test_the_probe_passes_in_its_own_interpreter"
    "::pytester-subprocess#1@runpytest_subprocess": (_PYTEST_ON_THIS_CHECKOUT),
    "tests/unit/test_unit_tool_guard.py"
    "::test_the_check_fails_each_test_that_starts_a_tool_or_leaves_its_files"
    "::pytester-subprocess#1@runpytest_subprocess": (_PYTEST_ON_THIS_CHECKOUT),
    "tests/unit/workspace/test_project_isolation_leak_check.py"
    "::test_a_leak_fails_the_test_that_made_it_and_no_other"
    "::pytester-subprocess#1@runpytest_subprocess": (_PYTEST_ON_THIS_CHECKOUT),
    "tests/unit/utils/test_pre_installed_tool.py"
    "::test_a_version_mismatch_summary_names_no_interpreter_and_no_constraint"
    "::unread-script#1@_judge": (
        "the launched program is the planted uv stand-in, a two-line shell "
        "script that prints uv's unsatisfiable marker and exits; "
        "sys.executable is only the --python value that stand-in is asked "
        "about, and no Python child runs"
    ),
    "tests/unit/utils/test_cancel_stops_the_whole_process_tree.py"
    "::test_an_unsandboxed_child_in_a_cancel_scope_leads_its_own_group"
    "::unread-code#1@run_command": (_STANDARD_LIBRARY_GROUP_REPORT),
    "tests/unit/utils/test_cancel_stops_the_whole_process_tree.py"
    "::test_a_sandboxed_child_is_not_given_a_group_here"
    "::unread-code#1@_run_cancellable": (_STANDARD_LIBRARY_GROUP_REPORT),
    "tests/unit/utils/test_cancel_stops_the_whole_process_tree.py"
    "::test_outside_a_cancel_scope_nothing_changes::unread-code#1@run_command": (
        _STANDARD_LIBRARY_GROUP_REPORT
    ),
    "tests/utils/test_tool_guard.py"
    "::test_the_detect_secrets_and_cdk_nag_workers_may_start"
    "::module#1@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/test_tool_guard.py"
    "::test_the_detect_secrets_and_cdk_nag_workers_may_start"
    "::unread-code#1@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/test_tool_guard.py"
    "::test_a_tool_inside_the_landlock_wrapper_is_judged_by_itself"
    "::isolated-unread-script#1@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/test_tool_guard.py"
    "::test_a_tool_inside_the_landlock_wrapper_is_judged_by_itself"
    "::isolated-unread-script#2@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/test_tool_guard.py"
    "::test_a_probe_through_the_landlock_wrapper_is_a_probe"
    "::isolated-unread-script#1@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/test_tool_guard.py"
    "::test_a_probe_through_the_landlock_wrapper_is_a_probe"
    "::isolated-unread-script#2@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/test_tool_guard.py"
    "::test_a_python_running_a_tools_module_is_a_tool_start"
    "::unread-script#1@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/test_tool_guard.py"
    "::test_a_python_running_anything_else_is_no_tool_start"
    "::unread-script#1@_popen_event": (_AUDIT_EVENT_ONLY),
    "tests/utils/optimization.py::run_tests_with_optimization::test-run#1@run": (
        _SELECTION_TOOL
    ),
    "tests/utils/selection.py::get_tests_by_marker::test-run#1@run": _SELECTION_TOOL,
    "tests/utils/selection.py::get_tests_by_keyword::test-run#1@run": _SELECTION_TOOL,
    "tests/utils/selection.py::get_slow_tests::test-run#1@run": _SELECTION_TOOL,
    "tests/utils/selection.py::run_selected_tests::test-run#1@run": _SELECTION_TOOL,
}


@dataclass(frozen=True)
class Launch:
    """One child launch the scan found unrouted, at the call that takes its command
    line."""

    path: str
    line: int
    function: str
    kind: str
    #: Its place among the launches of this kind by this consumer in this function,
    #: from 1, in the order they are written.
    ordinal: int = 1
    column: int = 0
    #: The call that takes the command line, by the name it calls, with "+cwd" when
    #: it is given a working directory.
    consumer: str = ""

    @property
    def key(self) -> str:
        """The launch site: the file, the function the call is in, the kind and
        place of the launch there, and the call. ALLOWED is keyed by it, so an
        entry allows that one launch and no other the function makes or gains: the
        same command line given to another call, or the same call given a working
        directory, is a launch of its own."""
        return (
            f"{self.path}::{self.function}::{self.kind}#{self.ordinal}@{self.consumer}"
        )


#: What sys names the interpreter by.
_INTERPRETER_ATTRIBUTES = frozenset({"executable", "_base_executable"})
#: The sys prefixes the interpreter's own console scripts are installed under.
_PREFIX_ATTRIBUTES = frozenset(
    {"prefix", "exec_prefix", "base_prefix", "base_exec_prefix"}
)
#: A Python interpreter's name, as ``shutil.which`` is asked for it.
_PYTHON_NAME = re.compile(r"python[0-9.]*w?(\.exe)?")
#: Calls given the program and then each argument by itself, which may start
#: with the program alone: sh's ``Command(program)(args...)``, pexpect's
#: ``spawn(program, [args])`` and asyncio's ``create_subprocess_exec``.
_ONE_BY_ONE = frozenset({"Command", "spawn", "create_subprocess_exec"})
#: Calls given the program, then argv[0] again, then each argument by itself.
_PROGRAM_THEN_ARG0 = frozenset(
    {"execl", "execle", "execlp", "execlpe", "spawnl", "spawnle", "spawnlp", "spawnlpe"}
)
#: Calls given the program, then its argv as one list: the list is the command
#: line the scan reads, not the program beside it.
_PROGRAM_THEN_ARGV = frozenset(
    "execv execve execvp execvpe spawnv spawnve spawnvp spawnvpe posix_spawn "
    "posix_spawnp spawnv_passfds".split()
)
#: Calls that run one string as a command line, through a shell or not.
_STRING_RUNNERS = frozenset(
    "system popen getoutput getstatusoutput create_subprocess_shell run Popen call "
    "check_call check_output spawn".split()
)
#: Calls that take the interpreter as a value and start nothing: they read its
#: path, copy or compare it, log it, or record an audit event or a mock call made
#: with it.
_NOT_LAUNCHERS = frozenset(
    "str repr bool len print id hash type isinstance getattr setattr "
    "Path PurePath PosixPath WindowsPath PurePosixPath PureWindowsPath fspath "
    "fsencode dirname basename split splitext realpath abspath normpath normcase "
    "relpath resolve readlink exists lexists isfile isdir islink is_file samefile "
    "which access stat lstat open copy copy2 copyfile copytree move symlink link "
    "join joinpath with_name relative_to startswith endswith index count append "
    "extend insert remove add get setdefault setenv setitem call param approx "
    "escape quote format replace debug info warning error exception log "
    "audit".split()
)
#: Calls a command line can be given that start nothing with it: an audit event
#: (``sys.audit``), a print, a length.
_STARTS_NOTHING = frozenset({"audit", "print", "len", "repr", "isinstance"})
#: Calls a bare interpreter command line, with nothing to read and nothing
#: feeding it, can be given as a VALUE: the reads and copies above, a finished
#: run's record (a CompletedProcess subclass takes ``args`` beside
#: ``returncode``), and the suite's argv checker, which judges a command line
#: and starts nothing (tests/utils/tool_guard.py). This list is closed on
#: purpose: a callee not on it keeps the launch, because a launcher the scan
#: does not know by name still starts the child on the suite's own standard
#: input, and a launcher list (_STRING_RUNNERS) is what the next launcher
#: escapes. A launcher by name is never a value taker, whatever else shares its
#: name: ``call`` reads as a value in _NOT_LAUNCHERS (a mock's call record) but
#: is subprocess.call too, so it is taken back out here.
#:
#: The records are every CompletedProcess subclass and SubprocessError
#: subprocess_utils defines (test_the_value_takers_name_every_finished_run_record
#: holds the list to the module).
_FINISHED_RUN_RECORDS = frozenset(
    {
        "CompletedProcess",
        "CancelledProcess",
        "PostRunError",
        "PostRunErrorProcess",
        "ResultRejectedProcess",
        "SignaledProcess",
        "SpawnFailedProcess",
        "TimedOutProcess",
    }
)
#: Calls that store what they are given for a later use: a pytest parameter, a
#: list, set or dict entry (and a dict's default), an attribute. In
#: _NOT_LAUNCHERS they start nothing themselves, but a bare interpreter stored
#: there reaches whatever runs it later (a parameter into the test body, an
#: item out of the list), and the scan does not follow it there. So a store
#: is no value taker: it keeps the launch, as an unknown callee does.
_STORES_FOR_LATER = frozenset(
    "append extend insert add get setdefault setitem setattr param".split()
)
_VALUE_TAKERS = (
    (
        _NOT_LAUNCHERS
        | _STARTS_NOTHING
        | _FINISHED_RUN_RECORDS
        | frozenset({"_hold_to_the_home_rule"})
    )
    - _STRING_RUNNERS
    - _STORES_FOR_LATER
)
#: Calls an environment can be given that read or copy it and change nothing in it.
_ENV_READERS = frozenset(
    "dict copy deepcopy print len repr str sorted list set tuple isinstance dumps "
    "pformat update ChainMap".split()
)
#: Calls that hand a command line on, copied or joined into one string: what their
#: result is given to is what starts it.
_PASSES_ON = frozenset({"list", "tuple", "join", "list2cmdline"})
#: Interpreter options that print and exit, running no code.
_PRINTS_AND_EXITS = frozenset({"--version", "-V", "--help", "-h", "-?"})
#: multiprocessing start methods whose child is a new interpreter.
_FRESH_START_METHODS = frozenset({"spawn", "forkserver"})
#: pytester calls that run pytest in a new interpreter: no env can be given, so
#: none can be routed.
_PYTEST_SUBPROCESS_RUNS = frozenset({"runpytest_subprocess", "spawn_pytest"})
#: A ``%`` field of printf-style formatting, or an escaped ``%%`` (no name). A
#: mapping key, ``%(key)s``, is a name no value is read for.
_PERCENT_FIELD = re.compile(
    r"%(?:%|(?:\((?P<key>\w+)\))?(?P<name>)[-#0 +*]*\d*(?:\.\d+)?[diouxXeEfFgGcrsa])"
)
#: A ``str.format`` field (``{}``, ``{0}``, ``{name}``, with a conversion and a
#: spec), or an escaped ``{{`` or ``}}`` (no name).
_FORMAT_FIELD = re.compile(r"\{\{|\}\}|\{(?P<name>[^{}!:]*)(?:![rsa])?(?::[^{}]*)?\}")
#: Shell words that end the command a shell string starts with.
_SHELL_SEPARATORS = frozenset({"&&", "||", ";", "|", "&"})


def _call_name(node: ast.AST) -> Optional[str]:
    """The name a call calls: ``f`` for ``f(...)`` and ``a.b.f(...)``."""
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _calls(node: ast.AST, name: str) -> bool:
    """Whether ``node`` is a call of a function named ``name`` (bare or attribute)."""
    return _call_name(node) == name


def _imports_ash(code: str) -> bool:
    """Whether ``code`` imports ASH: an import statement, or a string naming an ASH
    module (for ``import_module`` or ``runpy``). Text that does not parse, such as a
    template with ``{}`` holes, counts when it names ASH at all."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return ASH in code
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name.split(".")[0] == ASH for alias in node.names
        ):
            return True
        if (
            isinstance(node, ast.ImportFrom)
            and (node.module or "").split(".")[0] == ASH
        ):
            return True
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith(ASH)
        ):
            return True
    return False


def _constant_text(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value if isinstance(part, ast.Constant) else "{}"
            for part in node.values
        )
    return None


def _written_out(node: ast.AST) -> Optional[str]:
    """A string written out whole: not an f-string, whose holes _constant_text
    reads as ``{}`` and which can hold any text there."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _binds(node: ast.AST, name: str) -> bool:
    """Whether ``node`` binds ``name`` again: an assignment, ``del`` or walrus to
    it, a ``for``, ``with`` or ``match`` target, an ``except ... as``, an import,
    or a function or class of that name."""
    if isinstance(node, ast.Name):
        return node.id == name and not isinstance(node.ctx, ast.Load)
    if isinstance(node, ast.ExceptHandler):
        return node.name == name
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return any(
            (alias.asname or alias.name.split(".")[0]) == name for alias in node.names
        )
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == name
    if type(node).__name__ in ("MatchAs", "MatchStar"):
        return getattr(node, "name", None) == name
    if type(node).__name__ == "MatchMapping":
        return getattr(node, "rest", None) == name
    return False


class _File:
    """One test file's names and the text each can hold."""

    def __init__(self, path: Path, source: Optional[str] = None):
        self.path = path
        self.tree = ast.parse(
            path.read_text(encoding="utf-8") if source is None else source
        )
        self.parents: Dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
        # Assignments by scope: each function's own (not its nested functions'),
        # and the module's under None. And each function of the file by its name.
        self.scoped: Dict[Optional[ast.AST], Dict[str, List[ast.AST]]] = {}
        self.functions: Dict[str, List[ast.AST]] = {}
        # The names sys is imported as, and each name `from sys import` binds to
        # the attribute it names.
        self.sys_modules: Set[str] = {"sys"}
        self.sys_names: Dict[str, str] = {}
        # Each call by the name it calls, and the answers of the reads below that
        # every launch site asks again.
        self.calls_named: Dict[str, List[ast.Call]] = {}
        self._values: Dict[int, List[ast.AST]] = {}
        self._returns: Dict[str, List[ast.AST]] = {}
        self._interpreter: Dict[int, bool] = {}
        self._console_script: Dict[int, bool] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "sys":
                        self.sys_modules.add(alias.asname or "sys")
            elif (
                isinstance(node, ast.ImportFrom)
                and node.module == "sys"
                and not node.level
            ):
                for alias in node.names:
                    self.sys_names[alias.asname or alias.name] = alias.name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, []).append(node)
            name = _call_name(node)
            if name is not None:
                self.calls_named.setdefault(name, []).append(node)  # type: ignore[arg-type]
            targets: List[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    value = node.value  # type: ignore[attr-defined]
                    scope = self._function_of_node(node)
                    self.scoped.setdefault(scope, {}).setdefault(target.id, []).append(
                        value
                    )

    def _function_of_node(self, node: ast.AST) -> Optional[ast.AST]:
        current = self.parents.get(node)
        while current is not None and not isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            current = self.parents.get(current)
        return current

    def values_of(self, name: ast.Name) -> List[ast.AST]:
        """What ``name`` can hold where it is used: the innermost enclosing scope that
        assigns it, else a parameter of the function using it."""
        if id(name) not in self._values:
            self._values[id(name)] = self._values_of(name)
        return self._values[id(name)]

    def _values_of(self, name: ast.Name) -> List[ast.AST]:
        scope = self._function_of_node(name)
        while True:
            values = self.scoped.get(scope, {}).get(name.id)
            if values:
                return values
            if scope is None:
                break
            parameters = self.parameter_values(name, scope)
            if parameters:
                return parameters
            scope = self._function_of_node(scope)
        return []

    def text(self, node: ast.AST, seen: Optional[Set[str]] = None) -> Optional[str]:
        """The code ``node`` holds, ROUTED if it goes through importing_this_checkout
        or module_from_this_checkout, or None when it cannot be read."""
        seen = set() if seen is None else seen
        if _calls(node, "importing_this_checkout") or _calls(
            node, "module_from_this_checkout"
        ):
            return ROUTED
        constant = _constant_text(node)
        if constant is not None:
            return constant
        if isinstance(node, ast.Call) and node.args and _calls(node, "dedent"):
            return self.text(node.args[0], seen)
        if isinstance(node, ast.Call):
            # A wrapper this scan does not know, such as one that prepends set-up
            # code: what it is given that imports ASH still runs in the child, so
            # the child counts as running ASH. Otherwise its result is unread.
            given = [self.text(arg, seen) for arg in node.args]
            given += [self.text(k.value, seen) for k in node.keywords]
            if ROUTED in given:
                return ROUTED
            if any(text is not None and ASH in text for text in given):
                return "\n".join(t for t in given if t is not None)
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.text(node.left, seen), self.text(node.right, seen)
            if ROUTED in (left, right):
                return ROUTED
            if left is None or right is None:
                return None
            return left + right
        if isinstance(node, ast.Name) and node.id not in seen:
            values = self.values_of(node)
            if not values:
                return None
            texts = [self.text(value, seen | {node.id}) for value in values]
            if ROUTED in texts:
                return ROUTED
            if any(t is None for t in texts):
                return None
            return "\n".join(t for t in texts if t is not None)
        return None

    def parameter_values(self, name: ast.Name, function: ast.AST) -> List[ast.AST]:
        """What a parameter ``name`` of ``function`` is given: its default, and the
        matching argument of each call of that function in this file."""
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        positional = [a.arg for a in function.args.posonlyargs + function.args.args]
        keyword_only = [a.arg for a in function.args.kwonlyargs]
        if name.id not in positional and name.id not in keyword_only:
            return []
        values: List[ast.AST] = []
        defaults = function.args.defaults
        if name.id in positional and defaults:
            offset = len(positional) - len(defaults)
            index = positional.index(name.id)
            if index >= offset:
                values.append(defaults[index - offset])
        for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
            if arg.arg == name.id and default is not None:
                values.append(default)
        method = bool(positional) and positional[0] in ("self", "cls")
        for call in self.calls_named.get(function.name, ()):
            for keyword in call.keywords:
                if keyword.arg == name.id:
                    values.append(keyword.value)
            if name.id in positional:
                index = positional.index(name.id) - (
                    1 if method and isinstance(call.func, ast.Attribute) else 0
                )
                if 0 <= index < len(call.args):
                    values.append(call.args[index])
        return values

    def _module_aliases(self) -> Dict[str, str]:
        """Each name an ``import a.b.c as x`` or ``from a.b import c`` binds, and the
        module it names."""
        aliases: Dict[str, str] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        return aliases

    def path_of(self, node: ast.AST, seen: Optional[Set[str]] = None) -> Optional[Path]:
        """The file ``node`` names, when it is built from ``__file__``, a module's
        ``__file__``, ``.parent``, ``.parents[N]``, ``/`` and string parts."""
        seen = set() if seen is None else seen
        if isinstance(node, ast.Name):
            if node.id == "__file__":
                return self.path
            if node.id in seen:
                return None
            for value in self.values_of(node):
                found = self.path_of(value, seen | {node.id})
                if found is not None:
                    return found
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return Path(node.value)
        if (
            isinstance(node, ast.Call)
            and node.args
            and (_calls(node, "str") or _calls(node, "Path") or _calls(node, "fspath"))
        ):
            return self.path_of(node.args[0], seen)
        if (
            isinstance(node, ast.Call)
            and not node.args
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("resolve", "absolute")
        ):
            return self.path_of(node.func.value, seen)
        if isinstance(node, ast.Attribute):
            if node.attr == "parent":
                inner = self.path_of(node.value, seen)
                return inner.parent if inner is not None else None
            if node.attr == "__file__" and isinstance(node.value, ast.Name):
                module = self._module_aliases().get(node.value.id)
                if module:
                    candidate = REPO_ROOT.joinpath(*module.split("."))
                    for found in (
                        candidate.with_suffix(".py"),
                        candidate / "__init__.py",
                    ):
                        if found.is_file():
                            return found
            return None
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "parents"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, int)
        ):
            inner = self.path_of(node.value.value, seen)
            return inner.parents[node.slice.value] if inner is not None else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = self.path_of(node.left, seen)
            right = _constant_text(node.right)
            if left is not None and right is not None:
                return left / right
        return None

    def script_text(self, node: ast.AST) -> Optional[str]:
        """The source of the script ``node`` names: the repository file it resolves
        to, or what the test writes to it with ``write_text`` in the same scope."""
        path = self.path_of(node)
        if path is not None and path.is_absolute() and path.is_file():
            try:
                return path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return None
        target = node.args[0] if _calls(node, "str") and node.args else node
        if isinstance(target, ast.Name):
            scope = self._function_of_node(target) or self.tree
            written = [
                call.args[0]
                for call in ast.walk(scope)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "write_text"
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == target.id
                and call.args
            ]
            texts = [self.text(arg) for arg in written]
            if texts and all(t is not None for t in texts):
                return "\n".join(t for t in texts if t is not None)
        return None

    def returns_of(self, call: ast.Call) -> List[ast.AST]:
        """What each function of this file that ``call`` can name returns: by its
        bare name, or by the attribute a method or ``Class.method`` call uses."""
        name = _call_name(call)
        if name is None:
            return []
        if name not in self._returns:
            self._returns[name] = [
                node.value
                for function in self.functions.get(name, ())
                for node in ast.walk(function)
                if isinstance(node, ast.Return) and node.value is not None
            ]
        return self._returns[name]

    def sys_attribute(self, node: ast.AST) -> Optional[str]:
        """The attribute of sys ``node`` reads: ``sys.executable``, the same through
        ``import sys as ...``, or a name ``from sys import`` bound and nothing in
        this file assigns. None for anything else."""
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in self.sys_modules
        ):
            return node.attr
        if (
            isinstance(node, ast.Name)
            and node.id in self.sys_names
            and not self.values_of(node)
        ):
            return self.sys_names[node.id]
        return None

    def is_interpreter(self, node: ast.AST, seen: Optional[Set[int]] = None) -> bool:
        """``sys.executable`` or ``sys._base_executable`` (however sys or the name is
        imported), ``shutil.which("python...")``, also through ``str()`` or
        ``Path()``, a name's values where it is used, and a function of this file
        that can return it."""
        if seen is None:
            if id(node) not in self._interpreter:
                self._interpreter[id(node)] = self.is_interpreter(node, set())
            return self._interpreter[id(node)]
        if id(node) in seen:
            return False
        # One set for the whole walk, so that a node reached on two paths is read
        # once: the walk through call sites' arguments can branch at every call.
        seen.add(id(node))
        if self.sys_attribute(node) in _INTERPRETER_ATTRIBUTES:
            return True
        if isinstance(node, ast.Call):
            if node.args and (
                _calls(node, "str") or _calls(node, "Path") or _calls(node, "fspath")
            ):
                return self.is_interpreter(node.args[0], seen)
            if _calls(node, "which") and node.args:
                text = _constant_text(node.args[0])
                if text is not None and _PYTHON_NAME.fullmatch(text):
                    return True
            return any(self.is_interpreter(r, seen) for r in self.returns_of(node))
        if isinstance(node, ast.Name):
            return any(self.is_interpreter(v, seen) for v in self.values_of(node))
        return False

    def _from_the_install(self, node: ast.AST) -> bool:
        """Whether ``node`` reads the interpreter or one of sys's install prefixes."""
        return self.sys_attribute(node) in (
            _INTERPRETER_ATTRIBUTES | _PREFIX_ATTRIBUTES
        )

    def _names_a_console_script(self, node: ast.AST) -> bool:
        """``Path(sys.executable).with_name("ash...")``, ``.parent / "ash"``,
        ``shutil.which("ash")``, ``os.path.join(<the interpreter's directory>,
        "ash")`` or ``Path(sys.prefix, "bin", "ash")``, for each of CONSOLE_SCRIPTS."""
        for inner in ast.walk(node):
            if _calls(inner, "which") and inner.args:
                text = _constant_text(inner.args[0])
                if text is not None and _a_console_script_name(text):
                    return True
            if (
                _calls(inner, "with_name")
                and inner.args
                and isinstance(inner.func, ast.Attribute)
                and any(self._from_the_install(n) for n in ast.walk(inner.func.value))
            ):
                text = _constant_text(inner.args[0])
                if text is not None and _a_console_script_name(text):
                    return True
            if (
                isinstance(inner, ast.BinOp)
                and isinstance(inner.op, ast.Div)
                and any(self._from_the_install(n) for n in ast.walk(inner.left))
            ):
                text = _constant_text(inner.right)
                if text is not None and _a_console_script_name(text):
                    return True
            if (
                isinstance(inner, ast.Call)
                and _call_name(inner) in ("join", "Path", "PurePath")
                and len(inner.args) >= 2
                and any(
                    self._from_the_install(n)
                    for given in inner.args[:-1]
                    for n in ast.walk(given)
                )
            ):
                text = _constant_text(inner.args[-1])
                if text is not None and _a_console_script_name(text):
                    return True
        return False

    def _may_name_a_console_script(self, node: ast.AST, seen: Set[int]) -> bool:
        """Whether a ``with_name`` argument beside the interpreter can be one of
        CONSOLE_SCRIPTS: a name it cannot read, such as a test's parameter, counts."""
        text = _constant_text(node)
        if text is not None:
            return text.startswith("{") or _a_console_script_name(text)
        if isinstance(node, ast.IfExp):
            return self._may_name_a_console_script(
                node.body, seen
            ) or self._may_name_a_console_script(node.orelse, seen)
        if isinstance(node, ast.Name) and id(node) not in seen:
            values = self.values_of(node)
            return not values or any(
                self._may_name_a_console_script(v, seen | {id(node)}) for v in values
            )
        return True

    def is_console_script(self, node: ast.AST, seen: Optional[Set[int]] = None) -> bool:
        """``_is_console_script``, also through ``str()``, a conditional, a name's
        values where it is used, ``with_name`` given a name holding "ash...", and a
        function of this file that can return it."""
        if seen is None:
            if id(node) not in self._console_script:
                self._console_script[id(node)] = self.is_console_script(node, set())
            return self._console_script[id(node)]
        if id(node) in seen:
            return False
        # One set for the whole walk, so that a node reached on two paths is read
        # once: the walk through call sites' arguments can branch at every call.
        seen.add(id(node))
        if self._names_a_console_script(node):
            return True
        if isinstance(node, ast.Call):
            if _calls(node, "str") and node.args:
                return self.is_console_script(node.args[0], seen)
            if (
                _calls(node, "with_name")
                and node.args
                and isinstance(node.func, ast.Attribute)
                and self.is_interpreter_path(node.func.value)
            ):
                return self._may_name_a_console_script(node.args[0], seen)
            return any(self.is_console_script(r, seen) for r in self.returns_of(node))
        if isinstance(node, ast.IfExp):
            return self.is_console_script(node.body, seen) or self.is_console_script(
                node.orelse, seen
            )
        if isinstance(node, ast.Name):
            return any(self.is_console_script(v, seen) for v in self.values_of(node))
        return False

    def is_interpreter_path(self, node: ast.AST) -> bool:
        """Whether ``node`` is built from the interpreter's path, as
        ``Path(sys.executable)`` or a name holding it."""
        return any(self.is_interpreter(inner) for inner in ast.walk(node))

    def function_of(self, node: ast.AST) -> str:
        names = []
        current = self.parents.get(node)
        while current is not None:
            if isinstance(
                current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                names.append(current.name)
            current = self.parents.get(current)
        return ".".join(reversed(names)) or "<module>"

    def _scope_of(self, node: ast.AST) -> ast.AST:
        return self._function_of_node(node) or self.tree

    @staticmethod
    def _assigned_names(statement: ast.AST) -> Set[str]:
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, (ast.AnnAssign, ast.AugAssign))
            else []
        )
        return {t.id for t in targets if isinstance(t, ast.Name)}

    def consumers(
        self, node: ast.AST, depth: int = 0
    ) -> List[Tuple[ast.Call, Optional[ast.AST]]]:
        """The calls ``node`` is passed to: as an argument (by position, starred or
        by keyword), as part of a ``+`` sum, through each name it is assigned to and
        each name assigned from that, and, when a function of this file returns it,
        at each call of that function. Each comes with the call site it is reached
        from when that is a call of such a function, else None."""
        if depth > 8:
            return []
        parent = self.parents.get(node)
        if isinstance(parent, ast.keyword):
            call = self.parents.get(parent)
            return self._consumed_by(call, depth) if isinstance(call, ast.Call) else []
        if isinstance(parent, ast.Call):
            return self._consumed_by(parent, depth) if node in parent.args else []
        if isinstance(parent, ast.Starred) or (
            isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add)
        ):
            return self.consumers(parent, depth + 1)
        if isinstance(parent, ast.Return):
            function = self._function_of_node(parent)
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return []
            found: List[Tuple[ast.Call, Optional[ast.AST]]] = []
            for call in self.calls_named.get(function.name, ()):
                found += [
                    (consumer, site or call)
                    for consumer, site in self.consumers(call, depth + 1)
                ]
            return found
        if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
            names = self._assigned_names(parent)
            found = []
            for use in ast.walk(self._scope_of(parent)):
                if (
                    isinstance(use, ast.Name)
                    and use.id in names
                    and isinstance(use.ctx, ast.Load)
                ):
                    found += self.consumers(use, depth + 1)
            return found
        return []

    def _consumed_by(
        self, call: ast.Call, depth: int
    ) -> List[Tuple[ast.Call, Optional[ast.AST]]]:
        """``call`` as a consumer: none when it starts nothing (an audit event, a
        print), what its result is passed to when it only copies or joins the
        command line (``list()``, ``" ".join()``), else itself."""
        name = _call_name(call)
        if name in _STARTS_NOTHING:
            return []
        if name in _PASSES_ON:
            return self.consumers(call, depth + 1)
        return [(call, None)]

    def calls_starting(self, argv: ast.AST) -> List[ast.Call]:
        """The calls ``argv`` is passed to (see ``consumers``)."""
        return [call for call, _ in self.consumers(argv)]

    def items_of(
        self, node: ast.AST, seen: FrozenSet[str] = frozenset()
    ) -> List[ast.AST]:
        """The command line ``node`` builds, item by item: a list or tuple, a ``+``
        sum of them, a name bound to one, or a function of this file returning one.
        Anything else is one item the scan cannot read."""
        if isinstance(node, (ast.List, ast.Tuple)):
            return _expanded(self, list(node.elts), seen)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.items_of(node.left, seen) + self.items_of(node.right, seen)
        if isinstance(node, ast.Name) and node.id not in seen:
            for value in self.values_of(node):
                if isinstance(value, (ast.List, ast.Tuple, ast.BinOp)):
                    return self.items_of(value, seen | {node.id})
        if isinstance(node, ast.Call):
            key = f"{_call_name(node)}()"
            if key not in seen:
                for value in self.returns_of(node):
                    if isinstance(value, (ast.List, ast.Tuple, ast.BinOp)):
                        return self.items_of(value, seen | {key})
        return [node]

    def appended_items(self, site: ast.AST) -> List[ast.AST]:
        """What is added to the list ``site`` after it is assigned: ``+=``,
        ``.append`` and ``.extend`` of the name it is bound to, in the order they
        are written; an ``.insert`` adds an item the scan cannot read."""
        parent = self.parents.get(site)
        if (
            not isinstance(parent, (ast.Assign, ast.AnnAssign))
            or parent.value is not site
        ):
            return []
        names = self._assigned_names(parent)
        added: List[Tuple[Tuple[int, int], List[ast.AST]]] = []
        for node in ast.walk(self._scope_of(parent)):
            where = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
            if (
                isinstance(node, ast.AugAssign)
                and isinstance(node.op, ast.Add)
                and self._assigned_names(node) & names
            ):
                added.append((where, self.items_of(node.value)))
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in names
            ):
                if node.func.attr == "append" and node.args:
                    added.append((where, [node.args[0]]))
                elif node.func.attr == "extend" and node.args:
                    added.append((where, self.items_of(node.args[0])))
                elif node.func.attr == "insert":
                    added.append((where, [node]))
        return [
            item for _, items in sorted(added, key=lambda a: a[0]) for item in items
        ]

    def string_pieces(self, node: ast.AST) -> Optional[List[object]]:
        """The parts of a string ``node`` builds (an f-string or a ``+`` sum with a
        string in it): text, the interpreter's node where it is put in, or None for
        a part the scan cannot read. None when ``node`` builds no string."""
        if isinstance(node, ast.Constant):
            return [node.value] if isinstance(node.value, str) else None
        if isinstance(node, ast.JoinedStr):
            pieces: List[object] = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    pieces.append(str(part.value))
                elif isinstance(part, ast.FormattedValue):
                    pieces.append(self._string_piece(part.value))
            return pieces
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
        ):
            given = node.right
            values = list(given.elts) if isinstance(given, ast.Tuple) else [given]
            return self._filled(node.left.value, _PERCENT_FIELD, values, {})
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
        ):
            named = {k.arg: k.value for k in node.keywords if k.arg is not None}
            return self._filled(
                node.func.value.value, _FORMAT_FIELD, list(node.args), named
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.string_pieces(node.left)
            right = self.string_pieces(node.right)
            if left is None and right is None:
                return None
            if isinstance(node.left, (ast.List, ast.Tuple)) or isinstance(
                node.right, (ast.List, ast.Tuple)
            ):
                return None
            return (left or [self._string_piece(node.left)]) + (
                right or [self._string_piece(node.right)]
            )
        return None

    def _filled(
        self,
        template: str,
        field: "re.Pattern[str]",
        positional: List[ast.AST],
        named: Dict[str, ast.AST],
    ) -> List[object]:
        """The pieces of ``template`` with each field (``%s`` or ``{}``) filled in
        from the values given, in order, by index or by name; a field with no value
        the scan can read is a piece it cannot read."""
        pieces: List[object] = []
        last, auto = 0, 0
        for match in field.finditer(template):
            pieces.append(template[last : match.start()])
            last = match.end()
            name = match.group("name")
            if name is None:  # an escaped "%%", "{{" or "}}"
                pieces.append(match.group(0)[0])
                continue
            value: Optional[ast.AST]
            if name == "":
                value = positional[auto] if auto < len(positional) else None
                auto += 1
            elif name.isdigit():
                index = int(name)
                value = positional[index] if index < len(positional) else None
            else:
                value = named.get(name)
            pieces.append(None if value is None else self._string_piece(value))
        pieces.append(template[last:])
        return pieces

    def _string_piece(self, node: ast.AST) -> object:
        if self.is_interpreter(node):
            return node
        text = self.text(node)
        return (
            text if text is not None and text != ROUTED and "\n" not in text else None
        )

    def environment_rewritten(self, name: ast.Name) -> bool:
        """Whether the environment bound to ``name`` has its PYTHONPATH set,
        dropped or replaced in the scope that uses it, or has a key the scan cannot
        read written: ``env["PYTHONPATH"] = ...``, ``env[key] = ...``, ``del``,
        ``.pop``, ``.setdefault``, ``.clear``, ``.popitem``, ``|=``, or an
        ``.update`` that is not a literal without PYTHONPATH. A PYTHONPATH that is
        set to a value keeping the one it had (``env.get("PYTHONPATH")`` in it) adds
        entries and keeps the checkout on it; the scan does not read what an added
        entry holds.

        The same is asked of each other name the environment is bound to
        (``alias = env``), and of the parameter of a function of this file it is
        given to. Given to any other call, it counts as rewritten unless the call is
        known to leave it alone: one of _ENV_READERS, a launch given it as ``env=``,
        or an ``os.exec*``/``os.spawn*`` call given it by position. Stored where no
        name holds it (an attribute, an item), it counts as rewritten too."""
        return self._rewritten_in(self._scope_of(name), name.id, frozenset())

    def _rewritten_in(
        self, scope: ast.AST, env: str, seen: FrozenSet[Tuple[int, str]]
    ) -> bool:
        if (id(scope), env) in seen:
            return False
        seen = seen | {(id(scope), env)}
        for node in ast.walk(scope):
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == env
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                statement = self.parents.get(node)
                kept = isinstance(statement, ast.Assign) and self._reads_pythonpath_of(
                    statement.value, env
                )
                # A value that keeps the old PYTHONPATH counts only for a key read
                # as written-out names.
                if self._may_be_pythonpath(node.slice) and not (
                    kept and self._keys_of(node.slice) is not None
                ):
                    return True
            if (
                isinstance(node, ast.AugAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == env
            ):
                return True
            if (
                isinstance(node, (ast.Assign, ast.AnnAssign))
                and isinstance(node.value, ast.Name)
                and node.value.id == env
            ):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if not isinstance(target, ast.Name):
                        return True
                    if target.id != env and self._rewritten_in(scope, target.id, seen):
                        return True
            if not isinstance(node, ast.Call):
                continue
            if self._given_away(node, env, seen):
                return True
            if not (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == env
            ):
                continue
            method = node.func.attr
            if method in ("clear", "popitem"):
                return True
            if method in ("pop", "setdefault"):
                if not node.args or self._may_be_pythonpath(node.args[0]):
                    return True
            if method == "update":
                if any(k.arg in (None, "PYTHONPATH") for k in node.keywords):
                    return True
                for given in node.args:
                    if not isinstance(given, ast.Dict) or any(
                        k is None or _written_out(k) in (None, "PYTHONPATH")
                        for k in given.keys
                    ):
                        return True
        return False

    def _given_away(
        self, call: ast.Call, env: str, seen: FrozenSet[Tuple[int, str]]
    ) -> bool:
        """Whether ``call`` is given the environment ``env`` names, by position or by
        keyword, and may rewrite it (see ``environment_rewritten``)."""
        given: List[Tuple[object, ast.AST]] = [
            (position, arg)
            for position, arg in enumerate(call.args)
            if isinstance(arg, ast.Name) and arg.id == env
        ]
        given += [
            (keyword.arg, keyword.value)
            for keyword in call.keywords
            if isinstance(keyword.value, ast.Name) and keyword.value.id == env
        ]
        if not given:
            return False
        name = _call_name(call)
        if name in _ENV_READERS:
            return False
        functions = [
            function
            for function in (
                self.functions.get(call.func.id, [])
                if isinstance(call.func, ast.Name)
                else []
            )
            if not isinstance(self.parents.get(function), ast.ClassDef)
        ]
        if functions:
            for function in functions:
                parameters = _parameters_given(function, [where for where, _ in given])
                if parameters is None or any(
                    self._rewritten_in(function, parameter, seen)
                    for parameter in parameters
                ):
                    return True
            return False
        if all(where == "env" for where, _ in given):
            return False
        if name in _PROGRAM_THEN_ARGV or name in _PROGRAM_THEN_ARG0:
            return False
        return True

    def _may_be_pythonpath(self, key: ast.AST) -> bool:
        """Whether a key of an environment can be PYTHONPATH: True when the scan
        cannot read it. A key is read as written-out names (_keys_of), or as the
        variable of a ``for`` over names a filter keeps by their prefix
        (_key_prefixes), which is PYTHONPATH only when PYTHONPATH has one of those
        prefixes."""
        keys = self._keys_of(key)
        if keys is not None:
            return "PYTHONPATH" in keys
        prefixes = self._key_prefixes(key)
        return prefixes is None or "PYTHONPATH".startswith(prefixes)

    def _keys_of(self, key: ast.AST) -> Optional[List[str]]:
        """The names a key of an environment can be: written out, or the variable
        of an enclosing ``for`` over a list, tuple or set of written-out names. None
        when the scan cannot read it, an f-string among them: its holes can hold
        any text."""
        text = _written_out(key)
        if text is not None:
            return [text]
        loop = self._loop_binding(key)
        if loop is None or not isinstance(loop.iter, (ast.List, ast.Tuple, ast.Set)):
            return None
        names = [_written_out(item) for item in loop.iter.elts]
        return [n for n in names if n is not None] if None not in names else None

    def _key_prefixes(self, key: ast.AST) -> Optional[Tuple[str, ...]]:
        """The prefixes every name a key of an environment can be starts with, when
        it is the variable of an enclosing ``for`` over a list, set or generator
        comprehension that yields its own variable and keeps it by a plain
        ``startswith`` of one or more written-out prefixes: ``for name in [name for
        name in env if name.startswith("PYTEST_")]``. None for any other key."""
        loop = self._loop_binding(key)
        if loop is None or not isinstance(
            loop.iter, (ast.ListComp, ast.SetComp, ast.GeneratorExp)
        ):
            return None
        comprehension = loop.iter
        if len(comprehension.generators) != 1:
            return None
        generator = comprehension.generators[0]
        if not (
            isinstance(generator.target, ast.Name)
            and isinstance(comprehension.elt, ast.Name)
            and comprehension.elt.id == generator.target.id
        ):
            return None
        for condition in generator.ifs:
            prefixes = self._startswith_prefixes(condition, generator.target.id)
            if prefixes is not None:
                return prefixes
        return None

    @staticmethod
    def _startswith_prefixes(
        condition: ast.AST, name: str
    ) -> Optional[Tuple[str, ...]]:
        """The written-out prefixes of ``<name>.startswith(<prefixes>)``, given no
        start or end: a string or a tuple of strings. None for any other test."""
        if not (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Attribute)
            and condition.func.attr == "startswith"
            and isinstance(condition.func.value, ast.Name)
            and condition.func.value.id == name
            and len(condition.args) == 1
            and not condition.keywords
        ):
            return None
        given = condition.args[0]
        items = given.elts if isinstance(given, ast.Tuple) else [given]
        prefixes = [_written_out(item) for item in items]
        if not prefixes or None in prefixes:
            return None
        return tuple(p for p in prefixes if p is not None)

    def _loop_binding(self, key: ast.AST) -> Optional[ast.For]:
        """The enclosing ``for`` whose variable the name ``key`` is, when nothing in
        the loop's body or its ``else`` binds that name again. None otherwise."""
        if not isinstance(key, ast.Name):
            return None
        current = self.parents.get(key)
        while current is not None:
            if (
                isinstance(current, ast.For)
                and isinstance(current.target, ast.Name)
                and current.target.id == key.id
            ):
                rebound = any(
                    _binds(node, key.id)
                    for statement in [*current.body, *current.orelse]
                    for node in ast.walk(statement)
                )
                return None if rebound else current
            current = self.parents.get(current)
        return None

    @staticmethod
    def _reads_pythonpath_of(value: ast.AST, env: str) -> bool:
        """Whether ``value`` reads ``env``'s own PYTHONPATH: ``env.get("PYTHONPATH")``
        or ``env["PYTHONPATH"]``."""
        for node in ast.walk(value):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == env
                and node.args
                and _constant_text(node.args[0]) == "PYTHONPATH"
            ):
                return True
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == env
                and isinstance(node.ctx, ast.Load)
                and _constant_text(node.slice) == "PYTHONPATH"
            ):
                return True
        return False

    def invocations_of(self, call: ast.Call) -> List[ast.Call]:
        """The calls of the name ``call``'s result is assigned to, in its scope:
        how a ``functools.partial`` is run."""
        parent = self.parents.get(call)
        if (
            not isinstance(parent, (ast.Assign, ast.AnnAssign))
            or parent.value is not call
        ):
            return []
        names = self._assigned_names(parent)
        return [
            node
            for node in ast.walk(self._scope_of(parent))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in names
        ]


def _keyword(call: ast.Call, name: str) -> Optional[ast.AST]:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _parameters_given(function: ast.AST, places: List[object]) -> Optional[List[str]]:
    """The parameters of ``function`` the arguments at ``places`` (a position, or a
    keyword's name) are bound to; None when one of them lands in ``*args`` or
    ``**kwargs``, or nowhere, where the scan cannot follow it."""
    arguments = function.args  # type: ignore[attr-defined]
    positional = [a.arg for a in arguments.posonlyargs + arguments.args]
    named = positional[len(arguments.posonlyargs) :] + [
        a.arg for a in arguments.kwonlyargs
    ]
    bound: List[str] = []
    for place in places:
        if isinstance(place, int) and place < len(positional):
            bound.append(positional[place])
        elif isinstance(place, str) and place in named:
            bound.append(place)
        else:
            return None
    return bound


def _routed_value(
    file: _File, node: ast.AST, seen: frozenset = frozenset(), drop_none: bool = False
) -> bool:
    """Whether the environment ``node`` gives is ``checkout_env(...)``: directly,
    through a name every binding of which is one and whose PYTHONPATH nothing then
    rewrites (``_File.environment_rewritten``), through a function of this file
    every ``return`` of which is one, or through both branches of a conditional."""
    if _calls(node, "checkout_env"):
        return True
    if isinstance(node, ast.IfExp):
        guarded = None
        test = node.test
        if (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.IsNot)
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None
        ):
            guarded = test.left.id
        body_ok = _routed_value(
            file,
            node.body,
            seen,
            drop_none=isinstance(node.body, ast.Name) and node.body.id == guarded,
        )
        return body_ok and _routed_value(file, node.orelse, seen)
    if isinstance(node, ast.Name) and id(node) not in seen:
        values = [
            v
            for v in file.values_of(node)
            if not (drop_none and isinstance(v, ast.Constant) and v.value is None)
        ]
        return (
            bool(values)
            and all(_routed_value(file, v, seen | {id(node)}) for v in values)
            and not file.environment_rewritten(node)
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id not in seen
    ):
        for function in ast.walk(file.tree):
            if (
                isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                and function.name == node.func.id
            ):
                returns = [
                    r.value
                    for r in ast.walk(function)
                    if isinstance(r, ast.Return) and r.value is not None
                ]
                return bool(returns) and all(
                    _routed_value(file, r, seen | {node.func.id}) for r in returns
                )
    if isinstance(node, ast.Call) and _calls(node, "child_env") and node.args:
        # ChildToolStarts.child_env copies the mapping it is given and writes
        # only PATH and uv's directories (tests/utils/child_tool_starts.py),
        # so it preserves PYTHONPATH: its result is routed iff its first
        # argument is.
        return _routed_value(file, node.args[0], seen)
    return False


def _routed_env(file: _File, calls: List[ast.Call]) -> bool:
    """Whether a call passes an ``env`` that is checkout_env(...) (_routed_value).
    A ``functools.partial`` counts when every run of it does: given a routed env,
    or given none where the partial's own env is routed."""
    for call in calls:
        env = _keyword(call, "env")
        own = env is not None and _routed_value(file, env)
        if not _calls(call, "partial"):
            if own:
                return True
            continue
        runs = file.invocations_of(call)

        def run_is_routed(run: ast.Call, own: bool = own) -> bool:
            given = _keyword(run, "env")
            return own if given is None else _routed_value(file, given)

        if (runs and all(run_is_routed(run) for run in runs)) or (not runs and own):
            return True
    return False


def _expanded(
    file: _File, items: List[ast.AST], seen: frozenset = frozenset()
) -> List[ast.AST]:
    """``items`` with each ``*NAME`` bound to a list or tuple, and each ``*f()`` of a
    function of this file that returns one, replaced by its items, and None items
    dropped (a caller that drops them from the command)."""
    out: List[ast.AST] = []
    for item in items:
        if isinstance(item, ast.Starred) and isinstance(item.value, ast.Call):
            key = f"{_call_name(item.value)}()"
            literal = next(
                (
                    r
                    for r in file.returns_of(item.value)
                    if isinstance(r, (ast.List, ast.Tuple))
                ),
                None,
            )
            if literal is not None and key not in seen:
                out.extend(_expanded(file, list(literal.elts), seen | {key}))
            else:
                out.append(item)
        elif (
            isinstance(item, ast.Starred)
            and isinstance(item.value, ast.Name)
            and item.value.id not in seen
        ):
            values = file.values_of(item.value)
            literal = next(
                (v for v in values if isinstance(v, (ast.List, ast.Tuple))), None
            )
            out.extend(
                _expanded(file, list(literal.elts), seen | {item.value.id})
                if literal
                else [item]
            )
        elif isinstance(item, ast.Constant) and item.value is None:
            continue
        else:
            out.append(item)
    return out


#: An item of a command line the scan cannot read.
_UNREAD = ast.Name(id="<unread>", ctx=ast.Load())


@dataclass
class _Site:
    """A place a child may be started from: the node it is reported at, its command
    line item by item, the index of the program in it, the calls that start it,
    and "shell-" when the command line is one string."""

    node: ast.AST
    items: List[ast.AST]
    index: int
    calls: List[ast.Call]
    form: str = ""


def _program_index(file: _File, items: List[ast.AST]) -> Optional[int]:
    """The index of the interpreter or a console script in a command line: the
    first item, or the first after wrapper words written as strings (``timeout``,
    ``setsid``). None when the command line starts some other program."""
    for index, item in enumerate(items):
        if file.is_interpreter(item) or file.is_console_script(item):
            return index
        if _constant_text(item) is None:
            return None
    return None


def _by_call_site(
    node: ast.AST, consumers: List[Tuple[ast.Call, Optional[ast.AST]]]
) -> List[Tuple[ast.AST, List[ast.Call]]]:
    """The calls that start ``node``, grouped by the site each is reached from:
    ``node`` itself, or each call of a function of the file that returns it."""
    groups: Dict[int, Tuple[ast.AST, List[ast.Call]]] = {}
    for call, site in consumers:
        where = site if site is not None else node
        groups.setdefault(id(where), (where, []))[1].append(call)
    return list(groups.values())


def _list_sites(file: _File) -> Iterator[_Site]:
    """Each list or tuple that holds the interpreter or a console script as its
    program, with a ``+`` sum it is part of and what is appended to it after it
    is assigned (``+=``, ``.append``, ``.extend``)."""
    done: Set[int] = set()
    for node in ast.walk(file.tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        site: ast.AST = node
        while isinstance(file.parents.get(site), ast.BinOp) and isinstance(
            file.parents[site].op,
            ast.Add,  # type: ignore[attr-defined]
        ):
            site = file.parents[site]
        if id(site) in done or isinstance(file.parents.get(site), ast.Compare):
            continue
        done.add(id(site))
        items = file.items_of(site) + file.appended_items(site)
        index = _program_index(file, items)
        if index is None:
            continue
        for where, calls in _by_call_site(site, file.consumers(site)):
            yield _Site(where, items, index, calls)


def _argument_items(file: _File, given: ast.AST) -> List[ast.AST]:
    if isinstance(given, (ast.List, ast.Tuple)):
        return _expanded(file, list(given.elts))
    if isinstance(given, ast.Starred):
        return _expanded(file, [given])
    return [given]


def _argument_sites(file: _File) -> Iterator[_Site]:
    """Each call given the interpreter or a console script by itself, followed by
    its arguments one by one (``os.execl``, ``os.spawnl``, asyncio's
    ``create_subprocess_exec``, pexpect, sh, pytester's ``run``, or a helper of the
    suite that runs what it is given). A call it returns that is called at once
    (``sh.Command(python)(args...)``) gives the rest of the command line."""
    for call in ast.walk(file.tree):
        name = _call_name(call)
        if (
            name is None
            or name in _NOT_LAUNCHERS
            or name in _PROGRAM_THEN_ARGV
            or name.startswith("assert")
        ):
            continue
        for position, given in enumerate(call.args):  # type: ignore[attr-defined]
            if isinstance(given, ast.Starred):
                break
            if not (file.is_interpreter(given) or file.is_console_script(given)):
                continue
            rest = call.args[position:]  # type: ignore[attr-defined]
            if len(rest) < 2 and name not in _ONE_BY_ONE:
                break
            items = [item for g in rest for item in _argument_items(file, g)]
            if name in _PROGRAM_THEN_ARG0 and len(items) > 1:
                items = [items[0], *items[2:]]
            outer: ast.AST = call
            while (
                isinstance(file.parents.get(outer), ast.Call)
                and file.parents[outer].func is outer  # type: ignore[attr-defined]
            ):
                outer = file.parents[outer]
                items += [
                    item
                    for g in outer.args  # type: ignore[attr-defined]
                    for item in _argument_items(file, g)
                ]
            yield _Site(call, items, 0, [outer])  # type: ignore[list-item]
            break


def _subscript_sites(file: _File) -> Iterator[_Site]:
    """Each command built by indexing with the interpreter, as plumbum's
    ``local[python]["-m", module]()`` is, and called."""
    for node in ast.walk(file.tree):
        if not isinstance(node, ast.Subscript) or not (
            file.is_interpreter(node.slice) or file.is_console_script(node.slice)
        ):
            continue
        items: List[ast.AST] = [node.slice]
        outer: ast.AST = node
        while (
            isinstance(file.parents.get(outer), ast.Subscript)
            and file.parents[outer].value is outer  # type: ignore[attr-defined]
        ):
            outer = file.parents[outer]
            items += _argument_items(file, outer.slice)  # type: ignore[attr-defined]
        while (
            isinstance(file.parents.get(outer), ast.Call)
            and file.parents[outer].func is outer  # type: ignore[attr-defined]
        ):
            outer = file.parents[outer]
            items += [
                item
                for g in outer.args  # type: ignore[attr-defined]
                for item in _argument_items(file, g)
            ]
        if isinstance(outer, ast.Call):
            yield _Site(node, items, 0, [outer])


def _shell_words(pieces: List[object]) -> List[ast.AST]:
    """The command line a string's pieces make, as a shell splits it into words:
    the first command in it (between ``&&``, ``;``, ``|`` and the like) that holds
    the interpreter, each of its words a string, the interpreter's node, or
    _UNREAD for one the scan cannot read."""
    marks: Dict[str, ast.AST] = {}
    text: List[str] = []
    for piece in pieces:
        if isinstance(piece, ast.AST):
            mark = f"\x00{len(marks)}\x00"
            marks[mark] = piece
            text.append(mark)
        else:
            text.append("\x01" if piece is None else str(piece))
    try:
        words = shlex.split("".join(text))
    except ValueError:
        return [_UNREAD]
    commands: List[List[ast.AST]] = [[]]
    for word in words:
        if word in _SHELL_SEPARATORS:
            commands.append([])
        elif word in marks:
            commands[-1].append(marks[word])
        elif "\x00" in word or "\x01" in word:
            commands[-1].append(_UNREAD)
        else:
            commands[-1].append(ast.Constant(word))
    return next(
        (command for command in commands if any(w in marks.values() for w in command)),
        [_UNREAD],
    )


def _shell_sites(file: _File) -> Iterator[_Site]:
    """Each string command line with the interpreter in it (an f-string, a ``+`` sum,
    ``%`` formatting or ``str.format``) that is run: given to os.system, os.popen, a
    subprocess call, asyncio's ``create_subprocess_shell`` or pexpect, or split with
    shlex and given to any call. A list joined into one string (``" ".join``,
    ``shlex.join``) is read as the list it was (see ``_PASSES_ON``)."""
    for node in ast.walk(file.tree):
        if not (
            isinstance(node, ast.JoinedStr)
            or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
            or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
            )
        ):
            continue
        parent = file.parents.get(node)
        if isinstance(parent, (ast.FormattedValue, ast.Compare)) or (
            isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add)
        ):
            continue
        pieces = file.string_pieces(node)
        if not pieces or not any(isinstance(piece, ast.AST) for piece in pieces):
            continue
        items = _shell_words(pieces)
        index = _program_index(file, items)
        if index is None:
            continue
        calls: List[ast.Call] = []
        for call, _ in file.consumers(node):
            if _calls(call, "split"):
                calls += file.calls_starting(call)
            elif _call_name(call) in _STRING_RUNNERS:
                calls.append(call)
        yield _Site(node, items, index, calls, form="shell-")


def _flags_and_mode(items: List[ast.AST]) -> Tuple[Set[str], Optional[str], int]:
    """The interpreter options before the mode, the mode ("-c", "-m", "-" or None
    for a script), and the index of what follows the mode. ``-Im`` counts as
    ``-I -m``."""
    flags: Set[str] = set()
    position = 0
    while position < len(items):
        text = _constant_text(items[position])
        if text is None or not text.startswith("-") or text == "--":
            return flags, None, position
        if text in ("-c", "-m", "-"):
            return flags, text, position + 1
        if text.startswith("--"):
            flags.add(text)
            position += 1
            continue
        cluster = text[1:]
        for at, letter in enumerate(cluster):
            if letter in "cm":
                return flags, f"-{letter}", position + 1
            if letter in "XW":
                if at == len(cluster) - 1:
                    position += 1
                break
            flags.add(f"-{letter}")
        position += 1
    return flags, None, position


def _keyword_launches(file: _File) -> Iterator[Tuple[ast.Call, List[ast.AST]]]:
    """Each call that names its program by keyword, as an MCP client's
    ``StdioServerParameters(command=sys.executable, args=[...], env=...)`` does:
    the call and its command line."""
    for node in ast.walk(file.tree):
        if not isinstance(node, ast.Call):
            continue
        command = _keyword(node, "command")
        if command is None or not file.is_interpreter(command):
            continue
        args = _keyword(node, "args")
        items: List[ast.AST] = [command]
        if isinstance(args, (ast.List, ast.Tuple)):
            items += _expanded(file, list(args.elts))
        elif isinstance(args, ast.Name):
            literal = next(
                (
                    v
                    for v in file.values_of(args)
                    if isinstance(v, (ast.List, ast.Tuple))
                ),
                None,
            )
            if literal is not None:
                items += _expanded(file, list(literal.elts))
        yield node, items


def unrouted_launches(path: Path) -> List[Launch]:
    """The child launches in ``path`` that run ASH, or may, and are not routed."""
    return unrouted_launches_in(
        path.read_text(encoding="utf-8"), path.relative_to(REPO_ROOT).as_posix()
    )


def _module_name(file: _File, operand: Optional[ast.AST]) -> Optional[str]:
    """The module a ``-m`` runs: written out, or a name holding it."""
    if operand is None:
        return None
    text = _constant_text(operand)
    if text is None and isinstance(operand, ast.Name):
        text = file.text(operand)
        if text == ROUTED or (text is not None and "\n" in text):
            return None
    return text


def _kind(file: _File, site: _Site) -> Optional[str]:
    """The kind of launch ``site`` is when it runs ASH, or may, unrouted; None when
    it needs nothing. A ``-c`` or ``-m`` with nothing after it, and an interpreter
    given no script (which reads its code from standard input), count as code or a
    module the scan cannot read."""
    calls, items = site.calls, site.items
    head = items[site.index]
    if not file.is_interpreter(head):
        return None if _routed_env(file, calls) else "console-script"
    rest = items[site.index + 1 :]
    flags, mode, position = _flags_and_mode(rest)
    isolated = bool(ISOLATING_FLAGS & flags)
    operand = rest[position] if position < len(rest) else None
    routed = not isolated and _routed_env(file, calls)
    if mode == "-c":
        code = file.text(operand) if operand is not None else None
        if code == ROUTED or (code is not None and not _imports_ash(code)) or routed:
            return None
        return "code" if code else "unread-code"
    if mode == "-m":
        module = _module_name(file, operand)
        runs_tests = module is not None and module.split(".")[0] == "pytest"
        if module is not None and not module.startswith(ASH) and not runs_tests:
            return None
        if routed:
            return None
        if module is None:
            return "unread-module"
        kind = "test-run" if runs_tests else "module"
        return f"isolated-{kind}" if isolated else kind
    if mode is None and operand is None and flags & _PRINTS_AND_EXITS:
        return None
    if mode == "-" or operand is None:
        code = None
        fed = mode == "-"
        for call in calls:
            given = _keyword(call, "input")
            if given is not None:
                code = file.text(given)
                fed = True
            if _keyword(call, "stdin") is not None:
                fed = True
        if code == ROUTED or (code is not None and not _imports_ash(code)) or routed:
            return None
        if not fed and _takes_only_values(calls):
            # A bare interpreter nothing feeds, given only to calls known to
            # take a command line as a value (a record, the argv checker, a
            # read): not a start (the stdin paragraph above). Any other callee
            # keeps the launch: a launcher the scan does not know by name
            # still starts the child on the suite's own stdin.
            return None
        return "stdin"
    code = file.script_text(operand)
    if (code is not None and not _imports_ash(code)) or routed:
        return None
    kind = "script" if code else "unread-script"
    return f"isolated-{kind}" if isolated else kind


def _takes_only_values(calls: List[ast.Call]) -> bool:
    """Whether every one of ``calls`` takes a command line as a value and starts
    nothing (_VALUE_TAKERS). The default is inverted on purpose: one callee not
    on that closed list keeps the launch, since a launcher the scan does not
    know by name (asyncio's exec form, the suite's own runners, an os spawn, a
    name bound to subprocess.run) starts the child on the suite's own standard
    input. No calls at all is a value too: a line nothing is given to starts
    nothing."""
    return all(_call_name(call) in _VALUE_TAKERS for call in calls)


def _numbered(found: List[Launch]) -> List[Launch]:
    """``found`` in the order written, each with its place among the launches of
    its kind by its consumer in its function."""
    counts: Counter[Tuple[str, str, str]] = collections.Counter()
    numbered = []
    for launch in sorted(found, key=lambda l: (l.line, l.column, l.kind)):
        place = (launch.function, launch.kind, launch.consumer)
        counts[place] += 1
        numbered.append(dataclasses.replace(launch, ordinal=counts[place]))
    return numbered


def _consumer(call: ast.Call) -> str:
    """The call a command line is given to, as a key names it: the name it calls
    (``Command()`` for sh's ``Command(python)(...)``), and "+cwd" when it is given a
    working directory, which a reason for allowing it can depend on."""
    name = _call_name(call)
    if name is None and isinstance(call.func, ast.Call):
        name = f"{_call_name(call.func) or '<call>'}()"
    return (name or "<call>") + ("+cwd" if _keyword(call, "cwd") is not None else "")


def unrouted_launches_in(source: str, rel: str) -> List[Launch]:
    """``unrouted_launches`` of ``source`` read as the file ``rel`` below the
    repository. Each call a command line is given to is judged and reported by
    itself, in the function it is in: a list one call starts routed and another
    unrouted is an unrouted launch, and a module-level list is reported where each
    call uses it."""
    file = _File(REPO_ROOT / rel, source)
    sites: List[_Site] = [
        *_list_sites(file),
        *_argument_sites(file),
        *_subscript_sites(file),
        *_shell_sites(file),
        *(_Site(call, items, 0, [call]) for call, items in _keyword_launches(file)),
    ]
    found: List[Launch] = []
    reported: Set[Tuple[int, str]] = set()
    for site in sites:
        for call in {id(call): call for call in site.calls}.values():
            kind = _kind(file, dataclasses.replace(site, calls=[call]))
            if kind is None or (id(call), site.form + kind) in reported:
                continue
            reported.add((id(call), site.form + kind))
            found.append(
                Launch(
                    rel,
                    call.lineno,
                    file.function_of(call),
                    site.form + kind,
                    column=call.col_offset,
                    consumer=_consumer(call),
                )
            )
    for call in ast.walk(file.tree):
        if not isinstance(call, ast.Call):
            continue
        name = _call_name(call)
        if name in _PYTEST_SUBPROCESS_RUNS:
            kind = "pytester-subprocess"
        elif (
            name in ("get_context", "set_start_method")
            and call.args
            and (_constant_text(call.args[0]) or "") in _FRESH_START_METHODS
        ):
            kind = "fresh-interpreter"
        else:
            continue
        found.append(
            Launch(
                rel,
                call.lineno,
                file.function_of(call),
                kind,
                column=call.col_offset,
                consumer=_consumer(call),
            )
        )
    return _numbered(found)


@functools.lru_cache(maxsize=None)
def all_unrouted_launches() -> Tuple[Launch, ...]:
    """Every unrouted launch under tests/, the tests' scratch tree left out (another
    worker's files come and go there; see iter_repo_files)."""
    found: List[Launch] = []
    for path in sorted(p for p in iter_repo_files(TESTS) if p.suffix == ".py"):
        found.extend(unrouted_launches(path))
    return tuple(found)


def _not_allowed(launches: Tuple[Launch, ...]) -> List[Launch]:
    return [launch for launch in launches if launch.key not in ALLOWED]


def test_every_child_running_ash_imports_this_checkout():
    launches = _not_allowed(all_unrouted_launches())
    assert not launches, "\n".join(
        f"{launch.path}:{launch.line} {launch.function}: {launch.kind}"
        f" given to {launch.consumer} ({launch.key})"
        for launch in launches
    )


def test_every_allowed_launch_is_still_there():
    """An entry whose launch is gone, or now routed, is removed, so the list only
    names launches that need it."""
    keys = {launch.key for launch in all_unrouted_launches()}
    assert not set(ALLOWED) - keys, sorted(set(ALLOWED) - keys)


#: Launch shapes the scan must catch, one test function each, kept as text so that the
#: scan of tests/ above does not read them as launches of this suite. The scan reads
#: the file as if it were _PLANTED_AS.
_PLANTS = TESTS / "test_data" / "child_launch_shapes" / "launch_shapes.py.txt"
_PLANTED_AS = "tests/unit/test_zz_plant_launch_shapes.py"
#: The plants that are routed (env=checkout_env(), directly or wrapped by the
#: record helper's child_env, which preserves what checkout_env routed) and so
#: must not be found.
_ROUTED_PLANTS = ("test_s38_control_routed", "test_s47_control_child_env_routed")


@functools.lru_cache(maxsize=None)
def _planted_launches() -> Tuple[Launch, ...]:
    return tuple(unrouted_launches_in(_PLANTS.read_text(encoding="utf-8"), _PLANTED_AS))


def _plant_functions(plants: Path = _PLANTS) -> List[str]:
    """The test functions and test classes of a plant file, by name."""
    tree = ast.parse(plants.read_text(encoding="utf-8"))
    return [
        node.name
        for node in tree.body
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        )
        or (isinstance(node, ast.ClassDef) and node.name.startswith("Test"))
    ]


@pytest.mark.parametrize(
    "function", [name for name in _plant_functions() if name not in _ROUTED_PLANTS]
)
def test_a_planted_launch_shape_is_found(function: str) -> None:
    """Each shape a child running ASH can be started in is read, unrouted."""
    assert any(launch.function == function for launch in _planted_launches()), (
        f"{function} in {_PLANTS.name} starts ASH unrouted and is not found"
    )


def test_the_routed_plant_is_not_found() -> None:
    assert not [
        launch for launch in _planted_launches() if launch.function in _ROUTED_PLANTS
    ]


#: Launch shapes the scan does not read (the module docstring's Known limits), kept
#: as text like _PLANTS and read as the same file.
_KNOWN_LIMITS = TESTS / "test_data" / "child_launch_shapes" / "known_limits.py.txt"
#: The one shape there that is routed and reported anyway.
_ROUTED_BUT_REPORTED = "test_k25_routed_env_given_by_position"


@functools.lru_cache(maxsize=None)
def _known_limit_launches() -> Tuple[Launch, ...]:
    return tuple(
        unrouted_launches_in(_KNOWN_LIMITS.read_text(encoding="utf-8"), _PLANTED_AS)
    )


def _launches_of(launches: Tuple[Launch, ...], name: str) -> List[Launch]:
    """The launches in the plant function ``name``, or in the methods of the plant
    class ``name``."""
    return [
        launch
        for launch in launches
        if launch.function == name or launch.function.startswith(f"{name}.")
    ]


@pytest.mark.parametrize(
    "function",
    [name for name in _plant_functions(_KNOWN_LIMITS) if name != _ROUTED_BUT_REPORTED],
)
def test_a_known_limit_of_the_scan_is_not_found(function: str) -> None:
    """Each of these starts ASH unrouted and the scan does not see it. A scan that
    learns one turns this cell red: move that plant to launch_shapes.py.txt, where it
    must be found, and drop it from the module docstring's Known limits."""
    assert not _launches_of(_known_limit_launches(), function), (
        f"{function} in {_KNOWN_LIMITS.name} is found now; move it to {_PLANTS.name}"
    )


def test_a_routed_env_given_by_position_is_reported() -> None:
    """The known limit the other way: os.execve's env is given by position, which
    the scan does not read, so a routed child is reported. A scan that reads it turns
    this cell red: then the plant moves to launch_shapes.py.txt as a routed control."""
    assert _launches_of(_known_limit_launches(), _ROUTED_BUT_REPORTED)


def test_a_list_joined_into_a_shell_line_is_routed_by_the_call_that_runs_it() -> None:
    """A command line list joined into one string (" ".join, shlex.join) is read as
    that list, given to the call the string is given to: run with checkout_env(), it
    needs nothing."""
    source = textwrap.dedent(
        """\
        import shlex
        import subprocess
        import sys

        from tests.utils.helpers import checkout_env


        def joined():
            line = " ".join([sys.executable, "-m", "automated_security_helper"])
            subprocess.run(line, shell=True, env=checkout_env())


        def shlex_joined():
            line = shlex.join([sys.executable, "-m", "automated_security_helper"])
            subprocess.run(line, shell=True, env=checkout_env())
        """
    )
    assert unrouted_launches_in(source, _PLANTED_AS) == []


def test_a_bare_interpreter_held_as_a_record_is_not_a_launch() -> None:
    """A bare interpreter command line given to a call that is no launcher, with
    nothing to read (no explicit ``-``, no ``input=``, no ``stdin=``), is a
    value: a finished run's record (a CompletedProcess subclass takes ``args``
    beside ``returncode``) or an argv a checker is handed. Nothing feeds the
    child code, and the call starts nothing (measured with an audit hook over
    the spawn events: zero)."""
    source = textwrap.dedent(
        """\
        import sys

        from automated_security_helper.utils.subprocess_utils import (
            CancelledProcess,
            PostRunError,
            PostRunErrorProcess,
            ResultRejectedProcess,
            SignaledProcess,
            SpawnFailedProcess,
            TimedOutProcess,
        )


        def records():
            result = PostRunErrorProcess(
                args=[sys.executable], returncode=3, stdout="", stderr="", error="e"
            )
            raised = PostRunError([sys.executable], 3, "e")
            return result, raised


        def kept():
            # Every finished-run record subprocess_utils defines, by keyword and
            # by position, the way the suite builds them.
            return (
                SignaledProcess(
                    args=[sys.executable],
                    returncode=-9,
                    stdout="",
                    stderr="",
                    error="e",
                    signal=9,
                ),
                TimedOutProcess(args=[sys.executable], returncode=124, error="e"),
                SpawnFailedProcess([sys.executable], 127, "", "", error="e"),
                CancelledProcess(args=[sys.executable], returncode=None, error="e"),
                ResultRejectedProcess(args=[sys.executable], returncode=0, error="e"),
            )


        def finished():
            return subprocess.CompletedProcess(args=[sys.executable], returncode=0)


        def judged():
            _hold_to_the_home_rule([sys.executable], None)
        """
    )
    assert unrouted_launches_in(source, _PLANTED_AS) == []


def test_a_bare_interpreter_fed_or_started_is_still_a_launch() -> None:
    """The must-flag side of the rule above: a launcher by name given the bare
    interpreter starts it on the suite's stdin, a call given ``input=`` or
    ``stdin=`` feeds it, and an explicit ``-`` says it reads code. Each is
    judged as before.

    The fed, piped and explicit plants give the interpreter to a value taker
    (PostRunError), which on its own would make it a value: so each of them is
    flagged by its own check (the ``input=``, the ``stdin=``, the ``-``) and by
    nothing else, and dropping that check turns its plant green. Given to an
    unknown callee instead, the callee alone would flag them."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys


        def launcher():
            subprocess.run([sys.executable])


        def fed():
            PostRunError([sys.executable], input="import automated_security_helper")


        def piped():
            PostRunError([sys.executable], stdin=open("given.py"))


        def explicit():
            PostRunError([sys.executable, "-"])


        def kept_fed():
            SignaledProcess([sys.executable], -9, input="import automated_security_helper")
        """
    )
    found = unrouted_launches_in(source, _PLANTED_AS)
    assert {launch.function for launch in found} == {
        "launcher",
        "fed",
        "piped",
        "explicit",
        "kept_fed",
    }, found
    assert all(launch.kind == "stdin" for launch in found), found


def test_the_value_takers_name_every_finished_run_record() -> None:
    """The records the value rule takes are subprocess_utils' own: every
    CompletedProcess subclass and every SubprocessError it defines. A record
    type added there and missing here would read as an unknown callee, and a
    test building one from the bare interpreter would be flagged as a launch."""
    import subprocess

    from automated_security_helper.utils import subprocess_utils

    defined = {
        name
        for name, value in vars(subprocess_utils).items()
        if isinstance(value, type)
        and value.__module__ == subprocess_utils.__name__
        and issubclass(value, (subprocess.CompletedProcess, subprocess.SubprocessError))
    }
    # The control: the scan found the records the suite builds.
    assert {"PostRunError", "SignaledProcess"} <= defined, defined
    assert defined <= _VALUE_TAKERS, sorted(defined - _VALUE_TAKERS)


def test_a_bare_interpreter_given_to_an_unknown_callee_is_a_launch() -> None:
    """The value rule is a closed list, not a launcher list: a bare interpreter
    is a value only when every call it is given to is known to take it as one
    (a record, a checker, a read). Any other callee keeps the launch, because a
    launcher the scan does not know by name -- asyncio's exec form, the suite's
    own runners, an os spawn, a name bound to subprocess.run or Popen -- still
    starts the child on the suite's own standard input. So does
    subprocess.call, bare or imported, whose name a mock's call record shares:
    a launcher by name is never a value taker."""
    source = textwrap.dedent(
        """\
        import asyncio
        import os
        import subprocess
        import sys


        def exec_form():
            asyncio.create_subprocess_exec(sys.executable)


        def suite_spawn():
            spawn_run([sys.executable])


        def suite_run():
            run_command([sys.executable])


        def os_spawn():
            os.posix_spawn(sys.executable, [sys.executable], {})


        def os_exec():
            os.execv(sys.executable, [sys.executable])


        def aliased_run():
            r = subprocess.run
            r([sys.executable])


        def aliased_popen():
            launcher = subprocess.Popen
            launcher([sys.executable])


        def subprocess_call():
            subprocess.call([sys.executable])


        def imported_call():
            from subprocess import call

            call([sys.executable])
        """
    )
    found = unrouted_launches_in(source, _PLANTED_AS)
    assert {launch.function for launch in found} == {
        "exec_form",
        "suite_spawn",
        "suite_run",
        "os_spawn",
        "os_exec",
        "aliased_run",
        "aliased_popen",
        "subprocess_call",
        "imported_call",
    }, found
    assert all(launch.kind == "stdin" for launch in found), found


def test_a_bare_interpreter_stored_for_a_later_launch_is_a_launch() -> None:
    """A call that stores the command line -- a pytest parameter, a list or
    set it is appended, inserted or added to, a dict default -- hands it on to
    whatever launches it later, and the scan does not follow it there (a
    parameter into the test body, an item out of the list). So the store is
    where it is judged, as an unknown callee is: it keeps the launch."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys

        import pytest


        @pytest.mark.parametrize(
            "argv", [pytest.param([sys.executable], id="stdin")]
        )
        def parametrized(argv):
            subprocess.run(argv, input="import automated_security_helper")


        def appended():
            cmds = []
            cmds.append([sys.executable])
            subprocess.run(cmds[0], input="import automated_security_helper")


        def inserted():
            cmds = []
            cmds.insert(0, [sys.executable])
            subprocess.run(cmds[0], input="import automated_security_helper")


        def defaulted():
            table = {}
            argv = table.setdefault("python", [sys.executable])
            subprocess.run(argv, input="import automated_security_helper")


        def looked_up():
            argv = {}.get("python", [sys.executable])
            subprocess.run(argv, input="import automated_security_helper")


        def appended_alone():
            argv = []
            argv.append(sys.executable)
            subprocess.run(argv, input="import automated_security_helper")


        def extended_alone():
            argv = []
            argv.extend([sys.executable])
            subprocess.run(argv, input="import automated_security_helper")
        """
    )
    found = unrouted_launches_in(source, _PLANTED_AS)
    # appended_alone and extended_alone: the interpreter given to a store by
    # itself, which the argument sites skip by name (_NOT_LAUNCHERS); the line
    # the store builds is still found where it is run.
    assert {
        "parametrized",
        "appended",
        "inserted",
        "defaulted",
        "looked_up",
        "appended_alone",
        "extended_alone",
    } <= {launch.function for launch in found}, found


def test_an_env_that_drops_other_names_in_a_loop_stays_routed() -> None:
    """Names dropped from a checkout_env() in a loop over written-out names are
    read: none is PYTHONPATH, so the env still puts this checkout first."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys

        from tests.utils.helpers import checkout_env


        def _env():
            env = checkout_env()
            for name in ("ASH_MCP_ALLOWED_ROOTS", "GITHUB_ACTIONS"):
                env.pop(name, None)
            return env


        def started():
            subprocess.run(
                [sys.executable, "-m", "automated_security_helper"], env=_env()
            )
        """
    )
    assert unrouted_launches_in(source, _PLANTED_AS) == []


def test_an_env_that_drops_pythonpath_in_a_loop_is_not_routed() -> None:
    """The control: the same loop with PYTHONPATH in it drops the checkout."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys

        from tests.utils.helpers import checkout_env


        def _env():
            env = checkout_env()
            for name in ("ASH_MCP_ALLOWED_ROOTS", "PYTHONPATH"):
                env.pop(name, None)
            return env


        def started():
            subprocess.run(
                [sys.executable, "-m", "automated_security_helper"], env=_env()
            )
        """
    )
    assert [launch.kind for launch in unrouted_launches_in(source, _PLANTED_AS)] == [
        "module"
    ]


def test_an_env_that_drops_names_by_a_prefix_in_a_loop_stays_routed() -> None:
    """Names dropped from a checkout_env() in a loop over the names a filter keeps
    by their prefix are read too: a child pytest drops this session's PYTEST_*
    variables so that it does not take itself for a worker, and PYTHONPATH has
    none of those prefixes, so the env still puts this checkout first."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys

        from tests.utils.helpers import checkout_env

        REPOSITORY = "."


        def by_del():
            env = checkout_env()
            for name in [name for name in env if name.startswith("PYTEST_")]:
                del env[name]
            subprocess.run(
                [sys.executable, "-m", "pytest", "-q"], cwd=REPOSITORY, env=env
            )


        def by_pop_of_two_prefixes():
            env = checkout_env()
            for key in {k for k in env if k.startswith(("PYTEST_", "XDIST_"))}:
                env.pop(key, None)
            subprocess.run([sys.executable, "-m", "automated_security_helper"], env=env)
        """
    )
    assert unrouted_launches_in(source, _PLANTED_AS) == []


def test_an_env_that_drops_names_a_prefix_does_not_bound_is_not_routed() -> None:
    """The controls: a drop loop is read as leaving PYTHONPATH only when the
    names it drops are the filtered ones themselves, kept by a plain
    ``startswith`` of written-out prefixes PYTHONPATH does not have, and the loop
    does not rebind its name. An f-string prefix or key can hold any text. Each of
    these drops PYTHONPATH, or may, and an env that is not checkout_env()'s is not
    routed whatever it drops."""
    source = textwrap.dedent(
        """\
        import os
        import subprocess
        import sys

        from tests.utils.helpers import checkout_env

        ASH = [sys.executable, "-m", "automated_security_helper"]


        def a_prefix_pythonpath_has():
            env = checkout_env()
            for name in [name for name in env if name.startswith("PYTHON")]:
                del env[name]
            subprocess.run(ASH, env=env)


        def an_empty_prefix():
            env = checkout_env()
            for name in [name for name in env if name.startswith("")]:
                del env[name]
            subprocess.run(ASH, env=env)


        def a_name_other_than_the_filtered_one():
            env = checkout_env()
            for name in ["PYTHONPATH" for n in env if n.startswith("PYTEST_")]:
                del env[name]
            subprocess.run(ASH, env=env)


        def a_prefix_read_from_an_offset():
            env = checkout_env()
            for name in [name for name in env if name.startswith("THONPATH", 2)]:
                del env[name]
            subprocess.run(ASH, env=env)


        def a_negated_prefix():
            env = checkout_env()
            for name in [name for name in env if not name.startswith("PYTEST_")]:
                del env[name]
            subprocess.run(ASH, env=env)


        def a_prefix_or_another_name():
            env = checkout_env()
            for name in [
                name
                for name in env
                if name.startswith("PYTEST_") or name == "PYTHONPATH"
            ]:
                del env[name]
            subprocess.run(ASH, env=env)


        def a_prefixed_name_rebound_in_the_loop():
            env = checkout_env()
            for name in [name for name in env if name.startswith("PYTEST_")]:
                name = "PYTHONPATH"
                del env[name]
            subprocess.run(ASH, env=env)


        def a_written_out_name_rebound_in_the_loop():
            env = checkout_env()
            for name in ("GITHUB_ACTIONS",):
                name = "PYTHONPATH"
                env.pop(name, None)
            subprocess.run(ASH, env=env)


        def a_name_rebound_in_the_loops_else():
            env = checkout_env()
            for name in ("GITHUB_ACTIONS",):
                env.pop(name, None)
            else:
                name = "PYTHONPATH"
                env.pop(name, None)
            subprocess.run(ASH, env=env)


        def not_a_checkout_env():
            env = dict(os.environ)
            for name in [name for name in env if name.startswith("PYTEST_")]:
                del env[name]
            subprocess.run(ASH, env=env)


        def a_prefix_from_an_fstring():
            env = checkout_env()
            for name in [name for name in env if name.startswith(f"{PREFIX}")]:
                del env[name]
            subprocess.run(ASH, env=env)


        def a_key_from_an_fstring():
            env = checkout_env()
            env.pop(f"{PREFIX}PATH", None)
            subprocess.run(ASH, env=env)


        def an_updated_key_from_an_fstring():
            env = checkout_env()
            env.update({f"{PREFIX}PATH": ""})
            subprocess.run(ASH, env=env)


        PREFIX = "PYTHON"
        """
    )
    assert sorted(
        launch.function for launch in unrouted_launches_in(source, _PLANTED_AS)
    ) == [
        "a_key_from_an_fstring",
        "a_name_other_than_the_filtered_one",
        "a_name_rebound_in_the_loops_else",
        "a_negated_prefix",
        "a_prefix_from_an_fstring",
        "a_prefix_or_another_name",
        "a_prefix_pythonpath_has",
        "a_prefix_read_from_an_offset",
        "a_prefixed_name_rebound_in_the_loop",
        "a_written_out_name_rebound_in_the_loop",
        "an_empty_prefix",
        "an_updated_key_from_an_fstring",
        "not_a_checkout_env",
    ]


def test_a_command_line_finished_after_it_is_assigned_is_read_whole() -> None:
    """What is added with += or .append is read with the list, so a child running
    known code that imports nothing from ASH needs nothing, as when it is written
    out in one list."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys


        def added():
            cmd = [sys.executable]
            cmd += ["-c", "print(1)"]
            subprocess.run(cmd)


        def appended():
            cmd = [sys.executable, "-c"]
            cmd.append("print(1)")
            subprocess.run(cmd)
        """
    )
    assert unrouted_launches_in(source, _PLANTED_AS) == []


def test_a_second_launch_in_an_allowed_function_is_not_allowed() -> None:
    """An entry allows one launch site, not every launch its function makes: here
    get_tests_by_marker gains a run of ASH beside the pytest run it is allowed."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys


        def get_tests_by_marker(marker):
            subprocess.run([sys.executable, "-m", "pytest", "-m", marker])
            subprocess.run([sys.executable, "-m", "automated_security_helper"])
        """
    )
    launches = tuple(unrouted_launches_in(source, "tests/utils/selection.py"))
    assert len(launches) == 2
    assert [launch.line for launch in _not_allowed(launches)] == [7]


def test_an_env_read_through_an_alias_or_a_helper_stays_routed() -> None:
    """The control for test_s43 to test_s45: an alias that only reads the env, and a
    helper of the file that only reads its parameter, leave PYTHONPATH as
    checkout_env() set it."""
    source = textwrap.dedent(
        """\
        import subprocess
        import sys

        from tests.utils.helpers import checkout_env


        def _show(env):
            print(env.get("PATH"))


        def read_through_an_alias():
            env = checkout_env()
            alias = env
            print(alias["PATH"])
            subprocess.run([sys.executable, "-m", "automated_security_helper"], env=env)


        def read_by_a_helper():
            env = checkout_env()
            _show(env)
            subprocess.run([sys.executable, "-m", "automated_security_helper"], env=env)
        """
    )
    assert unrouted_launches_in(source, _PLANTED_AS) == []


def _with_one_change(rel: str, old: str, new: str, after: str = "") -> str:
    """The text of ``rel`` with the first ``old`` after ``after`` replaced by ``new``.
    Fails when there is none, so a cell built on it cannot pass on a file it no
    longer changes."""
    source = (REPO_ROOT / rel).read_text(encoding="utf-8")
    start = source.index(after) if after else 0
    at = source.index(old, start)
    return source[:at] + new + source[at + len(old) :]


def test_a_new_call_given_an_allowed_command_line_is_not_allowed() -> None:
    """An entry names the call that takes the command line, so another call given
    the same list is a launch of its own. Here the tool guard's _THIS_INTERPRETER,
    allowed where _audit hands it to _hold_to_the_home_rule, is also run with code
    that imports ASH on its standard input."""
    rel = "tests/utils/tool_guard.py"
    source = _with_one_change(
        rel,
        "_THIS_INTERPRETER = [sys.executable]\n",
        "_THIS_INTERPRETER = [sys.executable]\n"
        "\n\n"
        "def _started_with_the_allowed_command_line():\n"
        "    subprocess.run(\n"
        '        _THIS_INTERPRETER, input="import automated_security_helper", text=True\n'
        "    )\n",
    )
    not_allowed = _not_allowed(tuple(unrouted_launches_in(source, rel)))
    assert [launch.function for launch in not_allowed] == [
        "_started_with_the_allowed_command_line"
    ], not_allowed


def test_an_allowed_audit_event_made_a_real_start_is_not_allowed() -> None:
    """The detect-secrets worker's argv is allowed where it is handed to
    _popen_event, which records an audit event and starts nothing. The same argv
    given to subprocess.Popen starts the worker, and needs an entry of its own."""
    rel = "tests/utils/test_tool_guard.py"
    source = _with_one_change(
        rel,
        "    _popen_event(\n",
        "    subprocess.Popen(\n",
        after="def test_the_detect_secrets_and_cdk_nag_workers_may_start(",
    )
    not_allowed = _not_allowed(tuple(unrouted_launches_in(source, rel)))
    assert [(launch.function, launch.kind) for launch in not_allowed] == [
        ("test_the_detect_secrets_and_cdk_nag_workers_may_start", "module")
    ], not_allowed


def test_an_allowed_test_run_given_another_working_directory_is_not_allowed() -> None:
    """A selection tool's pytest run is allowed because `-m pytest` puts the
    working directory, the repository root it is run from, first on sys.path. Given
    a cwd, that reason no longer holds for it."""
    rel = "tests/utils/selection.py"
    source = _with_one_change(
        rel,
        "            capture_output=True,\n",
        '            capture_output=True,\n            cwd="/tmp",\n',
        after="def get_tests_by_marker(",
    )
    not_allowed = _not_allowed(tuple(unrouted_launches_in(source, rel)))
    assert [(launch.function, launch.kind) for launch in not_allowed] == [
        ("get_tests_by_marker", "test-run")
    ], not_allowed
