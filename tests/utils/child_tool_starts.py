# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A record of the tools a child ``ash scan`` started, for a test to hold at none.

A child process is outside the unit-test guard (tests/utils/tool_guard.py): the
guard's monkeypatches and audit hook live in the test's own process. A cell that
runs ``ash scan`` in a child gives it ``ChildToolStarts.program`` as its code: the
stubs in ``CHILD_TOOL_PROBE_STUBS`` answer the scan's tool probes without a
process, and this module is how the cell shows it worked.

Three parts, each doing what the others cannot:

* An audit hook installed in the child before anything else runs
  (``ChildToolStarts.prelude``). It appends a line to the log for every process
  start (``subprocess.Popen``, ``os.posix_spawn``, ``os.exec``, ``os.spawn``,
  ``os.system``) whose command names a probed tool, whatever found it: a bare name
  looked up on PATH, a stand-in, or the uv installed with ASH, which the child asks
  for by path before it searches PATH (``uv_tool_runner.bundled_uv_executable``).
  A tool named by path inside a shell ``-c`` command line and a tool run as an
  interpreter's ``-m`` module count too, and the second report subprocess makes
  of one start (``os.posix_spawn`` right after ``subprocess.Popen``) is not a
  second line. This is the record a cell reads.
* Recording stand-ins for ``uv``, ``uvx`` and ``detect-secrets`` first on the
  child's PATH, so a start that does look a probed tool up on PATH reaches a program
  that logs and fails, never the tool. The prelude checks that each name resolves to
  its stand-in before the child's code runs, and ends the child with a line in the
  log when one does not: a directory ahead of the stand-ins on PATH would otherwise
  let the real tool start where the cell looks for it.
* The uv cache and tool directories given to the child. A uv that started, bundled
  or not, and resolved anything leaves its cache directory non-empty, so an entry
  is a start the other two did not see (for example one made through C code that the
  audit hook cannot observe). A uv that resolves nothing leaves none, which is why
  this is a second record, not the first.

``child_env`` only adds to the environment it is given (PATH's front and the uv
directories): every other variable, ``PYTHONPATH`` included, passes through
unchanged, which is what lets a launch scan follow the caller's import path.

The prelude's reading of a command line (which words of an argv can name a tool) is
plain functions with no state, kept apart from the hook in ``_READERS`` so that
``readers`` can run them in the test's own process: the tests that pin the walk call
them on an argv and start nothing. The shell tables, the shell walk and the -m walk
are not copied into this file: the prelude takes the tables from tests/conftest.py's
objects, the shell walk from its ``_shell_command_string`` source and the -m walk
from tests/utils/tool_guard.py's ``_module_run_by`` source when it is built, so the
child reads a command line exactly as the in-process guard does.

The stand-ins are ``#!/bin/sh`` scripts, which Windows does not find on PATH, so the
cells that use this class are skipped off POSIX (``POSIX_ONLY``).
"""

from __future__ import annotations

import inspect
import os
import shlex
from pathlib import Path
from typing import Mapping

import pytest

from tests.utils import tool_guard
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

#: The tools a child scan's availability probes start by name.
PROBED_TOOLS = ("uv", "uvx", "detect-secrets")

#: Skips a cell on a platform where the stand-ins cannot be found on PATH.
POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix",
    reason="the recording stand-ins are #!/bin/sh scripts, which PATH lookup "
    "finds on POSIX only",
)

#: What the exit status of a child is when a stand-in is not what PATH finds.
SHADOWED_EXIT = 97

#: Python source run first in the child, in three parts: the names the hook needs
#: (``@LOG@``, ``@NAMES@`` and ``@STAND_INS@`` are replaced with the quoted log path,
#: the probed names and the stand-ins' directory), the readers of a command line
#: (``_READERS``, run in-process too by ``readers``) and the hook itself. Every name
#: starts with an underscore so it cannot collide with the code that follows in the
#: same namespace.
_PRELUDE_HEAD = """\
from __future__ import annotations

import os as _os
import shutil as _shutil
import sys as _sys

_LOG = @LOG@
_NAMES = @NAMES@
_STAND_INS = @STAND_INS@
_EVENTS = ("subprocess.Popen", "os.posix_spawn", "os.exec", "os.spawn", "os.system")
"""

#: The shell tables the readers use, taken from the root conftest's own objects
#: when the prelude is built (``_tables_source``), so the child reads the set the
#: in-process guard reads: ``_SHELLS``, the shells whose -c runs its first operand;
#: ``_SHELL_OPTIONS_WITH_A_VALUE``, the options whose value is the next argument;
#: ``_SHELL_CLUSTER_LETTERS_WITH_A_VALUE``, the letters that take the next argument
#: from inside a short cluster; ``_SHELL_LONG_FLAGS``, the long options that take no
#: value.
_TABLE_NAMES = (
    "_SHELLS",
    "_SHELL_OPTIONS_WITH_A_VALUE",
    "_SHELL_CLUSTER_LETTERS_WITH_A_VALUE",
    "_SHELL_LONG_FLAGS",
)

#: The readers of a command line: which words of an argv a probed name can hide in.
#: Plain functions of ``_os``, ``_NAMES``, the tables, ``_shell_command_string`` (the
#: root conftest's own shell walk) and ``_module_run_by`` (the tool guard's own -m
#: walk), the last two taken as source from their homes in ``_readers_source``, so
#: ``readers`` can run them in the test's own process on an argv that is never
#: started.
_READERS = '''\
def _named(command):
    """The probed name *command* is, or None; a path counts by its last part."""
    try:
        text = _os.fsdecode(command)
    except Exception:
        return None
    last = _os.path.basename(text.strip()).lower()
    if last.endswith(".exe"):
        last = last[:-4]
    return last if last in _NAMES else None


def _as_text(value):
    return _os.fsdecode(value) if isinstance(value, bytes) else str(value)


def _shell_command_line(arguments):
    """The command string of ``sh [OPTION]... -c STRING``, or None.

    Read by the test conftest's own _shell_command_string, whose source joins this
    text: every option is read first, c is noted wherever a short cluster holds
    it, a value-taking option or letter skips its value, ``--`` and a lone ``-``
    end the options, and STRING is the first operand after them. None when there
    is no -c, when an operand comes before it (a script), or when a long option
    the walk does not know leaves the options unread (it might take a value, and
    then where STRING is would be a guess).
    """
    index, _options_read = _shell_command_string(arguments)
    return None if index is None else arguments[index]


def _module_word(argv):
    """The word a probed name takes when *argv* runs it as an interpreter's -m
    module, or None: the module's top-level package, with the hyphen a probed
    name uses where an import needs an underscore (detect_secrets.main runs
    detect-secrets)."""
    module = _module_run_by(argv)
    if module is None:
        return None
    return module.split(".")[0].replace("_", "-")


def _with_module_words(words):
    """*words* plus, for each word in it that is a Python interpreter, the word
    of the module the rest of the line runs with -m: ``python3 -m detect_secrets
    scan`` inside a shell line names detect-secrets after the interpreter's own
    word, where a word-by-word compare sees only python3."""
    found = list(words)
    for position, word in enumerate(words):
        if _os.path.basename(word).startswith("python"):
            module_word = _module_word(words[position:])
            if module_word is not None:
                found.append(module_word)
    return found


def _words_of(argv):
    """The words of *argv* a probed name can hide in: the program word, every
    word of a shell command line (os.system's string, or the operand after a
    shell's -c wherever its options put it), and the module an interpreter
    runs with -m, read with the interpreter's own option rules
    (_module_run_by) and compared by its top-level package, with the hyphen a
    probed name uses; the -m rule is read on an interpreter that is the program
    and on one that is a word of a shell command line alike."""
    if isinstance(argv, (str, bytes, _os.PathLike)):
        # A shell command line: any word of it can be the tool.
        return _with_module_words(_os.fsdecode(argv).split())
    if not argv:
        return []
    arguments = []
    for argument in argv:
        try:
            arguments.append(_os.fsdecode(argument))
        except Exception:
            arguments.append("")
    words = arguments[:1]
    first = _os.path.basename(arguments[0])
    if first in _SHELLS:
        command = _shell_command_line(arguments)
        if command is not None:
            words += _with_module_words(command.split())
    if first.startswith("python"):
        module_word = _module_word(arguments)
        if module_word is not None:
            words.append(module_word)
    return words


def _popen_reported(frame):
    """Whether the os.posix_spawn audited from *frame* is subprocess's own call
    for a Popen it has already reported: the frame is Popen._posix_spawn, in the
    subprocess module. subprocess takes that path, and so reports one start
    twice, only when the executable has a directory part, no descriptor or
    session option is set and, before Python 3.13, close_fds is off; reading the
    caller instead of predicting those conditions holds whatever the version
    decides, and needs no state shared between starts or threads."""
    try:
        return (
            frame is not None
            and frame.f_code.co_name == "_posix_spawn"
            and frame.f_globals.get("__name__") == "subprocess"
        )
    except Exception:
        return False
'''

#: The hook: it logs a start whose words name a probed tool, then the check that
#: PATH finds each stand-in. ``@SHADOWED_EXIT@`` is replaced with the exit status.
_HOOK = """\
def _note(line):
    fd = _os.open(_LOG, _os.O_WRONLY | _os.O_APPEND | _os.O_CREAT, 0o644)
    try:
        _os.write(fd, (line + "\\n").encode("utf-8", "replace"))
    finally:
        _os.close(fd)


def _audit(event, args):
    if event not in _EVENTS:
        return
    try:
        if event == "os.spawn":
            program, argv = args[1], args[2]
        elif event == "os.system":
            program, argv = None, args[0]
        else:
            program, argv = args[0], args[1]
        # subprocess reports one start twice when it uses posix_spawn (both
        # subprocess.Popen and os.posix_spawn): keep the first report, read
        # from the frame that made the call, and still log a posix_spawn that
        # stands alone (_sys._getframe(1) is the frame the event fired in).
        if event == "os.posix_spawn" and _popen_reported(_sys._getframe(1)):
            return
        words = _words_of(argv)
        found = [
            name
            for name in map(_named, ([program] if program is not None else []) + words)
            if name
        ]
        if found:
            _note(event + " " + found[0] + " " + repr(argv))
    except Exception:
        # An audit hook that raises would break the start it watches.
        return


_sys.addaudithook(_audit)

for _name in _NAMES:
    _found = _shutil.which(_name)
    if _found is None or _os.path.realpath(_os.path.dirname(_found)) != _os.path.realpath(
        _STAND_INS
    ):
        _note("stand-in for " + _name + " is shadowed: PATH finds " + repr(_found))
        raise SystemExit(@SHADOWED_EXIT@)
"""


def _tables_source() -> str:
    """The shell tables as Python source, each the root conftest's object as it is
    now, so a change to the conftest's set reaches the child without a copy to
    keep in step."""
    from tests import conftest as root_conftest

    return "".join(
        f"{name} = {tuple(sorted(getattr(root_conftest, name)))!r}\n"
        for name in _TABLE_NAMES
    )


def _shell_command_string_source() -> str:
    """The root conftest's ``_shell_command_string`` as source: the one shell walk,
    read from its home so the child reads ``sh [OPTION]... -c STRING`` as the
    in-process guard does. It needs only the tables, which ``_tables_source``
    defines under the same names; its annotations are never evaluated, because
    the prelude and ``readers`` both run it under ``from __future__ import
    annotations``."""
    from tests import conftest as root_conftest

    return inspect.getsource(root_conftest._shell_command_string)


def _module_run_by_source() -> str:
    """The tool guard's ``_module_run_by`` as source: the one -m walk, read from
    its home so the child runs what the in-process guard runs. It needs only
    ``_as_text``, which the readers define under the same name."""
    return inspect.getsource(tool_guard._module_run_by)


def _readers_source() -> str:
    """The tables, the two walks taken from their homes and the readers, as the
    prelude carries them."""
    return (
        _tables_source()
        + "\n\n"
        + _shell_command_string_source()
        + "\n\n"
        + _READERS
        + "\n\n"
        + _module_run_by_source()
    )


def readers() -> dict:
    """The prelude's readers of a command line, run in this process.

    The same text the child runs, with ``_os`` and the probed names bound and no
    hook installed, so a test can call ``_words_of`` or ``_shell_command_line`` on
    an argv the way the child's hook would, without starting anything.
    """
    namespace: dict = {"_os": os, "_NAMES": PROBED_TOOLS}
    # This module's own text, never a caller's: the tests read what the child runs,
    # under the future import the prelude's head puts first.
    source = "from __future__ import annotations\n" + _readers_source()
    exec(source, namespace)  # nosec B102 - the prelude's own source
    return namespace


class ChildToolStarts:
    """Stand-ins to put first on a child's PATH, and what the child started."""

    def __init__(self, root: Path) -> None:
        self.directory = root / "child-tool-stand-ins"
        self.log = root / "child-tool-starts.log"
        #: The uv cache and tool directories the child is given, named once here:
        #: ``child_env`` sets them and ``starts`` reads them.
        self.uv_cache = root / "uv-cache"
        self.uv_tools = root / "uv-tools"
        self.uv_directories = (self.uv_cache, self.uv_tools)
        self.directory.mkdir(parents=True)
        for name in PROBED_TOOLS:
            stand_in = self.directory / name
            stand_in.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"{name} $*\" >> {shlex.quote(str(self.log))}\n"
                "exit 1\n",
                encoding="utf-8",
            )
            stand_in.chmod(0o755)

    def child_env(self, env: Mapping[str, str]) -> dict[str, str]:
        """*env* with the stand-ins first on PATH and uv offline in the audited
        directories. Give the child this environment as it will have it: a later
        change to PATH can put a directory ahead of the stand-ins, which the
        prelude's check ends the child for."""
        given = env.copy() if isinstance(env, dict) else dict(env)
        given["PATH"] = f"{self.directory}{os.pathsep}{given.get('PATH', '')}"
        given["UV_CACHE_DIR"] = str(self.uv_cache)
        given["UV_TOOL_DIR"] = str(self.uv_tools)
        given["UV_OFFLINE"] = "1"
        return given

    def prelude(self) -> str:
        """Python source to run first in the child: the audit hook and the check
        that PATH finds each stand-in."""
        head = (
            _PRELUDE_HEAD.replace("@LOG@", repr(str(self.log)))
            .replace("@NAMES@", repr(PROBED_TOOLS))
            .replace("@STAND_INS@", repr(str(self.directory)))
        )
        hook = _HOOK.replace("@SHADOWED_EXIT@", str(SHADOWED_EXIT))
        return head + "\n" + _readers_source() + "\n\n" + hook

    def program(self, source: str) -> str:
        """The code for ``python -c``: the prelude, the stubs that answer the
        scan's tool probes, then *source*."""
        return self.prelude() + CHILD_TOOL_PROBE_STUBS + source

    def starts(self) -> list[str]:
        """Each start the audit hook and the stand-ins logged, then each entry a
        uv left in its directories."""
        called = (
            self.log.read_text(encoding="utf-8").splitlines()
            if self.log.exists()
            else []
        )
        left = [
            str(path.relative_to(directory.parent))
            for directory in self.uv_directories
            if directory.exists()
            for path in sorted(directory.rglob("*"))
        ]
        return [*called, *left]
