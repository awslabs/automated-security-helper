# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stand-in programs a test puts on PATH, in a form the host can start.

``CreateProcess`` runs executable images and nothing else, so a script that begins
with a shebang line is never started on Windows. A stand-in there is a
``<name>.py`` script and a ``<name>.bat`` launcher for it, the form a package manager
leaves on PATH. ``.bat`` and not ``.cmd``: the unit tool guard narrows a guarded
name's candidates to ``<name>.bat`` on Windows (``tests/utils/tool_guard.py``). On
POSIX the stand-in is the script itself, with the interpreter in its shebang line.

Windows is decided the way the tool guard decides it, by ``platform.system()``, so a
test that reports Windows to ASH's lookup gets the Windows stand-ins too.

The launcher is read by cmd.exe, and two things in its line are not what Python
writes by default:

* a ``%`` starts a variable reference, so each path has its ``%`` doubled;
* the file is read in the console's active code page, not as UTF-8, and a test cannot
  know which that is: ``chcp 65001`` is common on CI shells, and a path that fits the
  OEM code page would be written one way and read the other. Only ASCII reads the same
  in all of them, so a launcher whose line holds anything else is refused with
  ``ValueError`` before anything is written, on every host.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import NamedTuple

#: A tool that answers ``<name> db status -o json`` with ``status`` and exits ``code``.
STATUS_TOOL = """\
import json, sys
print(json.dumps({status}))
sys.exit({code})
"""


class StandIn(NamedTuple):
    """The files a stand-in is made of."""

    #: The file that holds the program: the script on POSIX, ``<name>.py`` on Windows.
    program: Path
    #: Every file written, the program first.
    files: tuple[Path, ...]


def on_windows() -> bool:
    """Whether the host is Windows, decided as the unit tool guard decides it."""
    return platform.system().lower() == "windows"


def launcher_text(
    python: str | os.PathLike[str], script: str | os.PathLike[str]
) -> str:
    """The ``.bat`` launcher line that starts ``script`` with ``python``.

    A ``%`` in either path is doubled, which is how a batch file spells a literal
    one; the ``%*`` that passes the arguments through is not.
    """

    def literal(path: str | os.PathLike[str]) -> str:
        return os.fspath(path).replace("%", "%%")

    return f'@"{literal(python)}" "{literal(script)}" %*\r\n'


def write_stand_in(
    bin_dir: Path,
    name: str,
    source: str,
    *,
    windows: bool | None = None,
    python: str | None = None,
) -> StandIn:
    """Put a stand-in named ``name`` in ``bin_dir`` that runs ``source``.

    Args:
        bin_dir: An existing directory.
        name: The tool's name, without an extension.
        source: The Python program the stand-in runs.
        windows: Write the Windows form; defaults to the host (``on_windows``).
        python: The interpreter that runs ``source``; defaults to this one.

    Raises:
        ValueError: ``windows`` and the launcher's line holds a character outside
            ASCII, on any host. The message names the directory, the program name or
            the interpreter that holds it. Nothing is written.
    """
    if windows is None:
        windows = on_windows()
    interpreter = sys.executable if python is None else python
    if not windows:
        script = bin_dir / name
        script.write_text(f"#!{interpreter}\n{source}", encoding="utf-8")
        script.chmod(0o755)
        return StandIn(script, (script,))
    script = bin_dir / f"{name}.py"
    launcher = bin_dir / f"{name}.bat"
    text = launcher_text(interpreter, script)
    if not text.isascii():
        holding = " and ".join(
            f'{label} "{value}"'
            for label, value in (
                ("the directory", bin_dir),
                ("the program name", name),
                ("the interpreter", interpreter),
            )
            if not str(value).isascii()
        )
        raise ValueError(
            f"the launcher for {name!r} cannot be written: {holding} holds a "
            "character outside ASCII. cmd.exe reads a batch file in the console's "
            "active code page, which a test cannot know, so such a path could reach "
            "it as a different path and the stand-in would not start. Use a plain "
            "ASCII directory, and a plain ASCII interpreter path, for the test."
        )
    script.write_text(source, encoding="utf-8")
    launcher.write_bytes(text.encode("ascii"))
    return StandIn(script, (script, launcher))


def status_tool(
    bin_dir: Path,
    status: dict,
    code: int,
    *,
    name: str = "grype",
    windows: bool | None = None,
) -> StandIn:
    """Put a ``name`` in ``bin_dir`` that prints ``status`` as JSON and exits ``code``."""
    return write_stand_in(
        bin_dir,
        name,
        STATUS_TOOL.format(status=repr(status), code=code),
        windows=windows,
    )


def search_path(bin_dir: Path, *, windows: bool | None = None) -> str:
    """PATH for a stand-in layout: the stand-ins' directory, then the system's on POSIX.

    Joined with the host's separator: a ``:`` joins nothing on Windows, where one
    follows a drive letter. Windows needs no system directory, because a launcher
    names its interpreter by path, and ``/usr/bin`` there is a place that does not
    exist.
    """
    if windows is None:
        windows = on_windows()
    directories = [str(bin_dir)] if windows else [str(bin_dir), "/usr/bin", "/bin"]
    return os.pathsep.join(directories)
