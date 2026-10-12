# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Start ASH's own interpreter as a child that imports nothing from where it starts.

``python -m`` and ``python -c`` put the working directory first on ``sys.path``:
``-m`` as its full path, ``-c`` as ``''``, which follows a later ``os.chdir``. ASH
usually runs inside the repository it scans, ``ash dependencies install`` takes the
current directory as the source tree, and a scanner's subprocesses start in the
scanned tree by default. A ``pip/``, ``json.py`` or ``automated_security_helper/``
there was therefore imported in place of the real module.

Two measures, because neither covers every supported Python on its own:

* ``-P`` (Python 3.11 and later) stops Python adding the working directory at all.
  The flag rather than ``PYTHONSAFEPATH=1``: the variable is inherited by the child's
  own children, and pip runs ``setup.py`` builds that import modules beside
  ``setup.py`` through exactly that entry.
* The child starts in an empty directory created for it and removed afterwards, so
  on 3.10, which has no ``-P``, the entry Python adds names nothing.

``-I`` would cover both on every version, but it also ignores ``PYTHONPATH`` and the
user site-packages directory, which an install of ASH may depend on.

A child that changes directory after it starts should not rely on this: under 3.10
its ``''`` entry follows it. ``utils/cdk_nag_worker.py`` removes that entry itself
for that reason.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Sequence

#: What makes the interpreter skip the working directory, where it can.
_SAFE_PATH_FLAGS: List[str] = ["-P"] if sys.version_info >= (3, 11) else []


@dataclass(frozen=True)
class PythonChild:
    """The argv to spawn and the directory to spawn it in."""

    argv: List[str]
    cwd: Path


@contextmanager
def python_child(*args: str, parent: Optional[Path] = None) -> Iterator[PythonChild]:
    """ASH's interpreter with ``args``, and an empty directory to start it in.

    ``args`` is everything after the interpreter, such as ``"-m", "pip", "install"``.
    Spawn ``child.argv`` with ``cwd=child.cwd``. The directory is created under
    ``parent`` when given (a sandboxed child can only see the directories its policy
    grants, so a caller under a sandbox passes one it can see) and removed when the
    block ends.
    """
    directory = Path(
        tempfile.mkdtemp(prefix="ash-python-", dir=str(parent) if parent else None)
    ).absolute()
    try:
        yield PythonChild(
            argv=[sys.executable, *_SAFE_PATH_FLAGS, *args], cwd=directory
        )
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def runs_module_or_code(argv: Sequence[str]) -> bool:
    """Whether ``argv`` starts ASH's interpreter with ``-m`` or ``-c``.

    Only interpreter options may come before it, so ``python script.py -c`` is not
    one: a script's own directory is what Python adds for it, and ``-P`` would drop
    that too.
    """
    if not argv or argv[0] != sys.executable:
        return False
    options = iter(argv[1:])
    for arg in options:
        if arg in ("-m", "-c"):
            return True
        if arg in ("-X", "-W"):
            next(options, None)
        elif not arg.startswith("-") or arg == "-":
            return False
    return False
