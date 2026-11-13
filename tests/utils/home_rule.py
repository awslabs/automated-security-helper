# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HOME rule tests/conftest.py enforces, for code that sees starts it does not.

tests/conftest.py refuses, at subprocess.Popen and before it runs, a child that would
write under the developer's home: a Python or ASH child whose HOME is the developer's
or none, and a tool installer aimed there (_refuse_tool_installs_into_the_developer_home).
Some starts never reach Popen: os.posix_spawn, os.system, os.exec* and os.spawn*, a
fork, and multiprocessing's spawn and forkserver starts, which call _posixsubprocess
directly. tests/utils/tool_guard.py's recorder sees them wherever its guard is in, which
is every unit test, and applies the rule to them through these functions; outside a
guard nothing does. These functions are the rule, exported so that a reader of those
starts can apply it without a second definition of its own.

The rule lives in tests/conftest.py, beside the homes it protects. pytest loads that file
as the module ``conftest``; importing it again as ``tests.conftest`` would build a second
copy, with its own state, and run none of its setup. So these functions call the copy
pytest loaded.
"""

from __future__ import annotations

import functools
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, List, Optional

ROOT_CONFTEST = Path(__file__).resolve().parents[1] / "conftest.py"
#: The sys.modules key tests/conftest.py registers itself under when it is first
#: imported. pytest imports every conftest.py outside a package as ``conftest``, and
#: drops ``sys.modules["conftest"]`` before it imports another (tests/unit/conftest.py,
#: tests/snapshot/conftest.py), so that name stops naming the root conftest.
ROOT_CONFTEST_MODULE = "ash_tests_root_conftest"


@functools.lru_cache(maxsize=1)
def loaded_conftest() -> ModuleType:
    """tests/conftest.py as pytest loaded it.

    Raises RuntimeError outside a pytest run that loaded it: the rule is defined there.
    """
    candidates = [
        sys.modules.get(ROOT_CONFTEST_MODULE),
        sys.modules.get("conftest"),
        *list(sys.modules.values()),
    ]
    for module in candidates:
        path = getattr(module, "__file__", None)
        if path and Path(path).resolve() == ROOT_CONFTEST:
            return module  # type: ignore[return-value]
    raise RuntimeError(f"{ROOT_CONFTEST} is not loaded; the HOME rule is defined there")


def home_rule_refusal(
    args: Any,
    env: Optional[Any] = None,
    cwd: Optional[Any] = None,
    *,
    basetemp: Optional[Any] = None,
    shell: bool = False,
    executable: Optional[Any] = None,
) -> Optional[str]:
    """Why starting ``args`` breaks the HOME rule, or None when it does not.

    ``args``, ``env`` (None for this process's), ``cwd``, ``shell`` and ``executable``
    as subprocess.Popen takes them: ``os.system(line)`` is ``home_rule_refusal(line,
    shell=True)``, and ``os.posix_spawn(path, argv, env)`` is ``home_rule_refusal(argv,
    env, executable=path)``. ``basetemp`` is tmp_path_factory.getbasetemp(), one of the
    run's own directories. Read through env, prefix-command and shell wrappers as the
    Popen guard reads them. That guard gives an env with no HOME the test's home before
    it checks; this answers for the start as given, so such an env breaks the rule here.
    """
    return loaded_conftest().home_rule_refusal(
        args, env, cwd, basetemp=basetemp, shell=shell, executable=executable
    )


def run_temp_roots(basetemp: Optional[Any] = None) -> List[str]:
    """The run's own directories, which are not the developer's even inside the home.

    The temp directories the run started with, pytest's temp root, the session
    directory and ``basetemp``, without one that holds the developer's home or sits in
    their ~/.ash. The HOME rule's exemption, exported so that tests/utils/tool_guard.py
    can count a test's own files by the same definition.
    """
    return loaded_conftest()._run_temp_roots(basetemp)


def inside_the_runs_own_directories(
    path: Any, basetemp: Optional[Any] = None, cwd: Optional[Any] = None
) -> bool:
    """Whether ``path`` is in one of :func:`run_temp_roots`, the run's own directories.

    Each test's home is inside them (under ``basetemp``), and so is everything a test
    makes with tmp_path. Compared as the HOME rule compares, with links resolved and by
    identity, so a link from the run's directories into the developer's home is not
    the run's. A relative ``path`` is taken from ``cwd``.
    """
    conftest = loaded_conftest()
    cwd = os.fsdecode(cwd) if cwd is not None else None
    return any(
        conftest._within(os.fspath(path), root, cwd)
        for root in conftest._run_temp_roots(basetemp)
    )
