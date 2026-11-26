# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The framework names of the installed checkov, read without running checkov.

Shared by the integration gate that compares them with ASH's mirror and floor
(tests/integration/scanners/test_checkov_real_config_and_paths.py) and by the
unit tests of the discovery itself, which plant a fake checkov and need none
installed.
"""

import ast
import os
import shlex
import subprocess  # nosec B404 - the interpreter a console script names
import tempfile
from pathlib import Path
from typing import Optional

import pytest

_SHELLS = ("sh", "bash")


def console_script_interpreter(script_text: str) -> Optional[str]:
    """The interpreter a console script names, or None when it names none.

    The first line is the shebang. pip and uv write a shell trampoline when the
    interpreter's path is too long or holds a space: the shebang then names a
    shell and the second line is ``'''exec' <python> "$0" "$@"``, with the path
    quoted when it holds a space. That line is parsed as the shell does
    (``shlex``), which reduces ``'''exec'`` to ``exec``, so the interpreter is
    the element after it however the path is quoted.
    """
    lines = script_text.splitlines()
    first_line = lines[0].strip() if lines else ""
    if not first_line.startswith("#!"):
        return None
    words = first_line[2:].split()
    if not words:
        return None
    interpreter = words[0]
    if os.path.basename(interpreter) in _SHELLS and len(lines) > 1:
        try:
            trampoline = shlex.split(lines[1])
        except ValueError:
            trampoline = []
        if len(trampoline) > 1 and trampoline[0] == "exec":
            interpreter = trampoline[1]
    return interpreter


def installed_checkov_frameworks(checkov_path: str) -> set:
    """The framework names the installed checkov enumerates, read statically.

    checkov builds ``checkov_runners`` (its --framework and --skip-framework
    vocabulary) from the string constants of the ``CheckType`` class in
    ``checkov/common/bridgecrew/check_type.py``. The package is located through
    the console script's own interpreter with ``importlib.util.find_spec`` on
    the top-level ``checkov`` package (no checkov code runs, and a
    ``pip install --user`` is seen as that interpreter sees it) and the file is
    parsed with ``ast``.

    A console script that names no interpreter this can resolve (no shebang, or
    ``env``) SKIPS: that is the environment, not a checkov change. Once a
    console script was found, everything after it FAILS: an interpreter that
    does not exist or cannot be run to locate the package, a package it cannot
    locate, a located package without the registry file, or an empty parse.
    checkov is installed (the caller found its script), so each means the
    install or a checkov refactor needs a look, and for the registry the
    VCS-configuration floor in checkov_vcs_frameworks.py must be re-measured.
    """
    with open(checkov_path, "rb") as handle:
        script_text = handle.read(4096).decode("utf-8", errors="replace")
    interpreter = console_script_interpreter(script_text)
    if interpreter is None:
        pytest.skip("checkov console script has no shebang; cannot find its env")
    if os.path.basename(interpreter) == "env":
        pytest.skip(f"cannot resolve checkov's interpreter from shebang {interpreter}")
    if not os.path.isfile(interpreter):
        pytest.fail(
            f"checkov's console script {checkov_path} names the interpreter "
            f"{interpreter}, which is not a file"
        )
    # find_spec of the top-level package imports none of it and, without -I,
    # sees a `pip install --user` the way the interpreter does. Run from an
    # empty directory so nothing in the cwd shadows the module.
    with tempfile.TemporaryDirectory() as empty_cwd:
        located = subprocess.run(  # nosec B603 - fixed argv, interpreter from the script
            [
                interpreter,
                "-c",
                (
                    "import importlib.util as u; s = u.find_spec('checkov'); "
                    "print(list(s.submodule_search_locations)[0] if s else '')"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=empty_cwd,
        )
    package_dir = (
        located.stdout.strip().splitlines()[-1] if located.stdout.strip() else ""
    )
    if located.returncode != 0 or not package_dir:
        pytest.fail(
            f"cannot locate the checkov package with {interpreter} "
            f"(exit {located.returncode}): {located.stderr.strip()[-200:]}"
        )
    check_type_py = Path(package_dir) / "common" / "bridgecrew" / "check_type.py"
    if not check_type_py.is_file():
        pytest.fail(
            f"checkov is installed at {package_dir} but {check_type_py} does not "
            "exist: checkov moved its framework registry; re-measure the "
            "VCS-configuration floor in checkov_vcs_frameworks.py against this "
            "checkov"
        )
    tree = ast.parse(check_type_py.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "CheckType":
            frameworks = {
                statement.value.value
                for statement in node.body
                if isinstance(statement, ast.Assign)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            }
            if frameworks:
                return frameworks
    pytest.fail(
        f"{check_type_py} no longer holds a CheckType class with string "
        "constants: checkov refactored its framework registry; re-measure the "
        "VCS-configuration floor in checkov_vcs_frameworks.py"
    )
