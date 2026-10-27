# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stand-in for ``nbconvert --to python|script``, for tests that replace the tool.

It reads its arguments the way nbconvert 7 does, in the parts the Jupyter converter
depends on, so a converter that hands nbconvert something the real tool would
mishandle fails here too:

- Each notebook argument is expanded with ``glob.glob``, as
  ``NbConvertApp.init_notebooks`` expands it, together with the pattern plus
  ``.ipynb``. A pattern matching no file is an error, as it is for nbconvert.
- ``--output`` goes through ``str.format(notebook_name=...)``, as
  ``NbConvertApp._notebook_filename_to_name`` passes it.
- The output is ``<--output-dir>/<--output>`` plus the exporter's extension: ``.py``
  for ``python``, and for ``script`` the notebook's ``language_info.file_extension``
  or ``.txt``, as ``ScriptExporter`` chooses it.

The converted file holds the notebook's code cells, joined, so whatever the
converter handed nbconvert ends up in it.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
from pathlib import Path

_VALUE_FLAGS = {"--log-level", "--to", "--output", "--output-dir"}


def _value(args: list[str], flag: str) -> str | None:
    return args[args.index(flag) + 1] if flag in args else None


def notebook_patterns(args: list[str]) -> list[str]:
    """The positional arguments: what nbconvert treats as notebook patterns.

    ``args`` is nbconvert's own arguments, or a whole command line: the
    ``jupyter nbconvert`` the uv route is handed, or ``<path>/jupyter-nbconvert``
    as the direct route runs it.
    """
    if "nbconvert" in args:
        args = args[args.index("nbconvert") + 1 :]
    elif args and os.path.basename(args[0]).startswith("jupyter-nbconvert"):
        args = args[1:]
    patterns: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in _VALUE_FLAGS:
            skip = True
        elif not arg.startswith("--"):
            patterns.append(arg)
    return patterns


def accept_stand_in_nbconvert(monkeypatch) -> list[str]:
    """Take any jupyter-nbconvert as one whose nbconvert satisfies ``tool_version``.

    The converter runs a jupyter-nbconvert from PATH only once
    ``verify_pre_installed_tool`` says its nbconvert satisfies the requirement, and a
    stand-in script belongs to no nbconvert distribution, so none would run. Tests
    about anything but that check use this; the check itself is
    test_nbconvert_runs_directly_only_once_verified's subject. Returns the list of
    executables the converter asked about, in order.
    """
    from automated_security_helper.utils import pre_installed_tool

    asked: list[str] = []

    def satisfied(executable, package, *args, **kwargs):
        asked.append(executable)
        return pre_installed_tool.PreInstalledToolVerdict(
            "satisfied", executable, package, ""
        )

    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", satisfied)
    return asked


def expand(pattern: str) -> list[str]:
    """``NbConvertApp.init_notebooks`` for one pattern."""
    found = glob.glob(pattern) + glob.glob(pattern + ".ipynb")
    return list(dict.fromkeys(found))


def run_like_nbconvert(args: list[str]) -> subprocess.CompletedProcess:
    """Convert the notebooks ``args`` name; returns what the process would."""
    notebooks = [
        path for pattern in notebook_patterns(args) for path in expand(pattern)
    ]
    if not notebooks:
        return subprocess.CompletedProcess(
            args, 255, "", "[NbConvertApp] WARNING | pattern matched no files"
        )
    exporter = _value(args, "--to")
    for notebook_path in notebooks:
        notebook = json.loads(Path(notebook_path).read_text(encoding="utf-8"))
        name = os.path.basename(notebook_path)
        name = name[: name.rfind(".")]
        base = (_value(args, "--output") or "{notebook_name}").format(
            notebook_name=name
        )
        if exporter == "python":
            extension = ".py"
        else:
            language_info = notebook.get("metadata", {}).get("language_info", {})
            extension = language_info.get("file_extension", ".txt")
        build_directory = _value(args, "--output-dir") or os.path.dirname(notebook_path)
        code = "".join(
            "".join(cell.get("source", []))
            for cell in notebook.get("cells", [])
            if cell.get("cell_type") == "code"
        )
        Path(build_directory, base + extension).write_text(code, encoding="utf-8")
    return subprocess.CompletedProcess(args, 0, "", "")
