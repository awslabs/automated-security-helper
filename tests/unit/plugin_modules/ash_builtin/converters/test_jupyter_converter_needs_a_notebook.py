# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The jupyter converter resolves and installs nbconvert only when there is a notebook.

Why this file exists
--------------------
Every scan constructs the jupyter converter and checks its dependencies. The version
probe, ``uv tool run --from nbconvert jupyter-nbconvert --version``, resolves and
downloads nbconvert, and the dependency check runs
``uv tool install --with jupyter nbconvert...`` when it is not installed, so both
wait for a notebook: a repository with no notebook pays for neither, and with no
network the check logs no "Converter jupyter-nbconvert is not available" for a
converter that has nothing to do.

What the test does
------------------
A child interpreter, with a stand-in ``uv`` first on ``PATH`` that records every
call and fails, constructs the converter as the convert phase does, inside
``deferred_tool_version_probes()``, checks its dependencies and converts. The
child turns off the lookup of the uv installed beside its interpreter, which comes
before ``PATH``, so the stand-in is the uv the converter runs. With
no notebook in the tree, uv is asked nothing about nbconvert. With one, it is, as
expected, and so it is when the notebooks cannot be counted, since that is not a count
of zero. A child process because the uv runner memoizes uv's availability and tool
versions process-wide.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="the stand-in uv is a POSIX shell script"
    ),
]

STUB_UV = textwrap.dedent(
    """\
    #!/bin/sh
    echo "$*" >> "$UV_STUB_LOG"
    case "$1" in --version) echo "uv 0.12.24"; exit 0;; esac
    exit 2
    """
)

DRIVER = textwrap.dedent(
    """
    import json, sys
    from pathlib import Path

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.base.uv_tool_mixin import deferred_tool_version_probes
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
    )
    from automated_security_helper.utils import uv_tool_runner

    # The uv beside this interpreter is preferred over PATH; without this the
    # stand-in would never be asked and the real uv would resolve nbconvert.
    uv_tool_runner.bundled_uv_executable = lambda: None

    source = Path(sys.argv[1])
    if sys.argv[2] == "uncountable":
        # The scan set cannot be read, so candidate_input_count answers None.
        def _unreadable(self):
            raise OSError("the scan set could not be read")

        JupyterConverter._notebooks_in_scan_set = _unreadable
    context = PluginContext(
        source_dir=source,
        output_dir=source.parent / "out",
        config=AshConfig(project_name="jupyter-needs-a-notebook"),
    )
    # Built as the convert phase builds it (core/phases/convert_phase.py): the
    # version probe is kept for the dependency check, which runs it only once a
    # notebook needs nbconvert.
    with deferred_tool_version_probes():
        converter = JupyterConverter(context=context)
    satisfied = converter.validate_plugin_dependencies()
    count = converter.candidate_input_count()
    converted = None if count is None else len(converter.convert())
    print(json.dumps({"satisfied": satisfied, "count": count, "converted": converted}))
    """
)


def _run(tmp_path: Path, with_notebook: bool, countable: bool = True):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(STUB_UV, encoding="utf-8")
    uv.chmod(0o755)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    if with_notebook:
        (source / "nb.ipynb").write_text(
            json.dumps(
                {
                    "cells": [
                        {
                            "cell_type": "code",
                            "metadata": {},
                            "execution_count": None,
                            "outputs": [],
                            "source": ["print(1)\n"],
                        }
                    ],
                    "metadata": {},
                    "nbformat": 4,
                    "nbformat_minor": 5,
                }
            ),
            encoding="utf-8",
        )
    log = tmp_path / "uv.log"
    log.write_text("", encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            # The stand-in, and no directory that could hold a real nbconvert.
            "PATH": os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]),
            "UV_STUB_LOG": str(log),
            "HOME": str(tmp_path / "home"),
        }
    )
    env.pop("ASH_OFFLINE", None)
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(DRIVER),
            str(source),
            "countable" if countable else "uncountable",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    calls = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
    return result, calls, completed


def test_with_no_notebook_uv_is_asked_nothing_about_nbconvert(tmp_path):
    result, calls, completed = _run(tmp_path, with_notebook=False)

    assert [c for c in calls if "nbconvert" in c] == [], calls
    assert result == {"satisfied": True, "count": 0, "converted": 0}
    assert "is not available" not in completed.stderr + completed.stdout


def test_with_a_notebook_nbconvert_is_resolved(tmp_path):
    """Control: the same stand-in sees the nbconvert calls when there is work.

    The version probe itself included, which only a check that found a notebook
    runs.
    """
    result, calls, _ = _run(tmp_path, with_notebook=True)

    assert any("nbconvert" in c for c in calls), calls
    # The probe resolves under the converter's requirement, the run's own spec.
    assert any(
        c.startswith("tool run --from nbconvert>=7.16.0,<8.0.0 jupyter-nbconvert")
        and c.endswith(" --version")
        for c in calls
    ), calls


def test_when_the_notebooks_cannot_be_counted_nbconvert_is_resolved(tmp_path):
    """A count of None means the scan set could not be read, not that it is empty."""
    result, calls, _ = _run(tmp_path, with_notebook=False, countable=False)

    assert result["count"] is None, result
    assert any("nbconvert" in c for c in calls), calls
