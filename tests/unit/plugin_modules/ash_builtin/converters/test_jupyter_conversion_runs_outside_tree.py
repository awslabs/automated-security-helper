# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""nbconvert runs outside the scanned tree, with an exporter ASH chooses.

Two nbconvert behaviors make the notebook and the directory nbconvert runs in matter.
``NbConvertApp.init_syspath`` puts the working directory first on ``sys.path``, and
``ScriptExporter.from_notebook_node`` imports the exporter class a notebook names in
``metadata.language_info.nbconvert_exporter``. The converter therefore runs nbconvert in
the staging directory that holds only the copied notebook, removes
``nbconvert_exporter`` from that copy, and picks the exporter itself from the
notebook's language.

These tests observe what the converter hands nbconvert, on both of the routes it can
take: ``uv tool run`` (``use_uv_tool``, the default) and the direct ``jupyter``
fallback. Real nbconvert is exercised in
``tests/integration/converters/test_nbconvert_runs_outside_tree.py``.

The process boundary is replaced without touching the standard library's
``subprocess`` module: the converter module's own ``subprocess`` name is pointed at a
namespace whose ``run`` is the stand-in, and the uv runner is replaced through
``get_uv_tool_runner``. The converter is constructed before either is in place, so its
own tool probes run against the real environment.
"""

from __future__ import annotations

import json
import subprocess
import types
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    jupyter_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
)
from automated_security_helper.utils import uv_tool_runner

PROBE_EXPORTER = "ashprobe_exporter.ProbeExporter"


def notebook(language: str | None, exporter: str | None, code: str = "x = 1\n"):
    language_info: dict = {"file_extension": ".py"}
    if language is not None:
        language_info["name"] = language
    if exporter is not None:
        language_info["nbconvert_exporter"] = exporter
    return {
        "cells": [
            {
                "cell_type": "code",
                "metadata": {},
                "execution_count": None,
                "outputs": [],
                "source": [code],
            }
        ],
        "metadata": {"language_info": language_info},
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def as_nbformat_writes(nb: dict) -> bytes:
    """The bytes nbformat writes: one-space indent, non-ASCII kept, trailing newline.

    Default ``json.dumps`` output would survive a parse-and-dump round trip unchanged,
    so a test written with it could not tell a copied notebook from a re-serialized
    one.
    """
    return (json.dumps(nb, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def notebook_argument(cmd: list[str]) -> Path:
    """The notebook on an nbconvert command line, found by its suffix."""
    (path,) = [arg for arg in cmd if arg.endswith(".ipynb")]
    return Path(path)


def output_argument(cmd: list[str]) -> Path:
    return Path(cmd[cmd.index("--output") + 1] + ".py")


class Observed:
    """What nbconvert was handed, recorded at the boundary and asserted afterwards.

    Nothing is asserted inside the stand-ins: convert() catches every exception a
    conversion raises, so an assertion there would be logged and lost.
    """

    def __init__(self):
        self.calls: list[dict] = []

    def record(self, cmd: list[str], cwd) -> None:
        staged = notebook_argument(cmd)
        self.calls.append(
            {
                "cmd": list(cmd),
                "cwd": None if cwd is None else Path(cwd),
                "notebook": staged,
                "staged_bytes": staged.read_bytes(),
                "beside": sorted(p.name for p in staged.parent.iterdir()),
            }
        )
        output_argument(cmd).write_text("x = 1\n", encoding="utf-8")


@pytest.fixture
def tree(test_plugin_context):
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    return source


@pytest.fixture(params=["uv", "direct"])
def route(request, test_plugin_context, monkeypatch):
    """A converter, built first, then the route it takes to nbconvert replaced."""
    converter = JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )
    observed = Observed()

    if request.param == "uv":
        converter.use_uv_tool = True

        class Runner:
            def is_uv_available(self):
                return True

            def run_tool(self, **kwargs):
                cmd = ["jupyter", "nbconvert", *kwargs["args"]]
                observed.record(cmd, kwargs.get("cwd"))
                return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: Runner())
    else:
        converter.use_uv_tool = False

        def run(cmd, *args, **kwargs):
            observed.record(cmd, kwargs.get("cwd"))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(
            jupyter_converter,
            "subprocess",
            types.SimpleNamespace(
                run=run,
                CompletedProcess=subprocess.CompletedProcess,
                CalledProcessError=subprocess.CalledProcessError,
                TimeoutExpired=subprocess.TimeoutExpired,
            ),
        )
    return converter, observed


def convert_one(converter, notebook_path: Path, monkeypatch) -> list[Path]:
    monkeypatch.setattr(
        f"{jupyter_converter.__name__}.scan_set", lambda **kw: [str(notebook_path)]
    )
    return converter.convert()


@pytest.mark.parametrize(
    "language, expected_exporter",
    [("python", "python"), (None, "python"), ("R", "script")],
)
def test_nbconvert_runs_beside_a_copy_with_an_exporter_ash_chose(
    language, expected_exporter, route, tree, monkeypatch
):
    converter, observed = route
    (tree / "nb.ipynb").write_bytes(
        as_nbformat_writes(notebook(language, PROBE_EXPORTER))
    )
    # Run from inside the tree, as `cd repo && ash scan` does, so a route that
    # inherited ASH's working directory would run nbconvert in the tree.
    monkeypatch.chdir(tree)

    (converted,) = convert_one(converter, tree / "nb.ipynb", monkeypatch)

    (call,) = observed.calls
    assert call["cwd"] is not None, "nbconvert inherited ASH's working directory"
    assert not call["cwd"].resolve().is_relative_to(tree.resolve())
    assert call["cwd"] == call["notebook"].parent
    assert call["beside"] == ["nb.ipynb"], "nbconvert's directory holds only the copy"
    assert call["notebook"] != tree / "nb.ipynb"
    assert call["cmd"][call["cmd"].index("--to") + 1] == expected_exporter
    staged = json.loads(call["staged_bytes"])
    assert "nbconvert_exporter" not in staged["metadata"]["language_info"]
    assert staged["cells"] == notebook(language, None)["cells"]
    assert converted.read_text() == "x = 1\n"


def test_a_notebook_without_an_exporter_is_copied_byte_for_byte(
    route, tree, monkeypatch
):
    converter, observed = route
    original = as_nbformat_writes(notebook("python", None, code="print('café')\n"))
    (tree / "nb.ipynb").write_bytes(original)

    (converted,) = convert_one(converter, tree / "nb.ipynb", monkeypatch)

    (call,) = observed.calls
    assert call["notebook"] != tree / "nb.ipynb", "nbconvert was given the tree path"
    assert call["staged_bytes"] == original
    assert converted.read_text() == "x = 1\n"
