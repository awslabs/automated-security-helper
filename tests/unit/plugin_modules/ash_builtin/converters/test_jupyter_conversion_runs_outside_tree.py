# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""nbconvert runs outside the scanned tree, with an exporter ASH chooses.

nbconvert puts its working directory first on ``sys.path``, reads
``jupyter_nbconvert_config`` files from it, and, for ``--to script``, imports the
exporter class a notebook names in ``metadata.language_info.nbconvert_exporter``. The
converter therefore runs nbconvert in the staging directory that holds only the copied
notebook, removes ``nbconvert_exporter`` from that copy, and picks the exporter itself
from the notebook's language.

The stand-in throughout is a module in the scanned tree that writes a flag file next to
itself when it is imported, named as a notebook's exporter. It must never be imported.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
)

MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter"
)

PROBE_MODULE = "ashprobe_exporter"

PROBE_SOURCE = """\
from pathlib import Path

Path(__file__).with_name("probe-imported.flag").write_text("imported\\n")

from nbconvert.exporters import PythonExporter


class ProbeExporter(PythonExporter):
    pass
"""


def notebook(language: str | None, exporter: str | None) -> str:
    language_info: dict = {"file_extension": ".py"}
    if language is not None:
        language_info["name"] = language
    if exporter is not None:
        language_info["nbconvert_exporter"] = exporter
    return json.dumps(
        {
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": None,
                    "outputs": [],
                    "source": ["print('in tree')\n"],
                }
            ],
            "metadata": {"language_info": language_info},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
    )


@pytest.fixture
def tree(test_plugin_context):
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    (source / f"{PROBE_MODULE}.py").write_text(PROBE_SOURCE)
    return source


def probe_flag(tree: Path) -> Path:
    return tree / "probe-imported.flag"


class TestHowNbconvertIsRun:
    """What the converter hands nbconvert, observed at the process boundary."""

    @pytest.mark.parametrize(
        "language, expected_exporter",
        [("python", "python"), (None, "python"), ("R", "script")],
    )
    def test_nbconvert_never_runs_in_the_tree_or_sees_the_named_exporter(
        self,
        language,
        expected_exporter,
        tree,
        test_plugin_context,
        monkeypatch,
    ):
        (tree / "nb.ipynb").write_text(
            notebook(language, f"{PROBE_MODULE}.ProbeExporter")
        )
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kw: [str(tree / "nb.ipynb")])
        # Run from inside the tree, as `cd repo && ash scan` does.
        monkeypatch.chdir(tree)
        seen = []

        def nbconvert(cmd, *args, **kwargs):
            staged = json.loads(Path(cmd[6]).read_text(encoding="utf-8"))
            beside = sorted(p.name for p in Path(cmd[6]).parent.iterdir())
            seen.append((list(cmd), kwargs.get("cwd"), staged, beside))
            Path(cmd[cmd.index("--output") + 1] + ".py").write_text("x = 1\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(f"{MODULE}.subprocess.run", nbconvert)
        converter = JupyterConverter(
            context=test_plugin_context, config=JupyterConverterConfig()
        )
        converter.use_uv_tool = False

        converter.convert()

        ((cmd, cwd, staged, beside),) = seen
        assert cwd is not None, "nbconvert inherited ASH's working directory"
        assert not Path(cwd).resolve().is_relative_to(tree.resolve())
        # It runs beside the copy, in a directory holding nothing else.
        assert Path(cwd) == Path(cmd[6]).parent
        assert beside == ["nb.ipynb"]
        assert cmd[cmd.index("--to") + 1] == expected_exporter
        assert "nbconvert_exporter" not in staged["metadata"]["language_info"]
        assert staged["cells"] == json.loads(notebook(language, None))["cells"]

    def test_a_notebook_without_an_exporter_is_copied_byte_for_byte(
        self, tree, test_plugin_context, monkeypatch
    ):
        original = notebook("python", None).encode()
        (tree / "nb.ipynb").write_bytes(original)
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kw: [str(tree / "nb.ipynb")])
        copies = []

        def nbconvert(cmd, *args, **kwargs):
            assert Path(cmd[6]) != tree / "nb.ipynb", (
                "nbconvert was given the tree path"
            )
            copies.append(Path(cmd[6]).read_bytes())
            Path(cmd[cmd.index("--output") + 1] + ".py").write_text("x = 1\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(f"{MODULE}.subprocess.run", nbconvert)
        converter = JupyterConverter(
            context=test_plugin_context, config=JupyterConverterConfig()
        )
        converter.use_uv_tool = False

        (converted,) = converter.convert()

        assert copies == [original]
        assert converted.read_text() == "x = 1\n"


class TestWithRealNbconvert:
    """The same property against nbconvert itself, where it is installed."""

    def test_an_exporter_module_in_the_tree_is_never_imported(
        self, tree, test_plugin_context, monkeypatch
    ):
        if shutil.which("jupyter") is None:
            pytest.skip("jupyter is not on PATH, and this test does not install it")
        converter = JupyterConverter(
            context=test_plugin_context, config=JupyterConverterConfig()
        )
        converter.use_uv_tool = False
        (tree / "nb.ipynb").write_text(
            notebook("python", f"{PROBE_MODULE}.ProbeExporter")
        )
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kw: [str(tree / "nb.ipynb")])
        monkeypatch.chdir(tree)

        results = converter.convert()

        assert not probe_flag(tree).exists(), (
            "nbconvert imported a module from the scanned tree"
        )
        (converted,) = results
        assert "print('in tree')" in converted.read_text()
