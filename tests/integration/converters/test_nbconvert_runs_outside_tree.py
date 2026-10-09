# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Jupyter converter against real nbconvert: no module in the scanned tree is imported.

nbconvert imports the exporter class a notebook names in
``metadata.language_info.nbconvert_exporter`` (``ScriptExporter.from_notebook_node``,
so only for ``--to script``), and ``NbConvertApp.init_syspath`` puts its working
directory first on ``sys.path``. The converter has one defense against each: it
removes the key from the copy nbconvert reads, and it runs nbconvert in the directory
holding only that copy. Each test below takes the other defense away, so a regression
in either one fails a test of its own.

The stand-in is a module in the scanned tree that writes a flag file next to itself
when it is imported, named as a notebook's exporter. The notebooks are R notebooks,
because only ``--to script`` reads the key.

nbconvert is provisioned the way ASH provisions it, with ``uv tool``, and run on the
converter's default route (``use_uv_tool``). This module is under
``tests/integration``, so it runs with ``--run-integration``, which the
``integration-test`` job in ``ash-unified-ci.yml`` passes. A host where nbconvert
cannot be provided fails here rather than skipping.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    jupyter_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
)
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_runner

PROBE_MODULE = "ashprobe_exporter"
PROBE_EXPORTER = f"{PROBE_MODULE}.ProbeExporter"

PROBE_SOURCE = """\
from pathlib import Path

Path(__file__).with_name("probe-imported.flag").write_text("imported\\n")

from nbconvert.exporters import PythonExporter


class ProbeExporter(PythonExporter):
    pass
"""


def r_notebook_with_exporter() -> str:
    return json.dumps(
        {
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": None,
                    "outputs": [],
                    "source": ["x <- 1\n"],
                }
            ],
            "metadata": {
                "language_info": {
                    "name": "R",
                    "file_extension": ".py",
                    "nbconvert_exporter": PROBE_EXPORTER,
                }
            },
            "nbformat": 4,
            "nbformat_minor": 5,
        },
        indent=1,
    )


@pytest.fixture
def tree(test_plugin_context):
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    (source / f"{PROBE_MODULE}.py").write_text(PROBE_SOURCE)
    (source / "nb.ipynb").write_text(r_notebook_with_exporter())
    return source


@pytest.fixture
def flag(tree) -> Path:
    return tree / "probe-imported.flag"


@pytest.fixture
def converter(test_plugin_context, tree, monkeypatch):
    built = JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )
    if not built.validate_plugin_dependencies():
        pytest.fail(
            "nbconvert could not be provided with uv tool, so the converter cannot "
            "be tested against it; this test needs network access or a uv cache"
        )
    assert built.use_uv_tool, "the default route is the one under test"
    monkeypatch.setattr(
        f"{jupyter_converter.__name__}.scan_set", lambda **kw: [str(tree / "nb.ipynb")]
    )
    # Run from inside the tree, as `cd repo && ash scan` does.
    monkeypatch.chdir(tree)
    return built


@pytest.fixture
def ash_debug():
    records: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Collector(level=logging.DEBUG)
    logger = logging.getLogger("ash")
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


def run_nbconvert(args: list[str], cwd: Path):
    return get_uv_tool_runner().run_tool(
        tool_name="jupyter-nbconvert",
        package_name="nbconvert",
        args=args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


class TestTheStandInCanBeImported:
    """Positive controls: without the converter, nbconvert does import the module."""

    def test_through_the_working_directory(self, converter, tree, flag, tmp_path):
        run_nbconvert(
            ["--to", "script", str(tree / "nb.ipynb"), "--output", str(tmp_path / "o")],
            cwd=tree,
        )
        assert flag.exists(), "nbconvert run in the tree did not import the module"

    def test_through_pythonpath(self, converter, tree, flag, tmp_path, monkeypatch):
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setenv("PYTHONPATH", str(tree))
        run_nbconvert(
            ["--to", "script", str(tree / "nb.ipynb"), "--output", str(tmp_path / "o")],
            cwd=empty,
        )
        assert flag.exists(), "nbconvert did not import the module from PYTHONPATH"


def test_removing_the_exporter_key_keeps_the_module_from_loading(
    converter, flag, monkeypatch
):
    """The module is importable from anywhere here, so only the key removal holds."""
    monkeypatch.setenv("PYTHONPATH", str(flag.parent))

    results = converter.convert()

    assert not flag.exists(), "nbconvert imported the exporter the notebook named"
    (converted,) = results
    assert "x <- 1" in converted.read_text()


def test_running_outside_the_tree_keeps_the_module_from_loading(
    converter, flag, monkeypatch, ash_debug
):
    """The copy keeps the key here, so only the working directory holds."""
    stage = JupyterConverter._stage_notebook

    def stage_keeping_the_key(content: bytes, staged: Path) -> str:
        exporter = stage(content, staged)
        staged.write_bytes(content)
        return exporter

    monkeypatch.setattr(
        JupyterConverter, "_stage_notebook", staticmethod(stage_keeping_the_key)
    )

    converter.convert()

    assert not flag.exists(), "nbconvert imported a module from the scanned tree"
    # nbconvert did run and went looking for the module: it was not found.
    assert any(PROBE_MODULE in message for message in ash_debug), ash_debug
