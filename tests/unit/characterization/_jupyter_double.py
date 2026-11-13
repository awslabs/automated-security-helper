# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The nbconvert and jupyter doubles the jupyter converter scenarios build on.

``test_jupyter_converter`` pins how the converter launches nbconvert; the
explicit-executor cells run the same conversion against other executors. Both build on
what is here: the fixture notebooks, ``jupyter-nbconvert`` as ASH drives it, and the
``jupyter`` launcher that runs it. This module imports nothing from a test file.
"""

from __future__ import annotations

import json
from typing import Optional

from tests.unit.characterization._harness import (
    FIXTURES_DIR,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

NOTEBOOKS = FIXTURES_DIR / "jupyter"


class NbconvertDouble(ToolDouble):
    """``jupyter-nbconvert`` as ASH drives it.

    ``--version`` prints a version. A conversion needs ``--to python`` or
    ``--to script`` and one notebook, and writes ``<--output><ext>``: ``.py`` for
    ``python``, the notebook's ``language_info.file_extension`` (``.txt`` when it
    has none) for ``script``, as nbconvert's exporters do.
    """

    GRAMMAR = ArgvGrammar(
        value_flags=frozenset({"--log-level", "--to", "--output"}),
        min_positionals=1,
        max_positionals=1,
    )

    def __init__(
        self, convert: Optional[Outcome] = None, *, version: Optional[Outcome] = None
    ) -> None:
        self.convert = convert
        self.version = version or Exit(0, stdout="7.16.4\n")

    def run(self, call: ToolCall) -> Outcome:
        if call.args == ["--version"]:
            return self.version
        parsed = self.GRAMMAR.parse(call)
        exporter = parsed.last("--to")
        if exporter not in ("python", "script"):
            raise call.reject(f"--to {exporter}")
        notebook = call.confined(parsed.positionals[0])
        output = parsed.last("--output")
        if not notebook.is_file() or output is None:
            raise call.reject(f"notebook {notebook} or --output {output}")
        if self.convert is not None:
            return self.convert
        data = json.loads(call.read(notebook).decode("utf-8"))
        language_info = data.get("metadata", {}).get("language_info", {})
        suffix = (
            ".py"
            if exporter == "python"
            else language_info.get("file_extension", ".txt")
        )
        code = "".join(
            "\n# In[ ]:\n\n\n" + "".join(cell["source"]) + "\n"
            for cell in data["cells"]
            if cell["cell_type"] == "code"
        )
        call.write(
            output + suffix,
            ("#!/usr/bin/env python\n# coding: utf-8\n" + code).encode("utf-8"),
        )
        return Exit(
            0, stderr=f"[NbConvertApp] Converting notebook {notebook} to {exporter}\n"
        )


class JupyterDouble(ToolDouble):
    """The ``jupyter`` launcher: ``jupyter nbconvert ARGS`` runs ``jupyter-nbconvert``."""

    def run(self, call: ToolCall) -> Outcome:
        if call.args[:1] != ["nbconvert"]:
            raise call.reject("ASH only runs jupyter nbconvert")
        return call.dispatch("jupyter-nbconvert", call.args[1:], "jupyter")
