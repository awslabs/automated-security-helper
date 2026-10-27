# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ash config commands print through utils/console, never typer's own echo.

Their messages quote paths, names and values from the configuration and the
environment, such as the file ASH_CONFIG names. utils/console.echo and secho show
that text instead of obeying it (controls as escapes, CI command forms broken),
which typer.echo and typer.secho do not.
"""

import ast
from pathlib import Path

import automated_security_helper.cli.config as config_module

RAW_WRITERS = {"echo", "secho"}


def _raw_writes(source: str):
    """Each ``typer.echo(...)``/``typer.secho(...)`` call, and each import of them."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in RAW_WRITERS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "typer"
        ):
            found.append(f"line {node.lineno}: typer.{node.func.attr}")
        if isinstance(node, ast.ImportFrom) and node.module == "typer":
            found += [
                f"line {node.lineno}: from typer import {alias.name}"
                for alias in node.names
                if alias.name in RAW_WRITERS
            ]
    return found


def test_cli_config_has_no_raw_typer_writes():
    source = Path(config_module.__file__).read_text(encoding="utf-8")

    assert _raw_writes(source) == []


def test_the_check_finds_a_raw_write():
    """The check above can fail: it finds both spellings."""
    assert sorted(
        _raw_writes(
            "import typer\nfrom typer import secho\ntyper.secho('x')\ntyper.echo('y')\n"
        )
    ) == [
        "line 2: from typer import secho",
        "line 3: typer.secho",
        "line 4: typer.echo",
    ]
