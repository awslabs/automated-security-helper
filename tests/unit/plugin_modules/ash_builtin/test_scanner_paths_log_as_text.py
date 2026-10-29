# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A path a scanner logs is printed as the text it is.

The console log handler reads Rich markup, and a "[/" in a message is a
closing tag that raises MarkupError, which ends the scan. A skip path, its
reason and an output directory are data from the config and the command line,
so each is logged with markup off; read as markup, a checkov skip path
"[/]tests/" would stop the scan under --debug.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest
from rich.console import Console
from rich.logging import RichHandler

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.log import ASH_LOGGER

PluginContext.model_rebuild()

from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (  # noqa: E402
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (  # noqa: E402
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)

PATH = "[/]tests/"
REASON = "kept out [/bold] on purpose"


@pytest.fixture
def console() -> io.StringIO:
    """The console handler a debug scan logs through, markup on."""
    buffer = io.StringIO()
    handler = RichHandler(
        console=Console(file=buffer, width=400),
        markup=True,
        level=logging.DEBUG,
    )
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield buffer
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _shown(buffer: io.StringIO) -> str:
    return " ".join(buffer.getvalue().split())


def _context(tmp_path: Path, output_dir: Path | None = None) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output_dir or tmp_path / "out",
        config=AshConfig(),
    )


def test_a_checkov_skip_path(tmp_path, console):
    CheckovScanner(
        context=_context(tmp_path),
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                skip_path=[{"path": PATH, "reason": REASON}]
            )
        ),
    )
    assert f"Path '{PATH}' excluded" in _shown(console)
    assert REASON in _shown(console)


def test_a_syft_exclude(tmp_path, console):
    SyftScanner(
        context=_context(tmp_path),
        config=SyftScannerConfig(
            options=SyftScannerConfigOptions(exclude=[{"path": PATH, "reason": REASON}])
        ),
    )
    assert f"Path '{PATH}' excluded" in _shown(console)
    assert REASON in _shown(console)


@pytest.mark.parametrize(
    "name",
    ["o[/b]", "o[/b](x)"],
    ids=["excluded", "not excluded, has a parenthesis"],
)
def test_checkov_names_an_output_directory_inside_the_source(tmp_path, console, name):
    source = tmp_path / "src"
    output_dir = source / name
    output_dir.mkdir(parents=True)
    scanner = CheckovScanner(
        context=_context(tmp_path, output_dir),
        config=CheckovScannerConfig(),
    )
    scanner._output_dir_skip_patterns(source)
    assert f"/{name}/" in _shown(console)
