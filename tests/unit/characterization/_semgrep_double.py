# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The semgrep double, its config and its uv route, as the cells share them.

``test_semgrep`` pins how ASH launches semgrep; the cells of an executor without uv
scan with the same double, source and route. They live here, not in a test file, so
no cell file has to import another to use them.
"""

from __future__ import annotations

from typing import Optional

from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)
from tests.unit.characterization._grep_doubles import GrepDouble
from tests.unit.characterization._harness import UvDouble

SOURCE = {"app.py": "eval(input())\n"}


def _semgrep(scan=None, **kwargs) -> GrepDouble:
    return GrepDouble("semgrep", scan, **kwargs)


def _config(**options) -> SemgrepScannerConfig:
    return SemgrepScannerConfig(options=SemgrepScannerConfigOptions(**options))


def _uv_route(char, semgrep: Optional[GrepDouble] = None, **uv) -> None:
    """uv on PATH, with semgrep installed as a uv tool and nowhere else."""
    char.absent("semgrep")
    char.tool("uv", UvDouble(installed=["semgrep"], **uv))
    char.tool("semgrep", semgrep or _semgrep(), on=None)
    char.write_source(SOURCE)
