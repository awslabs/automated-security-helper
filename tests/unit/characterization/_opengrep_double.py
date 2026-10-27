# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The opengrep double, with the source and the config the cells scan with.

It lives here, and not in ``test_opengrep``, so that the cells of other test files can
build the same world without importing a test file. It imports nothing from one.
"""

from __future__ import annotations

from typing import Optional

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from tests.unit.characterization._grep_doubles import GrepDouble
from tests.unit.characterization._harness import Exit

SOURCE = {"app.py": "eval(input())\n"}


def _opengrep(scan=None, *, version: Optional[str] = None, **kwargs) -> GrepDouble:
    if version is not None:
        kwargs["version"] = Exit(0, stdout=f"{version}\n")
    return GrepDouble("opengrep", scan, **kwargs)


def _config(**options) -> OpengrepScannerConfig:
    return OpengrepScannerConfig(options=OpengrepScannerConfigOptions(**options))
