# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every scanner that describes its own failures takes what the template passes.

The template ``scan()`` calls ``_describe_scan_failure(exc, results_file,
tool_started=...)``, and a failure before the tool started says so instead of
giving an exit code (tests/unit/base/test_scanner_refusal_message.py). A scanner
that overrides the method with the older two-argument signature turned every
failure into a TypeError naming the keyword, and the cause was lost.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import List

import automated_security_helper.plugin_modules as plugin_modules
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError

PluginContext.model_rebuild()


def _overrides() -> List[type]:
    for module in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        importlib.import_module(module.name)
    found = []
    pending = list(ScannerPluginBase.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if "_describe_scan_failure" in vars(cls):
            found.append(cls)
    return found


def test_control_an_override_is_found():
    names = {cls.__name__ for cls in _overrides()}

    assert "GitleaksScanner" in names, sorted(names)


def test_every_override_takes_tool_started():
    missing = [
        cls.__name__
        for cls in _overrides()
        if "tool_started"
        not in inspect.signature(vars(cls)["_describe_scan_failure"]).parameters
    ]

    assert missing == []


def test_gitleaks_says_it_was_not_started_and_gives_no_exit_code(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
        GitleaksScanner,
        GitleaksScannerConfig,
    )

    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    scanner = GitleaksScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=AshConfig(),
        ),
        config=GitleaksScannerConfig(),
    )
    results_file = Path(output) / "scanners" / "gitleaks" / "source" / "x.sarif"

    message = scanner._describe_scan_failure(
        ScannerError("refused"), results_file, tool_started=False
    )

    assert "refused" in message
    assert "gitleaks was not started" in message
    assert "exit code" not in message
