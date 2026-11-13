# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config and the unused-suppressions report the ``--fix-unused`` tests share.

Two test modules in ``tests/unit/cli`` each wrote the same config text, the same
suppression entry and the same directory layout for a report next to it. They
take them from here, so a change to the layout (the report's place or name) is
made once.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Tuple

#: A config with one suppression; ``ENTRY`` is how a report lists it as unused.
CONFIG = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: src/a.py\n"
    "      rule_id: B101\n"
    "      reason: one\n"
)
ENTRY = {"path": "src/a.py", "rule_id": "B101", "reason": "one"}


def lay_out(tmp_path: Path, report: Any, age_seconds: int = 0) -> Tuple[Path, Path]:
    """Write ``CONFIG`` and a report beside it; return (config, report path).

    ``report`` is the report's text, or a value written as JSON. A positive
    ``age_seconds`` sets the report file's modification time that far back.
    """
    config = tmp_path / ".ashrc.yaml"
    config.write_text(CONFIG, encoding="utf-8")
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    path = reports / "ash.unused-suppressions.json"
    text = report if isinstance(report, str) else json.dumps(report)
    path.write_text(text, encoding="utf-8")
    if age_seconds:
        then = time.time() - age_seconds
        os.utime(path, (then, then))
    return config, path
