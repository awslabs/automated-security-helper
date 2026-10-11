# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every built-in plugin group registers, whichever ASH module a process imports first.

The mechanism
-------------
Importing ``models.asharp_model`` runs ``_resolve_forward_refs()``, which imports
``config.ash_config``, which imports built-in plugin modules for their config
classes, and that loads every built-in plugin group (``ash_builtin/__init__``). The
plugin modules import core modules back: the reporters import
``core.unified_metrics`` and ``core.scanner_statistics_calculator``, and the
scanners, converters and event handlers import ``utils.sarif_utils`` and
``utils.suppression_matcher``. When one of those core modules is the first ASH
module a process imports, it is still empty when its plugins import it, the import
raises, and ``ash_builtin`` records the whole group as failed. Nothing imported it
again, so the group stayed lost for the rest of the process.

Measured by importing each of the 211 modules of the package first in a fresh
interpreter, then calling ``load_internal_plugins()``: seven lost at least one group.
``interactions.run_ash_scan`` is one of them -- the documented programmatic entry
point -- and it lost all 15 reporters. ``utils.suppression_matcher`` lost every group.

Why a subprocess
----------------
The defect is in which module is imported FIRST, and a pytest process has imported
most of the package before any test runs. A clean interpreter is the only way to
measure what a process that starts at one of these modules gets.

Why the expected counts are measured, not written down
------------------------------------------------------
The control is a clean interpreter that calls ``load_internal_plugins()`` before
importing anything else. Hard-coding "15 reporters" would make this test fail for
every reporter added, and get loosened; comparing to the control keeps the claim to
"the import order changes nothing".
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The modules that lost a plugin group when imported first (measured; see above).
FIRST_IMPORTS = (
    "automated_security_helper.core.unified_metrics",
    "automated_security_helper.core.scanner_statistics_calculator",
    "automated_security_helper.interactions.run_ash_scan",
    "automated_security_helper.cli.scan",
    "automated_security_helper.cli.image",
    "automated_security_helper.utils.sarif_utils",
    "automated_security_helper.utils.suppression_matcher",
)

_PROBE = """
import importlib
import json
import sys

first = sys.argv[1]
if first:
    importlib.import_module(first)

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    load_internal_plugins,
    plugin_load_errors,
)

loaded = load_internal_plugins()
print(
    "ASH_PROBE_RESULT="
    + json.dumps(
        {
            "loaded": {
                group: sorted(cls.__name__ for cls in classes)
                for group, classes in loaded.items()
            },
            "registered_reporters": sorted(
                cls.__name__ for cls in ash_plugin_manager.plugin_modules("reporter")
            ),
            "event_handlers": sorted(
                f"{event}:{handler.__name__}"
                for event, handlers in importlib.import_module(
                    "automated_security_helper.plugin_modules.ash_builtin"
                ).ASH_EVENT_HANDLERS.items()
                for handler in handlers
            ),
            "errors": plugin_load_errors(),
        }
    )
)
"""


def _probe(first_import: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(_PROBE), first_import],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"probe interpreter failed outright.\nstdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )
    marker = "ASH_PROBE_RESULT="
    for line in proc.stdout.splitlines():
        if line.startswith(marker):
            return json.loads(line[len(marker) :])
    raise AssertionError(
        f"probe printed no result.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


@pytest.fixture(scope="module")
def control() -> dict:
    """What a process that loads the plugins before importing anything else gets."""
    result = _probe("")
    assert result["errors"] == {}, result["errors"]
    # A control that loaded nothing would let every comparison below pass.
    assert all(result["loaded"][group] for group in result["loaded"]), result
    assert result["registered_reporters"], result
    assert result["event_handlers"], result
    return result


@pytest.mark.parametrize("first_import", FIRST_IMPORTS)
def test_every_plugin_group_registers_whichever_module_is_imported_first(
    control, first_import
):
    result = _probe(first_import)

    assert result["errors"] == {}, (
        f"with {first_import} imported first, plugin groups failed to load: "
        f"{result['errors']}"
    )
    assert result["loaded"] == control["loaded"]
    assert result["registered_reporters"] == control["registered_reporters"]
    assert result["event_handlers"] == control["event_handlers"]
