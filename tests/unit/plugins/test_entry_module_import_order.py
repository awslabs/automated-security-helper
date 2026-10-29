# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every built-in plugin group loads whichever ASH module a process imports first.

The defect
----------
A process that imported certain modules before anything else lost whole built-in
plugin groups. ``models.asharp_model`` imported ``config.ash_config`` while it was
itself being imported, to resolve a forward reference; ``ash_config`` imports
built-in converter and reporter modules, which loads the ``ash_builtin`` package and
with it every plugin group. Those plugin modules import back the module that started
the chain -- ``core.scanner_statistics_calculator``, ``core.unified_metrics``,
``utils.sarif_utils``, ``utils.suppression_matcher`` -- while it is still partially
initialized, and fail with "cannot import name ... from partially initialized
module". ``ash_builtin`` isolates each group's import, so the loss surfaced only as
load-record entries and MISSING rows. A library caller that imported
``utils.sarif_utils`` first and then ran a scan exited 1.

What the test does
------------------
For every module in the package, a fresh interpreter imports it first, then loads
the internal plugins and reports what landed in the load record. A fresh interpreter
because the defect depends on import order, which a pytest worker has long since
fixed. The module list comes from the source tree, so a new module is covered
without editing this file. A module that cannot be imported because an optional
third-party package is absent (the ``cdk`` extra, say) still gets the rest of the
check: what matters is what the attempt left behind.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout

PACKAGE_ROOT = Path(__file__).resolve().parents[3] / "automated_security_helper"


def _module_names() -> list[str]:
    names = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT.parent).with_suffix("")
        parts = relative.parts
        if not all(part.isidentifier() for part in parts) or parts[-1] == "__main__":
            continue
        # Only modules inside packages: every directory up to the root has an
        # __init__.py.
        if not all(
            (PACKAGE_ROOT.parent.joinpath(*parts[:depth]) / "__init__.py").is_file()
            for depth in range(1, len(parts))
        ):
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]
        names.append(".".join(parts))
    return names


ENTRY_MODULES = _module_names()

DRIVER = """
import importlib, json, sys
outcome = None
try:
    importlib.import_module(sys.argv[1])
except ModuleNotFoundError as exc:
    # An optional third-party dependency of this module is not installed.
    if (exc.name or "").startswith("automated_security_helper"):
        raise
    outcome = f"optional dependency missing: {exc.name}"
from automated_security_helper.plugins.loader import (
    load_internal_plugins,
    recorded_load_errors,
)
record = {}
loaded = load_internal_plugins(record)
print(json.dumps({
    "outcome": outcome,
    "errors": recorded_load_errors(record),
    "counts": {kind: len(classes) for kind, classes in loaded.items()},
}))
"""


@pytest.mark.unit
def test_the_sweep_covers_the_package():
    """The positive control: the list is the package, not a handful of modules."""
    assert len(ENTRY_MODULES) > 150, len(ENTRY_MODULES)
    assert "automated_security_helper.utils.sarif_utils" in ENTRY_MODULES
    assert "automated_security_helper.interactions.run_ash_scan" in ENTRY_MODULES


@pytest.mark.parametrize("module", ENTRY_MODULES)
@pytest.mark.integration
def test_importing_a_module_first_loses_no_plugin_group(module):
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [sys.executable, "-I", "-c", importing_this_checkout(DRIVER), module],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    result = json.loads(completed.stdout.strip().splitlines()[-1])

    assert result["errors"] == {}, (
        f"importing {module} first broke a built-in plugin group: {result['errors']}"
    )
    assert all(count > 0 for count in result["counts"].values()), result["counts"]
