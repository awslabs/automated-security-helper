# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``check_scan_progress`` loads polars before it takes the registry lock.

``create_scan_progress_from_files`` runs under that lock and the aggregated
progress partition imports polars, a first import that costs a noticeable
fraction of a second. None of the MCP server's module-scope imports loads
polars, so the poll loads it itself, outside the lock, where it holds nothing up.
A fresh interpreter proves the order: polars is absent after importing the
registry and present at the moment the lock is entered.
"""

import subprocess
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.unit

_LOCK_PROBE = """
import sys

from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

assert "polars" not in sys.modules, "control: the registry module imports polars"
registry = ScanRegistry()
seen = []


class Watch:
    def __init__(self, inner):
        self.inner = inner

    def __enter__(self):
        seen.append("polars" in sys.modules)
        return self.inner.__enter__()

    def __exit__(self, *exc):
        return self.inner.__exit__(*exc)


registry._registry_lock = Watch(registry._registry_lock)
try:
    registry.check_scan_progress("no-such-scan-id")
except Exception:
    pass
print(seen)
"""


def test_polars_is_loaded_before_the_registry_lock_is_entered():
    done = subprocess.run(
        [sys.executable, "-I", "-B", "-c", importing_this_checkout(_LOCK_PROBE)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip() == "[True]"
