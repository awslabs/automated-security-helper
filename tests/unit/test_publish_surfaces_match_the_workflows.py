# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The publish-surface allowlist matches what the workflows upload and cache.

Why this file exists
--------------------
.github/scripts/assert-publish-surfaces.py censuses every artifact upload and cache
under .github/. It fails on a site its allowlist does not name, and on an entry that
no site matches. Only CI ran it (ash-unified-ci.yml), so when the scan uploads were
narrowed to reports/ and the aggregated results, per project in a workspace scan, the
entries for run-ash-security-scan.yml and run-scan-test still named the whole output
directory. The check then failed with two unexpected sites and two unmatched entries,
and no test failed.

What this asserts
-----------------
1. The script's own fixtures still come back red where they should (``--self-test``).
2. The script passes on this tree, run as CI runs it: every upload and cache is on
   the allowlist, and every entry matches one.
3. A control: with the scan workflow's entries left out, the same evaluation reports
   that workflow's upload as unexpected, so the pass above is not an evaluation that
   reports nothing.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "assert-publish-surfaces.py"
SCAN_WORKFLOW = ".github/workflows/run-ash-security-scan.yml"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 - this interpreter and a fixed script path
        [sys.executable, "-I", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.fixture(scope="module")
def surfaces() -> ModuleType:
    spec = importlib.util.spec_from_file_location("assert_publish_surfaces", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves string annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.integration
def test_the_self_test_passes():
    proc = _run("--self-test")
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]


@pytest.mark.integration
def test_every_upload_and_cache_matches_an_allowlist_entry():
    proc = _run()
    assert proc.returncode == 0, (
        "assert-publish-surfaces.py fails on this tree; its report:\n"
        + proc.stdout[-6000:]
        + proc.stderr[-2000:]
    )
    assert "OK: all" in proc.stdout, proc.stdout[-2000:]


@pytest.mark.unit
def test_a_missing_entry_is_reported(surfaces):
    found = surfaces.scan_tree(surfaces.GITHUB_DIR)
    assert any(site.surface.file == SCAN_WORKFLOW for site in found), (
        f"the census finds nothing in {SCAN_WORKFLOW}"
    )
    without_scan = tuple(e for e in surfaces.ALLOWLIST if e.file != SCAN_WORKFLOW)
    unexpected, _ = surfaces.evaluate(found, without_scan)
    assert any(site.surface.file == SCAN_WORKFLOW for site in unexpected), unexpected
