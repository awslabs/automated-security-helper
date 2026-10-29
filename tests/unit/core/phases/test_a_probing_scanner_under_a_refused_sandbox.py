# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that probes its tool is graded like any other when its sandbox is refused.

The grading cells (test_a_refused_sandbox_grades_the_scan.py) run a scanner whose
dependency check answers True without probing. Many scanners probe: their check
spawns the tool, and under a refused sandbox the probe may not run unsandboxed,
so it fails for the sandbox's reason. Ungated, that failed check graded the
scanner MISSING with a reason blaming the tool -- the exact misdirection the
named-backend ERROR grade exists to avoid.

So, through the real phase:

- Under a backend the operator NAMED that is unavailable, the dependency check
  is not run at all (its probes could only fail for the sandbox), the scanner is
  queued, and the executor refuses it before scan(): ERROR, could not start its
  tool, the sandbox named first even when the tool is also missing.
- Under AUTO with no working backend, MISSING stays the grade, and the recorded
  reason names the sandbox rather than a failed check of a tool that is there.
- A refusal that is not about availability, such as a results directory the
  scanned repository committed as a symlink, under a working backend named or
  auto: the check is not run either, and the scan is the ERROR naming the
  refusal that a non-probing scanner gets. Graded MISSING, it sent the operator
  to reinstall a tool when the repository planted the cause.
- The control: the same probing scanner with the sandbox off passes its check,
  so the sandbox is what fails the probes above, not the probes themselves.

The named backend in the first cell is sandbox-exec on a non-macOS POSIX host:
genuinely unavailable, so that cell exercises the real resolution path.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox import scope as sandbox_scope_module
from automated_security_helper.utils.sandbox.scope import (
    SandboxUnavailable,
    clear_backend_cache,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the probes and the planted symlink are POSIX's"
)


class _Config(ScannerPluginConfigBase):
    name: str = "probing"


class _Probing(ScannerPluginBase):
    """A scanner whose dependency check spawns a real probe of its tool."""

    probed: List[Any] = []

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = _Config()
        self.command = sys.executable
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        from automated_security_helper.utils.subprocess_utils import run_command

        try:
            result = run_command([sys.executable, "--version"], capture_output=True)
        except Exception as error:  # a refusing scope raises at the spawn
            type(self).probed.append(repr(error))
            return False
        type(self).probed.append(result.returncode)
        return result.returncode == 0

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        return {"severity_counts": {}}


def _context(tmp_path, mode: str) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="test", sandbox=SandboxConfig(mode=mode)),
    )


@pytest.fixture(autouse=True)
def _fresh_backend_cache():
    clear_backend_cache()
    _Probing.probed = []
    yield
    clear_backend_cache()


def _no_backend_works(monkeypatch) -> None:
    def refused(name: str):
        raise SandboxUnavailable(f"{name} is not available: no {name} on PATH")

    monkeypatch.setattr(sandbox_scope_module, "_probe_backend", refused)


def _every_backend_works(monkeypatch) -> None:
    monkeypatch.setattr(
        sandbox_scope_module,
        "_probe_backend",
        lambda name: SimpleNamespace(name=name),
    )


def _results_of(tmp_path, mode: str, *, plant_symlink: bool = False):
    context = _context(tmp_path, mode)
    if plant_symlink:
        # What a scanned repository can commit when the output directory is
        # inside it: the scanner's results directory as a link elsewhere.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        scanners_dir = Path(context.output_dir) / "scanners"
        scanners_dir.mkdir(parents=True, exist_ok=True)
        (scanners_dir / "probing").symlink_to(elsewhere)
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_Probing],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    return populate_metrics_from_unified_source(aggregated_results=results)


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="sandbox-exec is the named-but-unavailable backend off macOS",
)
@pytest.mark.unit
def test_a_probing_scanner_under_a_named_unavailable_backend_is_an_error(tmp_path):
    """The operator named sandbox-exec and it cannot run here. The probing
    scanner's check is not run (its probes could only fail for the sandbox),
    and the scan is the same ERROR a non-probing scanner gets: could not start
    its tool, the sandbox named, dependencies not blamed."""
    results = _results_of(tmp_path, "sandbox-exec")
    row = results.scanner_results.get("probing")
    assert row is not None, "the scanner left no row"

    assert row.status == ScannerStatus.ERROR, (row.status, row.missing_reason)
    assert row.dependencies_satisfied is True, row
    assert not row.missing_reason, row.missing_reason
    recorded = json.dumps(results.additional_reports.get("probing") or {})
    assert "could not start its tool" in recorded, recorded
    assert "sandbox-exec" in recorded, recorded


@pytest.mark.unit
def test_a_probing_scanner_under_auto_is_missing_naming_the_sandbox(
    tmp_path, monkeypatch
):
    """Auto with no working backend stays MISSING, and the reason names the
    sandbox: the tool is there, and a reason saying its check failed sent the
    operator to reinstall it."""
    _no_backend_works(monkeypatch)
    results = _results_of(tmp_path, "auto")
    row = results.scanner_results.get("probing")
    assert row is not None, "the scanner left no row"

    assert row.status == ScannerStatus.MISSING, row.status
    reason = row.missing_reason or ""
    assert "sandbox" in reason, reason
    assert "bwrap" in reason, reason


@pytest.mark.parametrize("mode", ["bwrap", "auto"])
@pytest.mark.unit
def test_a_probing_scanner_whose_sandbox_is_refused_is_an_error_naming_it(
    tmp_path, monkeypatch, mode
):
    """A working backend, and a results directory the scanned repository
    planted as a symlink. Nothing is missing, something was refused: the probing
    scanner's check is not run, and the scan is the ERROR naming the symlink
    that a non-probing scanner gets, never a MISSING that blames the tool."""
    _every_backend_works(monkeypatch)
    results = _results_of(tmp_path, mode, plant_symlink=True)
    row = results.scanner_results.get("probing")
    assert row is not None, "the scanner left no row"

    assert row.status == ScannerStatus.ERROR, (row.status, row.missing_reason)
    assert not row.missing_reason, row.missing_reason
    assert _Probing.probed == [], f"the check ran under the refusal: {_Probing.probed}"
    recorded = json.dumps(results.additional_reports.get("probing") or {})
    assert "sandbox was refused" in recorded, recorded
    assert "symlink" in recorded, recorded


@pytest.mark.unit
def test_a_planted_symlink_does_not_make_the_dependency_verdict_absent(
    tmp_path, monkeypatch
):
    """The probe scope records a refusal as the scanner's dependency reason only
    for an unavailable backend, never for a refusal like the planted symlink.

    `ash dependencies` asks _scan_can_run inside the same probe scope without
    ScanPhase's skip, and the base dependency check answers False whenever
    dependency_unavailable_reason is set -- so recording the symlink there would
    make the installer call a present tool absent. detect-secrets runs
    in-process, so its real check answers under the refusing scope, and the
    verdict must stay True."""
    from automated_security_helper.cli.dependencies import _scan_can_run
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    _every_backend_works(monkeypatch)
    context = _context(tmp_path, "bwrap")
    scanner = DetectSecretsScanner(context=context)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    results_dir = Path(scanner.results_dir)
    results_dir.parent.mkdir(parents=True, exist_ok=True)
    results_dir.symlink_to(elsewhere)

    assert _scan_can_run(scanner) is True, scanner.dependency_unavailable_reason
    assert not scanner.dependency_unavailable_reason, (
        scanner.dependency_unavailable_reason
    )


@pytest.mark.integration
def test_control_the_same_probes_pass_with_the_sandbox_off(tmp_path):
    """The probes themselves are sound: with no sandbox the check passes and the
    scanner runs, so the cells above show the sandbox failing them."""
    results = _results_of(tmp_path, "off")
    row = results.scanner_results.get("probing")
    assert row is not None, "the scanner left no row"

    assert _Probing.probed == [0], _Probing.probed
    assert row.status not in (ScannerStatus.MISSING, ScannerStatus.ERROR), row.status


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="sandbox-exec is the named-but-unavailable backend off macOS",
)
@pytest.mark.unit
def test_a_named_unavailable_backend_fails_the_dependency_verdict_naming_the_sandbox(
    tmp_path,
):
    """The probe scope records an unavailable backend, named or auto, as the
    scanner's dependency reason, so `ash dependencies`' probe-free check agrees
    with the scan: every scan under this sandbox refuses the scanner (the
    executor's ERROR naming the backend), so a verdict that it can run would
    lie. The recorded reason names the SANDBOX, never the tool -- that, not
    suppressing the record, is what keeps a present tool from being blamed.
    The real resolution path: sandbox-exec is genuinely unavailable here. The
    scan itself does not read the record (ScanPhase skips the check and the
    cells above pin the ERROR grade with dependencies_satisfied True)."""
    from automated_security_helper.cli.dependencies import _scan_can_run
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    context = _context(tmp_path, "sandbox-exec")
    scanner = DetectSecretsScanner(context=context)

    assert _scan_can_run(scanner) is False, scanner.dependency_unavailable_reason
    reason = scanner.dependency_unavailable_reason or ""
    assert reason.startswith("scanner sandbox unavailable:"), reason
    assert "sandbox-exec" in reason, reason
