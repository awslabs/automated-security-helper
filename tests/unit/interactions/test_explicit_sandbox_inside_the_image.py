# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Inside the image, an explicit ``ash scan --sandbox <mode>`` is the operator's own.

Why this file exists
--------------------
The wrappers (``./ash``, ``invoke-ash``, ``Invoke-ASH``) give the scan in the image
``--sandbox off``, and ``ash scan --mode container`` gives its inner scan
``sandbox.mode=off``: the container is the boundary
(tests/unit/test_sandbox_refused_by_every_container_entrypoint.py,
tests/unit/interactions/test_container_mode_reports_sandbox_not_applied.py).
Nothing refuses a ``--sandbox <mode>`` that an operator passes to ``ash scan`` run
directly inside the image, as in ``docker run <image> ash scan --sandbox landlock``.
That is the operator's own opt-in, and it keeps working. It fails closed: when the
backend the operator named cannot run there, each scanner is recorded ERROR, unable
to start its tool as requested, and none runs unsandboxed.

The chain is checked link by link, with the backend's probe stubbed both ways so no
real sandbox starts. With ASH_IN_CONTAINER=YES, as the image sets it, the CLI hands
the scan the local mode and the operator's mode as its last override. That override
resolves to the mode in the scan's config. Then the executor either runs the scanner
inside that backend's scope, or records it ERROR without running it.
"""

from datetime import datetime
from unittest import mock

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli import scan as scan_module
from automated_security_helper.cli.main import app
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.enums import RunMode, SandboxMode, ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.scope import (
    SandboxScope,
    active_scope,
    clear_backend_cache,
)
from tests.unit.core.phases.test_scanner_executor_lifecycle import (
    _ScannerConfig,
    _ScriptedScanner,
)

#: Landlock needs no package, so it is the mode an operator can most plausibly ask
#: for inside the image; the probe is stubbed, so the kernel here plays no part.
MODE = "landlock"
PROBE_FAILURE = "Landlock is not enabled in this kernel's LSM list"


class _ScopeRecordingScanner(_ScriptedScanner):
    """A scripted scanner that records the sandbox scope its scan ran under."""

    def scan(self, target, target_type=None, global_ignore_paths=None, config=None):
        self.scopes_seen.append(active_scope())
        return super().scan(target, target_type, global_ignore_paths, config)


@pytest.fixture
def in_the_image(monkeypatch):
    """ASH_IN_CONTAINER=YES, as the image sets it, and no probe result carried over.

    Probe results are cached per process and mode, so a result from another test
    would decide this one; the cache is cleared on both sides.
    """
    monkeypatch.setenv("ASH_IN_CONTAINER", "YES")
    clear_backend_cache()
    yield
    clear_backend_cache()


def _probe_reports(monkeypatch, reason):
    """Stub the backend's probe: None is OK, a string is why it cannot run."""
    monkeypatch.setattr(scope_module.BACKENDS[MODE], "probe", lambda self: reason)


def _operators_overrides(tmp_path):
    """What the CLI hands the scan for ``ash scan --sandbox <MODE>``, scanning nothing."""
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("print('x')\n", encoding="utf-8")
    captured = {}
    with mock.patch.object(
        scan_module, "run_ash_scan", lambda **kwargs: captured.update(kwargs)
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(source),
                "--output-dir",
                str(tmp_path / "output"),
                "--sandbox",
                MODE,
            ],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, result.output
    return captured


def _execute(tmp_path, overrides):
    """Run one scripted scanner through the executor with the resolved config."""
    source = tmp_path / "source"
    output = tmp_path / "output"
    work = tmp_path / "work"
    for path in (source, output, work):
        path.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=work,
        config=apply_config_overrides(AshConfig(project_name="test"), overrides),
    )
    scanner = _ScopeRecordingScanner(
        config=_ScannerConfig(enabled=True), context=context
    )
    scanner.scan_calls = []
    scanner.scopes_seen = []
    scanner.scripted_result = SarifReport(runs=[])
    scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
    scanner.end_time = datetime(2026, 1, 1, 10, 0, 7)
    scanner.exit_code = 0
    executor = ScannerExecutor(
        plugin_context=context, progress_display=mock.MagicMock(), scanner_tasks=[]
    )
    results = executor._execute_scanner(
        "scripted", scanner, [{"path": source, "type": "source"}]
    )
    return scanner, results


def test_the_cli_hands_the_scan_the_operators_mode(in_the_image, tmp_path):
    """Not refused in the image: the scan is local there, and the mode is its own."""
    captured = _operators_overrides(tmp_path)

    assert RunMode(captured["mode"]) == RunMode.local, captured["mode"]
    assert captured["config_overrides"][-1] == f"sandbox.mode={MODE}"
    config = apply_config_overrides(
        AshConfig(project_name="test"), captured["config_overrides"]
    )
    assert SandboxMode(config.sandbox.mode) == SandboxMode(MODE)


def test_the_mode_is_honored_when_the_backend_can_run(
    in_the_image, tmp_path, monkeypatch
):
    _probe_reports(monkeypatch, None)
    captured = _operators_overrides(tmp_path)

    scanner, results = _execute(tmp_path, captured["config_overrides"])

    assert len(scanner.scan_calls) == 1, "the scanner must run"
    (scope,) = scanner.scopes_seen
    assert isinstance(scope, SandboxScope), scope
    assert scope.backend.name == MODE, scope.backend.name
    assert results[0].status != ScannerStatus.MISSING


def test_the_scanners_are_in_error_when_the_backend_cannot_run(
    in_the_image, tmp_path, monkeypatch
):
    """Fail closed: the scanner never starts, unsandboxed or otherwise. The
    operator named this backend, so the scan is an ERROR that could not start
    its tool, with the start-failure code, never a missing dependency."""
    _probe_reports(monkeypatch, PROBE_FAILURE)
    captured = _operators_overrides(tmp_path)

    scanner, results = _execute(tmp_path, captured["config_overrides"])

    assert scanner.scan_calls == [], "the scanner must not run"
    assert len(results) == 1
    assert results[0].status == ScannerStatus.ERROR
    assert not results[0].missing_reason
    assert results[0].exit_code == 127
    raw = results[0].raw_results if isinstance(results[0].raw_results, dict) else {}
    lines = [str(line) for line in (*results[0].errors, *(raw.get("errors") or []))]
    assert any(
        "could not start its tool" in line and PROBE_FAILURE in line for line in lines
    ), lines
