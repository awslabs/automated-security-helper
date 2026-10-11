# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container and nix mode read an inner run's results back only when that run completed.

The inner run is a local scan, and its exit status alone does not tell the outer
process whether to read its results back: 0, 1 and 2 are verdicts the outer
process re-derives, and 1 is also what a refused or crashed inner run exits with.
A refused report file name leaves nothing in ``reports/`` for the outer process to
find, and a crash after the scan phase leaves a results file that reads as clean.

So the outer process gives the inner run an ID, and the inner run writes that ID
into its results file when it completes, or with the refusal when its reports are
refused. The outer process reads the file back only when it carries its own ID's
completion marker; with its own ID's refusal it exits 1 with the inner run's
message; otherwise it exits 1 saying the inner run did not complete. A record
another run wrote is ignored.

Most tests run the inner local scan in this process, with a stand-in orchestrator
around the real report phase, so the records are written by the code that writes
them in production. Some hand the outer process a results file written here, to
pin how it reads one. The last runs ``ash scan --mode nix`` as a child process,
with a stand-in ``nix`` on PATH that runs the inner command directly.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Callable, Dict, List, Literal, Optional
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ConfigDict

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_container_mode,
    _run_local_mode,
    _run_nix_mode,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.helpers import REPO_ROOT

RUN_ASH_SCAN = "automated_security_helper.interactions.run_ash_scan"
RUN_ID_ENV = "ASH_OUTER_RUN_ID"
REFUSED_NAME = "ash.../outer-modes-escape.txt"
OTHER_RUN = "0" * 32

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="permission and symlink fixtures are POSIX"
)


class _EscapingConfig(ReporterPluginConfigBase):
    """A default is not validated, so this reaches the report phase unchanged."""

    model_config = ConfigDict(validate_default=False)

    name: Literal["outer-modes-escaper"] = "outer-modes-escaper"
    extension: str = "../outer-modes-escape.txt"
    enabled: bool = True


class _Escaping(ReporterPluginBase[_EscapingConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _EscapingConfig()
        return super().model_post_init(context)

    def report(self, model) -> Optional[str]:  # pragma: no cover - refused first
        return "x"


class _InnerOrchestrator:
    """Stands in for the inner run's orchestrator: the scan phase, then reporting.

    Writes the results file as the scan phase does (``save_model``), or with
    ``use_existing`` reads it as ``--use-existing`` does, then runs the real report
    phase with the given reporters. ``after_scan`` runs between the two.
    """

    config = None

    def __init__(
        self,
        output_dir: Path,
        reporters: List[type],
        use_existing: bool,
        after_scan: Optional[Callable[[], None]],
    ):
        self.output_dir = output_dir
        self.reporters = reporters
        self.use_existing = use_existing
        self.after_scan = after_scan

    def execute_scan(self, phases=None) -> AshAggregatedResults:
        results_file = self.output_dir / "ash_aggregated_results.json"
        if self.use_existing:
            model = AshAggregatedResults.model_validate_json(
                results_file.read_text(encoding="utf-8")
            )
        else:
            model = AshAggregatedResults(name="inner scan")
            model.save_model(self.output_dir)
        if self.after_scan is not None:
            self.after_scan()
        return ReportPhase(
            plugins=self.reporters,
            plugin_context=PluginContext(
                source_dir=self.output_dir.parent / "src",
                output_dir=self.output_dir,
                config=AshConfig(),
            ),
            progress_display=LiveProgressDisplay(show_progress=False),
            asharp_model=model,
        ).execute(
            report_dir=self.output_dir / "reports",
            aggregated_results=model,
            cli_output_formats=None,
            python_based_plugins_only=False,
        )


def _inner_run(
    run_id: Optional[str],
    output_dir: Path,
    reporters: List[type],
    use_existing: bool = False,
    after_scan: Optional[Callable[[], None]] = None,
) -> int:
    """Run the inner local scan in this process and return its exit status.

    An exception that escapes it exits 1, as it would in the inner process.
    """
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    inner = ScanOptions(
        source_dir=output_dir.parent / "src", output_dir=output_dir, mode=RunMode.local
    )
    orchestrator = _InnerOrchestrator(output_dir, reporters, use_existing, after_scan)
    environment = {RUN_ID_ENV: run_id} if run_id else {}
    with (
        patch.dict(os.environ, environment),
        patch.object(
            ASHScanOrchestrator, "create", staticmethod(lambda **kwargs: orchestrator)
        ),
    ):
        try:
            _run_local_mode(inner, MagicMock())
        except SystemExit as exited:
            return int(exited.code or 0)
        except Exception:  # noqa: BLE001 - the inner process would exit 1
            return 1
    return 0


def _opts(tmp_path: Path, **overrides) -> ScanOptions:
    (tmp_path / "src").mkdir(exist_ok=True)
    return ScanOptions(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", **overrides
    )


def _run_id(kwargs: Dict) -> str:
    run_id = kwargs.get("outer_run_id")
    assert isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{32}", run_id), kwargs
    return run_id


def _container(opts, inner: Callable[[str], int], logger=None):
    """Run container mode with ``inner(run_id)`` standing in for the container."""

    def run(*args, **kwargs):
        return create_completed_process(
            args=["run"], returncode=inner(_run_id(kwargs)), stdout="", stderr=""
        )

    with patch(f"{RUN_ASH_SCAN}.run_ash_container", side_effect=run):
        return _run_container_mode(opts, logger or MagicMock())


def _nix(opts, inner: Callable[[str], int], logger=None):
    def run(*args, **kwargs):
        return create_completed_process(args=[], returncode=inner(_run_id(kwargs)))

    with patch(f"{RUN_ASH_SCAN}.run_ash_nix", side_effect=run):
        return _run_nix_mode(opts, logger or MagicMock())


OUTER = pytest.mark.parametrize("outer", [_container, _nix], ids=["container", "nix"])


def _scan(opts, reporters, **kwargs) -> Callable[[str], int]:
    return lambda run_id: _inner_run(run_id, opts.output_dir, reporters, **kwargs)


def _errors(logger: MagicMock) -> str:
    return "\n".join(str(call.args[0]) for call in logger.error.call_args_list)


@OUTER
def test_an_inner_name_refusal_refuses_the_outer_run(tmp_path, outer):
    opts = _opts(tmp_path)

    with pytest.raises(SystemExit) as refused:
        outer(opts, _scan(opts, [_Escaping]))

    assert refused.value.code == 1
    reason = getattr(refused.value, "reason", "")
    assert f"The report file name {REFUSED_NAME!r} is not a file in" in reason, reason
    assert f"{opts.output_dir.as_posix()}/reports" in reason, reason
    assert list((opts.output_dir / "reports").iterdir()) == []


@OUTER
def test_a_later_run_that_writes_its_reports_clears_the_refusal(tmp_path, outer):
    """``--use-existing`` reads the results file back, record included."""
    opts = _opts(tmp_path)
    with pytest.raises(SystemExit):
        outer(opts, _scan(opts, [_Escaping]))
    opts.existing_results = (opts.output_dir / "ash_aggregated_results.json").as_posix()

    results = outer(opts, _scan(opts, [], use_existing=True))

    assert results.name == "inner scan"
    recorded = json.loads(
        (opts.output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert not any(
        checkpoint.get("type") == "report_path_refused"
        for checkpoint in recorded["validation_checkpoints"]
    )


@OUTER
def test_an_inner_run_without_a_refusal_is_read_back(tmp_path, outer):
    opts = _opts(tmp_path)

    results = outer(opts, _scan(opts, []))

    assert results.name == "inner scan"


@OUTER
def test_a_refusal_that_could_not_be_recorded_still_fails_the_outer_run(
    tmp_path, outer
):
    """The record cannot be written (here a read-only output directory, as on ENOSPC)."""
    opts = _opts(tmp_path)

    def lock_output_dir() -> None:
        opts.output_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)

    try:
        with pytest.raises(SystemExit) as refused:
            outer(opts, _scan(opts, [_Escaping], after_scan=lock_output_dir))
    finally:
        opts.output_dir.chmod(stat.S_IRWXU)

    assert refused.value.code == 1


@OUTER
def test_an_inner_run_that_failed_after_the_scan_phase_fails_the_outer_run(
    tmp_path, outer
):
    """A crash after the results file exists used to be read back as a verdict."""
    opts = _opts(tmp_path)
    logger = MagicMock()

    def crash() -> None:
        raise RuntimeError("inner run failed after the scan phase")

    with pytest.raises(SystemExit) as refused:
        outer(opts, _scan(opts, [], after_scan=crash), logger)

    assert refused.value.code == 1
    assert "did not complete" in _errors(logger), _errors(logger)


def _write_results(output_dir: Path, *checkpoints: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    document = json.loads(
        AshAggregatedResults(name="written here").model_dump_json(by_alias=True)
    )
    document["validation_checkpoints"] = list(checkpoints)
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps(document), encoding="utf-8"
    )


def _completed(run_id: str) -> dict:
    return {"type": "run_completed", "metadata": {"run_id": run_id}}


def _refused(run_id: str, message: str) -> dict:
    return {
        "type": "report_path_refused",
        "message": message,
        "metadata": {"run_id": run_id},
    }


@OUTER
def test_a_refusal_another_run_recorded_is_ignored_when_this_run_completed(
    tmp_path, outer
):
    opts = _opts(tmp_path)

    def inner(run_id: str) -> int:
        _write_results(
            opts.output_dir,
            _refused(OTHER_RUN, "an earlier refusal"),
            _completed(run_id),
        )
        return 0

    results = outer(opts, inner)

    assert results.name == "written here"


@OUTER
def test_a_refusal_another_run_recorded_does_not_explain_this_one(tmp_path, outer):
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir, _refused(OTHER_RUN, "an earlier refusal"))
        return 1

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    assert "an earlier refusal" not in str(getattr(refused.value, "reason", ""))
    assert "did not complete" in _errors(logger), _errors(logger)


@OUTER
def test_a_results_file_without_a_completion_marker_is_not_read_back(tmp_path, outer):
    """As an inner ASH that predates the marker writes it, even with exit 0."""
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir)
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    errors = _errors(logger)
    assert "did not complete" in errors, errors
    assert "older" in errors, errors


@OUTER
def test_a_completion_marker_another_run_wrote_is_not_read_back(tmp_path, outer):
    opts = _opts(tmp_path)

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir, _completed(OTHER_RUN))
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner)

    assert refused.value.code == 1


def test_the_container_output_directory_in_a_refusal_is_given_as_the_hosts(tmp_path):
    """The container sees the output directory at another path, as /out."""
    opts = _opts(tmp_path)
    opts.output_dir.mkdir()
    container_view = tmp_path / "container-out"
    container_view.symlink_to(opts.output_dir, target_is_directory=True)

    with pytest.raises(SystemExit) as refused:
        _container(opts, lambda run_id: _inner_run(run_id, container_view, [_Escaping]))

    reason = getattr(refused.value, "reason", "")
    assert f"is not a file in {opts.output_dir.as_posix()}/reports" in reason, reason
    assert "container-out" not in reason, reason


# --------------------------------------------------------------------------- #
# ash scan --mode nix, end to end
# --------------------------------------------------------------------------- #

PLUGIN = textwrap.dedent(
    """
    from typing import Literal
    from automated_security_helper.base.reporter_plugin import (
        ReporterPluginBase,
        ReporterPluginConfigBase,
    )
    from automated_security_helper.plugins.decorators import ash_reporter_plugin


    class EscapingConfig(ReporterPluginConfigBase):
        name: Literal["outer-modes-escaper"] = "outer-modes-escaper"
        extension: str = "../outer-modes-escape.txt"
        enabled: bool = True


    @ash_reporter_plugin
    class EscapingReporter(ReporterPluginBase[EscapingConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = EscapingConfig()
            return super().model_post_init(context)

        def report(self, model):
            return "report body"


    ASH_REPORTERS = [EscapingReporter]
    """
)

# Drops `nix ... develop <ref> --command` and runs the rest, which is `ash ...`.
FAKE_NIX = '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "--command" ]; do shift; done\nshift\nexec "$@"\n'

ASH = Path(sys.executable).with_name("ash")


@pytest.mark.skipif(
    not ASH.is_file(), reason="no ash entry point beside the interpreter"
)
def test_ash_scan_in_nix_mode_exits_1_when_the_inner_run_refuses_a_name(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nix = bin_dir / "nix"
    nix.write_text(FAKE_NIX, encoding="utf-8")
    nix.chmod(nix.stat().st_mode | stat.S_IXUSR)
    plugins = tmp_path / "plugins" / "outer_modes_escaping_plugins"
    plugins.mkdir(parents=True)
    (plugins / "__init__.py").write_text(PLUGIN, encoding="utf-8")
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(indent=2, by_alias=True),
        encoding="utf-8",
    )
    env = dict(os.environ)
    env.pop(RUN_ID_ENV, None)
    env.update(
        {
            # The inner `ash` is the entry point beside this interpreter; this
            # checkout first on its path, then the plugin.
            "PATH": os.pathsep.join([str(bin_dir), str(ASH.parent), env["PATH"]]),
            "PYTHONPATH": os.pathsep.join([str(REPO_ROOT), str(plugins.parent)]),
            "ASH_NIX_FLAKE_REF": "path:/nonexistent",
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "2000",
        }
    )

    def scan(*extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(  # nosec B603 - fixed argv, the test's own entry point
            [
                str(ASH),
                "scan",
                "--mode",
                "nix",
                "--source-dir",
                str(source),
                "--output-dir",
                str(output),
                "--use-existing",
                "--no-progress",
                "--no-fail-on-findings",
                *extra,
            ],
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
            cwd=tmp_path,
        )

    refused = scan("--ash-plugin-modules", "outer_modes_escaping_plugins")
    console = re.sub(r"\x1b\[[0-9;]*m", "", refused.stdout + refused.stderr)

    assert "Nix shell exited with code 1" in console, console[-4000:]
    assert refused.returncode == 1, console[-4000:]
    # Printed by the inner run, then by the outer process from the recorded refusal.
    refusal = f"ERROR (1) The report file name {REFUSED_NAME!r} is not a file in"
    assert console.count(refusal) >= 2, console[-4000:]
    assert list((output / "reports").iterdir()) == []

    # Without the plugin the same output directory is reported on, and exits 0.
    written = scan()
    console = re.sub(r"\x1b\[[0-9;]*m", "", written.stdout + written.stderr)

    assert written.returncode == 0, console[-4000:]
    assert (output / "reports" / "ash.sarif").is_file()
