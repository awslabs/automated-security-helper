# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container and nix mode read an inner run's results back only when that run completed.

The inner run is a local scan, and its exit status alone does not tell the outer
process whether to read its results back: 0, 1 and 2 are verdicts the outer
process re-derives, and 1 is also what a refused or crashed inner run exits with.
A refused report file name leaves nothing in ``reports/`` for the outer process to
find, and a crash after the scan phase leaves a results file that reads as clean.

So the outer process gives the inner run an ID, and the inner run writes that ID
into its results file when it completes, or, with the refusal, into
``ash_inner_run_outcome.json`` beside it when its reports are refused. The outer
process reads the results back only when they carry its own ID's completion
marker; with its own ID's refusal it exits 1 with the inner run's message;
otherwise it exits 1 saying the inner run did not complete. A record another run
wrote is ignored. The refusal is kept out of the results file so that a file
holding only a refusal is never left for ``--use-existing`` to read as a scan.

Most tests run the inner local scan in this process, with a stand-in orchestrator
around the real report phase, so the records are written by the code that writes
them in production. Some hand the outer process a results file written here, to
pin how it reads one. The last runs ``ash scan --mode nix`` as a child process,
with a stand-in ``nix`` on PATH that runs the inner command directly.
"""

from __future__ import annotations

import json
import logging
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
        self.metadata: Dict[str, object] = {}

    def add_metadata(self, **values) -> None:
        """As ASHScanOrchestrator.add_metadata: the local run records the
        changed-files marker and the scan source on the orchestrator before
        execute_scan (run_ash_scan._run_local_mode)."""
        self.metadata.update(values)

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
    logger: Optional[MagicMock] = None,
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
            _run_local_mode(inner, logger or MagicMock())
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

    with (
        patch(f"{RUN_ASH_SCAN}.run_ash_nix", side_effect=run),
        patch(f"{RUN_ASH_SCAN}.nix_preflight", lambda: None),
    ):
        return _run_nix_mode(opts, logger or MagicMock())


OUTER = pytest.mark.parametrize("outer", [_container, _nix], ids=["container", "nix"])


def _scan(opts, reporters, **kwargs) -> Callable[[str], int]:
    return lambda run_id: _inner_run(run_id, opts.output_dir, reporters, **kwargs)


def _errors(logger: MagicMock) -> str:
    return "\n".join(str(call.args[0]) for call in logger.error.call_args_list)


@OUTER
@pytest.mark.unit
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
@pytest.mark.unit
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
@pytest.mark.unit
def test_an_inner_run_without_a_refusal_is_read_back(tmp_path, outer):
    opts = _opts(tmp_path)

    results = outer(opts, _scan(opts, []))

    assert results.name == "inner scan"


@OUTER
@pytest.mark.unit
def test_a_refusal_that_could_not_be_recorded_still_fails_the_outer_run(
    tmp_path, outer
):
    """The record's write fails (as on ENOSPC); the outer process finds no completion."""
    from automated_security_helper.utils import inner_run_outcome

    opts = _opts(tmp_path)
    inner_logger, outer_logger = MagicMock(), MagicMock()
    failing_write = MagicMock(side_effect=OSError("no space left on device"))

    with (
        patch.object(inner_run_outcome, "write_text_atomically", failing_write),
        pytest.raises(SystemExit) as refused,
    ):
        outer(
            opts,
            lambda run_id: _inner_run(
                run_id, opts.output_dir, [_Escaping], logger=inner_logger
            ),
            outer_logger,
        )

    assert refused.value.code == 1
    assert failing_write.called
    assert "did not complete" in _errors(outer_logger), _errors(outer_logger)
    written = json.loads(
        (opts.output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert not any(
        checkpoint.get("type") == "report_path_refused"
        for checkpoint in written["validation_checkpoints"]
    )
    warnings = "\n".join(
        str(call.args[0]) for call in inner_logger.warning.call_args_list
    )
    assert "Could not record the refusal" in warnings, warnings


@OUTER
@pytest.mark.unit
def test_a_completion_record_that_could_not_be_written_fails_the_outer_run(
    tmp_path, outer
):
    """The inner run's last write of its results fails, marker and all."""
    from automated_security_helper.interactions import run_ash_scan

    opts = _opts(tmp_path)
    logger = MagicMock()
    results_file = opts.output_dir / "ash_aggregated_results.json"
    real_write = run_ash_scan.write_text_atomically

    def failing_results_write(path, content, *args, **kwargs):
        if Path(path) == results_file:
            raise OSError("no space left on device")
        return real_write(path, content, *args, **kwargs)

    with (
        patch.object(run_ash_scan, "write_text_atomically", failing_results_write),
        pytest.raises(SystemExit) as refused,
    ):
        outer(opts, _scan(opts, []), logger)

    assert refused.value.code == 1
    assert "did not complete" in _errors(logger), _errors(logger)


@OUTER
@pytest.mark.unit
def test_a_run_that_fails_after_reading_an_earlier_runs_results_says_so(
    tmp_path, outer
):
    """--use-existing: the file holds the earlier run's marker, not this run's."""
    opts = _opts(tmp_path)
    outer(opts, _scan(opts, []))
    opts.existing_results = (opts.output_dir / "ash_aggregated_results.json").as_posix()
    logger = MagicMock()

    def crash() -> None:
        raise RuntimeError("failed after reading the existing results")

    with pytest.raises(SystemExit) as refused:
        outer(opts, _scan(opts, [], use_existing=True, after_scan=crash), logger)

    assert refused.value.code == 1
    errors = _errors(logger)
    assert "did not complete" in errors and "earlier run" in errors, errors


@OUTER
@pytest.mark.unit
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


@OUTER
@pytest.mark.integration
def test_a_process_the_inner_run_starts_does_not_see_the_run_id(tmp_path, outer):
    """The ID is taken out of the environment when the inner run starts."""
    opts = _opts(tmp_path)
    seen: List[str] = []

    def spawn() -> None:
        seen.append(
            subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
                [
                    sys.executable,
                    "-c",
                    f"import os; print(os.environ.get({RUN_ID_ENV!r}, 'absent'))",
                ],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )

    results = outer(opts, _scan(opts, [], after_scan=spawn))

    assert seen == ["absent"]
    assert results.name == "inner scan"


@pytest.mark.unit
def test_a_malformed_run_id_is_reported_and_not_used(tmp_path, monkeypatch):
    """Not an ID this ASH gives an inner run, so no marker carries it."""
    from automated_security_helper.utils.log import ASH_LOGGER

    opts = _opts(tmp_path)
    warnings: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                warnings.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        status = _inner_run("not-a-run-id", opts.output_dir, [])
    finally:
        ASH_LOGGER.removeHandler(handler)

    assert status == 0
    assert any(RUN_ID_ENV in message for message in warnings), warnings
    written = json.loads(
        (opts.output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert not any(
        checkpoint.get("type") == "run_completed"
        for checkpoint in written["validation_checkpoints"]
    )


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


OUTCOME_FILE = "ash_inner_run_outcome.json"


def _write_outcome(output_dir: Path, record: dict) -> Path:
    """Write ``record`` where an inner run records a refusal."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / OUTCOME_FILE
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _refused(run_id: Optional[str], message: str) -> dict:
    metadata = {"run_id": run_id} if run_id else {}
    return {"type": "report_path_refused", "message": message, "metadata": metadata}


@OUTER
@pytest.mark.unit
def test_the_refusal_is_recorded_beside_the_results_not_in_them(tmp_path, outer):
    """So no results file is left that a later --use-existing reads as a scan."""
    opts = _opts(tmp_path)
    run_ids: List[str] = []

    def inner(run_id: str) -> int:
        run_ids.append(run_id)
        return _inner_run(run_id, opts.output_dir, [_Escaping])

    with pytest.raises(SystemExit):
        outer(opts, inner)

    outcome = json.loads((opts.output_dir / OUTCOME_FILE).read_text(encoding="utf-8"))
    assert outcome["type"] == "report_path_refused"
    assert outcome["metadata"]["run_id"] == run_ids[0]
    assert REFUSED_NAME in outcome["message"]
    recorded = json.loads(
        (opts.output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert not any(
        checkpoint.get("type") in ("report_path_refused", "run_completed")
        for checkpoint in recorded["validation_checkpoints"]
    )


class _RefusedBeforeWriting:
    """An inner orchestrator whose reports are refused before any results are written."""

    config = None

    def add_metadata(self, **values) -> None:
        """Recorded before execute_scan, as on the real orchestrator; nothing
        reads it here."""

    def execute_scan(self, phases=None):
        from automated_security_helper.utils.report_path_links import (
            ReportPathRefused,
        )

        raise ReportPathRefused("the report file name 'ash.x/y' is not a file in here")


@OUTER
@pytest.mark.unit
def test_a_refusal_before_any_results_file_is_reported_with_its_message(
    tmp_path, outer
):
    """As ``--phases report`` refuses: there is no results file to record it in."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    opts = _opts(tmp_path)

    def inner(run_id: str) -> int:
        inner_opts = ScanOptions(
            source_dir=opts.source_dir, output_dir=opts.output_dir, mode=RunMode.local
        )
        with (
            patch.dict(os.environ, {RUN_ID_ENV: run_id}),
            patch.object(
                ASHScanOrchestrator,
                "create",
                staticmethod(lambda **kwargs: _RefusedBeforeWriting()),
            ),
        ):
            try:
                _run_local_mode(inner_opts, MagicMock())
            except SystemExit as exited:
                return int(exited.code or 0)
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner)

    assert refused.value.code == 1
    reason = getattr(refused.value, "reason", "")
    assert "The report file name 'ash.x/y' is not a file in here" in reason, reason
    assert not (opts.output_dir / "ash_aggregated_results.json").exists()


@OUTER
@pytest.mark.unit
def test_a_refusal_record_that_is_a_link_is_not_read(tmp_path, outer):
    """It refuses the read-back, as a link in reports/ does."""
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir, _completed(run_id))
        target = tmp_path / "elsewhere.json"
        target.write_text(json.dumps(_refused(run_id, "from elsewhere")), "utf-8")
        (opts.output_dir / OUTCOME_FILE).symlink_to(target)
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    reason = str(getattr(refused.value, "reason", ""))
    assert f"{(opts.output_dir / OUTCOME_FILE).as_posix()} is a symlink" in reason
    assert "from elsewhere" not in _errors(logger) + reason


@OUTER
@pytest.mark.parametrize("kind", ["symlink", "directory"])
@pytest.mark.unit
def test_a_results_file_that_is_not_a_regular_file_is_not_read(tmp_path, outer, kind):
    """It refuses the read-back without being read: a link could name any file."""
    opts = _opts(tmp_path)
    logger = MagicMock()
    elsewhere = tmp_path / "elsewhere.ini"
    elsewhere.write_text("[default]\nkey = NOT-TO-BE-ECHOED\n", encoding="utf-8")
    results_file = opts.output_dir / "ash_aggregated_results.json"

    def inner(run_id: str) -> int:
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        if kind == "symlink":
            results_file.symlink_to(elsewhere)
        else:
            results_file.mkdir()
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    reason = str(getattr(refused.value, "reason", ""))
    expected = "is a symlink" if kind == "symlink" else "is not a regular file"
    assert f"{results_file.as_posix()} {expected}" in reason, reason
    assert "NOT-TO-BE-ECHOED" not in _errors(logger) + reason


@OUTER
@pytest.mark.unit
def test_a_results_file_that_does_not_parse_is_reported_without_its_content(
    tmp_path, outer
):
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        (opts.output_dir / "ash_aggregated_results.json").write_text(
            json.dumps({"name": {"value": "NOT-TO-BE-ECHOED"}}), encoding="utf-8"
        )
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    errors = _errors(logger)
    assert "Failed to parse results file" in errors, errors
    assert "name" in errors, errors
    assert "NOT-TO-BE-ECHOED" not in errors, errors


@OUTER
@pytest.mark.unit
def test_an_earlier_runs_refusal_record_is_removed_before_the_inner_run(
    tmp_path, outer
):
    """--use-existing keeps the results file, but not the record of another run."""
    opts = _opts(tmp_path)
    _write_results(opts.output_dir, _completed(OTHER_RUN))
    _write_outcome(opts.output_dir, _refused(OTHER_RUN, "an earlier refusal"))
    opts.existing_results = (opts.output_dir / "ash_aggregated_results.json").as_posix()
    present: List[bool] = []

    def inner(run_id: str) -> int:
        present.append((opts.output_dir / OUTCOME_FILE).exists())
        _write_results(opts.output_dir, _completed(run_id))
        return 0

    results = outer(opts, inner)

    assert present == [False]
    assert results.name == "written here"


@OUTER
@pytest.mark.unit
def test_a_refusal_another_run_recorded_is_ignored_when_this_run_completed(
    tmp_path, outer
):
    opts = _opts(tmp_path)

    def inner(run_id: str) -> int:
        _write_outcome(opts.output_dir, _refused(OTHER_RUN, "an earlier refusal"))
        _write_results(opts.output_dir, _completed(run_id))
        return 0

    results = outer(opts, inner)

    assert results.name == "written here"


@OUTER
@pytest.mark.unit
def test_a_refusal_another_run_recorded_does_not_explain_this_one(tmp_path, outer):
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_outcome(opts.output_dir, _refused(OTHER_RUN, "an earlier refusal"))
        _write_results(opts.output_dir)
        return 1

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    assert "an earlier refusal" not in str(getattr(refused.value, "reason", ""))
    assert "did not complete" in _errors(logger), _errors(logger)


@OUTER
@pytest.mark.parametrize("inner_status", [0, 2])
@pytest.mark.unit
def test_a_results_file_without_a_completion_marker_is_not_read_back(
    tmp_path, outer, inner_status
):
    """As an inner ASH that predates the marker writes it.

    Exit 1, ASH's scan-error status, whatever the inner run's status: 2 would claim
    findings this process never read.
    """
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir)
        return inner_status

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    errors = _errors(logger)
    assert "did not complete" in errors, errors
    if outer is _container:
        # The image can hold an older ASH, which a rebuild replaces.
        assert "rebuild the image from this ASH" in errors, errors
    else:
        # The shell runs this ASH's own interpreter, which the message names.
        assert sys.executable in errors, errors


@pytest.mark.parametrize(
    ("version", "revision", "named"),
    [
        # This checkout's own version: no v3.7.0 tag records completion.
        ("3.7.0", "LOCAL", "this ASH's own source tree"),
        ("3.7.1", "v3.7.1", "ASH revision v3.7.1"),
        # Not a release, so there is no tag to name.
        ("3.8.0.dev1", "main", "ASH revision main"),
        ("3.8.0rc1", None, "the revision this ASH was installed from"),
        # A release of this ASH, whose tag records completion.
        ("3.8.0", "v3.8.0", None),
    ],
)
@pytest.mark.unit
def test_the_container_hint_names_a_release_only_when_it_records_completion(
    tmp_path, monkeypatch, version, revision, named
):
    """``--ash-revision-to-install v<version>`` is offered only for a release that works.

    v3.7.1 and earlier do not record completion, so naming one of them would build
    an image that fails the same way. Otherwise the message names the revision a
    rebuild installs.
    """
    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import get_ash_version

    monkeypatch.setattr(get_ash_version, "get_ash_version", lambda: version)
    monkeypatch.setattr(
        run_ash_container, "get_ash_revision", lambda quiet=False: revision
    )
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir)
        return 0

    with pytest.raises(SystemExit) as refused:
        _container(opts, inner, logger)

    assert refused.value.code == 1
    errors = _errors(logger)
    hint = errors[errors.index("An ASH older than this one") :]
    # The rebuild comes first: it is the fix for every image.
    assert hint.startswith(
        "An ASH older than this one does not write that record: rebuild the image "
        "from this ASH"
    ), hint
    offered = f"--ash-revision-to-install v{version}"
    if named is None:
        assert offered in hint, hint
        assert f"to install ASH {version} in it" in hint, hint
    else:
        assert offered not in hint, hint
        assert f"the build installs {named}" in hint, hint


@OUTER
@pytest.mark.unit
def test_a_completion_marker_without_a_run_id_is_attributed_to_an_older_ash(
    tmp_path, outer
):
    """A marker this run did not write, whatever wrote it, is not this run's."""
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir, {"type": "run_completed"})
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    errors = _errors(logger)
    assert "did not complete" in errors, errors
    assert "a record without a run ID, which an ASH older than this one" in errors


@OUTER
@pytest.mark.unit
def test_a_refusal_recorded_without_a_run_id_is_not_this_runs(tmp_path, outer):
    opts = _opts(tmp_path)
    logger = MagicMock()

    def inner(run_id: str) -> int:
        _write_outcome(opts.output_dir, _refused(None, "a refusal with no run ID"))
        _write_results(opts.output_dir)
        return 1

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner, logger)

    assert refused.value.code == 1
    assert "did not complete" in _errors(logger), _errors(logger)
    assert "a refusal with no run ID" not in str(getattr(refused.value, "reason", ""))


@OUTER
@pytest.mark.unit
def test_a_completion_marker_another_run_wrote_is_not_read_back(tmp_path, outer):
    opts = _opts(tmp_path)

    def inner(run_id: str) -> int:
        _write_results(opts.output_dir, _completed(OTHER_RUN))
        return 0

    with pytest.raises(SystemExit) as refused:
        outer(opts, inner)

    assert refused.value.code == 1


@pytest.mark.unit
def test_a_workspace_refused_before_any_project_refuses_the_container_run(
    tmp_path, monkeypatch
):
    """No results file exists yet; the refusal is recorded beside where it would be."""
    from automated_security_helper.interactions.run_ash_scan import _run_workspace_mode
    from automated_security_helper.utils.report_path_links import ReportPathRefused
    from automated_security_helper.workspace import execution as workspace_execution
    from automated_security_helper.workspace.plan import WorkspacePlan

    opts = _opts(tmp_path)
    message = (
        f"the report file name 'ash.../x' is not a file in {opts.output_dir}/reports"
    )

    def refused_before_any_project(plan, settings):
        raise ReportPathRefused(message)

    monkeypatch.setattr(
        workspace_execution, "execute_workspace", refused_before_any_project
    )
    plan = WorkspacePlan(
        workspace_file=(tmp_path / "src" / "w.code-workspace").as_posix(),
        workspace_root=(tmp_path / "src").as_posix(),
        projects=[],
    )

    def inner(run_id: str) -> int:
        inner_opts = ScanOptions(
            source_dir=opts.source_dir,
            output_dir=opts.output_dir,
            workspace_plan=plan,
        )
        with patch.dict(os.environ, {RUN_ID_ENV: run_id}):
            try:
                _run_workspace_mode(inner_opts, MagicMock())
            except SystemExit as exited:
                return int(exited.code or 0)
        return 0

    with pytest.raises(SystemExit) as refused:
        _container(opts, inner)

    assert refused.value.code == 1
    assert "The report file name 'ash.../x' is not a file in" in getattr(
        refused.value, "reason", ""
    )
    # No results file holding only the refusal, which --use-existing would read.
    assert not (opts.output_dir / "ash_aggregated_results.json").exists()


@pytest.mark.unit
def test_the_container_output_directory_in_a_refusal_is_given_as_the_hosts(tmp_path):
    """The container sees the output directory at another path, as /out.

    The inner run writes to its own directory, standing in for the container's
    view of the mount, and what it wrote then appears in the host's output
    directory, as through the mount. A real directory rather than a link: ASH
    refuses to write through a link at its output directory.
    """
    import shutil

    opts = _opts(tmp_path)
    opts.output_dir.mkdir()
    container_view = tmp_path / "container-out"
    container_view.mkdir()

    def inner(run_id: str) -> int:
        status = _inner_run(run_id, container_view, [_Escaping])
        shutil.copytree(container_view, opts.output_dir, dirs_exist_ok=True)
        return status

    with pytest.raises(SystemExit) as refused:
        _container(opts, inner)

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
@pytest.mark.integration
def test_ash_scan_in_nix_mode_exits_1_when_the_inner_run_refuses_a_name(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nix = bin_dir / "nix"
    nix.write_text(FAKE_NIX, encoding="utf-8")
    nix.chmod(nix.stat().st_mode | stat.S_IXUSR)
    # A top-level package ending in _ash_plugins: a name in ASH's plugin namespace.
    plugins = tmp_path / "plugins" / "outer_modes_escaping_ash_plugins"
    plugins.mkdir(parents=True)
    (plugins / "__init__.py").write_text(PLUGIN, encoding="utf-8")
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    # A scan's results, with one scanner's entry: --use-existing refuses results
    # that hold no scan.
    existing = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    existing["scanner_results"] = {
        "bandit": {"source": {"scanner_name": "bandit", "status": "PASSED"}}
    }
    (output / "ash_aggregated_results.json").write_text(
        json.dumps(existing, indent=2), encoding="utf-8"
    )
    env = dict(os.environ)
    env.pop(RUN_ID_ENV, None)
    env.update(
        {
            # The inner run is started with the outer ASH's interpreter, the one
            # beside its entry point; this checkout first on its path, then the
            # plugin.
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

    refused = scan("--ash-plugin-modules", "outer_modes_escaping_ash_plugins")
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
