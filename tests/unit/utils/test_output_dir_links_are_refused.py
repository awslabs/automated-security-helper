"""ASH never writes through a symlink below its output directory, sandbox or not.

The default output directory is inside the scanned tree, so the repository can commit
a link at any path below it, such as the request file the detect-secrets worker reads
or the results file a scanner writes. ``fs_guard.open_for_write`` opens every path
below the output directory of a ``PluginContext`` without following a link at any
component, the file name included, and refuses one with ``OutputLinkRefused``. A
scanner whose write is refused is ERROR, and nothing is written where the link
points.

The controls are a regular file at the same path, which is written, and a path
outside every output directory, which is opened as ``open()`` would.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox import fs_guard
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX symlinks and directory descriptors"
)

ORIGINAL = "outside content\n"
REFUSAL = (
    "is a symlink, and ASH does not write through a symlink below its output directory"
)


class _Recorder:
    """A sandbox backend that runs each spawn unchanged."""

    name = "recorder"

    def probe(self):
        return None

    def plan(self, argv, env, policy):
        return SpawnPlan(argv=list(argv), env=dict(env))


@pytest.fixture
def recorder_backend(monkeypatch):
    scope_module.clear_backend_cache()
    monkeypatch.setitem(scope_module.BACKENDS, "bwrap", _Recorder)
    yield
    scope_module.clear_backend_cache()


@pytest.fixture
def layout(tmp_path, monkeypatch):
    for variable in (
        "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        monkeypatch.delenv(variable, raising=False)
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "target.txt"
    target.write_text(ORIGINAL)
    return source, output, target


def _context(source: Path, output: Path, mode: str = "off") -> PluginContext:
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="links", sandbox=SandboxConfig(mode=mode)),
    )


class TestOpenForWrite:
    def test_a_link_at_the_file_name_is_refused(self, layout):
        source, output, target = layout
        _context(source, output)
        path = output / "scanners" / "tool" / "source" / "out.log"
        path.parent.mkdir(parents=True)
        path.symlink_to(target)

        with pytest.raises(fs_guard.OutputLinkRefused) as refused:
            fs_guard.open_for_write(path)

        assert REFUSAL in str(refused.value)
        assert str(path) in str(refused.value)
        assert target.read_text() == ORIGINAL
        assert path.is_symlink(), "the refusal leaves the link where it was"

    def test_a_link_at_a_directory_component_is_refused(self, layout):
        source, output, target = layout
        _context(source, output)
        (output / "scanners" / "tool").mkdir(parents=True)
        (output / "scanners" / "tool" / "source").symlink_to(
            target.parent, target_is_directory=True
        )
        path = output / "scanners" / "tool" / "source" / "target.txt"

        with pytest.raises(fs_guard.OutputLinkRefused) as refused:
            fs_guard.open_for_write(path)

        assert REFUSAL in str(refused.value)
        assert target.read_text() == ORIGINAL

    def test_the_refusal_is_an_oserror(self):
        assert issubclass(fs_guard.OutputLinkRefused, OSError)

    def test_a_regular_file_there_is_written(self, layout):
        source, output, _target = layout
        _context(source, output)
        path = output / "scanners" / "tool" / "source" / "out.log"
        path.parent.mkdir(parents=True)
        path.write_text("previous\n")

        with fs_guard.open_for_write(path) as handle:
            handle.write("written\n")

        assert path.read_text() == "written\n"

    def test_outside_every_output_directory_a_link_is_followed(self, tmp_path):
        """Control: nothing changes for a path that is not below an output directory."""
        target = tmp_path / "target.txt"
        target.write_text(ORIGINAL)
        path = tmp_path / "elsewhere" / "out.log"
        path.parent.mkdir()
        path.symlink_to(target)

        with fs_guard.open_for_write(path) as handle:
            handle.write("written\n")

        assert target.read_text() == "written\n"


class TestStreamLogs:
    def test_a_link_at_a_stream_log_is_not_written_through(self, layout):
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )

        source, output, target = layout
        _context(source, output)
        results = output / "scanners" / "tool" / "source"
        results.mkdir(parents=True)
        (results / "Probe.stdout.log").symlink_to(target)

        response = run_command_with_output_handling(
            [sys.executable, "-c", "print('tool output')"],
            results_dir=results,
            class_name="Probe",
            stdout_preference="write",
        )

        assert target.read_text() == ORIGINAL
        assert REFUSAL in str(response.get("error", "")), response

    def test_a_regular_stream_log_is_written(self, layout):
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )

        source, output, _target = layout
        _context(source, output)
        results = output / "scanners" / "tool" / "source"
        results.mkdir(parents=True)
        (results / "Probe.stdout.log").write_text("previous\n")

        response = run_command_with_output_handling(
            [sys.executable, "-c", "print('tool output')"],
            results_dir=results,
            class_name="Probe",
            stdout_preference="write",
        )

        assert response["returncode"] == 0, response
        assert (results / "Probe.stdout.log").read_text() == "tool output\n"


#: The paths below the output directory the detect-secrets scanner writes for a
#: source scan, relative to its results directory.
DETECT_SECRETS_WRITES = {
    "worker request": Path("source") / "detect-secrets-worker-request.json",
    "results": Path("source") / "results_sarif.sarif",
}


def _detect_secrets_row(context: PluginContext):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "detect-secrets",
        scanner,
        [{"path": Path(context.source_dir), "type": "source"}],
    )
    return scanner, row


@pytest.mark.usefixtures("recorder_backend")
class TestDetectSecretsWrites:
    @pytest.mark.parametrize("mode", ["off", "bwrap"])
    @pytest.mark.parametrize("write", sorted(DETECT_SECRETS_WRITES))
    def test_a_link_at_the_path_is_refused(self, layout, mode, write):
        source, output, target = layout
        context = _context(source, output, mode)
        planted = output / "scanners" / "detect-secrets" / DETECT_SECRETS_WRITES[write]
        planted.parent.mkdir(parents=True)
        planted.symlink_to(target)

        _scanner, row = _detect_secrets_row(context)

        assert target.read_text() == ORIGINAL, (
            f"the {write} file was written through a link with --sandbox {mode}"
        )
        assert row.status == ScannerStatus.ERROR, (
            f"--sandbox {mode}: the row was graded {row.status.value}"
        )
        assert any(REFUSAL in str(error) for error in row.errors), row.errors

    @pytest.mark.parametrize("mode", ["off", "bwrap"])
    def test_a_link_at_the_directory_that_holds_its_files_is_refused(
        self, layout, mode
    ):
        """The link is ``<output>/scanners/detect-secrets/source`` itself.

        The directory it names holds a file under the worker output's name, which
        ASH removes from the real directory before each run.
        """
        source, output, target = layout
        outside = target.parent
        held = outside / "detect-secrets-worker-output.json"
        held.write_text(ORIGINAL)
        context = _context(source, output, mode)
        planted = output / "scanners" / "detect-secrets" / "source"
        planted.parent.mkdir(parents=True)
        planted.symlink_to(outside, target_is_directory=True)

        _scanner, row = _detect_secrets_row(context)

        assert sorted(path.name for path in outside.iterdir()) == [
            held.name,
            target.name,
        ], f"--sandbox {mode}: the scanner changed the directory the link names"
        assert target.read_text() == ORIGINAL
        assert held.read_text() == ORIGINAL
        assert planted.is_symlink(), "the refusal leaves the link where it was"
        assert row.status == ScannerStatus.ERROR, (
            f"--sandbox {mode}: the row was graded {row.status.value}"
        )
        assert any(REFUSAL in str(error) for error in row.errors), row.errors

    @pytest.mark.parametrize("mode", ["off", "bwrap"])
    def test_regular_files_there_are_written(self, layout, mode):
        source, output, _target = layout
        context = _context(source, output, mode)
        results = output / "scanners" / "detect-secrets"
        for relative in DETECT_SECRETS_WRITES.values():
            (results / relative).parent.mkdir(parents=True, exist_ok=True)
            (results / relative).write_text("previous\n")

        _scanner, row = _detect_secrets_row(context)

        assert row.status == ScannerStatus.PASSED, row.errors
        sarif = json.loads((results / DETECT_SECRETS_WRITES["results"]).read_text())
        assert sarif["runs"], sarif


class TestTheWorkerOutput:
    """The worker child writes its output file; ASH removes any entry there first."""

    def test_the_worker_does_not_write_through_a_link(self, tmp_path):
        from automated_security_helper.utils import detect_secrets_worker

        target = tmp_path / "target.txt"
        target.write_text(ORIGINAL)
        request = tmp_path / "request.json"
        request.write_text(
            json.dumps(
                {"root": str(tmp_path), "baseline": None, "settings": {}, "paths": []}
            )
        )
        output = tmp_path / "output.json"
        output.symlink_to(target)

        with pytest.raises(OSError):
            detect_secrets_worker.main([str(request), str(output)])

        assert target.read_text() == ORIGINAL

    def test_the_worker_writes_a_new_output_file(self, tmp_path):
        from automated_security_helper.utils import detect_secrets_worker

        request = tmp_path / "request.json"
        request.write_text(
            json.dumps(
                {"root": str(tmp_path), "baseline": None, "settings": {}, "paths": []}
            )
        )
        output = tmp_path / "output.json"

        assert detect_secrets_worker.main([str(request), str(output)]) == 0
        assert json.loads(output.read_text()) == []


TOOL_SOURCE = "print('tool output')\n"


def _stream_log_scanner_class():
    from typing import ClassVar, Literal

    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType

    class _Config(ScannerPluginConfigBase):
        name: Literal["stream-tool"] = "stream-tool"

    class StreamToolScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def model_post_init(self, context):
            self.command = "stream-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            results_dir = self.results_dir / target_type
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir / "results.sarif"
            sarif = {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "stream-tool"}}, "results": []}],
            }
            script = (
                "import json, sys\n"
                f"open({str(results_file)!r}, 'w').write({json.dumps(sarif)!r})\n"
                + TOOL_SOURCE
            )
            return [sys.executable, "-c", script], results_file, None

    return StreamToolScanner, _Config


@pytest.mark.usefixtures("recorder_backend")
class TestStreamLogsThroughTheExecutor:
    """The template writes its tool's stdout to ``<ClassName>.stdout.log``."""

    def _row(self, context):
        scanner_class, config_class = _stream_log_scanner_class()
        scanner = scanner_class(config=config_class(), context=context)
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )
        (row,) = executor._execute_scanner(
            "stream-tool",
            scanner,
            [{"path": Path(context.source_dir), "type": "source"}],
        )
        return row

    @pytest.mark.parametrize("mode", ["off", "bwrap"])
    def test_a_link_at_the_stream_log_is_refused(self, layout, mode):
        source, output, target = layout
        context = _context(source, output, mode)
        log = (
            output
            / "scanners"
            / "stream-tool"
            / "source"
            / "StreamToolScanner.stdout.log"
        )
        log.parent.mkdir(parents=True)
        log.symlink_to(target)

        row = self._row(context)

        assert target.read_text() == ORIGINAL, (
            f"--sandbox {mode} wrote through the link"
        )
        assert row.status == ScannerStatus.ERROR, row.errors
        assert any(REFUSAL in str(error) for error in row.errors), row.errors

    @pytest.mark.parametrize("mode", ["off", "bwrap"])
    def test_a_regular_stream_log_is_written(self, layout, mode):
        source, output, _target = layout
        context = _context(source, output, mode)
        log = (
            output
            / "scanners"
            / "stream-tool"
            / "source"
            / "StreamToolScanner.stdout.log"
        )
        log.parent.mkdir(parents=True)
        log.write_text("previous\n")

        row = self._row(context)

        assert row.status == ScannerStatus.PASSED, row.errors
        assert log.read_text() == "tool output\n"
