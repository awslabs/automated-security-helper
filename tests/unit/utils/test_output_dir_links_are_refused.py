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
import os
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
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX symlinks and directory descriptors"
)

ORIGINAL = "outside content\n"
REFUSAL = (
    "is a symlink, and ASH does not write through a symlink below its output directory"
)
HARD_LINK_REFUSAL = (
    "and ASH does not write to a file below its output directory that another name "
    "refers to"
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


@pytest.mark.unit
class TestOpenForWrite:
    def test_a_link_at_the_file_name_is_refused(self, layout):
        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
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
        _held = _context(source, output)  # its root lasts as long as it does
        (output / "scanners" / "tool").mkdir(parents=True)
        (output / "scanners" / "tool" / "source").symlink_to(
            target.parent, target_is_directory=True
        )
        path = output / "scanners" / "tool" / "source" / "target.txt"

        with pytest.raises(fs_guard.OutputLinkRefused) as refused:
            fs_guard.open_for_write(path)

        assert REFUSAL in str(refused.value)
        assert target.read_text() == ORIGINAL

    def test_a_file_another_name_refers_to_is_refused(self, layout):
        """A hard link to a file outside the output directory, as an archive can hold."""
        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "scanners" / "tool" / "source" / "out.log"
        path.parent.mkdir(parents=True)
        os.link(target, path)

        with pytest.raises(fs_guard.OutputHardLinkRefused) as refused:
            fs_guard.open_for_write(path)

        assert HARD_LINK_REFUSAL in str(refused.value)
        assert str(path) in str(refused.value)
        assert target.read_bytes() == ORIGINAL.encode(), "the file was truncated"
        assert os.stat(path).st_nlink == 2, "the refusal leaves both names in place"

    def test_the_refusals_are_oserrors(self):
        assert issubclass(fs_guard.OutputLinkRefused, OSError)
        assert issubclass(fs_guard.OutputHardLinkRefused, OSError)

    def test_a_regular_file_there_is_written(self, layout):
        source, output, _target = layout
        _held = _context(source, output)  # its root lasts as long as it does
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


@pytest.mark.unit
class TestWithoutDirectoryDescriptors:
    """Windows has no O_NOFOLLOW or dir_fd; open_for_write checks each component.

    Forced here by turning off fs_guard's directory-descriptor support. A link is
    a symlink (``S_ISLNK``) or, on Windows, anything with the reparse-point
    attribute, such as a junction; the latter is simulated through ``_lstat``.
    """

    @pytest.fixture(autouse=True)
    def no_directory_descriptors(self, monkeypatch):
        monkeypatch.setattr(fs_guard, "_HAS_DIR_FD", False)

    def test_a_link_at_the_file_name_is_refused(self, layout):
        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "reports" / "ash.sarif"
        path.parent.mkdir()
        path.symlink_to(target)

        with pytest.raises(fs_guard.OutputLinkRefused):
            fs_guard.open_for_write(path)

        assert target.read_text() == ORIGINAL

    def test_a_link_at_a_directory_component_is_refused(self, layout):
        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        (output / "reports").symlink_to(target.parent, target_is_directory=True)

        with pytest.raises(fs_guard.OutputLinkRefused):
            fs_guard.open_for_write(output / "reports" / "ash.sarif")

        assert sorted(p.name for p in target.parent.iterdir()) == [target.name]

    def test_a_reparse_point_at_a_directory_component_is_refused(
        self, layout, monkeypatch
    ):
        import stat as stat_module
        from types import SimpleNamespace

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        junction = output / "reports"
        junction.mkdir()
        real_lstat = fs_guard._lstat

        def lstat(path):
            if Path(path) == junction:
                return SimpleNamespace(
                    st_mode=stat_module.S_IFDIR | 0o755,
                    st_nlink=1,
                    st_file_attributes=0x400,  # FILE_ATTRIBUTE_REPARSE_POINT
                )
            return real_lstat(path)

        monkeypatch.setattr(fs_guard, "_lstat", lstat)

        with pytest.raises(fs_guard.OutputLinkRefused):
            fs_guard.open_for_write(junction / "ash.sarif")

        assert list(junction.iterdir()) == []

    def test_a_file_another_name_refers_to_is_refused(self, layout):
        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "ash_aggregated_results.json"
        os.link(target, path)

        with pytest.raises(fs_guard.OutputHardLinkRefused):
            fs_guard.open_for_write(path)

        assert target.read_bytes() == ORIGINAL.encode()

    def test_an_atomic_write_through_a_linked_directory_is_refused(self, layout):
        from automated_security_helper.utils.atomic_write import write_text_atomically

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        (output / "reports").symlink_to(target.parent, target_is_directory=True)

        with pytest.raises(fs_guard.OutputLinkRefused):
            write_text_atomically(output / "reports" / "ash.sarif", "{}")

        assert sorted(p.name for p in target.parent.iterdir()) == [target.name]

    def test_a_regular_file_there_is_written_and_directories_made(self, layout):
        source, output, _target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "reports" / "nested" / "ash.sarif"

        with fs_guard.open_for_write(path) as handle:
            handle.write("written\n")

        assert path.read_text() == "written\n"


@pytest.mark.unit
class TestRefuseLinksBelow:
    """The check of a sandboxed scanner's results directory before the scanner runs."""

    def test_a_file_another_name_refers_to_is_refused(self, layout):
        _source, output, target = layout
        results = output / "scanners" / "tool"
        (results / "source").mkdir(parents=True)
        os.link(target, results / "source" / "out.sarif")

        with pytest.raises(fs_guard.OutputHardLinkRefused) as refused:
            fs_guard.refuse_links_below(results)

        assert HARD_LINK_REFUSAL in str(refused.value)
        assert target.read_bytes() == ORIGINAL.encode()

    def test_regular_files_and_directories_pass(self, layout):
        _source, output, _target = layout
        results = output / "scanners" / "tool"
        (results / "source" / "nested").mkdir(parents=True)
        (results / "source" / "out.sarif").write_text("{}\n")
        (results / "source" / "nested" / "out.log").write_text("log\n")

        fs_guard.refuse_links_below(results)


@pytest.mark.integration
class TestStreamLogs:
    def test_a_link_at_a_stream_log_is_not_written_through(self, layout):
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        results = output / "scanners" / "tool" / "source"
        results.mkdir(parents=True)
        (results / "Probe.stdout.log").symlink_to(target)

        response = run_command_with_output_handling(
            [sys.executable, "-c", "print('tool output')"],
            results_dir=results,
            class_name="Probe",
            stdout_preference="write",
            timeout=CHILD_TIMEOUT_SECONDS,
        )

        assert target.read_text() == ORIGINAL
        assert REFUSAL in str(response.get("error", "")), response

    def test_a_stream_log_another_name_refers_to_is_not_written(self, layout):
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        results = output / "scanners" / "tool" / "source"
        results.mkdir(parents=True)
        os.link(target, results / "Probe.stdout.log")

        response = run_command_with_output_handling(
            [sys.executable, "-c", "print('tool output')"],
            results_dir=results,
            class_name="Probe",
            stdout_preference="write",
            timeout=CHILD_TIMEOUT_SECONDS,
        )

        assert target.read_bytes() == ORIGINAL.encode()
        assert HARD_LINK_REFUSAL in str(response.get("error", "")), response

    def test_a_regular_stream_log_is_written(self, layout):
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )

        source, output, _target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        results = output / "scanners" / "tool" / "source"
        results.mkdir(parents=True)
        (results / "Probe.stdout.log").write_text("previous\n")

        response = run_command_with_output_handling(
            [sys.executable, "-c", "print('tool output')"],
            results_dir=results,
            class_name="Probe",
            stdout_preference="write",
            timeout=CHILD_TIMEOUT_SECONDS,
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


@pytest.mark.integration
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
        if write == "worker request" and mode == "off":
            # Without a sandbox nothing checks the results directory before the
            # scan; the scanner removes its own exchange names first, beneath the
            # directory without following a link (unlink_beneath), writes the
            # request fresh, and its finally removes both names again. So the
            # planted link is gone, not followed, and the scan is graded by what
            # it found. Under a sandbox refuse_links_below refuses it before the
            # scan starts (the other branch).
            assert not planted.is_symlink() and not planted.exists(), (
                "the planted link at the worker request name was not removed"
            )
            assert row.status != ScannerStatus.ERROR, row.errors
            assert not any(REFUSAL in str(error) for error in row.errors), row.errors
            return
        assert row.status == ScannerStatus.ERROR, (
            f"--sandbox {mode}: the row was graded {row.status.value}"
        )
        assert any(REFUSAL in str(error) for error in row.errors), row.errors

    @pytest.mark.parametrize("mode", ["off", "bwrap"])
    @pytest.mark.parametrize("write", sorted(DETECT_SECRETS_WRITES))
    def test_a_file_another_name_refers_to_is_refused(self, layout, mode, write):
        source, output, target = layout
        context = _context(source, output, mode)
        planted = output / "scanners" / "detect-secrets" / DETECT_SECRETS_WRITES[write]
        planted.parent.mkdir(parents=True)
        os.link(target, planted)

        _scanner, row = _detect_secrets_row(context)

        assert target.read_bytes() == ORIGINAL.encode(), (
            f"the {write} file was written through a hard link with --sandbox {mode}"
        )
        if write == "worker request" and mode == "off":
            # As for the symlink above: without a sandbox the scanner's own
            # cleanup unlinks the planted name before the request is written, so
            # the file the other name refers to keeps its bytes and is the only
            # name left, and the scan is graded by what it found.
            assert not planted.exists(), (
                "the planted hard link at the worker request name was not removed"
            )
            assert os.stat(target).st_nlink == 1
            assert row.status != ScannerStatus.ERROR, row.errors
            assert not any(HARD_LINK_REFUSAL in str(error) for error in row.errors), (
                row.errors
            )
            return
        assert row.status == ScannerStatus.ERROR, (
            f"--sandbox {mode}: the row was graded {row.status.value}"
        )
        assert any(HARD_LINK_REFUSAL in str(error) for error in row.errors), row.errors

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


@pytest.fixture
def log_name():
    """A logger of the test's own, closed afterwards, so ASH's logger is untouched."""
    import logging
    import uuid

    name = f"links-{uuid.uuid4().hex}"
    yield name
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def _get_logger(name: str, output: Path, truncate_log: bool = True):
    from automated_security_helper.utils.log import get_logger

    return get_logger(
        name=name,
        output_dir=output,
        log_format="BOTH",
        show_progress=True,
        truncate_log=truncate_log,
    )


@pytest.mark.unit
class TestTheLogFile:
    """``<output>/<name>.log`` and ``.log.jsonl``, which the logger opens itself."""

    @pytest.mark.parametrize("truncate_log", [True, False])
    @pytest.mark.parametrize("suffix", [".log", ".log.jsonl"])
    def test_a_link_at_the_log_file_is_refused(
        self, layout, log_name, suffix, truncate_log
    ):
        _source, output, target = layout
        planted = output / f"{log_name}{suffix}"
        planted.symlink_to(target)

        with pytest.raises(fs_guard.OutputLinkRefused) as refused:
            _get_logger(log_name, output, truncate_log)

        assert REFUSAL in str(refused.value)
        assert target.read_text() == ORIGINAL
        assert planted.is_symlink()

    def test_a_log_file_another_name_refers_to_is_refused(self, layout, log_name):
        _source, output, target = layout
        os.link(target, output / f"{log_name}.log")

        with pytest.raises(fs_guard.OutputHardLinkRefused):
            _get_logger(log_name, output)

        assert target.read_bytes() == ORIGINAL.encode()

    def test_a_scan_stops_before_writing_through_a_linked_ash_log(self, layout, capsys):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _setup_logger,
        )
        from automated_security_helper.utils.log import ASH_LOGGER

        source, output, target = layout
        (output / "ash.log").symlink_to(target)
        handlers = list(ASH_LOGGER.handlers)
        try:
            with pytest.raises(SystemExit) as exited:
                _setup_logger(ScanOptions(source_dir=source, output_dir=output))
        finally:
            for handler in ASH_LOGGER.handlers:
                if handler not in handlers:
                    handler.close()
            ASH_LOGGER.handlers = handlers

        assert exited.value.code == 3
        assert target.read_text() == ORIGINAL
        assert REFUSAL in " ".join(capsys.readouterr().out.split())

    def test_the_log_files_are_written(self, layout, log_name):
        _source, output, _target = layout
        (output / f"{log_name}.log").write_text("previous run\n")

        logger = _get_logger(log_name, output)
        logger.info("written by this run")
        for handler in logger.handlers:
            handler.flush()

        text = (output / f"{log_name}.log").read_text()
        assert "written by this run" in text
        assert "previous run" not in text
        assert "written by this run" in (output / f"{log_name}.log.jsonl").read_text()

    def test_without_truncation_the_log_is_appended_to(self, layout, log_name):
        _source, output, _target = layout
        (output / f"{log_name}.log").write_text("previous run\n")

        logger = _get_logger(log_name, output, truncate_log=False)
        logger.info("written by this run")
        for handler in logger.handlers:
            handler.flush()

        text = (output / f"{log_name}.log").read_text()
        assert text.startswith("previous run\n")
        assert "written by this run" in text


@pytest.mark.unit
class TestAtomicWrites:
    """``write_text_atomically``: a staging file in the target's directory, renamed."""

    def test_a_link_at_a_directory_component_is_refused(self, layout):
        from automated_security_helper.utils.atomic_write import write_text_atomically

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        (output / "reports").symlink_to(target.parent, target_is_directory=True)

        with pytest.raises(fs_guard.OutputLinkRefused) as refused:
            write_text_atomically(output / "reports" / "ash.sarif", "{}")

        assert REFUSAL in str(refused.value)
        assert sorted(p.name for p in target.parent.iterdir()) == [target.name]

    def test_a_link_at_the_file_name_is_refused(self, layout):
        from automated_security_helper.utils.atomic_write import write_text_atomically

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "ash_aggregated_results.json"
        path.symlink_to(target)

        with pytest.raises(fs_guard.OutputLinkRefused):
            write_text_atomically(path, "{}")

        assert target.read_text() == ORIGINAL
        assert path.is_symlink()
        assert [p.name for p in output.iterdir() if p.name.endswith(".tmp")] == []

    def test_a_file_another_name_refers_to_is_refused(self, layout):
        from automated_security_helper.utils.atomic_write import write_text_atomically

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "ash_aggregated_results.json"
        os.link(target, path)

        with pytest.raises(fs_guard.OutputHardLinkRefused):
            write_text_atomically(path, "{}")

        assert target.read_bytes() == ORIGINAL.encode()

    def test_a_regular_file_there_is_replaced(self, layout):
        from automated_security_helper.utils.atomic_write import write_text_atomically

        source, output, _target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "reports" / "ash.sarif"
        path.parent.mkdir()
        path.write_text("previous\n")

        write_text_atomically(path, "replaced\n")

        assert path.read_text() == "replaced\n"
        assert sorted(p.name for p in path.parent.iterdir()) == ["ash.sarif"]

    def test_outside_every_output_directory_it_writes_as_before(self, tmp_path):
        from automated_security_helper.utils.atomic_write import write_text_atomically

        path = tmp_path / "elsewhere" / "merged.json"
        path.parent.mkdir()

        write_text_atomically(path, "merged\n")

        assert path.read_text() == "merged\n"


@pytest.mark.unit
class TestOtherOutputWriters:
    def test_the_unused_suppressions_markdown_is_not_written_through_a_link(
        self, layout
    ):
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
            UnusedSuppressionsReporter,
        )

        source, output, target = layout
        context = _context(source, output)
        (output / "reports").mkdir()
        (output / "reports" / "ash.unused-suppressions.md").symlink_to(target)
        reporter = UnusedSuppressionsReporter(context=context)

        with pytest.raises(fs_guard.OutputLinkRefused):
            reporter.report(AshAggregatedResults())

        assert target.read_text() == ORIGINAL

    def test_safe_write_json_file_does_not_write_through_a_link(self, layout):
        from automated_security_helper.core.resource_management.error_handling import (
            safe_write_json_file,
        )

        source, output, target = layout
        _held = _context(source, output)  # its root lasts as long as it does
        path = output / "mcp" / "state.json"
        path.parent.mkdir()
        path.symlink_to(target)

        error = safe_write_json_file(path, {"written": True})

        assert target.read_text() == ORIGINAL
        assert error is not None and REFUSAL in str(error), error


@pytest.mark.unit
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


@pytest.mark.integration
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
