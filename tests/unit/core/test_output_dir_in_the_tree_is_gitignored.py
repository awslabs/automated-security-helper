# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An output directory inside the scanned tree gets a ``.gitignore`` that ignores it.

``snyk code test`` reads the directory it tests, uploads the files it reads, and has
no option that leaves out a path; it does honor the ``.gitignore`` files there (read
from snyk's sources, not measured). ASH's default output directory,
``.ash/ash_output``, is inside the tree, so on any run after the first, snyk-code
uploaded the earlier run's reports and logs, and the converted files, unless the
tree happened to ignore them. ``ash config init`` writes ``.ash/.gitignore`` for
this; a tree that never ran it had nothing.

Now ASH writes ``<output_dir>/.gitignore`` holding ``*`` when the output directory
is inside the source directory and nothing is at that name: from the CLI once the
logger has made the directory, before any mode starts (so container mode's host
writes it too), and from the orchestrator when it makes its directories (MCP and
API scans). An existing file is left alone, nothing is written for an output
directory outside the tree, and a link at the name is refused without being
followed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.interactions import run_ash_scan
from automated_security_helper.interactions.run_ash_scan import (
    OutputDirRefusedExit,
    ScanOptions,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import get_scan_set, output_dir_links
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    linked_output_component,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _orchestrator(source: Path, output: Path) -> ASHScanOrchestrator:
    """Constructed without initialize(); the constructor does no filesystem I/O."""
    return ASHScanOrchestrator(
        source_dir=source,
        output_dir=output,
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )


@pytest.fixture
def source(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n", encoding="utf-8")
    return source


def _rules(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


class TestTheOrchestrator:
    def test_an_output_directory_in_the_tree_ignores_everything_in_it(self, source):
        output = source / ".ash" / "ash_output"

        _orchestrator(source, output).ensure_directories()

        assert _rules(output / ".gitignore") == ["*"]

    def test_the_scan_set_does_not_count_it_as_an_earlier_runs_file(self, source):
        """It is this run's, like ash.log, so the warning about files already in
        the output directory does not fire for it."""
        output = source / ".ash" / "ash_output"
        _orchestrator(source, output).ensure_directories()
        (output / "reports" / "ash.html").write_text("<p/>\n", encoding="utf-8")

        assert (output / ".gitignore").is_file()
        assert get_scan_set._count_files_in_own_output(str(output)) == 1

    def test_an_existing_gitignore_is_left_as_it_is(self, source):
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (output / ".gitignore").write_text("reports/\n", encoding="utf-8")

        _orchestrator(source, output).ensure_directories()

        assert (output / ".gitignore").read_text(encoding="utf-8") == "reports/\n"

    def test_nothing_is_written_for_an_output_directory_outside_the_tree(
        self, source, tmp_path
    ):
        output = tmp_path / "out"

        _orchestrator(source, output).ensure_directories()

        assert output.is_dir()
        assert not (output / ".gitignore").exists()

    def test_a_link_at_the_name_is_refused_and_not_followed(self, source, tmp_path):
        host = tmp_path / "host"
        host.mkdir()
        target = host / "keep.txt"
        target.write_text("keep\n", encoding="utf-8")
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (output / ".gitignore").symlink_to(target)

        with pytest.raises(ASHValidationError) as refused:
            _orchestrator(source, output).ensure_directories()

        assert ".gitignore" in str(refused.value)
        assert target.read_text(encoding="utf-8") == "keep\n"
        assert [p.name for p in host.iterdir()] == ["keep.txt"]

    def test_a_dangling_link_at_the_name_creates_nothing(self, source, tmp_path):
        missing = tmp_path / "host" / "made.txt"
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (output / ".gitignore").symlink_to(missing)

        with pytest.raises(ASHValidationError):
            _orchestrator(source, output).ensure_directories()

        assert not missing.exists()
        assert not missing.parent.exists()


@pytest.fixture
def restore_ash_logger():
    """Drop the handlers _setup_logger adds, so later tests log as before."""
    handlers = list(ASH_LOGGER.handlers)
    yield
    for handler in ASH_LOGGER.handlers:
        if handler not in handlers:
            handler.close()
    ASH_LOGGER.handlers = handlers


class TestTheCommandLine:
    def test_the_gitignore_is_there_before_any_mode_starts(
        self, source, monkeypatch, restore_ash_logger
    ):
        """Container mode included: the host writes it, before the container runs."""
        output = source / ".ash" / "ash_output"
        seen = {}

        class _Stop(Exception):
            pass

        def _record(opts, logger, **_kwargs):
            seen["rules"] = _rules(output / ".gitignore")
            raise _Stop

        monkeypatch.setattr(run_ash_scan, "_run_container_mode", _record)
        opts = ScanOptions(source_dir=source, output_dir=output, mode=RunMode.container)

        with pytest.raises(_Stop):
            run_ash_scan._run_with_options(opts, 0.0)

        assert seen == {"rules": ["*"]}

    def test_a_link_at_the_name_stops_the_scan_with_exit_3(
        self, source, tmp_path, monkeypatch
    ):
        target = tmp_path / "host.txt"
        target.write_text("keep\n", encoding="utf-8")
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (output / ".gitignore").symlink_to(target)
        opts = ScanOptions(source_dir=source, output_dir=output)

        with pytest.raises(OutputDirRefusedExit) as refused:
            run_ash_scan._ignore_output_dir_in_git(opts)

        assert refused.value.code == 3
        assert target.read_text(encoding="utf-8") == "keep\n"


class TestTheHelper:
    def test_returns_whether_it_wrote_the_file(self, source, tmp_path):
        inside = source / "out"
        inside.mkdir()
        outside = tmp_path / "out"
        outside.mkdir()

        write = output_dir_links.ignore_output_dir_in_git

        assert write(source, inside) is True
        assert write(source, inside) is False
        assert write(source, outside) is False
        assert write(source, source) is False
        assert write(source, source / "missing") is False
        assert not (outside / ".gitignore").exists()
        assert not (source / ".gitignore").exists()

    def test_the_link_check_names_a_linked_gitignore_only_inside_the_tree(
        self, source, tmp_path
    ):
        inside = source / ".ash" / "ash_output"
        inside.mkdir(parents=True)
        (inside / ".gitignore").symlink_to(tmp_path / "elsewhere")
        outside = tmp_path / "out"
        outside.mkdir()
        (outside / ".gitignore").symlink_to(tmp_path / "elsewhere")

        found = linked_output_component(source, inside)

        assert found is not None and found.endswith(".gitignore is a symlink")
        assert linked_output_component(source, outside) is None

    def test_a_link_made_after_the_check_is_refused_by_the_write(
        self, source, tmp_path
    ):
        target = tmp_path / "host.txt"
        target.write_text("keep\n", encoding="utf-8")
        output = source / "out"
        output.mkdir()
        (output / ".gitignore").symlink_to(target)

        with pytest.raises(OutputDirLinkRefused):
            output_dir_links.ignore_output_dir_in_git(source, output)

        assert target.read_text(encoding="utf-8") == "keep\n"
