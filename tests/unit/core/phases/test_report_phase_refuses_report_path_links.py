# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A link at a path a report goes to stops the report phase before any reporter runs.

What these tests are for
------------------------
The report phase writes each enabled reporter's report to
``reports/ash.<extension>``, and some reporters write files of their own beside it.
A link at one of those names that led out of the reports directory used to make
that one write fail: the error was logged, the run went on and exited 0, and the
link stayed for whatever read ``reports/ash.sarif`` next. The phase now raises
before any reporter runs, names the link, and leaves its target alone.

How the names are chosen
------------------------
None is written out here. A reporter's report file comes from its own
``extension``, and the files it writes itself are found by running it once in a
clean directory and listing what it wrote. A reporter that starts writing a new
file is covered without editing this file, and the declaration the phase checks
against is held to what the reporters really write
(``test_every_file_the_built_in_reporters_write_is_declared``).

The refusal is caught as ``ASHValidationError``, which predates the check, so on a
tree without it these tests fail on what they assert rather than on an import.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]

#: The content of every link target, so a read of one would show up.
MARKER = "TARGET-OF-A-LINK-IN-REPORTS-5b0e"


def _context(base: Path) -> PluginContext:
    output_dir = base / "out"
    return PluginContext(
        source_dir=base / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )


def _instance(reporter_class: type, context: PluginContext):
    """The reporter built the way ReportPhase builds it, with its configured section."""
    return reporter_class(
        context=context,
        config=context.config.get_plugin_config(
            plugin_type="reporter", plugin_name=plugin_config_key(reporter_class)
        ),
    )


def _enabled_by_default() -> List[type]:
    context = _context(Path("unused"))
    return [cls for cls in ASH_REPORTERS if _instance(cls, context).config.enabled]


#: The built-in reporters a default configuration runs.
ENABLED = _enabled_by_default()


def _report_dir(base: Path) -> Path:
    return base / "out" / "reports"


def _run_phase(base: Path, reporter_classes) -> Path:
    context = _context(base)
    model = AshAggregatedResults()
    ReportPhase(
        plugins=list(reporter_classes),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=model,
    ).execute(
        report_dir=_report_dir(base),
        aggregated_results=model,
        cli_output_formats=None,
        python_based_plugins_only=False,
    )
    return _report_dir(base)


def _report_file(reporter_class: type, base: Path) -> str:
    return f"ash.{_instance(reporter_class, _context(base)).config.extension}"


def _files_of(reporter_class: type, base: Path) -> List[str]:
    """Its report's file and every file it wrote when run alone in a clean directory."""
    written = sorted(path.name for path in _run_phase(base, [reporter_class]).iterdir())
    return sorted({_report_file(reporter_class, base), *written})


def _plant_link(base: Path, name: str) -> Path:
    """A symlink at reports/<name> to a file outside the output directory."""
    outside = base / "outside" / f"{name}.target"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text(MARKER, encoding="utf-8")
    _report_dir(base).mkdir(parents=True, exist_ok=True)
    (_report_dir(base) / name).symlink_to(outside)
    return outside


def _refusal_naming(path: Path) -> str:
    return re.escape(f"{path.as_posix()} is a symlink")


def test_a_link_at_the_sarif_report_refuses_the_phase(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    name = _report_file(SarifReporter, tmp_path)
    outside = _plant_link(tmp_path, name)

    with pytest.raises(
        ASHValidationError, match=_refusal_naming(_report_dir(tmp_path) / name)
    ):
        _run_phase(tmp_path, ENABLED)

    assert outside.read_text(encoding="utf-8") == MARKER
    assert (_report_dir(tmp_path) / name).is_symlink()
    # Refused before any reporter ran: nothing beside the link was written.
    assert [path.name for path in _report_dir(tmp_path).iterdir()] == [name]


@pytest.mark.parametrize("reporter_class", ENABLED, ids=lambda cls: cls.__name__)
def test_a_link_at_any_file_an_enabled_reporter_writes_refuses_the_phase(
    reporter_class, tmp_path
):
    names = _files_of(reporter_class, tmp_path / "clean")
    assert names

    for name in names:
        base = tmp_path / name
        outside = _plant_link(base, name)

        with pytest.raises(
            ASHValidationError, match=_refusal_naming(_report_dir(base) / name)
        ):
            _run_phase(base, ENABLED)

        assert outside.read_text(encoding="utf-8") == MARKER
        assert [path.name for path in _report_dir(base).iterdir()] == [name]


def test_a_link_beside_a_report_refuses_the_phase(tmp_path):
    """The unused-suppressions reporter's markdown, written by the reporter itself."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    report = _report_file(UnusedSuppressionsReporter, tmp_path)
    beside = [
        name
        for name in _files_of(UnusedSuppressionsReporter, tmp_path / "clean")
        if name != report
    ]
    assert beside, "the reporter wrote nothing beside its report on a default run"

    for name in beside:
        base = tmp_path / name
        outside = _plant_link(base, name)

        with pytest.raises(
            ASHValidationError, match=_refusal_naming(_report_dir(base) / name)
        ):
            _run_phase(base, ENABLED)

        assert outside.read_text(encoding="utf-8") == MARKER


def test_a_link_at_the_s3_local_copy_refuses_before_the_upload(tmp_path):
    """A reporter that is not on by default: its own file is checked once it is enabled."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import s3_reporter

    outside = _plant_link(tmp_path, "s3-report.json")
    context = _context(tmp_path)
    context.config = AshConfig.model_validate(
        {
            "reporters": {
                "s3": {
                    "enabled": True,
                    "options": {
                        "aws_region": "us-west-2",
                        "bucket_name": "test-bucket",
                        "file_format": "json",
                    },
                }
            }
        }
    )
    model = AshAggregatedResults()

    with (
        patch.object(s3_reporter, "boto3") as boto3,
        patch.object(
            s3_reporter.S3Reporter, "validate_plugin_dependencies", return_value=True
        ),
    ):
        boto3.Session.return_value.client.return_value = MagicMock()
        with pytest.raises(
            ASHValidationError,
            match=_refusal_naming(_report_dir(tmp_path) / "s3-report.json"),
        ):
            ReportPhase(
                plugins=[s3_reporter.S3Reporter],
                plugin_context=context,
                progress_display=LiveProgressDisplay(show_progress=False),
                asharp_model=model,
            ).execute(
                report_dir=_report_dir(tmp_path),
                aggregated_results=model,
                cli_output_formats=None,
                python_based_plugins_only=False,
            )

        boto3.Session.return_value.client.return_value.put_object.assert_not_called()
    assert outside.read_text(encoding="utf-8") == MARKER


def test_a_link_at_the_reports_directory_refuses_the_phase(tmp_path):
    outside = tmp_path / "outside-reports"
    outside.mkdir()
    (tmp_path / "out").mkdir()
    _report_dir(tmp_path).symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        ASHValidationError,
        match=re.escape(
            f"reports directory {_report_dir(tmp_path).as_posix()} is a symlink"
        ),
    ):
        _run_phase(tmp_path, ENABLED)

    assert list(outside.iterdir()) == []


def test_a_regular_file_at_a_report_path_is_still_replaced(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    name = _report_file(SarifReporter, tmp_path)
    _report_dir(tmp_path).mkdir(parents=True)
    (_report_dir(tmp_path) / name).write_text(
        "left by an earlier run", encoding="utf-8"
    )

    _run_phase(tmp_path, ENABLED)

    written = _report_dir(tmp_path) / name
    assert written.is_file() and not written.is_symlink()
    assert "runs" in json.loads(written.read_text(encoding="utf-8"))


def test_a_link_at_a_disabled_reporters_file_is_not_examined(tmp_path):
    """Only the reporters that will run decide which names are checked."""
    disabled = [cls for cls in ASH_REPORTERS if cls not in ENABLED]
    assert disabled, "every built-in reporter is on by default"
    name = _report_file(disabled[0], tmp_path)
    outside = _plant_link(tmp_path, name)

    _run_phase(tmp_path, ENABLED)

    assert (_report_dir(tmp_path) / name).is_symlink()
    assert outside.read_text(encoding="utf-8") == MARKER


def test_a_link_at_a_name_no_reporter_writes_is_not_examined(tmp_path):
    outside = _plant_link(tmp_path, "notes.txt")

    _run_phase(tmp_path, ENABLED)

    assert outside.read_text(encoding="utf-8") == MARKER
    assert len(list(_report_dir(tmp_path).iterdir())) > 1


def test_every_file_the_built_in_reporters_write_is_declared(tmp_path):
    """What the phase checks is what the reporters write: nothing is written undeclared."""
    from automated_security_helper.base.reporter_plugin import reporter_file_names

    context = _context(tmp_path)
    declared = {
        name for cls in ENABLED for name in reporter_file_names(_instance(cls, context))
    }
    written = {path.name for path in _run_phase(tmp_path, ENABLED).iterdir()}

    assert written
    assert written - declared == set()
