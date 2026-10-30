# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An OSError's text names its file as given, so a sink shows the name once.

``str(OSError)`` quotes ``filename`` (and ``filename2``) by repr, and a repr writes
a control as the text of its escape and doubles each backslash. error_text and
traceback_text give the names back as given, inside the quotes Python put around
them, so the console and ash.log (utils/terminal_text.py's shown_not_obeyed) show
each once. Shown again, the backslash doubles once more: a report that cannot be
written under an output directory holding an ESC would be logged as
``out\\\\x1b[31m``, two backslashes, where the path lines of the same run print
one, and a Windows path's every backslash would print twice.

With real ``ash scan``, the doubled form would show in the reporter error
arm (report_phase.py) and in its progress description.

Control characters are built with chr() here, so this file holds none itself.
"""

import contextlib
import logging
from pathlib import Path
from typing import Literal, Optional

import pytest

from automated_security_helper.utils.error_text import error_text, traceback_text
from automated_security_helper.utils.terminal_text import shown_not_obeyed

pytestmark = pytest.mark.unit

ESC = chr(0x1B)
BACKSLASH = chr(0x5C)

#: ash.log's format, as get_logger sets it.
_ASH_LOG_FORMAT = "%(asctime)s\t%(levelname)s\t%(filename)s:%(lineno)d\t%(message)s "


def _shown(text: str) -> str:
    return str(shown_not_obeyed(text))


def _shown_twice(text: str) -> str:
    # str() first: shown_not_obeyed returns text it was given shown already as it is.
    return _shown(_shown(text))


@pytest.mark.parametrize(
    "name",
    [
        # A lone ESC is not a complete escape code, so it stays as given. A
        # complete code in a name stays as given too, unless stripping it was
        # needed to hide a value (see
        # test_error_text_keeps_codes_unless_one_hides_a_value.py).
        pytest.param("/out/a" + ESC + "b", id="esc"),
        pytest.param("/out/a" + BACKSLASH + "x1b[31mb", id="the-text-of-its-escape"),
        pytest.param("C:" + BACKSLASH + "temp" + BACKSLASH + "ash", id="backslashes"),
        pytest.param("/out/it's", id="a-quote"),
        pytest.param("/out/[/x][bold]", id="markup-text"),
    ],
)
def test_the_file_is_named_as_given(name):
    error = FileNotFoundError(2, "No such file or directory", name)

    assert error_text(error) == f"[Errno 2] No such file or directory: '{name}'"


def test_both_files_of_a_rename_are_named_as_given():
    source, target = "/out/a" + ESC, "/out/b" + BACKSLASH + "c"
    error = FileExistsError(17, "File exists", source, None, target)

    assert error_text(error) == f"[Errno 17] File exists: '{source}' -> '{target}'"


def test_an_error_raised_from_one_names_its_file_as_given():
    name = "/out/a" + ESC + "b"
    inner = IsADirectoryError(21, "Is a directory", name)
    try:
        try:
            raise inner
        except OSError as caught:
            raise RuntimeError(f"could not write the report: {caught}") from caught
    except RuntimeError as outer:
        text = error_text(outer)

    assert text == f"could not write the report: [Errno 21] Is a directory: '{name}'"


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(
            FileNotFoundError(2, "No such file or directory", b"/out/a"), id="bytes"
        ),
        pytest.param(OSError("no file named"), id="no-file"),
        pytest.param(OSError(13, "Permission denied"), id="no-file-with-errno"),
    ],
)
def test_text_that_names_no_str_file_is_left_as_it_is(error):
    assert error_text(error) == str(error)


def test_an_error_with_its_own_text_is_left_as_it_is():
    class _Worded(OSError):
        def __str__(self) -> str:
            return "worded: " + repr(self.filename)

    error = _Worded(2, "No such file or directory", "/out/a" + ESC)

    assert error_text(error) == str(error)


def test_a_real_esc_and_the_text_of_its_escape_are_shown_once_and_stay_distinct():
    real = "/out/a" + ESC + "b"
    text = "/out/a" + BACKSLASH + "x1bb"

    shown_real = _shown(
        error_text(FileNotFoundError(2, "No such file or directory", real))
    )
    shown_text = _shown(
        error_text(FileNotFoundError(2, "No such file or directory", text))
    )

    assert _shown(real) in shown_real and _shown_twice(real) not in shown_real
    assert _shown(text) in shown_text and _shown_twice(text) not in shown_text
    assert shown_real != shown_text


def test_an_unexpected_os_error_is_logged_naming_its_file_as_given():
    from unittest.mock import MagicMock

    from automated_security_helper.utils.error_text import log_unexpected_error
    from automated_security_helper.utils.log import NO_MARKUP

    name = "/out/a" + ESC + "b"
    error = PermissionError(13, "Permission denied", name)
    logger = MagicMock()

    log_unexpected_error(logger, error)

    # An OSError that names a file by repr is logged pre-rendered, its traceback
    # text on the lines after the message, never with exc_info: the handler's
    # formatter would render the name by repr again and double its backslash.
    (message,), kwargs = logger.error.call_args
    first, traceback_line = message.split("\n", 1)
    assert first == f"[Errno 13] Permission denied: '{name}'"
    assert traceback_line == f"PermissionError: [Errno 13] Permission denied: '{name}'"
    assert "exc_info" not in kwargs
    assert kwargs["extra"] == NO_MARKUP


def test_a_traceback_names_its_file_as_given():
    name = "/out/a" + ESC + "b"
    try:
        raise IsADirectoryError(21, "Is a directory", name)
    except OSError as caught:
        text = traceback_text(caught)

    assert text.rstrip().endswith(
        f"IsADirectoryError: [Errno 21] Is a directory: '{name}'"
    )


# The reporter error arm in report_phase, driven as test_report_phase_falsy_report
# drives the phase: one stub reporter, here one that cannot write its file.


@contextlib.contextmanager
def _ash_log(path: Path):
    """ASH's logger writing to *path* as get_logger's ash.log handler does."""
    from automated_security_helper.utils.log import (
        ASH_LOGGER,
        LogFileHandler,
        TextFileFormatter,
    )

    handler = LogFileHandler(path.as_posix())
    handler.setLevel(logging.ERROR)
    handler.setFormatter(TextFileFormatter(fmt=_ASH_LOG_FORMAT))
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.ERROR)
    ASH_LOGGER.addHandler(handler)
    try:
        yield
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
        handler.close()


def test_a_reporter_that_cannot_write_its_file_names_it_once(tmp_path):
    from rich.text import Text

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.base.reporter_plugin import (
        ReporterPluginBase,
        ReporterPluginConfigBase,
    )
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.phases.report_phase import ReportPhase
    from automated_security_helper.core.progress import LiveProgressDisplay
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    # "[/x]" holds a slash, so this is "out[" with "x][bold]..." inside it.
    # A lone ESC: a complete code in a name is stripped in every print.
    output_dir = tmp_path / ("out[/x][bold]" + ESC + "x")
    blocked = output_dir / "reports" / "ash.stub.json"

    class _StubConfig(ReporterPluginConfigBase):
        name: Literal["stub-reporter"] = "stub-reporter"
        extension: str = "stub.json"
        enabled: bool = True

    class _UnwritableReporter(ReporterPluginBase[_StubConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = _StubConfig()
            return super().model_post_init(context)

        def report(self, model: AshAggregatedResults) -> Optional[str]:
            raise IsADirectoryError(21, "Is a directory", str(blocked))

    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    display = LiveProgressDisplay(show_progress=False)
    descriptions = []
    original = display.update_task

    def record(*args, **kwargs):
        if kwargs.get("description"):
            descriptions.append(kwargs["description"])
        return original(*args, **kwargs)

    display.update_task = record  # type: ignore[method-assign]
    phase = ReportPhase(
        plugins=[_UnwritableReporter],
        plugin_context=context,
        progress_display=display,
        asharp_model=AshAggregatedResults(),
    )
    log = tmp_path / "ash.log"
    with _ash_log(log):
        phase._execute_phase(
            report_dir=output_dir / "reports",
            aggregated_results=AshAggregatedResults(),
            cli_output_formats=["stub-reporter"],
            python_based_plugins_only=False,
        )

    written = log.read_bytes().decode("utf-8")
    once, twice = f"'{_shown(str(blocked))}'", f"'{_shown_twice(str(blocked))}'"
    assert "Error in reporter" in written, written
    assert once in written and twice not in written, ascii(written)
    failed = [Text.from_markup(d).plain for d in descriptions if "Failed" in d]
    assert failed, descriptions
    assert once in failed[-1] and twice not in failed[-1], ascii(failed[-1])
