"""Behavior tests for ``utils.log``.

Three shared hazards shape how these tests are written.

``addLoggingLevel`` mutates the ``logging`` module and the current logger class
in place, so any test that registers a real new level must unregister it,
including the two private name maps. ``_registered_level`` does that.

``configure_windows_safe_logging`` assigns ``sys.stdout``/``sys.stderr`` and calls
``locale.setlocale``. Both are process-global. Every test that reaches those
branches installs its streams through ``monkeypatch`` (so the assignment is
reverted) and patches ``locale.setlocale`` (so the process locale is never
actually changed).

``get_logger`` clears the handlers of the logger it is given and attaches
``FileHandler``s that hold open descriptors. Tests use a unique logger name and
the ``closed_logger`` fixture closes the handlers afterwards.
"""

import logging
import platform
import sys
from unittest.mock import create_autospec, patch

import pytest
from rich.console import Console

from automated_security_helper.utils import log as log_module
from automated_security_helper.utils.log import (
    ASHLogger,
    JsonFormatter,
    WindowsSafeFilter,
    _detect_encoding_issues,
    _get_default_emoji_fallback_map,
    _make_message_windows_safe,
    addLoggingLevel,
    configure_windows_safe_logging,
    get_logger,
)

CI_INDICATORS = [
    "CI",
    "GITHUB_ACTIONS",
    "AZURE_PIPELINES",
    "JENKINS_URL",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "APPVEYOR",
]


class FakeStream:
    """A stdout/stderr stand-in with controllable encoding and reconfigure."""

    def __init__(self, encoding="utf-8", reconfigure_error=None, detach_error=None):
        if encoding is not _OMITTED:
            self.encoding = encoding
        self._reconfigure_error = reconfigure_error
        self._detach_error = detach_error
        self.written = []

    def write(self, text):
        self.written.append(text)
        return len(text)

    def flush(self):
        return None

    def reconfigure(self, **kwargs):
        if self._reconfigure_error is not None:
            raise self._reconfigure_error

    def detach(self):
        if self._detach_error is not None:
            raise self._detach_error
        import io

        return io.BytesIO()


class _Omitted:
    pass


_OMITTED = _Omitted()


class EncodinglessStream(FakeStream):
    """A stream whose ``encoding`` lookup raises AttributeError."""

    def __init__(self, **kwargs):
        super().__init__(encoding=_OMITTED, **kwargs)


@pytest.fixture
def on_windows(monkeypatch):
    """Make the module believe it is running on Windows, with a clean env."""
    monkeypatch.setattr(log_module.platform, "system", lambda: "Windows")
    for name in CI_INDICATORS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
    return monkeypatch


@pytest.fixture
def registered_level():
    """Register a throwaway logging level and fully unregister it afterwards."""
    created = []

    def _register(level_name, level_num, method_name=None):
        created.append((level_name, level_num, method_name or level_name.lower()))
        addLoggingLevel(level_name, level_num, method_name)

    yield _register

    for level_name, level_num, method_name in created:
        for obj in (logging, logging.getLoggerClass()):
            if hasattr(obj, level_name):
                delattr(obj, level_name)
            if hasattr(obj, method_name):
                delattr(obj, method_name)
        logging._levelToName.pop(level_num, None)
        logging._nameToLevel.pop(level_name, None)


@pytest.fixture
def closed_logger():
    """Yield a factory for uniquely named loggers, closing handlers on teardown."""
    made = []

    def _name(suffix):
        name = f"ash_test_log_{suffix}"
        made.append(name)
        return name

    yield _name

    for name in made:
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        logger.filters = []


# ---------------------------------------------------------------------------
# addLoggingLevel
# ---------------------------------------------------------------------------


def test_re_registering_an_existing_level_is_a_no_op():
    """TRACE is registered at import time; a second call must not raise."""
    before = logging.TRACE

    addLoggingLevel("TRACE", 99)

    assert logging.TRACE == before


def test_an_existing_level_name_is_rejected_even_with_a_free_method_name():
    """Isolates the level-name guard from the two method-name guards.

    ``addLoggingLevel("TRACE", 99)`` alone cannot prove this guard does anything:
    the method name ``trace`` is also already taken, so the next guard rejects
    the same call. Pairing an existing level name with an unused method name
    leaves this guard as the only thing standing between the call and a silent
    re-binding of ``logging.INFO`` to a different number.
    """
    assert hasattr(logging, "INFO")
    assert not hasattr(logging, "zz_unused_method")
    assert not hasattr(logging.getLoggerClass(), "zz_unused_method")

    addLoggingLevel("INFO", 3, methodName="zz_unused_method")

    assert logging.INFO == 20
    assert not hasattr(logging, "zz_unused_method")


def test_registration_bails_when_the_method_name_is_taken_on_the_logging_module():
    """The module-attribute guard is the only one that can reject this name.

    ``basicConfig`` exists on the ``logging`` module but not on the logger class,
    so it isolates the second guard from the third. Using a name present on both
    -- ``info``, say -- would leave the test unable to fail if this guard were
    deleted, because the logger-class guard would reject the same input.
    """
    assert hasattr(logging, "basicConfig")
    assert not hasattr(logging.getLoggerClass(), "basicConfig")

    addLoggingLevel("ZZ_UNUSED_LEVEL_A", 3, methodName="basicConfig")

    assert not hasattr(logging, "ZZ_UNUSED_LEVEL_A")
    assert 3 not in logging._levelToName


def test_a_method_name_on_both_the_module_and_the_logger_class_is_also_rejected():
    """``info`` trips the module guard first; the class guard would catch it too."""
    addLoggingLevel("ZZ_UNUSED_LEVEL_C", 11, methodName="info")

    assert not hasattr(logging, "ZZ_UNUSED_LEVEL_C")
    assert 11 not in logging._levelToName


def test_registration_bails_when_the_method_name_is_taken_on_the_logger_class():
    """``isEnabledFor`` is on Logger but not on the module, so the third guard fires."""
    assert not hasattr(logging, "isEnabledFor")
    assert hasattr(logging.getLoggerClass(), "isEnabledFor")

    addLoggingLevel("ZZ_UNUSED_LEVEL_B", 4, methodName="isEnabledFor")

    assert not hasattr(logging, "ZZ_UNUSED_LEVEL_B")
    assert 4 not in logging._levelToName


def test_registering_a_new_level_installs_module_and_logger_entry_points(
    registered_level,
):
    registered_level("ZZ_NEWLEVEL", 7)

    assert logging.ZZ_NEWLEVEL == 7
    assert logging.getLevelName(7) == "ZZ_NEWLEVEL"
    assert callable(logging.zz_newlevel)
    assert callable(logging.getLoggerClass().zz_newlevel)


def test_the_new_logger_method_emits_only_when_the_level_is_enabled(
    registered_level, caplog
):
    registered_level("ZZ_EMITLEVEL", 8)
    logger = logging.getLogger("ash_test_addlevel_emit")
    logger.propagate = True

    with caplog.at_level(8, logger=logger.name):
        logger.zz_emitlevel("visible at level 8")
    assert "visible at level 8" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.CRITICAL, logger=logger.name):
        logger.zz_emitlevel("suppressed above level 8")
    assert "suppressed above level 8" not in caplog.text


def test_the_new_module_level_function_logs_to_the_root_logger(registered_level):
    registered_level("ZZ_ROOTLEVEL", 9)

    with patch.object(logging, "log") as root_log:
        logging.zz_rootlevel("to root", "extra")

    root_log.assert_called_once_with(9, "to root", "extra")


def test_a_custom_method_name_is_honored(registered_level):
    registered_level("ZZ_ALIASLEVEL", 6, "zz_alias")

    assert callable(logging.zz_alias)
    assert not hasattr(logging, "zz_aliaslevel")


# ---------------------------------------------------------------------------
# ASHLogger
# ---------------------------------------------------------------------------


def test_ash_logger_exposes_verbose_and_trace_as_methods():
    logger = ASHLogger("ash_test_methods", level=5)
    records = []
    logger.addHandler(
        type("H", (logging.Handler,), {"emit": lambda s, r: records.append(r)})()
    )

    logger.verbose("v")
    logger.trace("t")

    assert [r.levelno for r in records] == [15, 5]


def test_ash_logger_suppresses_verbose_and_trace_above_their_levels():
    logger = ASHLogger("ash_test_methods_off", level=logging.CRITICAL)
    records = []
    logger.addHandler(
        type("H", (logging.Handler,), {"emit": lambda s, r: records.append(r)})()
    )

    logger.verbose("v")
    logger.trace("t")

    assert records == []


# ---------------------------------------------------------------------------
# _detect_encoding_issues
# ---------------------------------------------------------------------------


def test_encoding_issues_are_never_reported_off_windows(monkeypatch):
    monkeypatch.setattr(log_module.platform, "system", lambda: "Linux")

    assert _detect_encoding_issues() is False


def test_a_utf8_windows_console_outside_ci_reports_no_encoding_issue(on_windows):
    on_windows.setattr(sys, "stdout", FakeStream(encoding="utf-8"))

    assert _detect_encoding_issues() is False


@pytest.mark.parametrize("indicator", CI_INDICATORS)
def test_any_ci_indicator_forces_the_encoding_issue_verdict(on_windows, indicator):
    on_windows.setattr(sys, "stdout", FakeStream(encoding="utf-8"))
    on_windows.setenv(indicator, "1")

    assert _detect_encoding_issues() is True


@pytest.mark.parametrize(
    "encoding", ["cp1252", "windows-1252", "cp850", "cp437", "ascii", "CP1252"]
)
def test_a_legacy_windows_codepage_reports_an_encoding_issue(on_windows, encoding):
    on_windows.setattr(sys, "stdout", FakeStream(encoding=encoding))

    assert _detect_encoding_issues() is True


def test_a_stream_without_an_encoding_attribute_reports_an_encoding_issue(on_windows):
    on_windows.setattr(sys, "stdout", EncodinglessStream())

    assert _detect_encoding_issues() is True


def test_an_unknown_codec_name_reports_an_encoding_issue(on_windows):
    """LookupError from the emoji probe counts as an encoding issue."""
    on_windows.setattr(sys, "stdout", FakeStream(encoding="not-a-real-codec"))

    assert _detect_encoding_issues() is True


def test_a_codec_that_cannot_encode_emoji_reports_an_encoding_issue(on_windows):
    """latin-1 is not on the deny list, so only the emoji probe can catch it."""
    on_windows.setattr(sys, "stdout", FakeStream(encoding="latin-1"))

    assert _detect_encoding_issues() is True


def test_a_none_encoding_falls_back_to_utf8_and_reports_no_issue(on_windows):
    on_windows.setattr(sys, "stdout", FakeStream(encoding=None))

    assert _detect_encoding_issues() is False


# ---------------------------------------------------------------------------
# Windows-safe message rewriting
# ---------------------------------------------------------------------------


def test_the_fallback_map_replaces_emoji_with_bracketed_ascii():
    mapping = _get_default_emoji_fallback_map()

    assert _make_message_windows_safe("✅ done", mapping) == "[OK] done"
    assert _make_message_windows_safe("a → b", mapping) == "a -> b"


def test_the_filter_is_inert_when_no_encoding_issue_is_detected(monkeypatch):
    monkeypatch.setattr(log_module.platform, "system", lambda: "Linux")
    log_filter = WindowsSafeFilter()
    record = logging.LogRecord("n", logging.INFO, "f", 1, "✅ kept", None, None)

    assert log_filter.filter(record) is True
    assert record.msg == "✅ kept"


def test_the_filter_rewrites_emoji_when_an_encoding_issue_is_detected(on_windows):
    on_windows.setattr(sys, "stdout", FakeStream(encoding="cp1252"))
    log_filter = WindowsSafeFilter()
    record = logging.LogRecord("n", logging.INFO, "f", 1, "✅ done", None, None)

    assert log_filter.filter(record) is True
    assert record.msg == "[OK] done"


def test_the_filter_strips_residual_non_ascii_after_substitution(on_windows):
    """A character with no mapping is dropped rather than left to raise later."""
    on_windows.setattr(sys, "stdout", FakeStream(encoding="cp1252"))
    log_filter = WindowsSafeFilter()
    record = logging.LogRecord("n", logging.INFO, "f", 1, "café ☃", None, None)

    log_filter.filter(record)

    assert record.msg.encode("ascii") == b"caf "


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------


def test_json_formatter_emits_only_the_requested_keys():
    import json

    formatter = JsonFormatter({"level": "levelname", "message": "message"})
    record = logging.LogRecord("n", logging.WARNING, "f", 1, "hi", None, None)

    payload = json.loads(formatter.format(record))

    assert payload == {"level": "WARNING", "message": "hi"}


def test_json_formatter_includes_asctime_only_when_requested():
    formatter = JsonFormatter({"timestamp": "asctime", "message": "message"})

    assert formatter.usesTime() is True
    assert JsonFormatter({"message": "message"}).usesTime() is False


def test_json_formatter_attaches_exception_and_stack_text():
    import json

    formatter = JsonFormatter({"message": "message"})
    try:
        raise ValueError("kaboom")
    except ValueError:
        exc_info = sys.exc_info()
    record = logging.LogRecord(
        "n", logging.ERROR, "f", 1, "failed", None, exc_info, sinfo="STACK"
    )

    payload = json.loads(formatter.format(record))

    assert "kaboom" in payload["exc_info"]
    assert payload["stack_info"] == "STACK"


# ---------------------------------------------------------------------------
# configure_windows_safe_logging
# ---------------------------------------------------------------------------


def test_configure_is_a_no_op_off_windows(monkeypatch):
    monkeypatch.setattr(log_module.platform, "system", lambda: "Linux")

    with patch("locale.setlocale") as setlocale:
        configure_windows_safe_logging()

    setlocale.assert_not_called()


def test_configure_returns_early_on_a_healthy_windows_console(on_windows):
    """No CI and a UTF-8 console means there is nothing to reconfigure."""
    stdout = FakeStream(encoding="utf-8")
    on_windows.setattr(sys, "stdout", stdout)
    on_windows.setattr(sys, "stderr", FakeStream(encoding="utf-8"))

    with patch("locale.setlocale") as setlocale:
        configure_windows_safe_logging()

    setlocale.assert_not_called()


def test_configure_reconfigures_both_streams_to_utf8_in_ci(on_windows):
    stdout = FakeStream(encoding="cp1252")
    stderr = FakeStream(encoding="cp1252")
    on_windows.setattr(sys, "stdout", stdout)
    on_windows.setattr(sys, "stderr", stderr)

    with patch("locale.setlocale") as setlocale:
        configure_windows_safe_logging()

    setlocale.assert_called_once()
    assert sys.stdout is stdout


def test_configure_treats_a_stream_without_encoding_as_needing_repair(on_windows):
    on_windows.setattr(sys, "stdout", EncodinglessStream())
    on_windows.setattr(sys, "stderr", FakeStream(encoding="utf-8"))

    with patch("locale.setlocale") as setlocale:
        configure_windows_safe_logging()

    setlocale.assert_called_once()


def test_configure_falls_back_to_a_codec_writer_when_reconfigure_fails(on_windows):
    """reconfigure raising OSError must fall through to wrapping the raw buffer."""
    on_windows.setattr(
        sys, "stdout", FakeStream(encoding="cp1252", reconfigure_error=OSError("nope"))
    )
    on_windows.setattr(
        sys, "stderr", FakeStream(encoding="cp1252", reconfigure_error=OSError("nope"))
    )

    with patch("locale.setlocale"):
        configure_windows_safe_logging()

    import codecs

    assert isinstance(sys.stdout, codecs.StreamWriter)
    assert isinstance(sys.stderr, codecs.StreamWriter)


def test_configure_gives_up_quietly_when_the_buffer_cannot_be_detached(on_windows):
    """Both repair strategies failing must leave the streams untouched, not raise."""
    stdout = FakeStream(
        encoding="cp1252",
        reconfigure_error=OSError("nope"),
        detach_error=AttributeError("no buffer"),
    )
    stderr = FakeStream(
        encoding="cp1252",
        reconfigure_error=OSError("nope"),
        detach_error=AttributeError("no buffer"),
    )
    on_windows.setattr(sys, "stdout", stdout)
    on_windows.setattr(sys, "stderr", stderr)

    with patch("locale.setlocale"):
        configure_windows_safe_logging()

    assert sys.stdout is stdout
    assert sys.stderr is stderr


def test_configure_skips_stream_repair_when_reconfigure_is_unavailable(on_windows):
    class NoReconfigure:
        encoding = "cp1252"

        def write(self, text):
            return len(text)

    on_windows.setattr(sys, "stdout", NoReconfigure())
    on_windows.setattr(sys, "stderr", NoReconfigure())

    with patch("locale.setlocale") as setlocale:
        configure_windows_safe_logging()

    # The locale step still runs even though the stream step was skipped.
    setlocale.assert_called_once()


def test_configure_retries_the_c_utf8_locale_when_the_us_locale_is_missing(on_windows):
    import locale as locale_module

    on_windows.setattr(sys, "stdout", FakeStream(encoding="cp1252"))
    on_windows.setattr(sys, "stderr", FakeStream(encoding="cp1252"))

    with patch(
        "locale.setlocale", side_effect=[locale_module.Error("no en_US"), None]
    ) as setlocale:
        configure_windows_safe_logging()

    assert [call.args[1] for call in setlocale.call_args_list] == [
        "en_US.UTF-8",
        "C.UTF-8",
    ]


def test_configure_keeps_the_default_locale_when_both_candidates_are_missing(
    on_windows,
):
    import locale as locale_module

    on_windows.setattr(sys, "stdout", FakeStream(encoding="cp1252"))
    on_windows.setattr(sys, "stderr", FakeStream(encoding="cp1252"))

    with patch(
        "locale.setlocale", side_effect=locale_module.Error("none")
    ) as setlocale:
        configure_windows_safe_logging()

    assert setlocale.call_count == 2


def test_configure_sets_the_subprocess_encoding_variable(on_windows):
    import os

    on_windows.delenv("PYTHONIOENCODING", raising=False)
    on_windows.setattr(sys, "stdout", FakeStream(encoding="cp1252"))
    on_windows.setattr(sys, "stderr", FakeStream(encoding="cp1252"))

    with patch("locale.setlocale"):
        configure_windows_safe_logging()

    assert os.environ["PYTHONIOENCODING"] == "utf-8:replace"


def test_configure_survives_locale_and_codecs_being_unimportable(on_windows):
    """The ImportError guard exists because the stdlib modules are imported lazily."""
    on_windows.setattr(sys, "stdout", FakeStream(encoding="cp1252"))
    on_windows.setattr(sys, "stderr", FakeStream(encoding="cp1252"))
    real_import = (
        __builtins__["__import__"]
        if isinstance(__builtins__, dict)
        else __builtins__.__import__
    )

    def _no_locale(name, *args, **kwargs):
        if name in ("locale", "codecs"):
            raise ImportError(f"no {name}")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_no_locale):
        configure_windows_safe_logging()

    # No exception escaped; the streams were left as-is.
    assert sys.stdout.encoding == "cp1252"


# ---------------------------------------------------------------------------
# get_logger
# ---------------------------------------------------------------------------


def test_get_logger_always_pins_the_logger_to_trace_level(closed_logger):
    """Why line 482's else-branch is unreachable: the level is forced to TRACE.

    ``get_logger`` sets the level to TRACE before computing ``SHOW_DEBUG_INFO``
    from ``getEffectiveLevel()``, so that value is always "TRACE" != "INFO" and
    the non-debug RichHandler construction can never run.
    """
    logger = get_logger(name=closed_logger("trace"), show_progress=True)

    assert logger.level == 5
    assert logging.getLevelName(logger.getEffectiveLevel()) == "TRACE"


def test_get_logger_attaches_a_console_handler_only_when_progress_is_off(closed_logger):
    with_progress = get_logger(name=closed_logger("prog_on"), show_progress=True)
    assert with_progress.handlers == []

    without_progress = get_logger(name=closed_logger("prog_off"), show_progress=False)
    assert len(without_progress.handlers) == 1


def test_get_logger_installs_exactly_one_windows_safe_filter(closed_logger):
    name = closed_logger("filters")

    get_logger(name=name)
    get_logger(name=name)

    logger = logging.getLogger(name)
    assert sum(isinstance(f, WindowsSafeFilter) for f in logger.filters) == 1


def test_get_logger_selects_the_windows_color_system_on_windows(
    closed_logger, monkeypatch
):
    console_cls = create_autospec(Console)
    monkeypatch.setattr(log_module, "Console", console_cls)
    monkeypatch.setattr(log_module.platform, "system", lambda: "Windows")

    get_logger(name=closed_logger("win_color"), show_progress=False, use_color=True)

    kwargs = console_cls.call_args.kwargs
    assert kwargs["color_system"] == "windows"
    assert kwargs["legacy_windows"] is True


def test_get_logger_selects_the_auto_color_system_elsewhere(closed_logger, monkeypatch):
    console_cls = create_autospec(Console)
    monkeypatch.setattr(log_module, "Console", console_cls)
    monkeypatch.setattr(log_module.platform, "system", lambda: "Linux")

    get_logger(name=closed_logger("nix_color"), show_progress=False, use_color=True)

    assert console_cls.call_args.kwargs["color_system"] == "auto"


def test_get_logger_disables_the_color_system_when_color_is_off(
    closed_logger, monkeypatch
):
    console_cls = create_autospec(Console)
    monkeypatch.setattr(log_module, "Console", console_cls)

    get_logger(name=closed_logger("no_color"), show_progress=False, use_color=False)

    assert console_cls.call_args.kwargs["color_system"] is None


def test_get_logger_constrains_the_console_width_inside_a_container(
    closed_logger, monkeypatch
):
    console_cls = create_autospec(Console)
    monkeypatch.setattr(log_module, "Console", console_cls)
    monkeypatch.setenv("ASH_IN_CONTAINER", "YES")

    get_logger(name=closed_logger("container"), show_progress=False)

    assert console_cls.call_args.kwargs["width"] == 150


def test_get_logger_leaves_the_console_width_unset_outside_a_container(
    closed_logger, monkeypatch
):
    console_cls = create_autospec(Console)
    monkeypatch.setattr(log_module, "Console", console_cls)
    monkeypatch.delenv("ASH_IN_CONTAINER", raising=False)

    get_logger(name=closed_logger("no_container"), show_progress=False)

    assert "width" not in console_cls.call_args.kwargs


@pytest.mark.parametrize(
    "env_value,expected", [("YES", True), ("1", True), ("true", True), ("NO", False)]
)
def test_get_logger_routes_the_console_to_stderr_on_request(
    closed_logger, monkeypatch, env_value, expected
):
    console_cls = create_autospec(Console)
    monkeypatch.setattr(log_module, "Console", console_cls)
    monkeypatch.setenv("ASH_LOG_TO_STDERR", env_value)

    get_logger(name=closed_logger(f"stderr_{env_value}"), show_progress=False)

    assert console_cls.call_args.kwargs["stderr"] is expected


def test_get_logger_writes_a_jsonl_file_when_asked(closed_logger, tmp_path):
    name = closed_logger("jsonl")

    logger = get_logger(name=name, output_dir=tmp_path, log_format="JSONL")
    logger.info("a jsonl line")

    jsonl = tmp_path / f"{name}.log.jsonl"
    assert jsonl.is_file()
    assert not (tmp_path / f"{name}.log").exists()
    assert "a jsonl line" in jsonl.read_text()


def test_get_logger_writes_a_tabular_file_when_asked(closed_logger, tmp_path):
    name = closed_logger("tabular")

    logger = get_logger(name=name, output_dir=tmp_path, log_format="TABULAR")
    logger.info("a tabular line")

    tab = tmp_path / f"{name}.log"
    assert tab.is_file()
    assert not (tmp_path / f"{name}.log.jsonl").exists()
    assert "a tabular line" in tab.read_text()


def test_get_logger_writes_both_files_for_the_both_format(closed_logger, tmp_path):
    name = closed_logger("both")

    logger = get_logger(name=name, output_dir=tmp_path, log_format="BOTH")

    assert (tmp_path / f"{name}.log.jsonl").is_file()
    assert (tmp_path / f"{name}.log").is_file()
    assert len([h for h in logger.handlers if isinstance(h, logging.FileHandler)]) == 2


def test_get_logger_creates_a_missing_output_directory(closed_logger, tmp_path):
    name = closed_logger("mkdir")
    nested = tmp_path / "deeply" / "nested"

    get_logger(name=name, output_dir=nested, log_format="BOTH")

    assert (nested / f"{name}.log").is_file()


def test_get_logger_truncates_existing_log_files_by_default(closed_logger, tmp_path):
    name = closed_logger("truncate")
    (tmp_path / f"{name}.log").write_text("stale tabular\n")
    (tmp_path / f"{name}.log.jsonl").write_text("stale jsonl\n")

    get_logger(name=name, output_dir=tmp_path, log_format="BOTH", truncate_log=True)

    assert "stale tabular" not in (tmp_path / f"{name}.log").read_text()
    assert "stale jsonl" not in (tmp_path / f"{name}.log.jsonl").read_text()


def test_get_logger_appends_to_existing_log_files_when_truncation_is_off(
    closed_logger, tmp_path
):
    name = closed_logger("append")
    (tmp_path / f"{name}.log").write_text("kept tabular\n")
    (tmp_path / f"{name}.log.jsonl").write_text("kept jsonl\n")

    logger = get_logger(
        name=name, output_dir=tmp_path, log_format="BOTH", truncate_log=False
    )
    logger.info("new line")

    assert "kept tabular" in (tmp_path / f"{name}.log").read_text()
    assert "kept jsonl" in (tmp_path / f"{name}.log.jsonl").read_text()


def test_get_logger_creates_absent_log_files_when_truncation_is_off(
    closed_logger, tmp_path
):
    name = closed_logger("append_new")

    get_logger(name=name, output_dir=tmp_path, log_format="BOTH", truncate_log=False)

    assert (tmp_path / f"{name}.log").is_file()
    assert (tmp_path / f"{name}.log.jsonl").is_file()


def test_get_logger_defaults_file_handlers_to_info_level(closed_logger, tmp_path):
    name = closed_logger("filelevel")

    logger = get_logger(name=name, output_dir=tmp_path, log_format="BOTH")

    levels = {h.level for h in logger.handlers if isinstance(h, logging.FileHandler)}
    assert levels == {logging.INFO}


def test_get_logger_honors_an_explicit_file_log_level(closed_logger, tmp_path):
    name = closed_logger("filelevel_explicit")

    logger = get_logger(
        name=name,
        output_dir=tmp_path,
        log_format="BOTH",
        file_log_level=logging.DEBUG,
    )

    levels = {h.level for h in logger.handlers if isinstance(h, logging.FileHandler)}
    assert levels == {logging.DEBUG}


def test_get_logger_attaches_no_file_handlers_without_an_output_directory(
    closed_logger,
):
    logger = get_logger(name=closed_logger("nofile"), show_progress=False)

    assert [h for h in logger.handlers if isinstance(h, logging.FileHandler)] == []


def test_get_logger_replaces_handlers_rather_than_accumulating_them(
    closed_logger, tmp_path
):
    name = closed_logger("replace")

    get_logger(name=name, output_dir=tmp_path, log_format="BOTH")
    second = get_logger(name=name, output_dir=tmp_path, log_format="BOTH")

    assert len(second.handlers) == 2


def test_the_jsonl_file_records_the_configured_field_names(closed_logger, tmp_path):
    import json

    name = closed_logger("jsonl_fields")
    logger = get_logger(name=name, output_dir=tmp_path, log_format="JSONL")

    logger.warning("structured")
    for handler in logger.handlers:
        handler.flush()

    lines = [
        line
        for line in (tmp_path / f"{name}.log.jsonl").read_text().splitlines()
        if line.strip()
    ]
    payload = json.loads(lines[-1])
    assert set(payload) >= {
        "timestamp",
        "level",
        "filename",
        "lineno",
        "message",
        "loggerName",
    }
    assert payload["level"] == "WARNING"
    assert payload["message"] == "structured"


def test_get_logger_accepts_a_named_level_without_error(closed_logger):
    logger = get_logger(
        name=closed_logger("named_level"), level="DEBUG", show_progress=False
    )

    assert logger.handlers[0].level == logging.DEBUG


def test_get_logger_accepts_a_numeric_level_without_error(closed_logger):
    logger = get_logger(
        name=closed_logger("numeric_level"), level=logging.ERROR, show_progress=False
    )

    assert logger.handlers[0].level == logging.ERROR


def test_module_platform_import_is_present():
    """Guards the monkeypatch target used throughout this file."""
    assert log_module.platform is platform
