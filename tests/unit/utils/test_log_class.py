import logging
import pytest
from automated_security_helper.utils.log import ASHLogger, ASH_LOGGER, WindowsSafeFilter


def test_logger_class_is_ash_logger():
    logger = logging.getLogger("ash")
    assert isinstance(logger, ASHLogger)


def test_ash_logger_verbose_is_callable():
    logger = logging.getLogger("ash.test_verbose")
    assert isinstance(logger, ASHLogger)
    logger.setLevel(1)
    logger.verbose("test verbose message")


def test_ash_logger_trace_is_callable():
    logger = logging.getLogger("ash.test_trace")
    assert isinstance(logger, ASHLogger)
    logger.setLevel(1)
    logger.trace("test trace message")


def test_ash_logger_module_instance_has_verbose():
    assert callable(getattr(ASH_LOGGER, "verbose", None))


def test_ash_logger_module_instance_has_trace():
    assert callable(getattr(ASH_LOGGER, "trace", None))


def test_windows_safe_filter_passthrough_on_ascii(monkeypatch):
    monkeypatch.setattr(
        "automated_security_helper.utils.log._detect_encoding_issues", lambda: False
    )
    f = WindowsSafeFilter()
    f._active = False
    record = logging.LogRecord(
        name="ash", level=logging.INFO, pathname="", lineno=0,
        msg="hello world", args=(), exc_info=None
    )
    assert f.filter(record) is True
    assert record.msg == "hello world"


def test_windows_safe_filter_replaces_emoji_when_active():
    f = WindowsSafeFilter()
    f._active = True
    record = logging.LogRecord(
        name="ash", level=logging.INFO, pathname="", lineno=0,
        msg="status: ✅ done", args=(), exc_info=None
    )
    assert f.filter(record) is True
    assert "✅" not in record.msg
    assert "[OK]" in record.msg


def test_windows_safe_filter_handles_unicode_encode_error(monkeypatch):
    f = WindowsSafeFilter()
    f._active = True
    # Inject a character that survives emoji substitution but fails ascii encode
    record = logging.LogRecord(
        name="ash", level=logging.INFO, pathname="", lineno=0,
        msg="café report", args=(), exc_info=None
    )
    result = f.filter(record)
    assert result is True
    # Message should be ASCII-safe (non-ASCII stripped)
    record.msg.encode("ascii")


def test_no_module_level_monkey_patches_remain():
    """ASH_LOGGER._log must be the standard Logger._log, not a closure patched at module level."""
    import inspect
    # A monkey-patched closure would not be a bound method of Logger
    assert inspect.ismethod(ASH_LOGGER._log)
    assert ASH_LOGGER._log.__func__ is logging.Logger._log


def test_windows_safe_filter_attached_to_ash_logger():
    assert any(isinstance(f, WindowsSafeFilter) for f in ASH_LOGGER.filters)


def test_new_get_logger_attaches_windows_safe_filter():
    from automated_security_helper.utils.log import get_logger
    logger = get_logger("ash.test_filter_attach")
    assert any(isinstance(f, WindowsSafeFilter) for f in logger.filters)
