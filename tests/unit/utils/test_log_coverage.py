"""Tests for utils/log.py — covers formatters, ASHLogger, get_logger, and helpers."""

import json
import logging
import os
import platform
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.utils.log import (
    addLoggingLevel,
    JsonFormatter,
    ASHLogger,
    get_logger,
    ASH_LOGGER,
)


class TestAddLoggingLevel:
    """Tests for addLoggingLevel."""

    def test_existing_level_does_not_re_register(self):
        # VERBOSE and TRACE are already registered at import time
        # Calling again should not raise
        addLoggingLevel("VERBOSE", 15)
        assert hasattr(logging, "VERBOSE")

    def test_custom_method_name(self):
        # If we try to add with a conflicting name it should return early
        addLoggingLevel("DEBUG", logging.DEBUG)
        # Should not raise



class TestJsonFormatter:
    """Tests for JsonFormatter."""

    def test_format_basic_record(self):
        formatter = JsonFormatter({"message": "message", "level": "levelname"})
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hello world",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["message"] == "Hello world"
        assert data["level"] == "INFO"

    def test_format_with_time(self):
        formatter = JsonFormatter(
            {"message": "message", "time": "asctime"},
            time_format="%Y-%m-%d",
        )
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="timed",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert "time" in data

    def test_uses_time_true(self):
        formatter = JsonFormatter({"time": "asctime"})
        assert formatter.usesTime() is True

    def test_uses_time_false(self):
        formatter = JsonFormatter({"message": "message"})
        assert formatter.usesTime() is False

    def test_format_with_exception(self):
        formatter = JsonFormatter({"message": "message"})
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="error",
                args=None,
                exc_info=sys.exc_info(),
            )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exc_info" in data

    def test_format_with_stack_info(self):
        formatter = JsonFormatter({"message": "message"})
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="stack",
            args=None,
            exc_info=None,
        )
        record.stack_info = "Stack trace here"
        output = formatter.format(record)
        data = json.loads(output)
        assert "stack_info" in data



class TestASHLogger:
    """Tests for ASHLogger class."""

    def test_verbose_method_exists(self):
        logger = ASHLogger("test.verbose")
        assert hasattr(logger, "verbose")

    def test_trace_method_exists(self):
        logger = ASHLogger("test.trace")
        assert hasattr(logger, "trace")

    def test_verbose_logs_at_correct_level(self):
        logger = ASHLogger("test.verbose_level")
        logger.setLevel(1)  # Enable all levels
        with patch.object(logger, "_log") as mock_log:
            logger.verbose("test message")
            mock_log.assert_called_once()
            # First arg should be the VERBOSE level (15)
            assert mock_log.call_args[0][0] == 15

    def test_trace_logs_at_correct_level(self):
        logger = ASHLogger("test.trace_level")
        logger.setLevel(1)
        with patch.object(logger, "_log") as mock_log:
            logger.trace("test message")
            mock_log.assert_called_once()
            assert mock_log.call_args[0][0] == 5


class TestGetLogger:
    """Tests for get_logger."""

    def test_returns_logger(self):
        logger = get_logger(name="test.get_logger")
        assert logger is not None

    def test_default_level(self):
        logger = get_logger(name="test.default_level")
        assert logger is not None

    def test_debug_level(self):
        logger = get_logger(name="test.debug_level", level=logging.DEBUG)
        assert logger.level <= logging.DEBUG

    def test_with_color(self):
        logger = get_logger(name="test.color", use_color=True)
        assert logger is not None

    def test_without_color(self):
        logger = get_logger(name="test.no_color", use_color=False)
        assert logger is not None


class TestASHLoggerInstance:
    """Tests for the module-level ASH_LOGGER."""

    def test_ash_logger_exists(self):
        assert ASH_LOGGER is not None

    def test_ash_logger_has_verbose(self):
        assert hasattr(ASH_LOGGER, "verbose")

    def test_ash_logger_has_trace(self):
        assert hasattr(ASH_LOGGER, "trace")
