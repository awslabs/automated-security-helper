"""Regression tests for get_scan_set bug fixes.

Bug #175: debug_echo returns None, passes tuple to logger.
"""

from unittest.mock import patch

import pytest


class TestDebugEchoReturnValue:
    """debug_echo should return the message string, not None."""

    def test_debug_echo_returns_string(self):
        from automated_security_helper.utils.get_scan_set import debug_echo

        result = debug_echo("hello", "world", debug=True)
        assert result is not None, "debug_echo returned None instead of a string"
        assert isinstance(result, str), f"debug_echo returned {type(result)}, expected str"

    def test_debug_echo_passes_string_not_tuple(self):
        """The logger should receive a proper string, not a raw tuple."""
        from automated_security_helper.utils.get_scan_set import debug_echo

        with patch("automated_security_helper.utils.get_scan_set.ASH_LOGGER") as mock_logger:
            debug_echo("hello", "world", debug=True)
            mock_logger.debug.assert_called_once()
            call_args = mock_logger.debug.call_args
            first_arg = call_args[0][0]
            assert not isinstance(first_arg, tuple), (
                f"Logger received a tuple {first_arg!r} instead of a string"
            )
