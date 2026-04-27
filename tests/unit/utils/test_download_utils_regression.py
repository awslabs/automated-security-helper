"""Regression tests for download_utils bug fixes.

PR#274 Bug #2: code injection via f-string in create_url_download_command.
"""

import shutil
import tempfile

import pytest


class TestDownloadUtilsCodeInjection:
    """A single quote in url/destination must not escape the Python string."""

    def test_single_quote_in_url_no_injection(self):
        """URL containing a single quote must not break the command args."""
        from automated_security_helper.utils.download_utils import (
            create_url_download_command,
        )

        evil_url = "https://example.com/bin'injection"
        dest = tempfile.mkdtemp()
        try:
            cmd = create_url_download_command(url=evil_url, destination=dest)
            # After the fix, the command should use --url/--dest flags or
            # env vars instead of interpolating into a python -c string.
            # No arg should contain the raw URL inside a python source string.
            for arg in cmd.args:
                if "-c" == arg:
                    # If -c is still used, the url must not appear raw
                    idx = cmd.args.index(arg)
                    if idx + 1 < len(cmd.args):
                        script = cmd.args[idx + 1]
                        assert "'" + "injection" not in script or "sys.argv" in script or "os.environ" in script, (
                            "URL interpolated raw into python -c script"
                        )
        finally:
            shutil.rmtree(dest, ignore_errors=True)

    def test_command_does_not_use_raw_interpolation(self):
        """The command should pass values safely, not via f-string interpolation."""
        from automated_security_helper.utils.download_utils import (
            create_url_download_command,
        )

        url = "https://example.com/binary"
        dest = tempfile.mkdtemp()
        try:
            cmd = create_url_download_command(url=url, destination=dest)
            # After fix: url and dest should be passed as separate args, not
            # interpolated into a python -c source string
            if "-c" in cmd.args:
                idx = cmd.args.index("-c")
                script = cmd.args[idx + 1]
                # The script should reference sys.argv, not contain the literal URL
                assert url not in script, (
                    f"URL appears literally in -c script: {script}"
                )
        finally:
            shutil.rmtree(dest, ignore_errors=True)
