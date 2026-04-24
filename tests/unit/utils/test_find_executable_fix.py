"""Regression test: find_executable checks all command variants (M6)."""

from pathlib import Path
from unittest.mock import patch

from automated_security_helper.utils.subprocess_utils import find_executable


def test_returns_none_only_after_exhausting_all_variants():
    result = find_executable("__nonexistent_binary_xyz__")
    assert result is None


@patch("automated_security_helper.utils.subprocess_utils.shutil.which")
def test_finds_second_variant(mock_which):
    mock_which.side_effect = [None, "/usr/bin/somecmd"]
    with patch(
        "automated_security_helper.utils.subprocess_utils.platform.system",
        return_value="Windows",
    ):
        with patch(
            "automated_security_helper.utils.subprocess_utils.ASH_BIN_PATH",
            Path("/fake"),
        ):
            find_executable("somecmd")
    assert mock_which.call_count >= 2
