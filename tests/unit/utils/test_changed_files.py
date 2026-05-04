# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for get_changed_files() in automated_security_helper.utils.get_scan_set."""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from automated_security_helper.utils.get_scan_set import get_changed_files


class TestGetChangedFiles:
    """Unit tests for the get_changed_files helper."""

    def test_returns_paths_on_success(self):
        fake_output = "src/app.py\nREADME.md\nlib/utils.js\n"
        mock_result = MagicMock(returncode=0, stdout=fake_output)
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result) as mock_run:
            result = get_changed_files("origin/main")

        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result == [Path("src/app.py"), Path("README.md"), Path("lib/utils.js")]

    def test_returns_empty_list_when_no_changes(self):
        mock_result = MagicMock(returncode=0, stdout="\n")
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result):
            result = get_changed_files()

        assert result == []

    def test_returns_none_when_git_not_found(self):
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            side_effect=FileNotFoundError("git not found"),
        ):
            result = get_changed_files()

        assert result is None

    def test_returns_none_on_timeout(self):
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=30),
        ):
            result = get_changed_files()

        assert result is None

    def test_returns_none_on_nonzero_exit(self):
        mock_result = MagicMock(returncode=128, stdout="", stderr="fatal: bad ref")
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result):
            result = get_changed_files("nonexistent-branch")

        assert result is None

    def test_custom_base_ref(self):
        mock_result = MagicMock(returncode=0, stdout="file.txt\n")
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result) as mock_run:
            result = get_changed_files("origin/develop")

        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "origin/develop...HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result == [Path("file.txt")]

    def test_strips_blank_lines(self):
        fake_output = "\n  a.py  \n\nb.py\n\n"
        mock_result = MagicMock(returncode=0, stdout=fake_output)
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result):
            result = get_changed_files()

        assert result == [Path("a.py"), Path("b.py")]
