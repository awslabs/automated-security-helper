# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With no ASH_BIN_PATH and no usable home directory, ASH has no bin directory.

``core.constants.ASH_BIN_PATH`` is then None (an empty HOME makes ``~/.ash/bin``
the filesystem root's, and a relative one names a directory under the working
directory). Each place that resolves the bin directory at call time says so instead
of using the text "None" or a directory under the working directory: tool lookup
searches no bin directory, an install command only refuses, and a direct install
raises before it creates anything.

Measured in this process with the constants patched to None, as
``download_utils.current_bin_path`` and ``subprocess_utils._bin_path`` fall back
to them when ASH_BIN_PATH is unset.
"""

from __future__ import annotations

import pytest

_REFUSAL_SOURCE = "import sys; sys.exit(sys.argv[1])"


@pytest.fixture
def no_bin_directory(monkeypatch, tmp_path):
    from automated_security_helper.utils import download_utils, subprocess_utils

    monkeypatch.setattr(download_utils, "ASH_BIN_PATH", None)
    monkeypatch.setattr(subprocess_utils, "ASH_BIN_PATH", None)
    monkeypatch.delenv("ASH_BIN_PATH", raising=False)
    monkeypatch.chdir(tmp_path)
    subprocess_utils.clear_find_executable_cache()
    yield tmp_path
    subprocess_utils.clear_find_executable_cache()


def _made_under(directory) -> list:
    return sorted(
        path.relative_to(directory).as_posix() for path in directory.rglob("*")
    )


def test_the_bin_directory_resolved_at_call_time_is_none(no_bin_directory):
    from automated_security_helper.utils import download_utils

    assert download_utils.current_bin_path() is None


def test_lookup_searches_no_bin_directory(no_bin_directory):
    """The directories searched whatever PATH says hold no None and no "None"."""
    from automated_security_helper.utils import subprocess_utils

    searched = subprocess_utils.path_independent_dirs()

    assert None not in searched
    assert all(str(directory) != "None" for directory in searched), searched


def test_no_bin_directory_is_not_reported_as_a_relative_one(no_bin_directory):
    """The incomplete-scan note names a relative ASH_BIN_PATH that lookups skip.
    With no bin directory at all there is none to name, not the text "None"."""
    from automated_security_helper.utils import subprocess_utils

    assert subprocess_utils.ignored_relative_bin_path() is None


@pytest.mark.parametrize("kind", ["pinned", "url"])
def test_an_install_command_only_refuses(no_bin_directory, kind):
    """A plugin builds its install commands whenever it is constructed, so one with
    no bin directory says why and exits 1, and building it creates nothing."""
    from automated_security_helper.utils import download_utils

    if kind == "pinned":
        command = download_utils.create_pinned_tool_install_command(
            "grype", "linux", "amd64"
        )
    else:
        command = download_utils.create_url_download_command(
            "https://example.invalid/tool", expected_sha256="0" * 64
        )

    assert command.args[2] == _REFUSAL_SOURCE, command.args
    assert "--bin-path" in command.args[3]
    assert _made_under(no_bin_directory) == []


def test_a_direct_install_raises_before_it_creates_anything(no_bin_directory):
    from automated_security_helper.utils import download_utils

    with pytest.raises(RuntimeError, match="--bin-path"):
        download_utils.install_pinned_tool("grype", "linux", "amd64")
    assert _made_under(no_bin_directory) == []
