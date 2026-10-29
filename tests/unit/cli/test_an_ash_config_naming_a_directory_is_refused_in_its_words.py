# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ASH_CONFIG that names a directory is refused in ASH_CONFIG's words.

get_default_config refuses an ASH_CONFIG naming something that is not a file:
"'<path>': ASH_CONFIG names it, and it is not a file". ``ash scan`` with no
``--config`` takes ASH_CONFIG as its ``--config``, and refused a directory as
"Configuration file not found" instead: it asked get_default_config only for a
path that does not exist, so a path that exists, and is not a file, was named
as missing. Nothing held get_default_config's words either: one that let the
directory through still refused the run with exit 3, later and in other words.

Each cell sets ASH_CONFIG to an empty directory, or to a FIFO, which also
exists and is not a file, and which get_default_config refuses from the name
alone, before anything opens it. The config commands, which also take
ASH_CONFIG as their ``--config``, refuse a path that is not a file in their own
words, checked in test_config_refusals_show_a_path_on_one_line.py.
"""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

WORDS = "ASH_CONFIG names it, and it is not a file"


@pytest.fixture
def directory(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    named = tmp_path / "config-directory"
    named.mkdir()
    monkeypatch.setenv("ASH_CONFIG", str(named))
    return named


@pytest.mark.parametrize(
    "kind",
    [
        "directory",
        pytest.param(
            "fifo",
            marks=pytest.mark.skipif(
                not hasattr(os, "mkfifo"), reason="the platform has no FIFOs"
            ),
        ),
    ],
)
def test_scan_refuses_it_in_ash_config_s_words(tmp_path, directory, monkeypatch, kind):
    import signal

    if kind == "directory":
        # The directory cell runs as it does where the platform has no
        # SIGALRM and no alarm (Windows): nothing here may need them.
        monkeypatch.delattr(signal, "SIGALRM", raising=False)
        monkeypatch.delattr(signal, "alarm", raising=False)
    if kind == "fifo":
        # A FIFO exists and is not a file. get_default_config refuses it from
        # the name alone, before anything opens it: an open would wait for a
        # writer, and nothing writes. The alarm turns a regression that opens
        # the path into a failure instead of a hung worker.
        named = tmp_path / "config-fifo"
        os.mkfifo(named)
        monkeypatch.setenv("ASH_CONFIG", str(named))
    source = tmp_path / "src"
    source.mkdir()

    def _blocked(signum, frame):
        raise TimeoutError("the refusal opened the path and blocked")

    # Only the FIFO can block. The FIFO cell runs only where os.mkfifo exists,
    # and every such platform has SIGALRM.
    armed = kind == "fifo"
    if armed:
        previous = signal.signal(signal.SIGALRM, _blocked)
        signal.alarm(60)
    try:
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(source),
                "--output-dir",
                str(tmp_path / "out"),
                "--no-progress",
            ],
        )
    finally:
        if armed:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    assert result.exit_code == 3, result.output
    assert "not found" not in result.output.lower(), result.output
    assert WORDS in result.output, result.output


def test_the_default_config_refuses_it_in_ash_config_s_words(directory):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    with pytest.raises(ASHConfigValidationError) as refused:
        get_default_config()

    assert WORDS in str(refused.value), refused.value
    assert refused.value.ash_config_file == directory
