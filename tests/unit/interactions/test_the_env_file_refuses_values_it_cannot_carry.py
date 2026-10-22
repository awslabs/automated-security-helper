# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container env file refuses a value it cannot carry, as a named refusal.

The env-file writer already refuses a line break or a NUL before anything is
made. A value the file's encoding cannot hold either -- a lone surrogate, which
``os.environ`` carries for bytes that were not UTF-8 -- surfaced at the write
instead, as a ``UnicodeEncodeError`` the container entry point does not catch:
a traceback and an unnamed exit where every other unusable input is a
``ContainerInputError`` and exit 3. The writer now refuses it the same way,
naming the variable, with the temporary directory cleaned up either way.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.interactions import run_ash_container
from automated_security_helper.interactions.run_ash_container import (
    ContainerInputError,
)


def _dirs(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return source, out


def test_a_value_the_file_cannot_encode_is_refused_naming_the_variable(tmp_path):
    source, out = _dirs(tmp_path)
    with pytest.raises(ContainerInputError, match="ASH_RECV_TOKEN"):
        run_ash_container._write_env_file(
            ["ASH_RECV_TOKEN"],
            # The suppression must be bandit's own, not an ASH suppression rule:
            # bandit 1.9.4's SARIF and JSON writers crash on a lone surrogate in
            # a finding's text (issue.as_dict's utf-8 encode), exit 1 with a
            # 0-byte results file, and ASH suppressions act only on the output
            # that never gets written.
            {"ASH_RECV_TOKEN": "a\udce9b"},  # nosec B105 - an unencodable fixture value, not a credential
            "docker",
            source,
            out,
        )


def test_a_carryable_value_is_written_and_removed_when_the_block_ends(tmp_path):
    source, out = _dirs(tmp_path)
    with run_ash_container._env_file(
        ["ASH_RECV_TOKEN"], {"ASH_RECV_TOKEN": "plain"}, "docker", source, out
    ) as (directory, path):
        assert path.read_text(encoding="utf-8") == "ASH_RECV_TOKEN=plain\n"

    assert not directory.exists()
