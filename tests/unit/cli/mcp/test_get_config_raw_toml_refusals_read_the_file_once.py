# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config(raw=True) refuses a TOML file from the text it read, not a second read.

Why this file exists
--------------------
The raw read gives back a config file as written, with no value read from the
environment (``_config_as_written``). For TOML it read the file, and when the text
did not parse, or a ``pyproject.toml`` had no ``[tool.ash]`` table, it called the
loader (``config_sources.read_config_file``) on the same name to get the loader's
error. The loader reads the file again and resolves every ``${VAR}`` in it. The
read is held to the file's identity, not its content, so a file rewritten in
place between the two reads, to text that parses or that now has the table, made
the second read succeed: the answer was the rewritten file with the server's
environment values in it, where the first read had refused.

The refusal is now made of the bytes the first read returned, decoded and judged
in the loader's own words (``config_sources.toml_text_of`` and
``toml_config_table``, which ``read_config_file`` uses too), and the file is read
once. Called by the tool, ``_config_as_written`` is given the bytes of the file
the grant check opened; called with a name alone, as here, it reads the name once
through ``config_sources.read_config_bytes``.

Why the tests are what they are
-------------------------------
Each test wraps the config byte reader so that the first read returns the file as
it was and then rewrites the file in place with text that holds a reference to a
variable the test sets. A second read of the file then sees that reference, and
the test asserts the refusal, that the value appears nowhere in the error, and
that the file was read once. The controls pass before and after: a file nothing
rewrites, refused and accepted in the same words.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, List

import pytest

from automated_security_helper.cli.mcp_tools import _config_as_written
from automated_security_helper.config import config_sources
from automated_security_helper.core.exceptions import ASHConfigSourceError

PROBE_VAR = "ASH_RAW_TOML_PROBE"
PROBE_VALUE = "a-value-the-servers-environment-holds"


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PROBE_VAR, PROBE_VALUE)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


@pytest.fixture
def file_reads(monkeypatch: pytest.MonkeyPatch) -> Callable[..., List[Path]]:
    """Install a wrapper on the config byte reader; returns the paths it read.

    ``rewrite_to``, when given, is written over the file in place after the first
    read returns, so the read's own answer is the file as it was. The loader's
    own TOML text reader goes through the same byte reader, so a second read
    made on its behalf is counted too.
    """

    real = config_sources.read_config_bytes

    def install(rewrite_to: str | None = None) -> List[Path]:
        reads: List[Path] = []

        def reading(path: Path, expect=None) -> bytes:
            data = real(path, expect=expect)
            reads.append(Path(path))
            if rewrite_to is not None and len(reads) == 1:
                Path(path).write_text(rewrite_to, encoding="utf-8")
            return data

        monkeypatch.setattr(config_sources, "read_config_bytes", reading)
        return reads

    return install


A_REFERENCE = f'project_name = "${{{PROBE_VAR}}}"\n'
A_REFERENCE_IN_A_PYPROJECT = f'[tool.ash]\nproject_name = "${{{PROBE_VAR}}}"\n'


def test_a_file_that_does_not_parse_is_refused_even_if_rewritten_after_the_read(
    tmp_path, file_reads
):
    target = tmp_path / "config.toml"
    target.write_text("project_name = [unclosed\n", encoding="utf-8")
    reads = file_reads(rewrite_to=A_REFERENCE)
    # Control: the rewrite is a file that parses, with the reference in it.
    assert config_sources._parse_toml(A_REFERENCE) == {
        "project_name": f"${{{PROBE_VAR}}}"
    }

    with pytest.raises(ASHConfigSourceError) as raised:
        _config_as_written(target)

    assert "could not be parsed (" in str(raised.value), raised.value
    assert PROBE_VALUE not in str(raised.value), raised.value
    assert len(reads) == 1, reads


def test_a_pyproject_without_the_table_is_refused_even_if_it_gains_one_after_the_read(
    tmp_path, file_reads
):
    target = tmp_path / "pyproject.toml"
    target.write_text('[tool.other]\nname = "x"\n', encoding="utf-8")
    reads = file_reads(rewrite_to=A_REFERENCE_IN_A_PYPROJECT)

    with pytest.raises(ASHConfigSourceError) as raised:
        _config_as_written(target)

    assert "has no [tool.ash] table" in str(raised.value), raised.value
    assert PROBE_VALUE not in str(raised.value), raised.value
    assert len(reads) == 1, reads


def test_a_pyproject_whose_table_is_not_a_table_is_refused_even_if_rewritten(
    tmp_path, file_reads
):
    target = tmp_path / "pyproject.toml"
    target.write_text("[tool]\nash = 3\n", encoding="utf-8")
    reads = file_reads(rewrite_to=A_REFERENCE_IN_A_PYPROJECT)

    with pytest.raises(ASHConfigSourceError) as raised:
        _config_as_written(target)

    assert "must be a table" in str(raised.value), raised.value
    assert PROBE_VALUE not in str(raised.value), raised.value
    assert len(reads) == 1, reads


def test_control_a_file_that_is_not_utf8_is_refused_in_the_loaders_words(
    tmp_path, file_reads
):
    target = tmp_path / "config.toml"
    target.write_bytes(b'project_name = "caf\xe9"\n')
    # The bytes are read and the file is rewritten; the decode of the bytes that
    # were read is what refuses, in the loader's words (the byte's offset, never
    # its value), and nothing reads again.
    reads = file_reads(rewrite_to=A_REFERENCE)

    with pytest.raises(ASHConfigSourceError) as raised:
        _config_as_written(target)

    assert "could not be parsed (not UTF-8 at byte offset" in str(raised.value), (
        raised.value
    )
    assert PROBE_VALUE not in str(raised.value), raised.value
    assert len(reads) == 1, reads


@pytest.mark.parametrize(
    ("name", "text", "fragment"),
    [
        ("config.toml", "project_name = [unclosed\n", "could not be parsed ("),
        ("pyproject.toml", '[tool.other]\nname = "x"\n', "has no [tool.ash] table"),
        ("pyproject.toml", "[tool]\nash = 3\n", "must be a table"),
    ],
    ids=["not-toml", "no-table", "not-a-table"],
)
def test_control_a_file_nothing_rewrites_is_refused_in_the_same_words(
    tmp_path, file_reads, name, text, fragment
):
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    file_reads()

    with pytest.raises(ASHConfigSourceError) as raised:
        _config_as_written(target)

    assert fragment in str(raised.value), raised.value


@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        ("config.toml", A_REFERENCE, {"project_name": f"!ENV ${{{PROBE_VAR}}}"}),
        (
            "pyproject.toml",
            A_REFERENCE_IN_A_PYPROJECT,
            {"project_name": f"!ENV ${{{PROBE_VAR}}}"},
        ),
        ("config.toml", 'project_name = "plain"\n', {"project_name": "plain"}),
    ],
    ids=["reference", "reference-in-pyproject", "plain"],
)
def test_control_a_file_that_parses_is_returned_as_written(
    tmp_path, file_reads, name, text, expected
):
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    reads = file_reads()

    assert _config_as_written(target) == expected
    assert len(reads) == 1, reads
