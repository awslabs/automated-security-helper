# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A text nested past the recursion limit is refused by the environment check.

``text_reads_the_environment`` parses the text to look for a reference before
the load does, so a client-delivered file that reads the environment is refused
before any value is read. A YAML or TOML text nested past the interpreter's
recursion limit made that parse raise a raw RecursionError, which escaped the
check; it was then answered False (``reads nothing``) with the load's own parse
left to refuse the depth. That failed open: the check's parse and the load's
parse run at different depths of the stack, so a text at the edge of the limit
could pass the check and then parse, with its references read. The check now
refuses such a text as an unparsed config, in the words ``parse_config_text``
uses for the same file. ``uses_env_references``, a lint convenience whose load
words the depth itself, still answers False.

Red at the base: ``text_reads_the_environment`` answered False for each deep
text below.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import (
    parse_config_text,
    text_reads_the_environment,
    uses_env_references,
)
from automated_security_helper.core.exceptions import ASHConfigUnparsedError

pytestmark = pytest.mark.unit

DEPTH = 20000
DEEP_YAML = "[" * DEPTH + "]" * DEPTH + "\n"
DEEP_TOML = "x = " + "[" * DEPTH + "]" * DEPTH + "\n"


def test_a_deep_yaml_text_is_refused_as_unparsed() -> None:
    with pytest.raises(ASHConfigUnparsedError) as refused:
        text_reads_the_environment(Path("deep.yaml"), DEEP_YAML)

    assert "deep.yaml" in str(refused.value)
    assert "could not be parsed" in str(refused.value)


def test_a_deep_toml_text_is_refused_as_unparsed() -> None:
    with pytest.raises(ASHConfigUnparsedError) as refused:
        text_reads_the_environment(Path("deep.toml"), DEEP_TOML)

    assert "deep.toml" in str(refused.value)
    assert "could not be parsed" in str(refused.value)


def test_a_deep_yaml_file_uses_no_references(tmp_path: Path) -> None:
    """The lint convenience keeps its answer; its load words the depth."""
    deep = tmp_path / ".ash.yaml"
    deep.write_text(DEEP_YAML, encoding="utf-8")

    assert uses_env_references(deep) is False


def test_a_refused_env_file_that_is_too_deep_is_an_unparsed_config() -> None:
    with pytest.raises(ASHConfigUnparsedError):
        parse_config_text(Path("deep.yaml"), DEEP_YAML, refuse_env=lambda path: True)


def test_a_shallow_reference_is_still_found() -> None:
    """The control."""
    assert text_reads_the_environment(Path("flat.yaml"), "a: ${ASH_U35_X}\n") is True
    assert text_reads_the_environment(Path("flat.toml"), 'a = "${ASH_U35_X}"\n') is True


def test_an_ordinary_parse_error_still_reads_nothing() -> None:
    """The control: a text that fails to parse for its own reasons reads
    nothing here, and its load says why, as before."""
    assert text_reads_the_environment(Path("bad.yaml"), "a: [\n") is False
    assert text_reads_the_environment(Path("bad.toml"), "a = [\n") is False
