# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A text nested past the recursion limit reads nothing from the environment.

``text_reads_the_environment`` and ``uses_env_references`` parse the text to
look for a reference. A YAML or TOML text nested past the interpreter's
recursion limit made that parse raise a raw RecursionError, which escaped them,
and ``parse_config_text`` runs the delivered-file environment check before its
own RecursionError handler, so a deeply nested client-delivered config escaped
as a raw RecursionError instead of ``ASHConfigUnparsedError``. The checks now
answer False for such a text, and the load's own parse words it as unparsed.

Red at the base: each call below raised RecursionError.
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


def test_a_deep_yaml_text_reads_nothing() -> None:
    assert text_reads_the_environment(Path("deep.yaml"), DEEP_YAML) is False


def test_a_deep_toml_text_reads_nothing() -> None:
    assert text_reads_the_environment(Path("deep.toml"), DEEP_TOML) is False


def test_a_deep_yaml_file_uses_no_references(tmp_path: Path) -> None:
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
