# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``${VAR:default}`` whose default runs across a line break is not a reference.

The pattern's greedy ``.*`` never crossed a newline, so a TOML multi-line string
or a YAML plain scalar folded across a blank line that starts like a reference
was the file's own text. The first-brace rewrite used ``[^}]*``, which does
cross one, so those values began to resolve. The recognizer excludes a newline
again, and the reader (``read_env_reference``) refuses one too.

Red at the base: ``ENV_REFERENCE_PATTERN.match("${ASH_U35_N:a\\nb}")`` matched,
and a TOML ``project_name = \"\"\"${ASH_U35_N:a\\nb}\"\"\"`` loaded as the variable's
value with it set.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    AshConfig,
    read_env_reference,
    resolve_env_references,
)

pytestmark = pytest.mark.unit

WRITTEN = "${ASH_U35_N:a\nb}"


def test_the_recognizer_and_the_reader_agree_it_is_no_reference() -> None:
    assert ENV_REFERENCE_PATTERN.match(WRITTEN) is None
    assert ENV_REFERENCE_PATTERN.match("${ASH_U35_N:a\r\nb}") is None
    assert read_env_reference(WRITTEN) is None
    assert read_env_reference("${ASH_U35_N:a\r\nb}") is None


def test_the_resolver_leaves_it_as_its_own_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASH_U35_N", "value")

    assert resolve_env_references(WRITTEN) == WRITTEN


def test_a_toml_multi_line_string_stays_literal(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASH_U35_N", "value")
    config_file = tmp_path / "ash.toml"
    config_file.write_text('project_name = """${ASH_U35_N:a\nb}"""\n', encoding="utf-8")

    config = AshConfig.from_file(config_file)

    assert config.project_name == WRITTEN


def test_a_folded_yaml_scalar_stays_literal(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain scalar folded across a blank line reads as ``${ASH_U35_N:a\\nb}``."""
    monkeypatch.setenv("ASH_U35_N", "value")
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text("project_name: ${ASH_U35_N:a\n\n  b}\n", encoding="utf-8")

    config = AshConfig.from_file(config_file)

    assert config.project_name == WRITTEN


def test_a_one_line_default_still_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control."""
    monkeypatch.setenv("ASH_U35_N", "value")
    assert str(resolve_env_references("${ASH_U35_N:a b}")) == "value"
    monkeypatch.delenv("ASH_U35_N", raising=False)
    assert str(resolve_env_references("${ASH_U35_N:a b}")) == "a b"
