# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reference the session config writer writes untagged is a reference again
when the file is loaded.

The loader's implicit resolver reads only a plain scalar as an environment
reference. The writer dumped an untagged reference as a plain string, so
whenever YAML could not write that text plain it quoted it, and the quoted
scalar loaded as a literal: the file held the reference's own text where the
variable's value belonged. The texts YAML cannot write plain include a
non-ASCII character (the dump does not allow unicode), a blank followed by
``#``, a colon followed by a blank, and a blank followed by ``::`` (a line the
config dumpers quote so no line is a CI workflow command). Such a reference is
written with the explicit ``!ENV`` tag, which the loader resolves however the
scalar is quoted.

The config is built in memory, with the rewrite that records the reference, so
each case names the reference text it writes.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig, load_yaml_config
from automated_security_helper.config.config_validator import EnvironmentRewrite
from automated_security_helper.config.config_writer import (
    render_config_file_as_written,
)

pytestmark = pytest.mark.unit

VARIABLE = "ASH_TEST_REGION_NAME"
VALUE = "read-from-the-environment"


def _config(written: str, resolved: str) -> AshConfig:
    """A config whose project name is ``resolved``, which its file read from the
    environment as the reference ``written``."""
    config = AshConfig.model_validate({"project_name": resolved})
    rewrite = EnvironmentRewrite(
        "value", ("project_name",), resolved, written, resolved, written
    )
    config._written_references = [rewrite]
    return config


@pytest.mark.parametrize(
    "default",
    [
        pytest.param("caf" + chr(0xE9), id="non-ascii"),
        pytest.param("a #b", id="blank-then-hash"),
        pytest.param("a: b", id="colon-then-blank"),
        pytest.param("a ::b", id="blank-then-double-colon"),
    ],
)
def test_a_reference_yaml_cannot_write_plain_is_read_again_from_the_environment(
    tmp_path, monkeypatch, default
):
    monkeypatch.setenv(VARIABLE, VALUE)
    written = "${" + VARIABLE + ":" + default + "}"

    text = render_config_file_as_written(
        tmp_path / "session.yaml", _config(written, default), []
    )

    assert str(load_yaml_config(text)["project_name"]) == VALUE, text


def test_a_reference_yaml_writes_plain_stays_plain(tmp_path, monkeypatch):
    monkeypatch.setenv(VARIABLE, VALUE)
    written = "${" + VARIABLE + "}"

    text = render_config_file_as_written(
        tmp_path / "session.yaml", _config(written, VALUE), []
    )

    assert "project_name: " + written + "\n" in text, text
    assert str(load_yaml_config(text)["project_name"]) == VALUE, text
