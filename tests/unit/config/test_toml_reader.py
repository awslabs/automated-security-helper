# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A TOML 1.0 config reads the same on every Python ASH supports.

On Python 3.10, which has no tomllib, config_sources fell back to `toml` 0.10.
That implements TOML 0.5 and refuses valid TOML 1.0, such as an array of mixed
types, so a config a scan on 3.11 and later accepted was "not valid TOML" on
3.10. It reads with tomli there, the parser tomllib was taken from, held below
2.4: from 2.4 tomli also reads TOML 1.1, which tomllib on 3.11 to 3.14 refuses,
so a config that only TOML 1.1 reads was accepted on 3.10 alone.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.config.config_sources import read_config_file
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


def test_an_array_of_mixed_types_is_read(tmp_path):
    target = tmp_path / ".ashrc.toml"
    target.write_text('project_name = "demo"\nmixed = ["a", 1]\n', encoding="utf-8")

    assert read_config_file(target) == {"project_name": "demo", "mixed": ["a", 1]}


def test_the_reader_is_tomllib_or_tomli():
    """tomllib, or on 3.10 tomli, the parser tomllib was taken from."""
    import automated_security_helper.config.config_sources as config_sources

    expected = "tomllib" if sys.version_info >= (3, 11) else "tomli"
    assert config_sources.tomllib.__name__ == expected


def test_a_toml_1_1_only_config_is_refused_on_every_python(tmp_path):
    """TOML 1.1 allows a trailing comma in an inline table, and TOML 1.0 does not.
    With tomli 2.4, 3.10 accepted a config that 3.11 and later refuse; with tomli
    held below 2.4 every Python refuses it. Lifting that cap, or a tomllib that
    learns TOML 1.1, fails here."""
    target = tmp_path / ".ashrc.toml"
    target.write_text("t = {a = 1,}\n", encoding="utf-8")

    with pytest.raises(ASHConfigSourceError):
        read_config_file(target)
