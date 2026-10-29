# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container mode's pre-flight parse check runs on every supported Python.

Its TOML parser import follows the version gate the config reader uses
(config/config_sources.py): tomllib is stdlib from Python 3.11, and before
that it is tomli, which pyproject.toml declares for Python below 3.11. A bare
``import tomllib`` would raise ModuleNotFoundError on 3.10 for every container
and build-image run, whatever the config's format.
"""

from __future__ import annotations

import sys
from importlib.machinery import ModuleSpec
from types import ModuleType, SimpleNamespace
from typing import NamedTuple

import pytest

pytestmark = pytest.mark.unit


def test_the_container_parse_check_accepts_a_toml_config(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import (
        _refuse_a_container_config_that_does_not_parse,
    )

    good = tmp_path / "ash.toml"
    good.write_text('[tool.ash]\nproject_name = "t"\n', encoding="utf-8")
    # The check reads run (a --no-run build parses nothing) and then only the
    # config and source_dir attributes (_container_config_to_parse). This cell
    # is a real run's pre-check.
    opts = SimpleNamespace(run=True, config=str(good), source_dir=str(tmp_path))

    assert _refuse_a_container_config_that_does_not_parse(opts) is None


class _VersionInfo(NamedTuple):
    """sys.version_info's shape, so a gate reading .major or .minor reads the
    fake."""

    major: int
    minor: int
    micro: int
    releaselevel: str
    serial: int


def test_the_toml_parser_import_follows_the_version_gate(tmp_path, monkeypatch):
    """Told it runs below 3.11, the check parses the TOML config with tomli,
    the gate's other arm. The cell puts its own recording tomli in sys.modules,
    so it holds on every interpreter whether or not a real tomli is installed
    (uv.lock installs one on 3.11, for coverage[toml]): a bare tomllib import
    would parse with the stdlib module and leave the stand-in uncalled. On a
    real 3.10 the gate takes the tomli arm without being told, and the
    stand-in is still the module it gets.

    The stand-in is a module as the import system makes one, so any version
    gate resolved when the check runs reaches it: it has a spec (a
    find_spec("tomli") gate reads it), it answers load as well as loads, and
    the fake version has version_info's fields. A gate keyed on whether
    tomllib imports (a try-import fallback, a find_spec("tomllib") check)
    takes the stdlib module on 3.11 and later, whatever the faked version
    says, and fails the cell too, though it is right on a real 3.10. A gate
    resolved earlier keeps what it resolved then:
    a tomllib taken from a module first imported under the real version is the
    stdlib's, so such a gate fails the cell even where it would be right on a
    real 3.10. The check runs once unfaked first, so the modules
    it imports lazily are imported under the real version: run alone, the
    first import of the config modules under the fake took pydantic's
    pre-3.11 path and failed before the gate."""
    from automated_security_helper.interactions.run_ash_scan import (
        _refuse_a_container_config_that_does_not_parse,
    )

    good = tmp_path / "ash.toml"
    text = '[tool.ash]\nproject_name = "t"\n'
    good.write_text(text, encoding="utf-8")
    opts = SimpleNamespace(run=True, config=str(good), source_dir=str(tmp_path))
    # The control, and the lazy imports: the real gate parses the config.
    assert _refuse_a_container_config_that_does_not_parse(opts) is None
    parsed: list[str] = []

    def loads(document: str) -> dict:
        parsed.append(document)
        return {}

    def load(handle) -> dict:
        parsed.append(handle.read().decode("utf-8"))
        return {}

    stand_in = ModuleType("tomli")
    stand_in.__spec__ = ModuleSpec("tomli", loader=None)
    stand_in.__dict__["loads"] = loads
    stand_in.__dict__["load"] = load
    monkeypatch.setitem(sys.modules, "tomli", stand_in)
    monkeypatch.setattr(sys, "version_info", _VersionInfo(3, 10, 20, "final", 0))

    assert _refuse_a_container_config_that_does_not_parse(opts) is None
    assert parsed == [text], parsed
