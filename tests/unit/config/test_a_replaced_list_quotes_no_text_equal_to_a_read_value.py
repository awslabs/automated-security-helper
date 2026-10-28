# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A replaced list's quoting shows no text equal to an environment read.

The suppression and ignore-path quoting (suppression_matcher's
recorded_suppressions and recorded_ignore_paths) matches list entries at any
index. When an extends overlay replaces a list whose base entry read from the
environment, and writes as its own literal the same text the base's entry
read, the recorded path for that entry is the reference's written form: the
record keeps every read the chain made, so a value it supplied is never shown
as plain text, whichever file ends up holding it.
"""

import json

import pytest

from automated_security_helper.config.resolve_config import load_config_file_for_run
from automated_security_helper.utils.suppression_matcher import (
    recorded_ignore_paths,
    recorded_suppressions,
)

VAR = "ASH_TEST_SUPP_A"
VALUE = "supp-needle-3b/"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR, VALUE)


def _load(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    _, config = load_config_file_for_run(tmp_path / "overlay.yaml")
    return config


def _base(section):
    return (
        f"global_settings:\n  {section}:\n"
        f"    - path: ${{{VAR}}}\n      reason: base-reason\n"
    )


def _overlay(section):
    return (
        f"extends: base.yaml\nglobal_settings:\n  {section}:\n"
        "    - path: first/\n      reason: overlay-reason\n"
        f"    - path: {VALUE}\n      reason: overlay-reason-2\n"
    )


def test_replaced_suppressions_list_quotes_no_text_equal_to_a_read_value(tmp_path):
    config = _load(
        tmp_path,
        {"base.yaml": _base("suppressions"), "overlay.yaml": _overlay("suppressions")},
    )
    entries = list(config.global_settings.suppressions)
    recorded = recorded_suppressions(config)
    paths = [recorded[id(s)]["path"] for s in entries]
    assert [s.path for s in entries] == ["first/", VALUE]
    assert VALUE not in json.dumps(paths), paths
    assert paths == ["first/", f"${{{VAR}}}"], paths


def test_replaced_ignore_paths_list_quotes_no_text_equal_to_a_read_value(tmp_path):
    config = _load(
        tmp_path,
        {"base.yaml": _base("ignore_paths"), "overlay.yaml": _overlay("ignore_paths")},
    )
    entries = list(config.global_settings.ignore_paths)
    recorded = recorded_ignore_paths(
        config, entries, ("global_settings", "ignore_paths")
    )
    paths = [recorded[id(e)]["path"] for e in entries]
    assert [e.path for e in entries] == ["first/", VALUE]
    assert VALUE not in json.dumps(paths), paths
    assert paths == ["first/", f"${{{VAR}}}"], paths


def test_control_one_file_suppression_is_quoted_by_its_reference(tmp_path):
    config = _load(
        tmp_path,
        {"base.yaml": _base("suppressions"), "overlay.yaml": "extends: base.yaml\n"},
    )
    entries = list(config.global_settings.suppressions)
    recorded = recorded_suppressions(config)
    assert [recorded[id(s)]["path"] for s in entries] == [f"${{{VAR}}}"]
