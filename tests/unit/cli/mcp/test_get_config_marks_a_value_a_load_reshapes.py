# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config marks a value the load reshapes after it was read from the environment.

get_config's resolved config of an operator's file shows a value read from the
environment as its reference also where the load reshapes the value. A list made
of the variable's text (``output_formats: ${VAR}`` holding ``html,sarif``) shows
the reference for each entry, and a relative path the load anchors at the file's
directory and normalizes (``../shared/bandit.yaml``, ``./conf/bandit.yaml``) shows
that directory and the reference, never the value. The cells run both routes to an
operator's file (the call names it, or ``ASH_CONFIG`` does) and keep the controls
that must not change: a list the file wrote as text, a relative path the anchoring
keeps whole, and a text field read from a variable.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp_tools import mcp_get_config
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


def _named_operator_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> Dict[str, Any]:
    """get_config of ``operator/ash.yaml``, which holds *body*, in no git checkout
    and in a directory ASH_MCP_ALLOWED_CONFIG_ROOTS names, named from a directory
    elsewhere."""
    named = tmp_path / "operator" / "ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(body, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return mcp_get_config(config_path=str(named))


def _ash_config_operator_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> Dict[str, Any]:
    """get_config with no file named: ASH_CONFIG names ``operator/ash.yaml``, which
    holds *body*, in no git checkout, and the process sits in a checkout of its own."""
    named = tmp_path / "operator" / "ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(body, encoding="utf-8")
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    monkeypatch.setenv("ASH_CONFIG", str(named))
    monkeypatch.chdir(checkout)
    return mcp_get_config(search_dir=str(checkout))


_ROUTES = pytest.mark.parametrize(
    "answer",
    [
        pytest.param(_named_operator_file, id="named-operator-file"),
        pytest.param(_ash_config_operator_file, id="ash-config-operator-file"),
    ],
)


@_ROUTES
def test_a_list_the_load_makes_of_a_variables_text_shows_the_reference_for_each_entry(
    tmp_path, monkeypatch, answer
):
    """The field's validator splits ``html,sarif`` into two names after the
    reference is recorded at the list's own place, so each entry is shown as the
    reference and no name is shown."""
    monkeypatch.setenv("ASH_TEST_FMT", "html,sarif")

    result = answer(tmp_path, monkeypatch, "output_formats: ${ASH_TEST_FMT}\n")

    assert result["output_formats"] == [
        "<from ${ASH_TEST_FMT}>",
        "<from ${ASH_TEST_FMT}>",
    ], result


@_ROUTES
def test_a_list_the_file_wrote_is_shown_as_its_names(tmp_path, monkeypatch, answer):
    """The control: the same text written in the file itself reads from no
    variable, so the entries stay the names the field splits it into."""
    result = answer(tmp_path, monkeypatch, "output_formats: html,sarif\n")

    assert result["output_formats"] == ["html", "sarif"], result


@_ROUTES
@pytest.mark.parametrize(
    "held, canary",
    [
        pytest.param("../shared-7f3a/bandit-7f3a.yaml", "shared-7f3a", id="parent-dir"),
        pytest.param("./conf-5b9c/bandit.yaml", "conf-5b9c", id="dot-dir"),
        pytest.param("conf-9d2e/bandit.yaml", "conf-9d2e", id="kept-whole"),
    ],
)
def test_a_relative_path_from_a_variable_shows_the_directory_and_the_reference(
    tmp_path, monkeypatch, answer, held, canary
):
    """The anchoring takes a relative path from the file's directory and folds a
    ``..`` or a ``./`` out of it (``parent-dir``, ``dot-dir``) or keeps it whole
    (``kept-whole``); either way the answer shows that directory and the
    reference, and none of the text the variable held."""
    monkeypatch.setenv("ASH_TEST_BANDIT_CFG", held)
    body = "scanners:\n  bandit:\n    options:\n      config_file: ${ASH_TEST_BANDIT_CFG}\n"

    result = answer(tmp_path, monkeypatch, body)

    shown = result["scanners"]["bandit"]["options"]["config_file"]
    expected = (
        os.path.join(os.path.realpath(tmp_path / "operator"), "")
        + "<from ${ASH_TEST_BANDIT_CFG}>"
    )
    assert shown == expected, shown
    assert canary not in json.dumps(result, default=str)


@_ROUTES
def test_a_text_field_from_a_variable_shows_the_reference(
    tmp_path, monkeypatch, answer
):
    """The control: a field the load leaves as text is shown as the reference, and
    none of the text the variable held is in the answer."""
    monkeypatch.setenv("ASH_TEST_PN", "probe-name-3e1c")

    result = answer(tmp_path, monkeypatch, "project_name: ${ASH_TEST_PN}\n")

    assert result["project_name"] == "<from ${ASH_TEST_PN}>", result
    assert "probe-name-3e1c" not in json.dumps(result, default=str)
