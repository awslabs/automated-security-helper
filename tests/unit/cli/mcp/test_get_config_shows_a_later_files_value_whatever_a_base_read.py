# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config shows a value a later file of the chain wrote as that file wrote it.

A base file reads a place from the environment and a file that extends it writes
the same place itself. The merged configuration holds the later file's value
there, whatever the variable holds, so the answer shows that value as the file
wrote it. The base's reference no longer describes the place, and the answer must
not change with the variable's value: a later literal that contains the value,
equals it, or anchors to the same path as it is shown as itself, and so is a later
literal under another spelling of an undeclared plugin section. The cells run
both routes to an operator's chain (the call names the file, or ``ASH_CONFIG``
does) and keep a control that never held the variable's value.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp_tools import mcp_get_config
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


def _named_operator_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: str, body: str
) -> Dict[str, Any]:
    """get_config of ``operator/ash.yaml``, which holds *body* and extends
    ``operator/base.yaml``, which holds *base*, in no git checkout and in a
    directory ASH_MCP_ALLOWED_CONFIG_ROOTS names, named from a directory
    elsewhere."""
    operator = tmp_path / "operator"
    operator.mkdir(parents=True)
    (operator / "base.yaml").write_text(base, encoding="utf-8")
    named = operator / "ash.yaml"
    named.write_text(body, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return mcp_get_config(config_path=str(named))


def _ash_config_operator_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: str, body: str
) -> Dict[str, Any]:
    """get_config with no file named: ASH_CONFIG names ``operator/ash.yaml``, which
    holds *body* and extends ``operator/base.yaml``, which holds *base*, in no git
    checkout, and the process sits in a checkout of its own."""
    operator = tmp_path / "operator"
    operator.mkdir(parents=True)
    (operator / "base.yaml").write_text(base, encoding="utf-8")
    named = operator / "ash.yaml"
    named.write_text(body, encoding="utf-8")
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    monkeypatch.setenv("ASH_CONFIG", str(named))
    monkeypatch.chdir(checkout)
    return mcp_get_config(search_dir=str(checkout))


_ROUTES = pytest.mark.parametrize(
    "answer",
    [
        pytest.param(_named_operator_chain, id="named-operator-file"),
        pytest.param(_ash_config_operator_chain, id="ash-config-operator-file"),
    ],
)


@_ROUTES
@pytest.mark.parametrize(
    "held",
    [
        pytest.param("sarif", id="inside"),
        pytest.param("html", id="other-entry"),
        pytest.param("markdown", id="control"),
    ],
)
def test_a_later_files_list_is_shown_as_written_whatever_the_base_read(
    tmp_path, monkeypatch, answer, held
):
    """The base reads ``output_formats`` from the variable and the file extending
    it writes its own list. Whether the variable names one of the later list's
    entries (``inside``, ``other-entry``) or none of them (``control``), the
    answer is that list, and no entry is shown as the base's reference."""
    monkeypatch.setenv("ASH_TEST_FMT", held)

    result = answer(
        tmp_path,
        monkeypatch,
        "output_formats: ${ASH_TEST_FMT}\n",
        "extends: base.yaml\noutput_formats: [html, sarif]\n",
    )

    assert result["output_formats"] == ["html", "sarif"], result


@_ROUTES
@pytest.mark.parametrize(
    "held, hidden",
    [
        pytest.param("prod-7c1e", None, id="inside"),
        pytest.param("acme-prod-7c1e", None, id="equal"),
        pytest.param("other-7c1e", "other-7c1e", id="control"),
    ],
)
def test_a_later_files_text_is_shown_as_written_whatever_the_base_read(
    tmp_path, monkeypatch, answer, held, hidden
):
    """The base reads ``project_name`` from the variable and the file extending it
    writes ``acme-prod-7c1e``. The variable's value is inside that text
    (``inside``), is that text (``equal``) or is another (``control``): the answer
    is the later file's text each time, never ``acme-<from ...>`` or the marker
    alone. In the control row, where the variable's value is not the later
    file's, the answer holds no trace of it."""
    monkeypatch.setenv("ASH_TEST_PN", held)

    result = answer(
        tmp_path,
        monkeypatch,
        "project_name: ${ASH_TEST_PN}\n",
        "extends: base.yaml\nproject_name: acme-prod-7c1e\n",
    )

    assert result["project_name"] == "acme-prod-7c1e", result
    if hidden is not None:
        assert hidden not in json.dumps(result, default=str)


@_ROUTES
@pytest.mark.parametrize(
    "held, hidden",
    [
        pytest.param("../shared-4a7d/bandit.yaml", None, id="same"),
        pytest.param("../other-9e3b/bandit.yaml", "other-9e3b", id="control"),
    ],
)
def test_a_later_files_relative_path_is_shown_as_its_anchored_text_whatever_the_base_read(
    tmp_path, monkeypatch, answer, held, hidden
):
    """The base reads bandit's ``config_file`` from the variable and the file
    extending it writes ``../shared-4a7d/bandit.yaml``, which the load anchors at
    the operator's directory. The variable names the same relative path
    (``same``), so the two anchor to one text, or another (``control``): the
    answer is the later file's anchored path each time, with no marker."""
    monkeypatch.setenv("ASH_TEST_BANDIT_CFG", held)

    result = answer(
        tmp_path,
        monkeypatch,
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        "      config_file: ${ASH_TEST_BANDIT_CFG}\n",
        "extends: base.yaml\n"
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        "      config_file: ../shared-4a7d/bandit.yaml\n",
    )

    shown = result["scanners"]["bandit"]["options"]["config_file"]
    expected = os.path.join(os.path.realpath(tmp_path), "shared-4a7d", "bandit.yaml")
    assert shown == expected, shown
    if hidden is not None:
        assert hidden not in json.dumps(result, default=str)


@_ROUTES
@pytest.mark.parametrize(
    "held, hidden",
    [
        pytest.param("prod", None, id="inside"),
        pytest.param("team-prod", None, id="equal"),
        pytest.param("other-4e1a", "other-4e1a", id="control"),
    ],
)
def test_a_later_files_respelled_plugin_section_is_shown_as_written_whatever_the_base_read(
    tmp_path, monkeypatch, answer, held, hidden
):
    """The base reads a scanner's ``ruleset`` option from the variable under
    ``my-scanner``, and the file extending it writes ``team-prod`` under
    ``MyScanner``, another spelling of the same undeclared section, which the
    merge joins under the later file's. The variable's value is inside that text
    (``inside``), is that text (``equal``) or is another (``control``): the answer
    is the later file's text under its own spelling each time, and in the control
    row it holds no trace of the value."""
    monkeypatch.setenv("ASH_TEST_RULE", held)

    result = answer(
        tmp_path,
        monkeypatch,
        "scanners:\n  my-scanner:\n    options:\n      ruleset: ${ASH_TEST_RULE}\n",
        "extends: base.yaml\n"
        "scanners:\n"
        "  MyScanner:\n"
        "    options:\n"
        "      ruleset: team-prod\n",
    )

    assert result["scanners"]["MyScanner"]["options"]["ruleset"] == "team-prod", result
    if hidden is not None:
        assert hidden not in json.dumps(result, default=str)
