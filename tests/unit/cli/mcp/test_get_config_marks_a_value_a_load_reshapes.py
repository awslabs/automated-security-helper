# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config marks a value the load reshapes after it was read from the environment.

get_config's resolved config of an operator's file shows a value read from the
environment as its reference also where the load reshapes the value. A list made
of the variable's text (``output_formats: ${VAR}`` holding ``html,sarif``) shows
the reference for each entry, and a relative path the load anchors at the file's
directory and normalizes (``../shared/bandit.yaml``, ``./conf/bandit.yaml``) shows
that directory and the reference, never the value. A relative path that a ``patch``
operation sets or appends, or that the file's own ``patch`` moves, is shown the same
way. The cells run both routes to an operator's file (the call names it, or
``ASH_CONFIG`` does) and keep the controls that must not change: a list the file
wrote as text, a relative path the anchoring keeps whole, and a text field read
from a variable.

A scanner's own config file is the operator's choice, so the config of a file in a
checkout takes the operator's value there when ASH_CONFIG names the operator's
file. The answer shows the operator's reference at that place too, with the
operator's directory, whether or not the checkout's own value equals the
operator's. Those cells run the checkout the server searches and a file named in
another checkout.

``tool_version`` is the operator's choice the same way, for every scanner and
converter section, so the config of a file in a checkout takes the operator's
value there too, and the answer shows the operator's reference at that place, in a
built-in section and in a plugin's, whether or not the checkout wrote a value.
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

_RELATIVE_PATHS = pytest.mark.parametrize(
    "held, canary",
    [
        pytest.param("../shared-6d0a/x-6d0a.yaml", "shared-6d0a", id="parent-dir"),
        pytest.param("./conf-8e2b/x.yaml", "conf-8e2b", id="dot-dir"),
        pytest.param("conf-1f4c/x.yaml", "conf-1f4c", id="kept-whole"),
    ],
)


def _searched_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operators_body: str,
    own_body: str,
) -> Dict[str, Any]:
    """get_config of the checkout the server searches: ``checkout/.ash.yaml`` holds
    *own_body* and the process sits in the checkout, while ASH_CONFIG names
    ``operator/ash.yaml``, which holds *operators_body*, in no checkout. The
    checkout's file is confined to the operator's for a scanner's config file."""
    operators_file = tmp_path / "operator" / "ash.yaml"
    operators_file.parent.mkdir(parents=True)
    operators_file.write_text(operators_body, encoding="utf-8")
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash.yaml").write_text(own_body, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operators_file))
    monkeypatch.chdir(checkout)
    return mcp_get_config(search_dir=str(checkout))


def _another_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operators_body: str,
    own_body: str,
) -> Dict[str, Any]:
    """get_config of ``checkout/.ash.yaml``, which holds *own_body*, named from a
    working directory elsewhere, while ASH_CONFIG names ``operator/ash.yaml``,
    which holds *operators_body*, in a plain directory outside every checkout."""
    operators_file = tmp_path / "operator" / "ash.yaml"
    operators_file.parent.mkdir(parents=True)
    operators_file.write_text(operators_body, encoding="utf-8")
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    named = checkout / ".ash.yaml"
    named.write_text(own_body, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("ASH_CONFIG", str(operators_file))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return mcp_get_config(config_path=str(named))


_CONFINED_ROUTES = pytest.mark.parametrize(
    "confined",
    [
        pytest.param(_searched_checkout, id="searched-checkout"),
        pytest.param(_another_checkout, id="another-checkout"),
    ],
)

_OPERATOR_READS_CONFIG_FILE = (
    "scanners:\n  bandit:\n    options:\n      config_file: ${ASH_TEST_BANDIT_CFG}\n"
)

#: A checkout's file that writes bandit's ``config_file`` itself, as a JSON string.
_CHECKOUT_WRITES_CONFIG_FILE = (
    "scanners:\n  bandit:\n    options:\n      config_file: {}\n"
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
@_RELATIVE_PATHS
def test_a_relative_path_a_patch_operation_sets_shows_the_directory_and_the_reference(
    tmp_path, monkeypatch, answer, held, canary
):
    """A ``patch`` operation's value is anchored at the file's directory like any
    other relative path, and its reference follows it to the place the operation
    sets; the answer shows that directory and the reference, and none of the text
    the variable held."""
    monkeypatch.setenv("ASH_TEST_PATCH_CFG", held)
    body = (
        "scanners:\n"
        "  bandit:\n"
        "    options: {}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /scanners/bandit/options/config_file\n"
        "    value: ${ASH_TEST_PATCH_CFG}\n"
    )

    result = answer(tmp_path, monkeypatch, body)

    base = os.path.realpath(tmp_path / "operator")
    shown = result["scanners"]["bandit"]["options"]["config_file"]
    expected = os.path.join(base, "") + "<from ${ASH_TEST_PATCH_CFG}>"
    assert shown == expected, shown
    assert canary not in json.dumps(result, default=str)


@_ROUTES
@_RELATIVE_PATHS
def test_a_relative_path_the_files_patch_moves_shows_the_directory_and_the_reference(
    tmp_path, monkeypatch, answer, held, canary
):
    """The file's own ``patch`` inserts an entry ahead of the one the variable
    wrote, so the entry moves to index 1; the answer shows the inserted entry as a
    path and the moved one as the file's directory and the reference, and none of
    the text the variable held."""
    monkeypatch.setenv("ASH_TEST_GUARD_RULES", held)
    body = (
        "scanners:\n"
        "  cfn-guard:\n"
        "    options:\n"
        "      rules_paths:\n"
        "        - ${ASH_TEST_GUARD_RULES}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /scanners/cfn-guard/options/rules_paths/0\n"
        "    value: literal-first.guard\n"
    )

    result = answer(tmp_path, monkeypatch, body)

    base = os.path.realpath(tmp_path / "operator")
    shown = result["scanners"]["cfn_guard"]["options"]["rules_paths"]
    expected = [
        os.path.join(base, "literal-first.guard"),
        os.path.join(base, "") + "<from ${ASH_TEST_GUARD_RULES}>",
    ]
    assert shown == expected, shown
    assert canary not in json.dumps(result, default=str)


@_ROUTES
@_RELATIVE_PATHS
def test_a_relative_path_a_patch_operation_appends_shows_the_directory_and_the_reference(
    tmp_path, monkeypatch, answer, held, canary
):
    """A ``patch`` operation appends the variable's path to a list (``/-``) and the
    anchoring takes it from the file's directory; the answer shows the file's own
    entry as a path and the appended one as that directory and the reference, and
    none of the text the variable held."""
    monkeypatch.setenv("ASH_TEST_GUARD_RULES", held)
    body = (
        "scanners:\n"
        "  cfn-guard:\n"
        "    options:\n"
        "      rules_paths:\n"
        "        - literal-first.guard\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /scanners/cfn-guard/options/rules_paths/-\n"
        "    value: ${ASH_TEST_GUARD_RULES}\n"
    )

    result = answer(tmp_path, monkeypatch, body)

    base = os.path.realpath(tmp_path / "operator")
    shown = result["scanners"]["cfn_guard"]["options"]["rules_paths"]
    expected = [
        os.path.join(base, "literal-first.guard"),
        os.path.join(base, "") + "<from ${ASH_TEST_GUARD_RULES}>",
    ]
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


@_CONFINED_ROUTES
@_RELATIVE_PATHS
def test_a_relative_path_the_operators_file_reads_shows_the_directory_and_the_reference_in_a_checkouts_config(
    tmp_path, monkeypatch, confined, held, canary
):
    """The operator's file reads bandit's ``config_file`` from a variable, and the
    file in a checkout sets nothing there. The load gives the checkout's config
    the operator's path, anchored at the operator's directory, so the answer shows
    that directory and the operator's reference, and none of the text the
    variable held."""
    monkeypatch.setenv("ASH_TEST_BANDIT_CFG", held)

    result = confined(
        tmp_path,
        monkeypatch,
        _OPERATOR_READS_CONFIG_FILE,
        "project_name: checkout-own-6a2f\n",
    )

    directory = os.path.realpath(tmp_path / "operator")
    shown = result["scanners"]["bandit"]["options"]["config_file"]
    assert shown == os.path.join(directory, "") + "<from ${ASH_TEST_BANDIT_CFG}>", shown
    assert canary not in json.dumps(result, default=str)


@_CONFINED_ROUTES
@pytest.mark.parametrize(
    "equal",
    [
        pytest.param(True, id="the-operators-path"),
        pytest.param(False, id="another-path"),
    ],
)
def test_a_checkouts_literal_does_not_tell_whether_it_equals_the_operators_relative_path(
    tmp_path, monkeypatch, confined, equal
):
    """The file in a checkout writes its own ``config_file``: the path the
    operator's variable gives (``the-operators-path``) or another (``another-path``).
    The load gives the checkout's config the operator's either way, so the answer
    is the operator's directory and reference in both, and shows nothing of the
    checkout's text."""
    monkeypatch.setenv("ASH_TEST_BANDIT_CFG", "conf-1f4c/x.yaml")
    directory = os.path.realpath(tmp_path / "operator")
    written = (
        os.path.normpath(os.path.join(directory, "conf-1f4c/x.yaml"))
        if equal
        else "checkout-own-9c4d.yaml"
    )
    own = _CHECKOUT_WRITES_CONFIG_FILE.format(json.dumps(written))

    result = confined(tmp_path, monkeypatch, _OPERATOR_READS_CONFIG_FILE, own)

    shown = result["scanners"]["bandit"]["options"]["config_file"]
    assert shown == os.path.join(directory, "") + "<from ${ASH_TEST_BANDIT_CFG}>", shown
    dumped = json.dumps(result, default=str)
    assert "conf-1f4c" not in dumped
    assert written not in dumped


@_CONFINED_ROUTES
def test_a_literal_relative_path_the_operators_file_writes_is_shown_anchored_in_a_checkouts_config(
    tmp_path, monkeypatch, confined
):
    """The control: where the operator's file writes the relative path itself,
    there is no reference to show, and the answer is the path the operator's
    file anchors it to."""
    operators_body = (
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        "      config_file: conf-lit-5e2a/bandit.yaml\n"
    )

    result = confined(
        tmp_path, monkeypatch, operators_body, "project_name: checkout-own-6a2f\n"
    )

    directory = os.path.realpath(tmp_path / "operator")
    shown = result["scanners"]["bandit"]["options"]["config_file"]
    assert shown == os.path.normpath(
        os.path.join(directory, "conf-lit-5e2a/bandit.yaml")
    )


#: A checkout's file that writes bandit's ``tool_version`` itself, as a quoted string.
_CHECKOUT_WRITES_TOOL_VERSION = (
    "scanners:\n  bandit:\n    options:\n      tool_version: '{}'\n"
)


def _operators_tool_version(section: str, written: str) -> str:
    """The operator's file, which gives the ``scanners`` section *section* the
    ``tool_version`` *written*: a reference, or a quoted specifier set."""
    return f"scanners:\n  {section}:\n    options:\n      tool_version: {written}\n"


@_CONFINED_ROUTES
@pytest.mark.parametrize(
    "own",
    [
        pytest.param("project_name: checkout-own-4b1e\n", id="written-nowhere"),
        pytest.param(
            _CHECKOUT_WRITES_TOOL_VERSION.format(">=1.7.8,<1.7.97"),
            id="the-operators-value",
        ),
        pytest.param(
            _CHECKOUT_WRITES_TOOL_VERSION.format(">=1.7.8,<1.7.95"),
            id="another-value",
        ),
    ],
)
def test_a_tool_version_the_operators_file_reads_is_shown_by_its_reference_in_a_checkouts_config(
    tmp_path, monkeypatch, confined, own
):
    """The operator's file reads bandit's ``tool_version`` from a variable. The
    load gives the checkout's config the operator's value, whether the checkout
    wrote none, the operator's value or another, so the answer shows the
    operator's reference in all three, and none of the text the variable held or
    the checkout wrote."""
    monkeypatch.setenv("ASH_TEST_TOOL_RANGE", ">=1.7.8,<1.7.97")

    result = confined(
        tmp_path,
        monkeypatch,
        _operators_tool_version("bandit", "${ASH_TEST_TOOL_RANGE}"),
        own,
    )

    shown = result["scanners"]["bandit"]["options"]["tool_version"]
    assert shown == "<from ${ASH_TEST_TOOL_RANGE}>", shown
    dumped = json.dumps(result, default=str)
    assert "1.7.97" not in dumped
    assert "1.7.95" not in dumped


@_CONFINED_ROUTES
def test_a_literal_tool_version_the_operators_file_writes_is_shown_as_written_in_a_checkouts_config(
    tmp_path, monkeypatch, confined
):
    """The control: where the operator's file writes the specifier set itself,
    there is no reference to show, and the answer is that set."""
    result = confined(
        tmp_path,
        monkeypatch,
        _operators_tool_version("bandit", "'>=1.7.8,<1.7.96'"),
        "project_name: checkout-own-4b1e\n",
    )

    shown = result["scanners"]["bandit"]["options"]["tool_version"]
    assert shown == ">=1.7.8,<1.7.96", shown


@_CONFINED_ROUTES
def test_a_tool_version_an_operators_plugin_section_reads_is_shown_by_its_reference_in_a_checkouts_config(
    tmp_path, monkeypatch, confined
):
    """The control: ferret-scan's section is a plugin's, which the configuration
    holds as an extra that keeps the loader's mark, so its ``tool_version`` read
    from a variable is shown by the reference whether the answer takes it from the
    operator's reference or from the mark."""
    monkeypatch.setenv("ASH_TEST_TOOL_RANGE", ">=1.7.8,<1.7.97")

    result = confined(
        tmp_path,
        monkeypatch,
        _operators_tool_version("ferret-scan", "${ASH_TEST_TOOL_RANGE}"),
        "project_name: checkout-own-4b1e\n",
    )

    shown = result["scanners"]["ferret-scan"]["options"]["tool_version"]
    assert shown == "<from ${ASH_TEST_TOOL_RANGE}>", shown
    assert "1.7.97" not in json.dumps(result, default=str)
