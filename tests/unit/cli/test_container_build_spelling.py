# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ashx container build`` is the command; ``build-image`` was its 3.8 spelling.

The old spelling was deprecated in 3.9, as every spelling that moved then was
(``ash report`` became ``ash results report``), and is removed in 4.0: the root
has no ``build-image`` command, so the spelling is a usage error that builds
nothing. The scan the command starts is replaced by a stand-in that records its
arguments, so no image is built.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

pytestmark = pytest.mark.unit


@pytest.fixture
def scans(monkeypatch):
    """The scan the build command starts, recorded."""
    calls: list[dict] = []
    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan",
        lambda **kwargs: calls.append(kwargs),
    )
    return calls


def _invoke(*args: str):
    from automated_security_helper.cli.main import app

    return CliRunner().invoke(app, list(args))


def _one_line(output: str) -> str:
    return " ".join(output.split())


def test_the_new_spelling_builds_and_does_not_warn(scans):
    result = _invoke("container", "build", "--no-run")

    assert result.exit_code == 0, result.output
    assert len(scans) == 1
    assert scans[0]["build"] is True and scans[0]["run"] is False
    assert "Deprecat" not in result.output


@pytest.mark.parametrize(
    "args", [["build-image", "--no-run"], ["build-image", "--help"]]
)
def test_the_removed_spelling_is_a_usage_error_that_builds_nothing(scans, args):
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    result = _invoke(*args)

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "No such command 'build-image'" in _one_line(result.output)
    assert scans == []


def test_the_root_no_longer_has_the_old_spelling():
    import typer.main

    from automated_security_helper.cli.main import app

    root = typer.main.get_command(app)
    assert "build-image" not in root.commands
    assert "build" in root.commands["container"].commands


def test_the_group_lists_build_in_its_help(scans):
    result = _invoke("container", "--help")

    assert result.exit_code == 0, result.output
    assert "build" in result.output


def test_the_root_help_names_the_group_and_hides_the_old_spelling(scans):
    result = _invoke("--help")

    assert "container" in result.output
    assert "build-image" not in result.output


def test_a_root_option_before_the_group_reaches_build(scans):
    """`ash --verbose container build` hands the root's --verbose to the leaf, as
    `ash --verbose build-image` handed it to the command."""
    result = _invoke("--verbose", "container", "build", "--no-run")

    assert result.exit_code == 0, result.output
    assert scans[0]["verbose"] is True


def test_an_unknown_option_to_build_is_a_usage_error(scans):
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    result = _invoke("container", "build", "--no-such-option")

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert scans == []


def test_a_root_option_the_leaf_takes_differently_names_the_leaf_in_the_refusal(scans):
    """`-f` is --output-formats on the root and --force on build. The refusal advises
    what the operator can type: the group takes no options, so `ash container
    --force` would be a usage error of its own."""
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    result = _invoke("-f", "sarif", "container", "build", "--no-run")

    # The refusal names the canonical command, `ashx` on the v4 line (main.py's
    # refusal text spells it), whichever console script the operator ran.
    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'ashx container build' takes -f as --force" in text, text
    assert (
        "give it after 'container build', as 'ashx container build --force ...'" in text
    ), text
    assert "'ashx container --force" not in text, text
    assert scans == []


def test_a_root_option_the_leaf_does_not_take_points_at_the_leafs_help(scans):
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    result = _invoke("--scanners", "bandit", "container", "build", "--no-run")

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'ashx container build' does not take --scanners" in text, text
    assert "(see 'ashx container build --help')" in text, text
    assert "'ashx container --help'" not in text, text
    assert scans == []


def test_a_root_option_reaches_the_leaf_of_a_group_that_is_not_container(monkeypatch):
    """The leaf routing is not specific to ``container``: it applies to every group.

    A root option before ``config get`` that ``get`` does not take is refused naming
    'config get', the command the operator would type, never the group alone.
    """
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    result = _invoke("--scanners", "bandit", "config", "get")

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'ashx config get' does not take --scanners" in text, text
    assert "(see 'ashx config get --help')" in text, text
