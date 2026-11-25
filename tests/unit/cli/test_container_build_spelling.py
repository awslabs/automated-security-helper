# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash container build`` is the command; ``ash build-image`` is its 3.8 spelling.

Both run the same image build with the same options. The old spelling prints one
deprecation warning on stderr first and is removed in 4.0; the new one prints
none. The scan the command starts is replaced by a stand-in that records its
arguments, so no image is built.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import deprecation

pytestmark = pytest.mark.unit

WARNING = (
    "Deprecated: 'ash build-image' is deprecated and will be removed in 4.0; "
    "use 'ash container build' instead."
)


@pytest.fixture
def scans(monkeypatch):
    """The scan the build command starts, recorded; and a fresh warned set."""
    calls: list[dict] = []
    monkeypatch.setattr(deprecation, "_warned", set())
    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan",
        lambda **kwargs: calls.append(kwargs),
    )
    return calls


def _invoke(*args: str):
    from automated_security_helper.cli.main import app

    return CliRunner().invoke(app, list(args))


def test_the_new_spelling_builds_and_does_not_warn(scans):
    result = _invoke("container", "build", "--no-run")

    assert result.exit_code == 0, result.output
    assert len(scans) == 1
    assert scans[0]["build"] is True and scans[0]["run"] is False
    assert "Deprecated" not in result.output


def test_the_old_spelling_still_builds_and_warns_once(scans):
    result = _invoke("build-image", "--no-run")

    assert result.exit_code == 0, result.output
    assert len(scans) == 1
    assert scans[0]["build"] is True and scans[0]["run"] is False
    assert result.output.count(WARNING) == 1, result.output


def test_both_spellings_start_the_same_scan(scans):
    _invoke("container", "build", "--no-build", "--force")
    _invoke("build-image", "--no-build", "--force")

    assert len(scans) == 2
    assert scans[0] == scans[1]


def test_the_old_spelling_warns_once_per_process(scans):
    first = _invoke("build-image", "--no-run")
    second = _invoke("build-image", "--no-run")

    assert first.output.count(WARNING) == 1
    assert "Deprecated" not in second.output
    assert len(scans) == 2


def test_the_warning_goes_through_stderr(scans, monkeypatch):
    seen: list[bool] = []
    monkeypatch.setattr(
        deprecation,
        "echo",
        lambda message, err=False, **_: seen.append(err),
    )
    _invoke("build-image", "--no-run")

    assert seen == [True]


def test_the_group_lists_build_in_its_help(scans):
    result = _invoke("container", "--help")

    assert result.exit_code == 0, result.output
    assert "build" in result.output


def test_the_root_help_names_the_group_and_marks_the_old_spelling(scans):
    result = _invoke("--help")

    assert "container" in result.output
    assert "build-image" in result.output
    assert "Deprecated" in result.output


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
