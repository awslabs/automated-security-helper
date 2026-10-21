# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An error added to a results container after it is built reaches the saved row.

The results row is dumped with ``exclude_unset=True``, and appending into a
field's default list never marks the field as set, so an error appended after the
container was built was silently left out of the saved results. ``add_error``
reassigns the list instead of appending into it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)


@pytest.fixture
def pinned_home(monkeypatch, tmp_path):
    """A home directory the cell controls, read per call by ``usable_home``.

    The runner's own home is no fixture: with ``HOME=/`` the rewrite deliberately
    does nothing (replacing the root would rewrite every absolute path), and on
    Windows the posix spelling differs, so these cells would turn on the host
    rather than on the rule."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def test_an_error_added_after_the_container_is_built_is_in_its_dump():
    container = ScanResultsContainer(scanner_name="scripted")

    container.add_error("no rule was evaluated against app.yaml")

    dumped = container.model_dump(exclude_unset=True)
    assert dumped.get("errors") == ["no rule was evaluated against app.yaml"], dumped


def test_a_second_error_and_a_duplicate_keep_the_recorded_list():
    container = ScanResultsContainer(scanner_name="scripted")

    container.add_error("first")
    container.add_error("second")
    container.add_error("first")

    dumped = container.model_dump(exclude_unset=True)
    assert dumped.get("errors") == ["first", "second"], dumped


def test_an_error_naming_the_home_directory_is_saved_with_a_tilde(pinned_home):
    """These errors go into the results and reports rather than ash.log, so the
    home directory in an error's text is written as ``~``, as the row's
    missing_reason already writes it beside them.

    Read from the field itself, so the cell turns on the tilde alone and not on
    whether the dump keeps an appended error (the cells above pin that)."""
    container = ScanResultsContainer(scanner_name="scripted")

    container.add_error(f"refused to read {pinned_home.as_posix()}/project/app.py")

    assert container.errors == ["refused to read ~/project/app.py"], container.errors


def test_an_error_given_at_construction_is_saved_with_a_tilde(pinned_home):
    """Some call sites build a container with ``errors=`` directly (a plugin
    module that failed to load, a scanner that could not be constructed), and
    those texts come from exception messages that can name files under the home
    directory. A validator applies the same rule add_error does, so the error
    reaches the saved results without the host-specific prefix whichever way it
    arrives."""
    container = ScanResultsContainer(
        scanner_name="scripted",
        errors=[f"could not import {pinned_home.as_posix()}/plugin.py"],
    )

    dumped = container.model_dump(exclude_unset=True)
    assert dumped.get("errors") == ["could not import ~/plugin.py"], dumped


def test_set_exception_saves_its_text_and_stack_trace_with_a_tilde(pinned_home):
    """set_exception's two fields persist in the saved results like the errors
    list, and a stack trace names files by their full paths, so a home
    directory in either is written as a tilde."""
    container = ScanResultsContainer(scanner_name="scripted")
    home = pinned_home.as_posix()
    try:
        raise OSError(f"cannot read {home}/project/.npmrc")
    except OSError as error:
        container.set_exception(error)

    dumped = container.model_dump(exclude_unset=True)
    assert "~/project/.npmrc" in (dumped.get("exception") or ""), dumped.get(
        "exception"
    )
    assert home not in (dumped.get("exception") or ""), dumped.get("exception")
    assert "~/project/.npmrc" in (dumped.get("stack_trace") or ""), dumped.get(
        "stack_trace"
    )
    assert home not in (dumped.get("stack_trace") or ""), dumped.get("stack_trace")


def test_exception_and_stack_trace_given_at_construction_are_tilded(pinned_home):
    """The constructor path gets the same rule set_exception applies, as the
    errors field already does."""
    home = pinned_home.as_posix()
    container = ScanResultsContainer(
        scanner_name="scripted",
        exception=f"OSError: cannot read {home}/project/.npmrc",
        stack_trace=f'  File "{home}/project/plugin.py", line 1\n',
    )

    dumped = container.model_dump(exclude_unset=True)
    assert dumped.get("exception") == "OSError: cannot read ~/project/.npmrc", dumped
    assert dumped.get("stack_trace") == '  File "~/project/plugin.py", line 1\n', dumped


def test_metadata_added_after_the_container_is_built_is_in_its_dump():
    """add_metadata written into the field's default dict never marks the field
    set, and the row is dumped with ``exclude_unset=True``, so metadata added
    after construction was dropped exactly as appended errors were."""
    container = ScanResultsContainer(scanner_name="scripted")

    container.add_metadata("staged_as", "app.yaml")

    dumped = container.model_dump(exclude_unset=True)
    assert dumped.get("metadata") == {"staged_as": "app.yaml"}, dumped
