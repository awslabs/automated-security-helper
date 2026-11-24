# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``sandbox_grants.checkout_judgment`` answers each shared layout the way the wrappers expect.

``./ash`` and ``Invoke-ASH`` carry ports of the checkout judgment, and the tests of the
wrappers and of container mode hold all three to the layouts in
``tests/utils/config_link_layouts.py``. Those tests assert what a route does with a
layout (which flag it passes, whether it refuses); this one pins the judgment they all
rest on, so a change to the judgment fails here by branch name before it shows up as a
disagreement between three implementations.

One row per branch of ``checkout_judgment``:

* a file the host marked as the scanned repository's, or as in another checkout;
* a name or a link that sits in a checkout (every layout in the shared tables);
* a name that follows no link into any checkout (the control layout, and a plain file);
* a walk that never finished (a loop of links), judged as in a checkout and reported
  as undecided.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.sandbox_grants import (
    checkout_judgment,
    marked_files_in_another_checkout,
    marked_files_repository_written,
)
from tests.utils.config_link_layouts import (
    LINKED_LAYOUTS,
    LINKS_OUTSIDE_EVERY_CHECKOUT,
    NAMES_STEERED_BY_THE_SCANNED_CHECKOUT,
    config_through_links,
)
from tests.utils.helpers import link_walk_cannot_examine, mark_git_checkout

pytestmark = pytest.mark.unit


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "repo"
    (root / "ci").mkdir(parents=True)
    mark_git_checkout(root)
    return root


@pytest.mark.parametrize(
    "layout", [*LINKED_LAYOUTS, *NAMES_STEERED_BY_THE_SCANNED_CHECKOUT]
)
def test_a_name_that_follows_a_link_in_a_checkout_is_judged_in_one(
    layout, checkout, tmp_path
):
    config = config_through_links(layout, checkout, tmp_path)

    judgment = checkout_judgment(config)

    assert (judgment.verdict, judgment.decided) == (True, True), layout


def test_control_links_outside_every_checkout_are_judged_outside_all(
    checkout, tmp_path
):
    config = config_through_links(LINKS_OUTSIDE_EVERY_CHECKOUT, checkout, tmp_path)

    judgment = checkout_judgment(config)

    assert (judgment.verdict, judgment.decided) == (False, True)


def test_a_plain_file_in_a_checkout_is_judged_in_one(checkout):
    config = checkout / "ci" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    assert checkout_judgment(config).verdict is True


def test_control_a_plain_file_outside_every_checkout_is_judged_outside(tmp_path):
    config = tmp_path / "operator" / "ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: p\n", encoding="utf-8")

    judgment = checkout_judgment(config)

    assert (judgment.verdict, judgment.decided) == (False, True)


def test_a_walk_that_never_finishes_is_judged_in_a_checkout_and_undecided(
    tmp_path, monkeypatch
):
    """A component the walk cannot examine may be a link nobody here can see, so the
    links beyond it were never seen and one in a checkout cannot be ruled out."""
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    refused = link_walk_cannot_examine(monkeypatch, unreadable)

    judgment = checkout_judgment(unreadable / "ash.yaml")

    assert refused.asked, "the walk never asked about the component"
    assert (judgment.verdict, judgment.decided) == (True, False)


def test_a_file_the_host_marked_is_judged_in_a_checkout_wherever_it_is(tmp_path):
    config = tmp_path / "operator" / "ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: p\n", encoding="utf-8")
    assert checkout_judgment(config).verdict is False

    with marked_files_repository_written([config]):
        assert (
            checkout_judgment(config).verdict,
            checkout_judgment(config).decided,
        ) == (
            True,
            True,
        )
    with marked_files_in_another_checkout([config]):
        assert (
            checkout_judgment(config).verdict,
            checkout_judgment(config).decided,
        ) == (
            True,
            True,
        )
    assert checkout_judgment(config).verdict is False
