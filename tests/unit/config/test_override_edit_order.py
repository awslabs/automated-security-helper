"""``--config-overrides`` edits of one list apply in the order they are written.

``KEY=[...]`` replaces the list, ``KEY+=[...]`` adds to its end and ``KEY-=[...]``
takes every occurrence of each item out of it. Each override edits the list the
overrides before it left, and the configuration is validated once, after the last
one: a list may be empty between two overrides, and only the list the last one
leaves has to be valid. A removal is an edit at its place in the order, not a filter
on what comes after it, so an item a later override adds or writes again stays.

trivy's ``scanners`` is the option these cases edit: it is typed, its default is
``["vuln"]``, and it holds at least one item.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides

pytestmark = pytest.mark.unit

KEY = "scanners.trivy.options.scanners"


def _trivy_scanners(config: AshConfig) -> list[str]:
    """The scanners the configuration gives trivy."""
    return list(config.scanners.trivy.options.scanners)


def test_a_removal_then_an_append_of_the_same_item_keeps_one():
    """The removal takes ``vuln`` out, and the append after it puts one back, at
    the end."""
    config = apply_config_overrides(
        AshConfig(),
        [f'{KEY}=["vuln", "secret"]', f'{KEY}-=["vuln"]', f'{KEY}+=["vuln"]'],
    )

    assert _trivy_scanners(config) == ["secret", "vuln"]


def test_an_append_then_a_removal_of_the_same_item_takes_every_copy():
    """The append leaves ``vuln`` in the list twice, and the removal after it takes
    both."""
    config = apply_config_overrides(
        AshConfig(),
        [f'{KEY}=["vuln", "secret"]', f'{KEY}+=["vuln"]', f'{KEY}-=["vuln"]'],
    )

    assert _trivy_scanners(config) == ["secret"]


@pytest.mark.parametrize(
    "own_configuration", [True, False], ids=["own-build", "replay"]
)
def test_a_list_emptied_between_two_overrides_is_not_refused(own_configuration):
    """The removal leaves the default empty and the append after it fills it again.
    The option holds at least one item, but only the list the last override leaves
    is validated, so nothing is refused: not in the application that builds the
    run's own configuration, which is the one that refuses, and not in a replay."""
    config = apply_config_overrides(
        AshConfig(),
        [f'{KEY}-=["vuln"]', f'{KEY}+=["secret"]'],
        warn_unread_appends=own_configuration,
    )

    assert _trivy_scanners(config) == ["secret"]


def test_a_replacement_after_a_removal_wins():
    """The removal takes ``vuln`` out of the default, and the replacement after it
    writes the whole list again, ``vuln`` included: a removal does not reach past
    the overrides that follow it."""
    config = apply_config_overrides(
        AshConfig(), [f'{KEY}-=["vuln"]', f'{KEY}=["vuln", "license"]']
    )

    assert _trivy_scanners(config) == ["vuln", "license"]


def test_the_same_removal_twice_is_the_same_as_once():
    """The second removal finds no ``secret`` left and changes nothing: an item the
    list does not hold is not refused."""
    written = f'{KEY}=["vuln", "secret", "misconfig"]'

    once = apply_config_overrides(AshConfig(), [written, f'{KEY}-=["secret"]'])
    twice = apply_config_overrides(
        AshConfig(), [written, f'{KEY}-=["secret"]', f'{KEY}-=["secret"]']
    )

    assert _trivy_scanners(once) == ["vuln", "misconfig"]
    assert _trivy_scanners(twice) == _trivy_scanners(once)


def test_a_replacement_after_an_append_wins():
    """Control: ``+=`` then ``=`` leaves the replacement alone, before the removal
    form exists and after it, so the cases above measure the removal and not the
    order the overrides apply in."""
    config = apply_config_overrides(
        AshConfig(), [f'{KEY}+=["secret"]', f'{KEY}=["license"]']
    )

    assert _trivy_scanners(config) == ["license"]


def test_an_append_after_a_replacement_adds_to_it():
    """Control: ``=`` then ``+=`` adds to the list the replacement wrote, not to the
    default, before the change and after it."""
    config = apply_config_overrides(
        AshConfig(), [f'{KEY}=["secret"]', f'{KEY}+=["license"]']
    )

    assert _trivy_scanners(config) == ["secret", "license"]
