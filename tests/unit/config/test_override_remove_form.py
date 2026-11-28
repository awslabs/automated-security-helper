"""``KEY-=VALUE`` in ``--config-overrides`` removes items from the list KEY holds.

``KEY=[...]`` replaces a list and ``KEY+=[...]`` adds to it. ``KEY-=[a, b]`` takes
every occurrence of each listed item out of it, and ``KEY-=a`` every occurrence of
``a``. On an option no config file wrote, the edit applies to the option's typed
default, as ``+=`` does. The configuration is validated once, after every override,
so a removal that leaves an option shorter than its minimum length is refused as an
invalid configuration.

trivy's ``scanners`` is the option these cases edit: it is typed, its default is
``["vuln"]``, and it holds at least one item.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

KEY = "scanners.trivy.options.scanners"


def _trivy_scanners(config: AshConfig) -> list[str]:
    """The scanners the configuration gives trivy."""
    return list(config.scanners.trivy.options.scanners)


def test_the_typed_default_is_the_one_these_cases_edit():
    """Control: the cases below read ``["vuln"]`` as trivy's default."""
    assert _trivy_scanners(AshConfig()) == ["vuln"]


def test_a_removal_takes_an_item_out_of_the_typed_default():
    """After ``+=["secret"]`` the list is the default and the added item; ``-=`` then
    takes the default's ``vuln`` out of it."""
    config = apply_config_overrides(
        AshConfig(), [f'{KEY}+=["secret"]', f'{KEY}-=["vuln"]']
    )

    assert _trivy_scanners(config) == ["secret"]


def test_a_removal_of_one_item_takes_out_every_occurrence_of_it():
    """``KEY-=item`` names one item without brackets, and removes it wherever the
    list holds it."""
    config = apply_config_overrides(
        AshConfig(),
        [f'{KEY}=["secret", "vuln", "secret"]', f"{KEY}-=secret"],
    )

    assert _trivy_scanners(config) == ["vuln"]


def test_a_removal_of_several_items_takes_out_each_of_them():
    config = apply_config_overrides(
        AshConfig(),
        [
            f'{KEY}=["vuln", "secret", "misconfig", "license"]',
            f'{KEY}-=["secret", "license"]',
        ],
    )

    assert _trivy_scanners(config) == ["vuln", "misconfig"]


def test_a_removal_of_an_item_the_list_does_not_hold_changes_nothing():
    config = apply_config_overrides(AshConfig(), [f'{KEY}-=["license"]'])

    assert _trivy_scanners(config) == ["vuln"]


def test_a_removal_that_empties_a_list_with_a_minimum_length_is_refused():
    """The default holds one item, so removing it alone leaves trivy no scanner to
    run. The result is validated after the overrides, and the option holds at least
    one item, so the configuration is refused there, at the option."""
    with pytest.raises(ASHConfigValidationError) as raised:
        apply_config_overrides(AshConfig(), [f'{KEY}-=["vuln"]'])

    error = raised.value.validation_error
    assert error is not None, str(raised.value)
    too_short = [
        item
        for item in error.errors()
        if item["type"] == "too_short" and "trivy" in [str(p) for p in item["loc"]]
    ]
    assert too_short, [item["type"] for item in error.errors()]


def test_a_removal_beside_another_item_keeps_the_option_valid():
    """Control for the refusal above: ``vuln`` goes when another scanner stays."""
    config = apply_config_overrides(
        AshConfig(), [f'{KEY}+=["license"]', f'{KEY}-=["vuln"]']
    )

    assert _trivy_scanners(config) == ["license"]


def test_a_replacement_and_an_append_are_unchanged():
    """Control: the two forms that exist already keep their meaning."""
    replaced = apply_config_overrides(AshConfig(), [f'{KEY}=["secret"]'])
    appended = apply_config_overrides(AshConfig(), [f'{KEY}+=["secret"]'])

    assert _trivy_scanners(replaced) == ["secret"]
    assert _trivy_scanners(appended) == ["vuln", "secret"]
