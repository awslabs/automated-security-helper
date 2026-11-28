"""``-=`` never empties a scanner selection.

``default_scanners.only`` and ``precommit.only_scanners`` narrow a run to the
scanners they name. Empty, each is no selection: the mode's default set runs, which
outside precommit mode is every enabled scanner. A ``-=`` that took the last name
out of one would turn a run narrowed to some scanners into a run of the default set,
the scanners the removal took out included, with no word. The application that
builds a command's own configuration (``warn_unread_appends=True``) refuses it,
naming the replace form, as the command line refuses an exclusion that cancels the
selection it applies to.

The empty value is the default, not a value that names every scanner, so every
other edit is applied as written: a removal that leaves a name, and ``+=`` onto the
empty list, which writes the names it lists. A replay of the same overrides onto
another base (a view, a gate) applies the emptying removal as written, as a replay
applies every removal.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

#: The two selection lists, by override key.
SELECTIONS = [
    pytest.param("default_scanners.only", id="default-scanners-only"),
    pytest.param("precommit.only_scanners", id="precommit-only-scanners"),
]


def _selection(key: str, overrides: list[str], own_configuration: bool) -> list[str]:
    """The list at *key* after *overrides*, each written as ``{key}{override}``."""
    config = apply_config_overrides(
        AshConfig(),
        [f"{key}{override}" for override in overrides],
        warn_unread_appends=own_configuration,
    )
    section, option = key.split(".")
    return list(getattr(getattr(config, section), option))


@pytest.mark.parametrize("key", SELECTIONS)
def test_a_removal_that_would_empty_a_scanner_selection_is_refused(key):
    """The first override narrows the run to detect-secrets. Taking that name out
    would leave the list empty, and the run would execute the mode's default
    scanners, detect-secrets among them. The run's own build refuses the removal and
    names the replace form."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _selection(
            key,
            ['=["detect-secrets"]', '-=["detect-secrets"]'],
            own_configuration=True,
        )

    text = str(refused.value)
    assert "would leave" in text, text
    assert f"'{key}=[...]'" in text, text


@pytest.mark.parametrize("key", SELECTIONS)
@pytest.mark.parametrize(
    ("overrides", "own_configuration", "expected"),
    [
        pytest.param(
            ['=["bandit", "detect-secrets"]', '-=["detect-secrets"]'],
            True,
            ["bandit"],
            id="removal-leaving-a-name",
        ),
        pytest.param(['+=["bandit"]'], True, ["bandit"], id="append-onto-empty"),
        pytest.param(
            ['=["detect-secrets"]', '-=["detect-secrets"]'],
            False,
            [],
            id="replayed-emptying-removal",
        ),
    ],
)
def test_every_other_edit_of_a_scanner_selection_is_applied(
    key, overrides, own_configuration, expected
):
    """Control: only the emptying removal is refused, and only in the run's own
    build. The removal takes the name out, the append writes the name it lists, and
    the replay leaves the list empty."""
    assert _selection(key, overrides, own_configuration) == expected
