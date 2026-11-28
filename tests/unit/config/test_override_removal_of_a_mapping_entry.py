"""A ``-=`` item that is a mapping removes the list entries it names by their keys.

``apply_config_overrides`` edits ``config.model_dump()``, which gives every entry of
``global_settings.ignore_paths`` all of its fields, the two a config file leaves to
their defaults included (``expires`` and ``client_supplied``). An operator writes an
entry as the file does, with ``path`` and ``reason``. So a mapping item removes each
entry that holds every key the item names with an equal value, without spelling the
fields the operator never wrote. An item whose value differs on a key it names keeps
the entry, and an empty mapping names no entry.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides

pytestmark = pytest.mark.unit

KEY = "global_settings.ignore_paths"

#: Two ignore paths as a config file writes them.
WRITTEN = (
    {"path": "dist/**", "reason": "build output"},
    {"path": "build/**", "reason": "build output"},
)

#: The first entry with every field the dump gives it, its defaults included.
EVERY_FIELD = (
    '{"path": "dist/**", "reason": "build output", "expires": null, '
    '"client_supplied": false}'
)


def _config() -> AshConfig:
    """A configuration holding WRITTEN, as loading a file that writes it gives."""
    return AshConfig(
        global_settings={"ignore_paths": [dict(entry) for entry in WRITTEN]}
    )


def _paths(config: AshConfig) -> list:
    """The paths of the configuration's ignore entries, in order."""
    return [entry.path for entry in config.global_settings.ignore_paths]


@pytest.mark.parametrize(
    ("item", "kept"),
    [
        ('{"path": "dist/**", "reason": "build output"}', ["build/**"]),
        ('{"path": "dist/**"}', ["build/**"]),
        (EVERY_FIELD, ["build/**"]),
        ('{"path": "dist/**", "reason": "other"}', ["dist/**", "build/**"]),
        ("{}", ["dist/**", "build/**"]),
    ],
    ids=["as-written", "path-only", "every-field", "other-reason", "empty-mapping"],
)
def test_a_mapping_item_removes_the_entries_it_names(item, kept):
    """``as-written`` and ``path-only`` name fewer keys than the dumped entry holds,
    so they pass only when the match reads the item's keys; ``every-field`` is the
    equal entry; ``other-reason`` and ``empty-mapping`` name no entry."""
    config = apply_config_overrides(
        _config(), [f"{KEY}-=[{item}]"], warn_unread_appends=True
    )

    assert _paths(config) == kept


def test_an_append_of_a_mapping_entry_still_adds_it():
    """Control: a ``+=`` of an entry adds it as before, so a removal row that fails
    at the base fails on its operator, not on this file's configuration."""
    config = apply_config_overrides(
        _config(),
        [f'{KEY}+=[{{"path": "out/**", "reason": "build output"}}]'],
        warn_unread_appends=True,
    )

    assert _paths(config) == ["dist/**", "build/**", "out/**"]


def test_the_dump_an_override_edits_holds_the_fields_the_file_left_out():
    """Control: the dump gives a written entry its ``expires`` and
    ``client_supplied`` defaults. While it does, an item spelled as the file writes
    an entry differs from the entry it names, and the ``as-written`` and
    ``path-only`` rows tell a match by the item's keys from a match by equality."""
    entry = _config().model_dump()["global_settings"]["ignore_paths"][0]

    assert entry["path"] == "dist/**"
    assert {"expires", "client_supplied"} <= set(entry)
    assert entry != {"path": "dist/**", "reason": "build output"}
