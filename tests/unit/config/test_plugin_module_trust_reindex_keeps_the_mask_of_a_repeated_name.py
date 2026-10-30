# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plain ``ash_plugin_modules`` entry that spells a module name does not take
the reference of an environment-read entry that follows it with the same value.

``reindex_plugin_module_references`` and ``_carry_trusted_module_references``
keep one reference per kept name: a name two entries both read is carried once,
from the first entry that reads it. A plain entry earlier in the list that
happens to spell the same name used to claim the name first, so the
environment-read entry after it lost its reference and the name was shown in
clear, although ``shown_module_names`` masks a name any entry read from the
environment. Only an entry that carries a reference claims a name now.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Tuple

import pytest

from tests.unit.config._plugin_module_helpers import (
    INSTALLED,
    SEC_ONE,
    entries_file as _entries_file,
    plant_site_and_environment,
    resolved_config as _resolved_config,
)

pytestmark = pytest.mark.unit

_LISTS = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return plant_site_and_environment(tmp_path, monkeypatch)


def _module_references(config, attribute: str) -> List[Any]:
    return [
        reference
        for reference in (getattr(config, attribute, ()) or ())
        if tuple(reference.path[:1]) == ("ash_plugin_modules",)
    ]


def _places(references: List[Any]) -> List[Tuple[Any, ...]]:
    return [tuple(reference.path[:2]) for reference in references]


def test_reindex_keeps_the_reference_of_a_read_entry_after_a_plain_entry_of_the_name(
    root: Path,
):
    """The file writes the name, then reads it from the environment. After a
    caller keeps the one name, the read entry's reference stands at the kept
    index in every list; before, the plain entry took the name and the read
    entry's reference was dropped."""
    from automated_security_helper.config.plugin_module_trust import (
        reindex_plugin_module_references,
    )

    config = _resolved_config(
        _entries_file(root / "plain-then-read.yaml", [SEC_ONE, "${ASH_RECV_ONE}"])
    )
    entries_as_written = list(config.ash_plugin_modules)
    assert entries_as_written == [SEC_ONE, SEC_ONE], entries_as_written
    before = {attribute: _module_references(config, attribute) for attribute in _LISTS}
    # The premise: the environment read sits at the second entry.
    assert _places(before["_environment_references"]) == [("ash_plugin_modules", 1)]
    config.ash_plugin_modules = [SEC_ONE]

    reindex_plugin_module_references(
        config, entries_as_written, config.ash_plugin_modules
    )

    for attribute, held in before.items():
        if not held:
            continue
        after = _module_references(config, attribute)
        assert _places(after) == [("ash_plugin_modules", 0)], (attribute, after)


def test_carry_keeps_the_reference_of_a_trusted_read_entry_after_a_plain_entry(
    root: Path,
):
    """The same rule for the trusted-base carry: the trusted file writes the
    name and then reads it from the environment, and the reference is carried
    to the name's index in the merged list."""
    from automated_security_helper.config.plugin_module_trust import (
        _carry_trusted_module_references,
    )

    trusted = _resolved_config(
        _entries_file(root / "trusted.yaml", [SEC_ONE, "${ASH_RECV_ONE}"])
    )
    assert list(trusted.ash_plugin_modules) == [SEC_ONE, SEC_ONE]
    assert _places(_module_references(trusted, "_environment_references")) == [
        ("ash_plugin_modules", 1)
    ]

    config = _resolved_config(_entries_file(root / "client.yaml", [INSTALLED]))
    loaded = [INSTALLED, SEC_ONE]
    config.ash_plugin_modules = list(loaded)

    _carry_trusted_module_references(config, trusted, loaded)

    carried = _module_references(config, "_environment_references")
    assert _places(carried) == [("ash_plugin_modules", 1)], carried
