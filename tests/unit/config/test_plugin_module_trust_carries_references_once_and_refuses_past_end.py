# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trusted-base carry of ``ash_plugin_modules`` references follows the
reindex rule.

``_carry_trusted_module_references`` moves the trusted config's environment
references onto the merged list. Before this change it walked the trusted
references on its own: a name two trusted entries both read was carried once
per entry, so the record held two rewrites at one index, and a reference past
the end of the trusted list was dropped where ``reindex_plugin_module_references``
refuses it. The carry now rebuilds through the same rule the reindex uses
(``_remapped_module_reference_lists``), and these checks hold the three
consequences: one reference per kept name, a refusal that leaves the config as
it was, and distinct entries still carried.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from tests.unit.config._plugin_module_helpers import (
    INSTALLED,
    SEC_ONE,
    SEC_TWO,
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


def _snapshot(config) -> Dict[str, tuple]:
    return {
        attribute: tuple(getattr(config, attribute, ()) or ()) for attribute in _LISTS
    }


def test_a_name_two_trusted_entries_read_is_carried_once(root: Path):
    """Two trusted entries read the same variable. The merged list holds the
    name once, so each reference list gains ONE reference at that index, the
    count the reindex leaves for the same shape (its seen-skip)."""
    from automated_security_helper.config.plugin_module_trust import (
        _carry_trusted_module_references,
    )

    trusted = _resolved_config(
        _entries_file(root / "trusted.yaml", ["${ASH_RECV_ONE}", "${ASH_RECV_ONE}"])
    )
    assert list(trusted.ash_plugin_modules) == [SEC_ONE, SEC_ONE]
    for attribute in _LISTS:
        assert len(_module_references(trusted, attribute)) == 2, attribute

    config = _resolved_config(_entries_file(root / "client.yaml", [INSTALLED]))
    loaded = [INSTALLED, SEC_ONE]
    config.ash_plugin_modules = list(loaded)

    _carry_trusted_module_references(config, trusted, loaded)

    for attribute in _LISTS:
        carried = _module_references(config, attribute)
        assert len(carried) == 1, (attribute, carried)
        assert tuple(carried[0].path[:2]) == ("ash_plugin_modules", 1), carried


def test_a_literal_spelling_before_the_read_entry_does_not_drop_its_reference(
    root: Path,
):
    """The trusted list names the module literally first and reads it from the
    environment second. Only the second entry carries a reference; the carry
    takes the duplicated name from the entry a reference names, so the kept
    name keeps its one reference rather than losing it to the literal entry."""
    from automated_security_helper.config.plugin_module_trust import (
        _carry_trusted_module_references,
    )

    trusted = _resolved_config(
        _entries_file(root / "trusted.yaml", [SEC_ONE, "${ASH_RECV_ONE}"])
    )
    assert list(trusted.ash_plugin_modules) == [SEC_ONE, SEC_ONE]
    for attribute in _LISTS:
        references = _module_references(trusted, attribute)
        assert [reference.path[1] for reference in references] == [1], attribute

    config = _resolved_config(_entries_file(root / "client.yaml", [INSTALLED]))
    loaded = [INSTALLED, SEC_ONE]
    config.ash_plugin_modules = list(loaded)

    _carry_trusted_module_references(config, trusted, loaded)

    for attribute in _LISTS:
        carried = _module_references(config, attribute)
        assert len(carried) == 1, (attribute, carried)
        assert tuple(carried[0].path[:2]) == ("ash_plugin_modules", 1), carried


def test_a_trusted_reference_past_the_trusted_list_refuses_the_carry(root: Path):
    """A trusted reference recorded past the end of the trusted list names no
    entry. The carry refuses it as the reindex does, before touching any list
    on the receiving config."""
    from automated_security_helper.config.plugin_module_trust import (
        PluginModuleReferenceError,
        _carry_trusted_module_references,
    )

    trusted = _resolved_config(
        _entries_file(root / "trusted.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    assert list(trusted.ash_plugin_modules) == [INSTALLED, SEC_ONE]
    # The read's reference sits at index 1; a one-entry trusted list leaves
    # it past the end.
    trusted.ash_plugin_modules = [INSTALLED]

    config = _resolved_config(_entries_file(root / "client.yaml", [SEC_TWO]))
    loaded = [SEC_TWO, INSTALLED, SEC_ONE]
    config.ash_plugin_modules = list(loaded)
    before = _snapshot(config)

    with pytest.raises(PluginModuleReferenceError, match=r"past the 1 entr") as caught:
        _carry_trusted_module_references(config, trusted, loaded)
    assert not isinstance(caught.value, ValueError), type(caught.value).__mro__
    assert _snapshot(config) == before


def test_a_refused_carry_leaves_the_list_as_it_was_in_the_merge_confinement(
    root: Path,
):
    """The merge swaps the config's list for the trusted one and carries the
    trusted references with it. A trusted reference past the end of the trusted
    list refuses the carry; the refusal used to come after the swap, so the
    config kept the trusted list with none of its references. It now comes
    before any assignment: the list and every reference list stay as they were.
    """
    from automated_security_helper.config.plugin_module_trust import (
        PluginModuleReferenceError,
        confine_plugin_modules,
    )
    from automated_security_helper.config.untrusted_source import SHARD_RECORDED

    trusted = _resolved_config(
        _entries_file(root / "trusted.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    trusted.ash_plugin_modules = [INSTALLED]

    config = _resolved_config(_entries_file(root / "client.yaml", [SEC_TWO]))
    list_before = list(config.ash_plugin_modules)
    before = _snapshot(config)

    with pytest.raises(PluginModuleReferenceError):
        confine_plugin_modules(
            config,
            trusted,
            [],
            root,
            [],
            checkout_membership=False,
            untrusted=True,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
            source=SHARD_RECORDED,
        )

    assert list(config.ash_plugin_modules) == list_before
    assert _snapshot(config) == before


def test_the_carry_plan_refuses_a_past_the_end_reference_without_a_config(root: Path):
    from automated_security_helper.config.plugin_module_trust import (
        PluginModuleReferenceError,
        _carried_module_references,
    )

    trusted = _resolved_config(
        _entries_file(root / "trusted.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    trusted.ash_plugin_modules = [INSTALLED]

    with pytest.raises(PluginModuleReferenceError):
        _carried_module_references(trusted, [SEC_TWO, INSTALLED, SEC_ONE])


def test_distinct_trusted_entries_are_each_carried(root: Path):
    """The contrast: two trusted entries reading two variables carry one
    reference each, at the index the merged list gives each NAME: the merged
    list holds the two names in the reverse of the trusted order, so a carry by
    trusted index would put each variable at the other name's slot."""
    from automated_security_helper.config.plugin_module_trust import (
        _carry_trusted_module_references,
    )

    trusted = _resolved_config(
        _entries_file(root / "trusted.yaml", ["${ASH_RECV_ONE}", "${ASH_RECV_TWO}"])
    )
    assert list(trusted.ash_plugin_modules) == [SEC_ONE, SEC_TWO]

    config = _resolved_config(_entries_file(root / "client.yaml", [INSTALLED]))
    loaded = [INSTALLED, SEC_TWO, SEC_ONE]
    config.ash_plugin_modules = list(loaded)

    _carry_trusted_module_references(config, trusted, loaded)

    for attribute in _LISTS:
        carried = _module_references(config, attribute)
        by_index = {reference.path[1]: reference.written for reference in carried}
        assert by_index == {1: "${ASH_RECV_TWO}", 2: "${ASH_RECV_ONE}"}, (
            attribute,
            carried,
        )
