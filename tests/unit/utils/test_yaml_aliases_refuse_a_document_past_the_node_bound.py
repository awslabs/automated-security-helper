# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""NoRecursiveAliasLoader refuses a document that holds too many nodes.

The alias bound counts only what aliases add, so a document with no alias was
composed without limit: a file of ``- 1`` lines becomes a node for each line,
and a node costs two marks and an event, many times the bytes that wrote it.
The config readers cap a file's bytes, which keeps their documents far under
any node bound, but the loader states no byte bound of its own. It now counts
the nodes composed in place (an alias adds none) and refuses at the first one
past MAX_COMPOSED_NODES, as a composer error, so a caller refuses the file as
one that does not parse and never builds the rest of it.

The bound is read through the module and patched low, as the alias bound's tests
do, so the cases stay a few lines long.
"""

from __future__ import annotations

import pytest
import yaml
from yaml.composer import ComposerError

from automated_security_helper.utils import yaml_aliases
from automated_security_helper.utils.yaml_aliases import NoRecursiveAliasLoader

pytestmark = pytest.mark.unit


def _plain_items(count: int) -> str:
    """A mapping of one sequence of ``count`` scalars: ``count`` + 3 nodes."""
    return "items:\n" + "".join(f"  - {n}\n" for n in range(count))


#: Ten nodes composed in place (the mapping, two keys, two sequences and five
#: scalars) and five aliases, which add none to the count.
ALIASED = "base: &base [1, 2, 3, 4, 5]\nuse: [*base, *base, *base, *base, *base]\n"


def test_a_plain_document_past_the_bound_is_refused_while_composing(monkeypatch):
    monkeypatch.setattr(yaml_aliases, "MAX_COMPOSED_NODES", 20)

    with pytest.raises(yaml_aliases.DocumentSizeError) as refused:
        yaml.load(_plain_items(18), Loader=NoRecursiveAliasLoader)  # 21 nodes

    assert isinstance(refused.value, ComposerError)
    assert "past 20 nodes" in str(refused.value), str(refused.value)
    assert refused.value.problem_mark is not None


def test_a_plain_document_at_the_bound_still_loads(monkeypatch):
    monkeypatch.setattr(yaml_aliases, "MAX_COMPOSED_NODES", 20)

    loaded = yaml.load(_plain_items(17), Loader=NoRecursiveAliasLoader)  # 20 nodes

    assert len(loaded["items"]) == 17


def test_an_alias_is_not_counted_as_a_node_composed_in_place(monkeypatch):
    # The alias bound is its own: ten nodes composed, thirty once the five
    # aliases are written out, and this bound counts the ten.
    monkeypatch.setattr(yaml_aliases, "MAX_COMPOSED_NODES", 10)

    loaded = yaml.load(ALIASED, Loader=NoRecursiveAliasLoader)
    assert loaded["use"][0] is loaded["base"]

    monkeypatch.setattr(yaml_aliases, "MAX_COMPOSED_NODES", 9)
    with pytest.raises(yaml_aliases.DocumentSizeError):
        yaml.load(ALIASED, Loader=NoRecursiveAliasLoader)


def test_the_bound_counts_each_document_of_a_stream_on_its_own(monkeypatch):
    monkeypatch.setattr(yaml_aliases, "MAX_COMPOSED_NODES", 12)

    loaded = list(
        yaml.load_all("---\n".join([ALIASED] * 3), Loader=NoRecursiveAliasLoader)
    )

    assert [len(found["use"]) for found in loaded] == [5, 5, 5]
    # The patched bound is live: the three documents' thirty nodes in one
    # document are refused under it.
    with pytest.raises(yaml_aliases.DocumentSizeError):
        yaml.load(_plain_items(27), Loader=NoRecursiveAliasLoader)  # 30 nodes


def test_the_default_bound_sits_above_what_the_alias_bound_lets_a_plain_file_hold():
    # A plain file of MAX_EXPANDED_NODES + 1 scalars loads (the alias bound's own
    # test); this bound stays above it, and above the most a file the config
    # chain reads can hold (1 MiB, two bytes to a flow scalar).
    assert yaml_aliases.MAX_COMPOSED_NODES > yaml_aliases.MAX_EXPANDED_NODES + 4
    assert yaml_aliases.MAX_COMPOSED_NODES > (1024 * 1024) // 2
