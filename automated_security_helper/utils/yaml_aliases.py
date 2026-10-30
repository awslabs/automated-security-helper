# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A YAML loader that refuses an alias inside the node it names, and a document
whose aliases expand past a bound.

YAML lets an alias name any anchor already seen, including one whose node is
still open, and PyYAML builds that as a mapping or a list that contains itself.
A configuration is a tree, so such a document is never a configuration, and
every walk of a loaded document (the record of what a file read from the
environment, the ``extends`` merge, the model's validation) recursed through it
until Python's recursion limit, which surfaced as a raw RecursionError instead
of the refusal any other malformed file gets. :class:`NoRecursiveAliasLoader`,
the base of a config loader, raises :class:`RecursiveAliasError`, a YAML
composer error, while the document is composed, before anything is constructed
or walked, so every caller refuses it as a file that does not parse. An alias
of a node that is already complete is a shared value, not a cycle, and loads as
before.

A shared value can still be too much: a few hundred bytes of nested anchors,
each level aliasing the level below several times, load as a small shared graph
whose every walk writes out a tree exponential in the depth. The loader counts,
while composing, how many nodes its aliases add once each is written out in its
place (the excess of the written-out document over the composed one), and raises
:class:`AliasExpansionError`, a composer error too, at the first alias past
:data:`MAX_EXPANDED_NODES`, so the cost of such a file is its read, never its
product. A large document with no alias is not refused here. Imports only yaml.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, Set, cast

import yaml
from yaml.composer import ComposerError

if TYPE_CHECKING:
    from yaml.error import Mark

#: The most nodes the aliases of a document may add once each is written out in
#: its place: mappings, sequences and scalars alike. Only the excess over the
#: document as composed is counted, so a large document with no alias, or few,
#: loads (its cost is its read), while one whose aliases multiply is refused. A
#: configuration a scan can use sits orders of magnitude below it. The config
#: chain's expansion budget (config_sources.refuse_past_expansion_bound) counts
#: the loaded places and does not tell the two apart.
MAX_EXPANDED_NODES = 100_000

#: The attribute the expanded node count is kept on, on each composed node.
_SIZE_ATTR = "_ash_expanded_nodes"


class RecursiveAliasError(ComposerError):
    """A YAML alias inside the node it names: the document never ends.

    The problem mark is the alias, the context mark the anchor it names. The
    class name is what a config refusal shows of a parse error (with its
    place), so it says what was found.
    """


class AliasExpansionError(ComposerError):
    """A document whose aliases, written out, hold more nodes than the bound.

    The problem mark is the alias that took the document past the bound. As for
    RecursiveAliasError, the class name is what a config refusal shows.
    """


class NoRecursiveAliasLoader(yaml.SafeLoader):
    """``yaml.SafeLoader``, refusing a recursive alias (RecursiveAliasError) and
    a document whose aliases expand past the bound (AliasExpansionError) while
    composing.

    The anchors of the nodes being composed are the open ones; an alias to one
    of them is inside the node it names. PyYAML refuses a duplicate anchor in a
    document, so an anchor name stands for one node. Each composed node is given
    its expanded size, one plus its children's, where an alias counts as the
    whole of the node it names; the running total of what the aliases add is
    checked as each alias is taken.
    """

    def compose_document(self) -> Any:
        # The bound is per document. One loader composes every document of a
        # yaml.load_all stream, so a total kept across documents refused a stream
        # whose documents each sit under the bound.
        self.__dict__["_ash_aliased_total"] = 0
        return super().compose_document()

    def compose_node(self, parent: Any, index: Any) -> Any:
        open_anchors: Set[str] = self.__dict__.setdefault("_ash_open_anchors", set())
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent):
            if event.anchor in open_anchors:
                # The stubs type an event's mark for the C parser too
                # (yaml._yaml.Mark), but this method only runs in the
                # pure-Python composer -- the C loaders compose in C and
                # never call it -- so the mark here is yaml.error.Mark
                # (measured: the C loader has no Python compose_node, and
                # this error's problem_mark is yaml.error.Mark).
                raise RecursiveAliasError(
                    "while composing the node this anchor names",
                    self.anchors[event.anchor].start_mark,
                    "found an alias to it inside it",
                    cast("Optional[Mark]", event.start_mark),
                )
            node = super().compose_node(parent, index)
            self._charge_expansion(getattr(node, _SIZE_ATTR, 1), event.start_mark)
            return node
        anchor = event.anchor
        if anchor is None:
            return self._sized(super().compose_node(parent, index))
        open_anchors.add(anchor)
        try:
            return self._sized(super().compose_node(parent, index))
        finally:
            open_anchors.discard(anchor)

    def _sized(self, node: Any) -> Any:
        """*node*, with its expanded size recorded: one plus its children's."""
        size = 1
        if isinstance(node, yaml.SequenceNode):
            size += sum(getattr(child, _SIZE_ATTR, 1) for child in node.value)
        elif isinstance(node, yaml.MappingNode):
            size += sum(
                getattr(key, _SIZE_ATTR, 1) + getattr(value, _SIZE_ATTR, 1)
                for key, value in node.value
            )
        setattr(node, _SIZE_ATTR, size)
        return node

    def _charge_expansion(self, size: int, mark: Any) -> None:
        """Count *size* nodes, the whole of the node an alias names, against the bound.

        Only what aliases add is counted: a node composed in place costs the
        read of the text that wrote it, and a document with no alias, however
        large, holds nothing an alias multiplied. Each alias adds the whole of the
        node it names, nested aliases in it included, so the total is the excess
        of the document written out over the document as it was composed. The
        check runs as each is counted, so the composer stops at the first alias
        past the bound and never builds the rest.
        """
        total = self.__dict__.get("_ash_aliased_total", 0) + size
        self.__dict__["_ash_aliased_total"] = total
        if total > MAX_EXPANDED_NODES:
            raise AliasExpansionError(
                "while composing the document",
                None,
                f"found an alias that takes the document past {MAX_EXPANDED_NODES} "
                "nodes written out in place of its aliases (each alias counted as "
                "the nodes it names)",
                cast("Optional[Mark]", mark),
            )
