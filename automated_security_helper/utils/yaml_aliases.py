# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A YAML loader that refuses an alias inside the node it names.

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
before. Imports only yaml.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, Set, cast

import yaml
from yaml.composer import ComposerError

if TYPE_CHECKING:
    from yaml.error import Mark


class RecursiveAliasError(ComposerError):
    """A YAML alias inside the node it names: the document never ends.

    The problem mark is the alias, the context mark the anchor it names. The
    class name is what a config refusal shows of a parse error (with its
    place), so it says what was found.
    """


class NoRecursiveAliasLoader(yaml.SafeLoader):
    """``yaml.SafeLoader``, refusing a recursive alias (RecursiveAliasError)
    while composing.

    The anchors of the nodes being composed are the open ones; an alias to one
    of them is inside the node it names. PyYAML refuses a duplicate anchor in a
    document, so an anchor name stands for one node.
    """

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
            return super().compose_node(parent, index)
        anchor = event.anchor
        if anchor is None:
            return super().compose_node(parent, index)
        open_anchors.add(anchor)
        try:
            return super().compose_node(parent, index)
        finally:
            open_anchors.discard(anchor)
