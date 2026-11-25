# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""RFC 6902 (JSON Patch) operation names, spelled once.

The values are the RFC's, not ASH's, so these are constants and not an enum:
a mirrored third-party vocabulary is never a place to invent members. What this
module removes is the dozen places that each spelled their own subset of the
six operations. Each subset a config reader tests membership in is named here
for what the subset is, and the readers import it.

Imports nothing from the package, so every config module can use it.
"""

from typing import FrozenSet

#: RFC 6902's six operations, as it spells them.
JSON_PATCH_OPS: FrozenSet[str] = frozenset(
    {"add", "remove", "replace", "move", "copy", "test"}
)

#: The operations that write the value an operation carries: ``add`` and
#: ``replace`` take a ``value``; ``remove`` takes none.
VALUE_WRITING_OPS: FrozenSet[str] = frozenset({"add", "replace"})

#: The operations that change a document, which each need a path and so are
#: checked against the rules; ``test`` writes nothing.
DOCUMENT_CHANGING_OPS: FrozenSet[str] = JSON_PATCH_OPS - {"test"}

#: Operations that add, replace or remove the node at a path (``move`` and
#: ``copy`` name a second path and are handled by the callers that allow them).
NODE_EDITING_OPS: FrozenSet[str] = frozenset({"add", "replace", "remove"})

#: Operations that insert or delete one node, which shift the indexes of a
#: list's later entries.
INSERT_OR_DELETE_OPS: FrozenSet[str] = frozenset({"add", "remove"})

#: Operations a runtime patch may never carry: they read one place of the
#: document to write another, which the denial rules cannot follow.
FORBIDDEN_RUNTIME_OPS: FrozenSet[str] = frozenset({"move", "copy"})

#: The operations a config source's own ``patch`` list accepts (no ``move`` or
#: ``copy``): the four that name one place.
CONFIG_SOURCE_OPS: FrozenSet[str] = frozenset({"add", "remove", "replace", "test"})
