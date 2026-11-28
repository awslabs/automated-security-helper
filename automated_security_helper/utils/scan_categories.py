"""Scan categories: their spellings, and the scanner and result lookups.

A scan category (``ScanCategory``) names a kind of finding, or for ``sbom`` a kind
of artifact. A scanner declares the categories it can serve on its operational row
(``TargetsFacet.categories``). This module reads category spellings; answers which
categories a scanner can serve from its config name, which categories one SARIF
result belongs to, and which set a category scope matches; and lists the legacy
names that 4.0 removes together with the derivation of categories from the legacy
scanner type.
"""

from __future__ import annotations

import difflib
from typing import Iterable, NamedTuple

from automated_security_helper.core.enums import ScanCategory, categories_of_tool_type
from automated_security_helper.utils.scanner_names import SCANNER_CATEGORIES
from automated_security_helper.utils.scanner_tool_types import (
    result_scanner_name,
    result_tags,
    scanner_tool_type,
)

#: The tag prefix a SARIF result carries for each category it belongs to, as in
#: ``category::secrets``.
CATEGORY_TAG_PREFIX = "category::"

#: The category values in canonical order.
_CATEGORY_VALUES: tuple[str, ...] = tuple(category.value for category in ScanCategory)


def normalize_category(value: object) -> ScanCategory:
    """The ``ScanCategory`` *value* names.

    A member is returned as it is; anything else is read as text, stripped and
    lower-cased. Text that names no category raises ValueError naming the value as
    given, the nearest category when one is close, and every category.
    """
    if isinstance(value, ScanCategory):
        return value
    text = str(value).strip().lower()
    if text in _CATEGORY_VALUES:
        return ScanCategory(text)
    message = f"unknown scan category {str(value)!r}"
    nearest = difflib.get_close_matches(text, _CATEGORY_VALUES, n=1)
    if nearest:
        message += f" (did you mean {nearest[0]!r}?)"
    raise ValueError(message + "; the categories are: " + ", ".join(_CATEGORY_VALUES))


def normalize_categories(values: Iterable[object]) -> tuple[ScanCategory, ...]:
    """Each of *values* read by :func:`normalize_category`, each once, in canonical
    order. A single string is one value, not a sequence of characters."""
    items: Iterable[object] = (values,) if isinstance(values, str) else values
    named = {normalize_category(item) for item in items}
    return tuple(category for category in ScanCategory if category in named)


def scanner_categories(scanner_name: object) -> tuple[ScanCategory, ...]:
    """The scan categories the scanner with this config name can serve.

    The first that answers, in order: the shipped table (``SCANNER_CATEGORIES``);
    the operational row of that name built in this process; the categories an
    instance of that name recorded; the category its loaded class's class-level
    ``tool_type`` stands for. A recorded empty tuple answers, so a scanner recorded
    as deriving nothing is ``()`` without the class-level read. ``()`` for a name
    that is not a non-empty string, and when nothing answers.
    """
    if not isinstance(scanner_name, str) or not scanner_name:
        return ()
    shipped = SCANNER_CATEGORIES.get(scanner_name)
    if shipped is not None:
        return shipped
    from automated_security_helper.base.scanner_operational_facets import (
        instance_categories,
        row_categories,
    )

    for recorded in (row_categories(scanner_name), instance_categories(scanner_name)):
        if recorded is not None:
            return recorded
    return categories_of_tool_type(scanner_tool_type(scanner_name))


def result_categories(result: object) -> frozenset[ScanCategory]:
    """The scan categories one SARIF result (a model or its JSON dict) belongs to.

    The categories its ``category::<value>`` tags name, each value read the way
    :func:`normalize_category` reads it (a tag that names no category is skipped);
    when no tag names one, the one category of the shipped single-category scanner
    its scanner name names; unclassified (``frozenset()``) otherwise. ``tool_type::``
    tags are not read.
    """
    tagged: set[ScanCategory] = set()
    for tag in result_tags(result):
        if not isinstance(tag, str) or not tag.startswith(CATEGORY_TAG_PREFIX):
            continue
        value = tag.removeprefix(CATEGORY_TAG_PREFIX).strip().lower()
        if value in _CATEGORY_VALUES:
            tagged.add(ScanCategory(value))
    if tagged:
        return frozenset(tagged)
    shipped = SCANNER_CATEGORIES.get(result_scanner_name(result) or "", ())
    return frozenset(shipped) if len(shipped) == 1 else frozenset()


def scope_categories(categories: Iterable[object]) -> frozenset[ScanCategory]:
    """The categories a category scope matches: *categories* read by
    :func:`normalize_categories`, or ``{other}`` when there are none (a scanner or
    result with no category meets a scope as ``other``)."""
    named = frozenset(normalize_categories(categories))
    return named or frozenset({ScanCategory.OTHER})


class RemovedName(NamedTuple):
    """One legacy name 4.0 removes, and what it is."""

    #: An identifier, ``Class.attribute``, or a tag prefix.
    name: str
    #: ``"name"``, ``"attribute"`` or ``"tag"``.
    kind: str
    #: One line: what it is.
    what: str


#: The legacy names 4.0 removes with the derivation of categories from the legacy
#: scanner type. A "name" is any identifier the package source defines or names; an
#: "attribute" is the field after the dot, defined in the class named before it; a
#: "tag" is a string constant in the package source that starts with the prefix.
REMOVED_IN_4_0: tuple[RemovedName, ...] = (
    RemovedName("ScannerToolType", "name", "the legacy scanner type enum"),
    RemovedName(
        "CATEGORY_OF_TOOL_TYPE", "name", "the category each legacy type stands for"
    ),
    RemovedName(
        "tool_type_member", "name", "reads a legacy type spelling as its enum member"
    ),
    RemovedName(
        "categories_of_tool_type", "name", "the categories a legacy type derives"
    ),
    RemovedName(
        "TargetsFacet.tool_type", "attribute", "the legacy type on an operational row"
    ),
    RemovedName(
        "TargetsFacet.tool_type_note",
        "attribute",
        "why an operational row's legacy type is what it is",
    ),
    RemovedName(
        "SCANNER_TOOL_TYPES", "name", "the shipped scanners' legacy types by name"
    ),
    RemovedName("scanner_tool_type", "name", "a scanner's legacy type by name"),
    RemovedName("result_tool_types", "name", "the legacy types a result's tags name"),
    RemovedName(
        "normalize_tool_type", "name", "reads a legacy type spelling as its text"
    ),
    RemovedName("tool_type::", "tag", "the result tag that carries a legacy type"),
    RemovedName("scanner_type", "name", "the legacy type field of a flat finding"),
    RemovedName(
        "exclude_scanner_types",
        "name",
        "the Bedrock summary reporter's option that drops findings by legacy type",
    ),
)
