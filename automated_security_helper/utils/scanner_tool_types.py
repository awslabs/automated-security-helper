# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which kind of scanner reported a SARIF result.

Secret masking (``utils/secret_masking.py``) and the Bedrock summary reporter's
``exclude_scanner_types`` both need to know whether a finding came from a secrets
scanner. A result does not carry its scanner's type as a field: the engine writes
``scanner_name`` on every result (``sarif_utils.attach_scanner_details``), and a
few scanners add a ``tool_type::<TYPE>`` tag of their own, spelled either
``tool_type::SECRETS`` or ``tool_type::ScannerToolType.SECRETS`` depending on how
the scanner formats the enum. So the type is read from both:

* each ``tool_type::`` tag, normalized (``normalize_tool_type``), and
* the scanner's type looked up by its name (``scanner_tool_type``): the type
  declared for every scanner ASH ships (``utils/scanner_names.SCANNER_TOOL_TYPES``),
  else the ``tool_type`` a loaded scanner class declares at class level.

A result for which neither yields a type has an unknown scanner type, which the
callers treat as their safe case requires.

Limit: a third-party scanner that sets its type only in ``model_post_init`` (as
ASH's own scanners do) and writes no ``tool_type::`` tag has an unknown type here.
Declaring ``tool_type`` on the class, or tagging results, makes it known.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional, Set

from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

TOOL_TYPE_TAG_PREFIX = "tool_type::"
SECRETS_TOOL_TYPE = "SECRETS"  # pragma: allowlist secret
UNKNOWN_TOOL_TYPE = "UNKNOWN"

#: The types a scanner can declare (``ScannerToolType``'s values), UNKNOWN left out.
KNOWN_TOOL_TYPES = frozenset(member.value for member in ScannerToolType) - {
    UNKNOWN_TOOL_TYPE
}

_ENUM_PREFIX = "SCANNERTOOLTYPE."
#: Spellings of a type that mean the same type.
_ALIASES = {"SECRET": SECRETS_TOOL_TYPE}


def normalize_tool_type(value: Any) -> Optional[str]:
    """``value`` as a ``ScannerToolType`` value: upper case, without an enum prefix.

    ``SECRET`` and ``SECRETS`` both give ``SECRETS``. An empty value, ``UNKNOWN``
    and any text that is no ``ScannerToolType`` value give None, since none says
    what the scanner is: the ``None`` a ``tool_type::None`` tag was formatted
    with, pydantic's undefined-default marker read from a ``tool_type`` field
    with no plain default, free text. Each used to come back upper-cased as a
    type of its own, which turned the callers' unknown-type handling off.
    """
    text = str(getattr(value, "value", value) or "").strip().upper()
    text = text.removeprefix(_ENUM_PREFIX)
    text = _ALIASES.get(text, text)
    if text not in KNOWN_TOOL_TYPES:
        return None
    return text


def _loaded_class_tool_type(scanner_name: str) -> Optional[str]:
    """The class-level ``tool_type`` of a loaded scanner class named ``scanner_name``.

    Found among the subclasses of ``ScannerPluginBase`` already imported, not
    through the plugin registry: the registry's state is the plugin manager's
    own (tests/unit/workspace/test_project_isolation.py). Imports nothing else
    and instantiates nothing.
    """
    try:
        from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    except ImportError:
        return None
    pending = list(ScannerPluginBase.__subclasses__())
    seen: Set[type] = set()
    while pending:
        cls = pending.pop()
        if cls in seen:
            continue
        seen.add(cls)
        pending.extend(cls.__subclasses__())
        if _class_config_name(cls) != scanner_name:
            continue
        field = (getattr(cls, "model_fields", None) or {}).get("tool_type")
        found = normalize_tool_type(getattr(field, "default", None))
        if found:
            return found
    return None


def _class_config_name(cls: type) -> Optional[str]:
    """A scanner class's config name, read from its config model's default."""
    field = (getattr(cls, "model_fields", None) or {}).get("config")
    annotation = getattr(field, "annotation", None)
    for arg in getattr(annotation, "__args__", None) or (annotation,):
        if not isinstance(arg, type) or not arg.__name__.endswith("ScannerConfig"):
            continue
        name_field = (getattr(arg, "model_fields", None) or {}).get("name")
        name = getattr(name_field, "default", None)
        if isinstance(name, str):
            return name
    return None


def scanner_tool_type(scanner_name: Any) -> Optional[str]:
    """The tool type of the scanner with this config name, or None if unknown."""
    if not isinstance(scanner_name, str) or not scanner_name:
        return None
    declared = SCANNER_TOOL_TYPES.get(scanner_name)
    if declared:
        return declared
    return _loaded_class_tool_type(scanner_name)


def _properties(result: Any) -> Any:
    if isinstance(result, dict):
        return result.get("properties") or {}
    return getattr(result, "properties", None)


def _get(properties: Any, name: str) -> Any:
    if properties is None:
        return None
    if isinstance(properties, dict):
        return properties.get(name)
    value = getattr(properties, name, None)
    if value is None:
        extra = getattr(properties, "__pydantic_extra__", None) or {}
        value = extra.get(name)
    return value


def result_tags(result: Any) -> Iterable[str]:
    """The tags of a SARIF result (a model or its JSON dict)."""
    tags = _get(_properties(result), "tags") or []
    return [tag for tag in tags if isinstance(tag, str)]


def result_scanner_name(result: Any) -> Optional[str]:
    name = _get(_properties(result), "scanner_name")
    return name if isinstance(name, str) and name else None


def result_tool_types(result: Any) -> Set[str]:
    """Every tool type a SARIF result's tags and scanner name give it; empty if unknown."""
    types: Set[str] = set()
    for tag in result_tags(result):
        if tag.startswith(TOOL_TYPE_TAG_PREFIX):
            found = normalize_tool_type(tag[len(TOOL_TYPE_TAG_PREFIX) :])
            if found:
                types.add(found)
    from_name = scanner_tool_type(result_scanner_name(result))
    if from_name:
        types.add(from_name)
    return types
