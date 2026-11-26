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

import functools
from typing import TYPE_CHECKING, Any, Iterable, Optional, Set

from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.utils.scanner_names import (
    IMAGE_SERVING_SCANNERS,
    SCANNER_TOOL_TYPES,
)

if TYPE_CHECKING:
    from automated_security_helper.base.scanner_facets import FacetState

TOOL_TYPE_TAG_PREFIX = "tool_type::"
SECRETS_TOOL_TYPE = ScannerToolType.SECRETS.value
UNKNOWN_TOOL_TYPE = ScannerToolType.UNKNOWN.value

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


def _loaded_scanner_classes() -> Iterable[type]:
    """Every loaded plugin subclass of ``ScannerPluginBase``, aliases skipped.

    Found among the subclasses already imported, not through the plugin
    registry: the registry's state is the plugin manager's own
    (tests/unit/workspace/test_project_isolation.py). Imports nothing else and
    instantiates nothing.

    A pydantic generic parametrization (``TrivyScannerBase[TrivyScannerConfig]``,
    ``ScannerPluginBase[GrypeScannerConfig]``) is a real runtime subclass that
    inherits the concrete config annotation, so it answers to the scanner's
    config name -- but it is an alias pydantic mints for the annotation, never a
    plugin, and it declares no register row of its own (the register reads a
    class's own ``vars()``). Walked as a match, the alias answered for the
    scanner: ``scanner_serves_container_images("trivy")`` read the alias first
    and returned False with the real class loaded, which stripped every image
    finding's attribution. An alias names the class it parametrizes in
    ``__pydantic_generic_metadata__["origin"]``; skip it.
    """
    try:
        from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    except ImportError:
        return
    pending = list(ScannerPluginBase.__subclasses__())
    seen: Set[type] = set()
    while pending:
        cls = pending.pop()
        if cls in seen:
            continue
        seen.add(cls)
        pending.extend(cls.__subclasses__())
        metadata = getattr(cls, "__pydantic_generic_metadata__", None) or {}
        if metadata.get("origin") is not None:
            continue
        yield cls


def _loaded_class_tool_type(scanner_name: str) -> Optional[str]:
    """The class-level ``tool_type`` of a loaded scanner class named ``scanner_name``."""
    for cls in _loaded_scanner_classes():
        if _class_config_name(cls) != scanner_name:
            continue
        field = (getattr(cls, "model_fields", None) or {}).get("tool_type")
        found = normalize_tool_type(getattr(field, "default", None))
        if found:
            return found
    return None


@functools.lru_cache(maxsize=None)
def _class_config_name(cls: type) -> Optional[str]:
    """A scanner class's config name, read from its config model's default.

    Cached per class: the by-name helpers below run once per finding and per
    reporter, and this read inspects pydantic ``model_fields`` annotations,
    which dominated the walk's cost. The cache holds a strong reference to
    each class it has seen -- a leak only for classes defined and discarded at
    runtime (test doubles), which is accepted.
    """
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


def scanner_resource_id_state(scanner_name: Any) -> Optional["FacetState"]:
    """The declared ``resource_id`` facet state (a :class:`FacetState` member)
    of the loaded scanner class named ``scanner_name``, or None if unknown.

    Read from the class's ``facets`` declaration, found among the loaded
    plugin classes (:func:`_loaded_scanner_classes`), importing and
    instantiating nothing else. A scanner that is not loaded or declares no
    facets answers None, and the caller treats that as "cannot decide", not as
    a declaration.
    """
    if not isinstance(scanner_name, str) or not scanner_name:
        return None
    try:
        from automated_security_helper.base.scanner_facets import FacetState
    except ImportError:
        return None
    for cls in _loaded_scanner_classes():
        if _class_config_name(cls) != scanner_name:
            continue
        decl = getattr(getattr(cls, "facets", None), "resource_id", None)
        state = getattr(decl, "state", None)
        if isinstance(state, FacetState):
            return state
    return None


def an_image_digest_consumer_is_selected(
    enabled_scanners: Optional[Iterable[Any]] = None,
    excluded_scanners: Optional[Iterable[Any]] = None,
    python_based_plugins_only: bool = False,
) -> bool:
    """Whether a selected scanner's finding ids the digest resolution would key.

    The digest ladder (``utils/image_digest_resolver``) exists to key FINDING
    ids, and only a loaded scanner that serves container images and declares
    the registry read (``Fetched.IMAGE_DIGEST``) produces such ids. With every
    such scanner excluded, left out of a non-empty allowlist, or dropped by
    ``python_based_plugins_only`` (the declaring scanners are pinned
    binaries), the ladder would resolve a digest nobody keys on, so the scan
    phase does not run it and no registry request is made for a scan whose
    operator deselected the consumers. The walk is the loaded-classes walk
    every helper here uses; a scanner this process has not imported cannot
    consume the digest either, because consumption IS the declaration.
    """
    try:
        from automated_security_helper.base import scanner_operational_facets as opsf
        from automated_security_helper.core.asset import AssetKind
    except ImportError:
        return False
    allow = {
        str(name).lower().strip()
        for name in (enabled_scanners or [])
        if str(name).strip()
    }
    deny = {
        str(name).lower().strip()
        for name in (excluded_scanners or [])
        if str(name).strip()
    }
    for cls in _loaded_scanner_classes():
        facets = opsf.declared_operational_facets(cls)
        network = getattr(facets, "network", None)
        if opsf.Fetched.IMAGE_DIGEST not in (getattr(network, "fetches", None) or ()):
            continue
        if not opsf.serves_asset_kind(cls, AssetKind.CONTAINER_IMAGE):
            continue
        if python_based_plugins_only and not getattr(
            getattr(facets, "runtime", None), "python_only", False
        ):
            continue
        name = (_class_config_name(cls) or "").lower()
        if not name or name in deny:
            continue
        if allow and name not in allow:
            continue
        return True
    return False


def scanner_serves_container_images(scanner_name: Any) -> Optional[bool]:
    """Whether the scanner named ``scanner_name`` declares container-image
    targets in its operational facets, or None if unknown.

    For a scanner ASH ships the answer is the static
    ``scanner_names.IMAGE_SERVING_SCANNERS`` table, so it is the same in every
    process: ``ash merge`` reads results another process wrote, and an answer
    that depended on which scanner modules this process had imported gave one
    result two identities (and made it matchable by ``image:`` suppressions in
    one process and not the other). A test checks the table against each
    shipped class's own register row.

    A third-party name falls back to the by-name form of ``serves_asset_kind``
    (``base/scanner_operational_facets``) over the loaded plugin classes
    (:func:`_loaded_scanner_classes`), importing and instantiating nothing
    else. The flat extractor reads it to honor the image attribution
    properties only for a scanner the executor could have stamped; None means
    "cannot decide", and the caller leaves the properties as read.
    """
    if not isinstance(scanner_name, str) or not scanner_name:
        return None
    if scanner_name in SCANNER_TOOL_TYPES:
        return scanner_name in IMAGE_SERVING_SCANNERS
    try:
        from automated_security_helper.base.scanner_operational_facets import (
            serves_asset_kind,
        )
        from automated_security_helper.core.asset import AssetKind
    except ImportError:
        return None
    for cls in _loaded_scanner_classes():
        if _class_config_name(cls) != scanner_name:
            continue
        return serves_asset_kind(cls, AssetKind.CONTAINER_IMAGE)
    return None
