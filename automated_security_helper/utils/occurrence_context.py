# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Curated occurrence evidence shared by flattening and SARIF composition.

Only referenced source evidence is retained. The merge marker is a lifecycle
hint, not authentication; exact validation still excludes arbitrary property
bags, raw arguments and cached opaque IDs.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple, TYPE_CHECKING

from automated_security_helper.utils.secret_masking import (
    mask_secret_in_text,
    _mask_secret_value,
)
from automated_security_helper.utils.scanner_names import SCANNER_TAG_NAMES

if TYPE_CHECKING:
    from automated_security_helper.schemas.sarif_schema_model import Region, Result, Run

_GENERIC_ASH_TOOL_NAME = "AWS Labs - Automated Security Helper"
CONTEXT_PROPERTY = "ash_occurrence_context"
MERGE_MARKER = "ash_occurrence_context_version"
CONTEXT_VERSION = 1


def _region_attr(attr: str, order: Iterable[Optional[Region]]) -> Optional[Any]:
    """Read the first non-None coordinate from finding region, then context."""
    for candidate in order:
        if candidate is None:
            continue
        value = getattr(candidate, attr, None)
        if value is not None:
            return value
    return None


def _canonical_identity_json(value: Any) -> str:
    """Serialize selected occurrence evidence without incidental key ordering."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _identity_fields(
    source: Any, strings: Iterable[str], numbers: Iterable[str] = ()
) -> Dict[str, Any]:
    """Select meaningful strings and nonnegative coordinates, excluding defaults."""
    selected: Dict[str, Any] = {}
    for key in strings:
        value = (
            source.get(key) if isinstance(source, dict) else getattr(source, key, None)
        )
        if isinstance(value, str) and value.strip():
            selected[key] = value
    for key in numbers:
        value = (
            source.get(key) if isinstance(source, dict) else getattr(source, key, None)
        )
        if type(value) is int and value >= 0:
            selected[key] = value
    return selected


def _location_identity(location: Any) -> Dict[str, Any]:
    """Select one occurrence's inline coordinates without run table lookup."""
    selected: Dict[str, Any] = {}
    physical = getattr(location.physicalLocation, "root", None)
    if physical is not None:
        address = _identity_fields(
            physical.address,
            ("kind", "name", "fullyQualifiedName"),
            ("absoluteAddress", "length", "index", "parentIndex"),
        )
        for key in ("relativeAddress", "offsetFromParent"):
            value = getattr(physical.address, key, None)
            if type(value) is int:
                address[key] = value
        if address:
            selected["address"] = address
        artifact = _identity_fields(
            physical.artifactLocation, ("uri", "uriBaseId"), ("index",)
        )
        region = _identity_fields(
            physical.region,
            (),
            (
                "startLine",
                "startColumn",
                "endLine",
                "endColumn",
                "charOffset",
                "charLength",
                "byteOffset",
                "byteLength",
            ),
        )
        for attr in ("startLine", "endLine"):
            value = _region_attr(attr, (physical.region, physical.contextRegion))
            if value is not None:
                region[attr] = value
        if artifact:
            selected["artifact"] = artifact
        if region:
            selected["region"] = region
    logical = [
        _identity_fields(
            item,
            ("name", "fullyQualifiedName", "decoratedName", "kind"),
            ("index", "parentIndex"),
        )
        for item in location.logicalLocations or []
    ]
    logical = [item for item in logical if item]
    if logical:
        selected["logical"] = sorted(logical, key=_canonical_identity_json)
    return selected


def _occurrence_locations(result: Any) -> List[Dict[str, Any]]:
    locations = [_location_identity(location) for location in result.locations or []]
    return sorted(
        [location for location in locations if location], key=_canonical_identity_json
    )


def _rule_reference_identity(result: "Result") -> Dict[str, Any]:
    reference = getattr(result.rule, "root", None)
    selected = _identity_fields(reference, ("id", "guid"), ("index",))
    component = _identity_fields(
        getattr(reference, "toolComponent", None), ("name", "guid"), ("index",)
    )
    if component:
        selected["component"] = component
    return selected


def _owning_component(result: "Result", run: Optional["Run"], scanner: str) -> Any:
    """Resolve an unambiguous component, honoring every supplied identifier."""
    tool = getattr(run, "tool", None)
    driver = getattr(tool, "driver", None)
    extensions = getattr(tool, "extensions", None) or []
    if not isinstance(extensions, list):
        return None
    reference = getattr(getattr(result.rule, "root", None), "toolComponent", None)
    constraints = _identity_fields(reference, ("name", "guid"), ("index",))
    if reference is not None:
        index = constraints.get("index")
        if index is not None:
            candidates = extensions[index : index + 1]
        else:
            candidates = [driver, *extensions] if constraints.get("guid") else [driver]
        candidates = [
            candidate
            for candidate in candidates
            if candidate is not None
            and all(
                _identifier_matches(key, getattr(candidate, key, None), value)
                for key, value in constraints.items()
                if key != "index"
            )
        ]
        return candidates[0] if len(candidates) == 1 else None
    if getattr(driver, "name", None) == _GENERIC_ASH_TOOL_NAME:
        candidates = [
            item for item in extensions if getattr(item, "name", None) == scanner
        ]
        return candidates[0] if len(candidates) == 1 else None
    return driver


def _owning_rule(result: "Result", component: Any) -> Any:
    """Select a rule only when all id, index and guid evidence agrees."""
    reference = _rule_reference_identity(result)
    ids = [value for value in (result.ruleId, reference.get("id")) if value is not None]
    indices = [
        value
        for value in (result.ruleIndex, reference.get("index"))
        if type(value) is int and value >= 0
    ]
    if len(set(indices)) > 1:
        return None
    rules = getattr(component, "rules", None) or []
    if not isinstance(rules, list):
        return None
    candidates = rules[indices[0] : indices[0] + 1] if indices else rules
    if not ids and not indices and not reference.get("guid"):
        return None
    candidates = [
        rule
        for rule in candidates
        if (
            (
                not ids
                or all(
                    _rule_id_matches(value, getattr(rule, "id", None)) for value in ids
                )
            )
            and (
                not reference.get("guid")
                or _identifier_matches(
                    "guid", getattr(rule, "guid", None), reference["guid"]
                )
            )
        )
    ]
    return candidates[0] if len(candidates) == 1 else None


def _rule_id_matches(result_id: str, descriptor_id: Any) -> bool:
    return isinstance(descriptor_id, str) and (
        result_id == descriptor_id
        or (
            result_id.startswith(descriptor_id + "/")
            and "/" not in result_id[len(descriptor_id) + 1 :]
            and bool(result_id[len(descriptor_id) + 1 :])
        )
    )


def _identifier_matches(key: str, actual: Any, expected: Any) -> bool:
    if key == "guid" and isinstance(actual, str) and isinstance(expected, str):
        return actual.casefold() == expected.casefold()
    return actual == expected


def _expand_message(template: str, arguments: Any) -> str:
    """Expand only numeric placeholders and escaped braces, never Python format."""
    arguments = arguments if isinstance(arguments, list) else []

    def replace(match: Any) -> str:
        token = match.group(0)
        if token in ("{{", "}}"):
            return token[0]
        digits = match.group(1).lstrip("0") or "0"
        if len(digits) > len(str(len(arguments))):
            return token
        index = int(digits)
        return (
            arguments[index]
            if index < len(arguments) and isinstance(arguments[index], str)
            else token
        )

    return re.sub(r"{{|}}|\{([0-9]+)\}", replace, template)


def _message_resolution(
    result: "Result", scanner: str, run: Optional["Run"]
) -> Tuple[str, Optional[str], bool]:
    """Resolve plain evidence locally; preserve display and exclude unused args."""
    message = getattr(result.message, "root", result.message)
    direct = getattr(message, "text", None)
    cached = persisted_context(result, run)
    if direct is None and cached is not None and "message" in cached:
        message_context = cached["message"]
        return (
            message_context["text"],
            message_context.get("id"),
            message_context["state"] == "resolved",
        )
    composed = is_composed_run(run)
    if composed:
        run = None
    template = direct if isinstance(direct, str) else None
    message_id = getattr(message, "id", None)
    message_id = message_id if isinstance(message_id, str) and message_id else None
    reference = getattr(result.rule, "root", None)
    effective_rule = result.ruleId or getattr(reference, "id", None)
    if effective_rule is None and cached is not None:
        effective_rule = cached.get("resolved_rule", {}).get("id")
    if template is None or effective_rule is None:
        component = _owning_component(result, run, scanner)
        rule = _owning_rule(result, component)
        effective_rule = effective_rule or getattr(rule, "id", None)
        if template is None and message_id is not None:
            for owner, key in (
                (rule, "messageStrings"),
                (component, "globalMessageStrings"),
            ):
                table = getattr(owner, key, None)
                item = table.get(message_id) if isinstance(table, dict) else None
                text = getattr(item, "text", None)
                if isinstance(text, str):
                    template = text
                    break
    arguments = getattr(message, "arguments", None)
    captured_direct_arguments = (
        cached is not None and cached.get("message", {}).get("state") == "resolved"
    )
    if composed and effective_rule is None and not captured_direct_arguments:
        arguments = []
    rendered = (
        _safe_message(template, arguments, effective_rule)
        if template is not None
        else ""
    )
    rendered = mask_secret_in_text(rendered, effective_rule).strip()
    return rendered, message_id if direct is None else None, template is not None


def _has_used_arguments(template: Any, arguments: Any) -> bool:
    if not isinstance(template, str) or not isinstance(arguments, list):
        return False
    for match in re.finditer(r"{{|}}|\{([0-9]+)\}", template):
        if match.group(1) is None:
            continue
        digits = match.group(1).lstrip("0") or "0"
        if len(digits) <= len(str(len(arguments))):
            index = int(digits)
            if index < len(arguments) and isinstance(arguments[index], str):
                return True
    return False


def _message_identity(result: Any, scanner: str, run: Any) -> Tuple[str, Optional[str]]:
    text, message_id, _ = _message_resolution(result, scanner, run)
    return text, message_id


def _safe_message(template: str, arguments: Any, rule_id: Optional[str]) -> str:
    """Use the template's secret boundaries, never delimiters inserted by args."""
    base_rule = rule_id.split("/", 1)[0] if isinstance(rule_id, str) else None
    if base_rule not in ("B105", "B106", "B107"):
        return _expand_message(template, arguments)
    opening = re.search(r"""Possible hardcoded password:\s*(["'])""", template)
    start = opening.end() if opening is not None else 0
    end = start
    closed = False
    if opening is not None:
        while end < len(template):
            if template[end] == "\\":
                end += 2
            elif template[end] == opening.group(1):
                closed = True
                break
            else:
                end += 1
    if closed:
        secret = _expand_message(template[start:end], arguments)
        # Redact other used substitutions conservatively for known secret rules.
        safe_args = (
            ["[REDACTED]"] * len(arguments) if isinstance(arguments, list) else []
        )
        return (
            _expand_message(template[:start], safe_args)
            + _mask_secret_value(secret)
            + _expand_message(template[end:], safe_args)
        )
    safe_args = ["[REDACTED]"] * len(arguments) if isinstance(arguments, list) else []
    return _expand_message(template, safe_args)


def is_composed_run(run: Any) -> bool:
    value = getattr(getattr(run, "properties", None), MERGE_MARKER, None)
    return type(value) is int and value == CONTEXT_VERSION


def _fields_schema(
    strings: Iterable[str], numbers: Iterable[str] = (), signed: Iterable[str] = ()
) -> Dict[str, Any]:
    return {
        **{key: "guid" if key == "guid" else "string" for key in strings},
        **dict.fromkeys(numbers, "nonnegative"),
        **dict.fromkeys(signed, "integer"),
    }


_ARTIFACT = _fields_schema(("uri", "uriBaseId"), ("index",))
_ADDRESS = _fields_schema(
    ("kind", "name", "fullyQualifiedName"),
    ("absoluteAddress", "length", "index", "parentIndex"),
    ("relativeAddress", "offsetFromParent"),
)
_LOGICAL = _fields_schema(
    ("name", "fullyQualifiedName", "decoratedName", "kind"), ("index", "parentIndex")
)
_COMPONENT = _fields_schema(("name", "guid"), ("index",))
_RULE = _fields_schema(("id", "guid"), ("index",))
_REFERENCE = {**_RULE, "component": _COMPONENT}
_REGION = _fields_schema(
    (),
    (
        "startLine",
        "startColumn",
        "endLine",
        "endColumn",
        "charOffset",
        "charLength",
        "byteOffset",
        "byteLength",
    ),
)
_INLINE = {
    "artifact": _ARTIFACT,
    "address": _ADDRESS,
    "region": _REGION,
    "logical": [_LOGICAL],
}
_ARTIFACT_ENTRY = {
    "location": _ARTIFACT,
    **_fields_schema((), ("offset", "length", "parentIndex")),
}
_BASE_CHAIN = {
    "entries": [{"id": "string", "location": _ARTIFACT}],
    "stop": {"end", "cycle", "out_of_range"},
}
_ARTIFACT_ENTRY["bases"] = _BASE_CHAIN


def _chain_schema(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {"entries": [entry], "stop": {"end", "cycle", "out_of_range"}}


_ARTIFACT_CHAIN = _chain_schema(_ARTIFACT_ENTRY)
_ADDRESS_REFS = {"index": _chain_schema(_ADDRESS), "parent": _chain_schema(_ADDRESS)}
_LOGICAL_REFS = {"index": _chain_schema(_LOGICAL), "parent": _chain_schema(_LOGICAL)}
_CONTEXT_SCHEMA = {
    "version": "version",
    "rule_index": "nonnegative",
    "rule_reference": _REFERENCE,
    "resolved_rule": _RULE,
    "component": _COMPONENT,
    "message": {"state": {"resolved", "unavailable"}, "text": "text", "id": "string"},
    "locations": [
        {
            "location": _INLINE,
            "artifact": _ARTIFACT_CHAIN,
            "bases": _BASE_CHAIN,
            "address": _ADDRESS_REFS,
            "logical": [{"location": _LOGICAL, "references": _LOGICAL_REFS}],
        }
    ],
    "analysis_target": {
        "location": _ARTIFACT,
        "artifact": _ARTIFACT_CHAIN,
        "bases": _BASE_CHAIN,
    },
}


def _valid(value: Any, schema: Any) -> bool:
    """Exact finite nested allowlist, without coercion or opaque digest trust."""
    if isinstance(schema, dict):
        if type(value) is not dict or not value.keys() <= schema.keys():
            return False
        if "entries" in schema and value.keys() != {"entries", "stop"}:
            return False
        if "state" in schema and not {"state", "text"} <= value.keys():
            return False
        if (
            "state" in value
            and value["state"] == "unavailable"
            and value.get("text") != ""
        ):
            return False
        if any(
            key in value and (type(value[key]) is not int or value[key] < 1)
            for key in ("startLine", "startColumn", "endLine", "endColumn")
            if key in schema
        ):
            return False
        return all(_valid(item, schema[key]) for key, item in value.items())
    if isinstance(schema, list):
        return type(value) is list and all(_valid(item, schema[0]) for item in value)
    if isinstance(schema, set):
        return type(value) is str and value in schema
    if schema in ("nonnegative", "integer", "version"):
        return (
            type(value) is int
            and (schema == "integer" or value >= 0)
            and (schema != "version" or value == CONTEXT_VERSION)
        )
    if schema in ("string", "text", "guid"):
        return (
            type(value) is str
            and (schema == "text" or bool(value.strip()))
            and (
                schema != "guid"
                or re.fullmatch(
                    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
                    value,
                )
                is not None
            )
        )
    return False


def valid_context(value: Any) -> bool:
    return (
        _valid(value, _CONTEXT_SCHEMA)
        and value.get("version") == CONTEXT_VERSION
        and len(value) > 1
    )


def persisted_context(result: Any, run: Any) -> Optional[Dict[str, Any]]:
    context = getattr(getattr(result, "properties", None), CONTEXT_PROPERTY, None)
    return context if is_composed_run(run) and valid_context(context) else None


def _base_chain(base: str, run: Any) -> Dict[str, Any]:
    table = getattr(run, "originalUriBaseIds", None)
    table = table if isinstance(table, dict) else {}
    seen: set[str] = set()
    entries: List[Dict[str, Any]] = []
    while True:
        if base in seen:
            return {"entries": entries, "stop": "cycle"}
        if base not in table:
            return {"entries": entries, "stop": "out_of_range"}
        seen.add(base)
        node = table[base]
        entries.append(
            {
                "id": base,
                "location": _identity_fields(node, ("uri", "uriBaseId"), ("index",)),
            }
        )
        parent = getattr(node, "uriBaseId", None)
        if not isinstance(parent, str) or not parent:
            return {"entries": entries, "stop": "end"}
        base = parent


def _artifact_entry(node: Any, run: Any = None) -> Dict[str, Any]:
    value = _identity_fields(node, (), ("offset", "length", "parentIndex"))
    location = _identity_fields(
        getattr(node, "location", None), ("uri", "uriBaseId"), ("index",)
    )
    if location:
        value["location"] = location
        if location.get("uriBaseId"):
            value["bases"] = _base_chain(location["uriBaseId"], run)
    return value


def _address_entry(node: Any) -> Dict[str, Any]:
    value = _identity_fields(
        node,
        ("kind", "name", "fullyQualifiedName"),
        ("absoluteAddress", "length", "index", "parentIndex"),
    )
    for key in ("relativeAddress", "offsetFromParent"):
        number = getattr(node, key, None)
        if type(number) is int:
            value[key] = number
    return value


def _logical_entry(node: Any) -> Dict[str, Any]:
    return _identity_fields(
        node,
        ("name", "fullyQualifiedName", "decoratedName", "kind"),
        ("index", "parentIndex"),
    )


def _chain(index: int, table: Any, select: Any) -> Dict[str, Any]:
    """Walk only referenced parents, bounded by the finite source table."""
    table = table if isinstance(table, list) else []
    seen: set[int] = set()
    entries: List[Dict[str, Any]] = []
    while True:
        if index in seen:
            return {"entries": entries, "stop": "cycle"}
        if index >= len(table):
            return {"entries": entries, "stop": "out_of_range"}
        seen.add(index)
        node = table[index]
        entries.append(select(node))
        parent = getattr(node, "parentIndex", None)
        if type(parent) is not int or parent < 0:
            return {"entries": entries, "stop": "end"}
        index = parent


def _references(node: Any, table: Any, select: Any) -> Dict[str, Any]:
    references = {}
    for attr, key in (("index", "index"), ("parentIndex", "parent")):
        value = getattr(node, attr, None)
        if type(value) is int and value >= 0:
            references[key] = _chain(value, table, select)
    return references


def _scanner(result: Any, run: Any) -> str:
    props = getattr(result, "properties", None)
    scanner = getattr(props, "scanner_name", None)
    if isinstance(scanner, str) and scanner:
        return scanner
    driver_name = getattr(
        getattr(getattr(run, "tool", None), "driver", None), "name", "Unknown"
    )
    tags = getattr(props, "tags", None) or []
    if driver_name == _GENERIC_ASH_TOOL_NAME:
        for tag in tags:
            if isinstance(tag, str) and tag.lower() in SCANNER_TAG_NAMES:
                return tag
    return driver_name


def occurrence_context(
    result: Any, run: Any, scanner: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Curate source references or retain a strictly validated composed context."""
    if is_composed_run(run):
        cached = persisted_context(result, run)
        return copy.deepcopy(cached) if cached is not None else None
    context: Dict[str, Any] = {"version": CONTEXT_VERSION}
    scanner = scanner or _scanner(result, run)
    resolved_locations = []
    for location in getattr(result, "locations", None) or []:
        physical = getattr(location.physicalLocation, "root", None)
        selected: Dict[str, Any] = {}
        artifact = getattr(physical, "artifactLocation", None)
        index = getattr(artifact, "index", None)
        if type(index) is int and index >= 0:
            selected["artifact"] = _chain(
                index,
                getattr(run, "artifacts", None),
                lambda node: _artifact_entry(node, run),
            )
        base = getattr(artifact, "uriBaseId", None)
        if isinstance(base, str) and base:
            selected["bases"] = _base_chain(base, run)
        address_refs = _references(
            getattr(physical, "address", None),
            getattr(run, "addresses", None),
            _address_entry,
        )
        if address_refs:
            selected["address"] = address_refs
        logical_refs = []
        for logical in location.logicalLocations or []:
            references = _references(
                logical, getattr(run, "logicalLocations", None), _logical_entry
            )
            if references:
                logical_refs.append(
                    {"location": _logical_entry(logical), "references": references}
                )
        if logical_refs:
            selected["logical"] = sorted(logical_refs, key=_canonical_identity_json)
        if selected:
            selected["location"] = _location_identity(location)
            resolved_locations.append(selected)
    if resolved_locations:
        context["locations"] = sorted(resolved_locations, key=_canonical_identity_json)
    inline = _occurrence_locations(result)
    if not any(
        item.get("artifact", {}).get("uri") or "index" in item.get("artifact", {})
        for item in inline
    ):
        target = getattr(result, "analysisTarget", None)
        index = getattr(target, "index", None)
        selected_target: Dict[str, Any] = {
            "location": _identity_fields(target, ("uri", "uriBaseId"), ("index",))
        }
        if type(index) is int and index >= 0:
            selected_target["artifact"] = _chain(
                index,
                getattr(run, "artifacts", None),
                lambda node: _artifact_entry(node, run),
            )
        base = getattr(target, "uriBaseId", None)
        if isinstance(base, str) and base:
            selected_target["bases"] = _base_chain(base, run)
        if len(selected_target) > 1:
            context["analysis_target"] = selected_target
    reference = _rule_reference_identity(result)
    index = getattr(result, "ruleIndex", None)
    if type(index) is int and index >= 0:
        context["rule_index"] = index
    if reference:
        context["rule_reference"] = reference
    message = getattr(result.message, "root", result.message)
    needs_message = getattr(message, "text", None) is None
    direct_arguments = not result.ruleId and _has_used_arguments(
        getattr(message, "text", None), getattr(message, "arguments", None)
    )
    if reference or "rule_index" in context or needs_message or direct_arguments:
        component = _owning_component(result, run, scanner)
        rule = _owning_rule(result, component)
        selected_component = _identity_fields(component, ("name", "guid"))
        selected_rule = _identity_fields(rule, ("id", "guid"))
        if selected_component:
            context["component"] = selected_component
        if selected_rule:
            context["resolved_rule"] = selected_rule
        text, message_id, available = _message_resolution(result, scanner, run)
        value = {"state": "resolved" if available else "unavailable", "text": text}
        if message_id is not None:
            value["id"] = message_id
        context["message"] = value
    return context if len(context) > 1 else None
