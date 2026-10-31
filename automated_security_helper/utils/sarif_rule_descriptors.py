# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rule a result's message is resolved against.

A SARIF message may name a string of its rule (``messageStrings``) instead of
carrying text, and a rule may leave a string to its tool component
(``globalMessageStrings``, SARIF 2.1.0 3.11.10), so the description of such a
result lives on the rule or on the component that declares it.

ASH writes one run per project whose ``tool.driver`` is ASH and whose
``tool.extensions`` are the scanners, each with its own rules, and same-named
extensions coexist. Two scanners can declare one rule id with different message
strings (grype and trivy on a CVE), so a map keyed on the bare rule id, built
over every run and extension and keeping the first descriptor, resolved one
scanner's message against another's. The lookup here is scoped the way the
SARIF dump scopes a result's ``rule`` reference: to the run the result sits in,
and within it to the component the result names (``rule.toolComponent``), else
the component its scanner name names, else the driver and then the extensions
in order.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from automated_security_helper.utils.sarif_utils import (
    result_rule_id,
    result_scanner_name,
)


@dataclass(frozen=True)
class RuleDescriptor:
    """What :func:`sarif_utils.result_message_text` reads from a rule.

    ``messageStrings`` holds the component's ``globalMessageStrings`` under the
    rule's own ``messageStrings`` (the rule's string wins, 3.11.10), so one
    lookup answers both. The attribute names are the SARIF property names so the
    reader treats this like the rule itself.
    """

    id: str
    messageStrings: Dict[str, Any] = field(default_factory=dict)
    shortDescription: Any = None


def _components(tool: Any) -> List[Any]:
    """The tool's driver, then its extensions, in order (skipping a missing one)."""
    found = [getattr(tool, "driver", None)]
    found.extend(getattr(tool, "extensions", None) or [])
    return [component for component in found if component is not None]


def _component_named_by(reference: Any, tool: Any) -> Optional[Any]:
    """The component a ``toolComponentReference`` points at, or None.

    ``index`` is a position in ``tool.extensions`` (``-1`` names none); a
    reference with only a name is matched against the driver and then the
    extensions.
    """
    extensions = list(getattr(tool, "extensions", None) or [])
    index = getattr(reference, "index", None)
    if isinstance(index, int) and 0 <= index < len(extensions):
        return extensions[index]
    name = getattr(reference, "name", None)
    if isinstance(name, str) and name:
        for component in _components(tool):
            if getattr(component, "name", None) == name:
                return component
    return None


def _candidate_components(result: Any, tool: Any) -> List[Any]:
    """The components to look the result's rule up in, in order."""
    reference = getattr(result, "rule", None)
    reference = getattr(reference, "root", reference)
    named = getattr(reference, "toolComponent", None)
    if named is not None:
        component = _component_named_by(named, tool)
        if component is not None:
            return [component]
    components = _components(tool)
    scanner = result_scanner_name(result)
    if scanner:
        by_scanner = [c for c in components if getattr(c, "name", None) == scanner]
        if by_scanner:
            return by_scanner
    return components


def _rule_in(component: Any, rule_id: str, hint: Any) -> Optional[Any]:
    """The rule of *component* with id *rule_id*, taking the one at position
    *hint* when it has that id (so same-id rules stay apart), else the first."""
    rules = list(getattr(component, "rules", None) or [])
    if isinstance(hint, int) and 0 <= hint < len(rules):
        if getattr(rules[hint], "id", None) == rule_id:
            return rules[hint]
    for rule in rules:
        if getattr(rule, "id", None) == rule_id:
            return rule
    return None


def _descriptor(component: Any, rule: Any, rule_id: str) -> RuleDescriptor:
    strings: Dict[str, Any] = {}
    strings.update(getattr(component, "globalMessageStrings", None) or {})
    strings.update(getattr(rule, "messageStrings", None) or {})
    return RuleDescriptor(
        id=rule_id,
        messageStrings=strings,
        shortDescription=getattr(rule, "shortDescription", None),
    )


def _descriptor_for(result: Any, tool: Any) -> Optional[RuleDescriptor]:
    rule_id = result_rule_id(result)
    if not rule_id:
        return None
    reference = getattr(result, "rule", None)
    reference = getattr(reference, "root", reference)
    hint = getattr(reference, "index", None)
    if not (isinstance(hint, int) and hint >= 0):
        hint = getattr(result, "ruleIndex", None)
    for component in _candidate_components(result, tool):
        rule = _rule_in(component, rule_id, hint)
        if rule is not None:
            return _descriptor(component, rule, rule_id)
    return None


def rule_descriptors_by_result(sarif: Any) -> List[Optional[RuleDescriptor]]:
    """The descriptor each result's message is resolved against, one entry per
    result in ``get_all_results()`` order; None where the result names no rule or
    no component declares it.

    A result whose lookup raises gets None: the descriptor only improves a
    description, so its absence costs the text, not the report.
    """
    found: List[Optional[RuleDescriptor]] = []
    for run in getattr(sarif, "runs", None) or []:
        tool = getattr(run, "tool", None)
        for result in getattr(run, "results", None) or []:
            try:
                found.append(_descriptor_for(result, tool))
            except Exception:  # noqa: BLE001 -- see the docstring
                found.append(None)
    return found
