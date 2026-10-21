# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whether the operator's scanner selection asks for a scanner.

One definition for the two places that ask: ``ScanPhase``'s selection loop, which
decides what this run executes, and the shard provenance, which records what the
selection asks for over every candidate scanner (``ShardAssignment.
intended_scanners``) so that ``ash merge`` can tell a scanner no job asked for from
one a job asked for and its owner did not run. Two copies of the rule would drift,
and a drift reads at merge time as a coverage hole that is not there, or hides one
that is.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional, Set


@dataclass(frozen=True)
class OperatorSelection:
    """The answers of the operator's filters for one scanner.

    Attributes:
        excluded: Named by ``--exclude-scanners`` (or, inside a shard, by the
            exclusions the shard adds).
        in_allowlist: ``--scanners`` is empty or names the scanner.
        enabled: The scanner's config has ``enabled`` set.
        python_only_ok: ``--python-only`` is off, or the scanner is Python-only.
    """

    excluded: bool
    in_allowlist: bool
    enabled: bool
    python_only_ok: bool = True

    @property
    def selected(self) -> bool:
        return (
            not self.excluded
            and self.in_allowlist
            and self.enabled
            and self.python_only_ok
        )


def _names(values: Optional[Iterable[str]]) -> Set[str]:
    return {value.lower().strip() for value in values or []}


def operator_selection(
    plugin_instance: Any,
    display_name: str,
    *,
    enabled_scanners: Optional[Iterable[str]] = None,
    excluded_scanners: Optional[Iterable[str]] = None,
    python_only: bool = False,
) -> OperatorSelection:
    """What the operator's selection says about *plugin_instance*.

    Names compare case-insensitively and without surrounding spaces, as everywhere
    else in the scan phase. A config without an ``enabled`` attribute counts as
    disabled, which cannot happen for a constructed scanner (``ScanPhase`` explains
    why). A scanner whose ``is_python_only`` raises counts as not Python-only.
    """
    name = display_name.lower().strip()
    allowlist = _names(enabled_scanners)
    config = getattr(plugin_instance, "config", None)
    python_only_ok = True
    if python_only:
        try:
            python_only_ok = bool(plugin_instance.is_python_only())
        except Exception:  # plugin-supplied, so the exception set is open
            python_only_ok = False
    return OperatorSelection(
        excluded=name in _names(excluded_scanners),
        in_allowlist=not allowlist or name in allowlist,
        enabled=bool(getattr(config, "enabled", False)),
        python_only_ok=python_only_ok,
    )
