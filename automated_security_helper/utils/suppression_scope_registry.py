# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where suppression-scope engine blocks meet the plugins that own them.

A suppression's ``scope.engines`` map (models/core.py SuppressionScope) carries
one block per scanner name, opaque to ASH's core. The named scanner plugin
owns the block: it validates it at config time and matches it against its own
findings at suppression time, through the three hooks ScannerPluginBase
declares (``validate_suppression_scope``, ``suppression_scope_matches``,
``split_rule_qualifier``).

This module is the meeting point. A plugin whose hooks do something registers
itself here when its module loads (``register_suppression_scope_engine``);
the matcher and the config checks look the scanner name up
(``engine_hooks_for``). It lives in utils, below both the models and the
plugins, so ``AshSuppression.matches`` can dispatch without importing any
plugin and no import cycle forms.

Everything fails closed. A scanner name with no registration -- the plugin is
not installed, not enabled this run, or does not support engine-scoped
suppressions -- matches nothing, and ``warn_once_unmatched_engine`` says so
once per name so an entry that silently stopped suppressing is visible.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, Set, Tuple

from automated_security_helper.utils.log import ASH_LOGGER


class SupportsSuppressionScope(Protocol):
    """The three hooks a scope-owning plugin class exposes.

    Structural: the registry stores class objects, which satisfy this through
    their bound classmethods (PEP 544), so a test's fake hooks class matches
    without inheriting ScannerPluginBase. The parameters stay ``Any`` because
    this module sits below the models and must not import them.
    """

    def validate_suppression_scope(self, block: Any) -> List[str]: ...

    def suppression_scope_matches(self, block: Any, finding: Any) -> bool: ...

    def split_rule_qualifier(self, rule_id: str) -> Tuple[str, Optional[str]]: ...


#: Scanner name -> the plugin class whose scope hooks handle its blocks.
#: Registration is per process, at plugin-module import, like the plugin
#: manager's own registry.
_ENGINE_HOOKS: Dict[str, SupportsSuppressionScope] = {}

#: Engine names already warned about this process, so a scan with many
#: findings logs each missing engine once.
_WARNED_ENGINES: Set[str] = set()


def register_suppression_scope_engine(
    scanner_name: str, plugin_cls: SupportsSuppressionScope
) -> None:
    """Register ``plugin_cls`` as the owner of ``scanner_name``'s scope blocks."""
    _ENGINE_HOOKS[scanner_name] = plugin_cls


def engine_hooks_for(
    scanner_name: Optional[str],
) -> Optional[SupportsSuppressionScope]:
    """The plugin class owning ``scanner_name``'s blocks, or None."""
    if scanner_name is None:
        return None
    return _ENGINE_HOOKS.get(scanner_name)


def registered_engine_names() -> Set[str]:
    """Every scanner name with registered scope hooks."""
    return set(_ENGINE_HOOKS)


def reset_unmatched_engine_warnings() -> None:
    """Forget which engines were warned about, so the next scan warns again.

    The set is per process, and a long-lived process (the MCP server, a
    workspace scan) runs many scans: without the reset only the first scan got
    the receipt that a listed engine's blocks suppress nothing. The execution
    engine calls this as it initializes.
    """
    _WARNED_ENGINES.clear()


def warn_once_unmatched_engine(scanner_name: str) -> None:
    """Warn, once per name, that a listed engine's blocks suppress nothing.

    Fail closed is the safe direction, and this is its receipt: without it an
    entry whose plugin went missing would stop suppressing with no sign.
    """
    if scanner_name in _WARNED_ENGINES:
        return
    _WARNED_ENGINES.add(scanner_name)
    ASH_LOGGER.warning(
        f"A suppression lists '{scanner_name}' under scope.engines, but no "
        "loaded scanner plugin of that name supports engine-scoped "
        "suppressions this run; its findings are NOT suppressed by that entry "
        "(fail closed)."
    )


def split_rule_qualifier_for(
    scanner_name: Optional[str], rule_id: str
) -> Tuple[str, Optional[str]]:
    """``(base, qualifier)`` for ``rule_id`` as the producing engine spells it.

    Dispatched to the scanner's ``split_rule_qualifier`` hook when one is
    registered; the default is ``(rule_id, None)``, no split.
    """
    hooks = engine_hooks_for(scanner_name)
    if hooks is None:
        return rule_id, None
    return hooks.split_rule_qualifier(rule_id)


def suppression_scope_problems(
    suppressions: Any,
    registered_scanner_names: Set[str],
    where: str = "global_settings.suppressions",
) -> List[str]:
    """What is wrong with the ``scope.engines`` blocks of ``suppressions``.

    Called once the run's scanner plugins are known, because a config loads
    before its plugin modules do. Two kinds of problem, both worded for the
    config's author: an engine name no registered scanner carries (with a
    did-you-mean over the registered names), and a known name's block the
    owning plugin refuses (its ``validate_suppression_scope`` strings). The
    caller routes them through the same warn-then-refuse policy as unknown
    keys (fail_on_unknown_keys).
    """
    from automated_security_helper.utils.unknown_keys import closest_key

    problems: List[str] = []
    for index, entry in enumerate(suppressions or []):
        scope = getattr(entry, "scope", None)
        engines = getattr(scope, "engines", None) if scope is not None else None
        if not engines:
            continue
        location = f"{where}[{index}]"
        for name, block in engines.items():
            if name not in registered_scanner_names:
                suggestion = closest_key(name, registered_scanner_names)
                problems.append(
                    f"{location}: scope.engines names '{name}', which is not a "
                    "scanner registered for this run"
                    + (f" (did you mean '{suggestion}'?)" if suggestion else "")
                    + "; its findings are not suppressed by this entry."
                )
                continue
            hooks = engine_hooks_for(name)
            if hooks is None:
                problems.append(
                    f"{location}: scanner '{name}' does not support "
                    "engine-scoped suppressions; its block suppresses nothing."
                )
                continue
            problems.extend(
                f"{location}: {problem}"
                for problem in hooks.validate_suppression_scope(block)
            )
    return problems
