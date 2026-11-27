# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusals of a scanner selection that cannot mean what it says.

Two of them. An allowlist its own exclusions empty is refused by
:func:`selection_after_exclusions`, which ``ScanExecutionEngine`` and the
workspace pre-flight both call, so the two refuse in the same words.

An allowlist that names no registered scanner is refused by
:func:`refuse_selection_matching_no_scanner`. ``ScanExecutionEngine`` makes that
check when it is built, from the registered scanner classes, so that
``ASHScanOrchestrator.create`` refuses the command line before the orchestrator
asks git anything or clears the output directory. ``ScanPhase`` makes it again
from the instantiated scanners, where the names first became authoritative; that
check stays as the backstop for an engine built some other way. An exclusion that
matches no scanner is not refused, but :func:`exclusions_matching_no_scanner` names
it so that ``ScanPhase`` can warn.

Also the names a selection's two inputs go by for each origin, which
``interactions.run_ash_scan`` needs at import time for ``ScanOptions``. This
module imports nothing that loads the phases or the config models, and that is
why the names live here and not in ``core.phases.scanner_selection``: importing
that package loads ``config.ash_config``, and ``run_ash_scan`` has to leave it
unloaded (see tests/unit/models/test_forward_ref_resolves_in_any_import_order.py).
"""

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Literal, Optional, Sequence

from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ScannerSelectionError,
)
from automated_security_helper.utils.scanner_names import selection_key

#: Who made the scanner selection: the CLI's ``--scanners`` and
#: ``--exclude-scanners``, or the MCP workspace tool's ``scanners`` and
#: ``excluded_scanners`` parameters. Only the MCP tool sets "mcp".
SelectionOrigin = Literal["cli", "mcp", "config", "cli+config", "mcp-config"]

AllowlistOrigin = Literal["mode", "operator", "precommit", "cli", "cli+operator"]


@dataclass(frozen=True)
class SelectionNames:
    """How a SKIPPED row and a selection refusal name the selection's two inputs.

    Attributes:
        allowlist: What names the scanners to run.
        exclusion: What names the scanners to leave out.
        drop_one: The sentence a refusal ends with when the two cancel out.
    """

    allowlist: str
    exclusion: str
    drop_one: str


_SELECTION_NAMES: Dict[str, SelectionNames] = {
    "cli": SelectionNames(
        allowlist="--scanners",
        exclusion="--exclude-scanners",
        drop_one="Drop one of the two flags.",
    ),
    "mcp": SelectionNames(
        allowlist="the scanners parameter",
        exclusion="the excluded_scanners parameter",
        drop_one="Drop one of the two.",
    ),
    "cli+config": SelectionNames(
        allowlist="--scanners and default_scanners in the ASH config",
        exclusion="--exclude-scanners",
        drop_one=(
            "Drop the exclusion, or change the flags or default_scanners in the "
            "operator's ASH config."
        ),
    ),
    "mcp-config": SelectionNames(
        allowlist="default_scanners in the ASH config",
        exclusion="the excluded_scanners parameter",
        drop_one=(
            "Drop the exclusion, or change default_scanners in the operator's "
            "ASH config."
        ),
    ),
    "config": SelectionNames(
        allowlist="default_scanners in the ASH config",
        exclusion="--exclude-scanners",
        drop_one=(
            "Drop the exclusion, or change default_scanners in the operator's "
            "ASH config."
        ),
    ),
}


@dataclass(frozen=True)
class FoldedSelection:
    names: List[str]
    origin: Optional[AllowlistOrigin]


def _unique(names: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(names))


@dataclass(frozen=True)
class SelectionLayers:
    mode_default: Sequence[str] = ()
    precommit_only: Sequence[str] = ()
    precommit_add: Sequence[str] = ()
    cli_only: Optional[Sequence[str]] = None
    cli_additive: Sequence[str] = ()
    workspace_required: Sequence[str] = ()

    def fold(
        self,
        operator_only: Sequence[str] = (),
        operator_add: Sequence[str] = (),
    ) -> FoldedSelection:
        if self.cli_only is not None:
            return FoldedSelection(list(self.cli_only), "cli")
        base: List[str] = list(self.mode_default)
        origin: Optional[AllowlistOrigin] = "mode" if base else None
        if operator_only:
            base, origin = list(operator_only), "operator"
        elif operator_add and base:
            base, origin = base + list(operator_add), "operator"
        if self.precommit_only:
            base, origin = list(self.precommit_only), "precommit"
        elif self.precommit_add and base:
            base, origin = base + list(self.precommit_add), "precommit"
        if base:
            base += list(self.workspace_required)
        if not self.cli_additive:
            return FoldedSelection(_unique(base), origin)
        if not base:
            return FoldedSelection(list(self.cli_additive), "cli")
        return FoldedSelection(
            _unique([*self.cli_additive, *base]),
            "cli+operator" if origin == "operator" else "cli",
        )


def selection_names(origin: SelectionOrigin = "cli") -> SelectionNames:
    """The names for *origin*'s selection inputs; the CLI's for any other value."""
    return _SELECTION_NAMES.get(origin, _SELECTION_NAMES["cli"])


def selection_after_exclusions(
    enabled: Sequence[str],
    excluded: Sequence[str],
    origin: SelectionOrigin = "cli",
) -> List[str]:
    """The allowlist *enabled* leaves once the names in *excluded* are taken out.

    Names are compared lower-cased and stripped, as the subtraction always
    compared them. An empty *enabled* comes back empty: an allowlist that was
    never given means no narrowing, and exclusions alone narrow the run in
    ScanPhase.

    Args:
        enabled: The ``--scanners`` names, or the MCP workspace tool's
            ``scanners``, already split on commas.
        excluded: The ``--exclude-scanners`` names, or its ``excluded_scanners``.
        origin: Who made the selection; the refusal names that caller's own
            inputs, the flags or the parameters.

    Raises:
        ScannerSelectionError: When *excluded* takes out every name in a
            non-empty *enabled*. Refused rather than resolved to either reading.
            Once the subtraction has run, an allowlist emptied by exclusions
            looks like one never given, and the scan phase reads an empty
            allowlist as "run every scanner": on a host with five of the ten
            tools installed, ``--scanners detect-secrets
            --exclude-scanners detect-secrets`` would run the nine scanners
            nobody asked for and SKIP the one that was. Running nothing instead
            would put every scanner in SKIPPED, which the completeness gate
            tolerates one entry at a time, so it would be a silent zero rather
            than a visible refusal.
    """
    # A stray comma ("--scanners bandit,") leaves an empty name, which names no
    # scanner and is no exclusion either. Left in, it survived the subtraction
    # and the refusal below never fired: "--scanners bandit, --exclude-scanners
    # bandit" came back as [""], and the later check called that a misspelling
    # of an empty name. An allowlist of nothing but empty names is left as given
    # so the check for names that match no scanner still refuses it.
    named = [name for name in enabled if name.strip()]
    if named:
        enabled = named
    excluded = [name for name in excluded if name.strip()]
    if not enabled or not excluded:
        return list(enabled)
    # Compared by the name a retired spelling resolves to, so
    # ``--scanners opengrep --exclude-scanners semgrep`` is the cancelled selection
    # it is: the scan phase serves ``semgrep`` with opengrep and would otherwise
    # run nothing for an allowlist this check let through.
    excluded_keys = {selection_key(name) for name in excluded}
    remaining = [name for name in enabled if selection_key(name) not in excluded_keys]
    if remaining:
        return remaining
    names = selection_names(origin)
    raise ScannerSelectionError(
        f"Every scanner named by {names.allowlist} is also named by "
        f"{names.exclusion}, so the selection cancels itself: "
        f"selected {', '.join(enabled)}; excluded {', '.join(excluded)}. "
        "Refused rather than guessed: an empty allowlist means "
        "'every scanner' further down, so this would silently run "
        "the scanners you excluded and skip the ones you chose. "
        f"{names.drop_one}"
    )


def refuse_selection_matching_no_scanner(
    requested: Sequence[str],
    registered_names: Iterable[str],
    origin: SelectionOrigin = "cli",
) -> None:
    """Raise ScannerSelectionError when none of *requested* is registered.

    Names are compared lower-cased and stripped, as ScanPhase compares them. A
    partly unresolvable allowlist is not refused: such a run still scans what did
    resolve, and ScanPhase warns about the rest.

    Args:
        requested: The ``--scanners`` names, after ``--exclude-scanners``, or the
            MCP workspace tool's ``scanners`` after its ``excluded_scanners``.
        registered_names: The registered scanners' selectable names.
        origin: Who made the selection; the refusal names that caller's own
            input, the flag or the parameter.
    """
    registered = sorted({selection_key(name) for name in registered_names})
    if not requested or not registered:
        return
    if any(selection_key(name) in registered for name in requested):
        return
    shown = sorted(name for name in requested if name.strip()) or ["(an empty name)"]
    raise ScannerSelectionError(
        "None of the requested scanners exist: "
        f"{', '.join(shown)}. "
        f"Registered scanners: {', '.join(registered)}. "
        "Refused rather than scanned, because an allowlist that "
        "matches nothing selects nothing: every scanner would be "
        "recorded SKIPPED, the run would produce no findings, and a "
        "scan that checked nothing would report itself clean. Check "
        "the spelling -- names use hyphens, not underscores -- or "
        f"drop {selection_names(origin).allowlist} to run them all."
    )


def exclusions_matching_no_scanner(
    excluded: Iterable[str],
    registered_names: Iterable[str],
) -> List[str]:
    """The names in *excluded* that no registered scanner goes by.

    An exclusion that matches nothing is not refused: a command line shared by
    several ASH versions or installs may name a scanner this one does not have.
    But it is silent, and a misspelled exclusion ("--exclude-scanners
    detect_secrets") leaves the scanner the operator meant to leave out running,
    so the caller says so.

    Names compare lower-cased and stripped, as the subtraction and ScanPhase
    compare them. Each name comes back once, in the spelling it was given.
    Empty names (a stray comma) are not reported. With no registered names there
    is nothing to compare against, and the answer is empty.

    Args:
        excluded: The ``--exclude-scanners`` names, or the MCP workspace tool's
            ``excluded_scanners``.
        registered_names: The registered scanners' selectable names.
    """
    registered = {selection_key(name) for name in registered_names}
    if not registered:
        return []
    unmatched: Dict[str, str] = {}
    for name in excluded:
        key = selection_key(name)
        if key and key not in registered:
            unmatched.setdefault(key, name.strip())
    return list(unmatched.values())


def _normalized(names: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(n.strip().lower() for n in names if n.strip()))


def selection_marker(only: Iterable[str], add: Iterable[str]) -> str:
    return json.dumps(
        {"only": _normalized(only), "add": _normalized(add)}, sort_keys=True
    )


def refuse_unmet_selection_marker(
    marker: str, only: Iterable[str], add: Iterable[str]
) -> None:
    try:
        wanted = json.loads(marker)
        ok = (
            isinstance(wanted, dict)
            and set(wanted) == {"only", "add"}
            and all(
                isinstance(wanted[key], list)
                and all(isinstance(n, str) for n in wanted[key])
                for key in wanted
            )
        )
    except ValueError:
        ok = False
    if not ok:
        raise ASHConfigValidationError(
            "The default_scanners check this scan was asked to make is not "
            "readable, so no scanner was started."
        )
    if json.loads(selection_marker(wanted["only"], wanted["add"])) != json.loads(
        selection_marker(only, add)
    ):
        raise ASHConfigValidationError(
            "The default_scanners this scan settled differs from the one the "
            "host read from the operator's config, so no scanner was started. "
            "The operator's config may not be mounted in the container, or the "
            "image reads it differently."
        )
