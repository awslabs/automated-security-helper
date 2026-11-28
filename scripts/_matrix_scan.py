"""The scanners matrix: how each scanner ASH ships loads, installs and runs where.

One row per scanner manifest. The manifests are the one list of scanners (a name, a
tier, whether the scanner's module loads on its own, which module to list when it does
not), so no list of scanners is written here: a scanner admitted with a manifest and the
two facet declarations every scanner class carries has a row the next time the generator
runs, and a scanner that is promoted from alpha moves to the supported rows the same way.

What each cell is read from
---------------------------
* Tier, "Loads on its own" and "Module to list": the manifest. A deprecated scanner
  names the scanner that supersedes it, and a manifest that names none, or one that has
  no manifest of its own, is refused.
* "Install methods": the runtime kind in the scanner class's operational facets,
  through ``RUNTIME_ROUTES``. A new runtime kind with no route word fails a unit test
  and, until it has one, this module.
* The six platform columns, one per ``PLATFORMS_ALL`` pair, hold the first reading that
  applies (see ``os_state``): the scanner's own refusal of that operating system, then
  whether the facets name a download for that pair, then the scanner's ``enabled``
  setting for that operating system, then the facets' provisionable pairs. The refusal
  is read through ``platform_refusal`` on the scanner's class, and the ``enabled``
  setting through ``platform_defaults``, which evaluates the class's own default
  expression once per operating system, so none of it depends on the machine that
  renders the page.
* "Linux libc": not measured for any row. The pinned downloads do not record which C
  library they link against, so the column says so instead of guessing.
* "Operating systems" (README view only): the six platform cells, grouped.

Where the data comes from, in one place
---------------------------------------
``read_scanner_inputs`` reads the world once and builds ``ScannerInput`` rows; the rest
of the module is pure functions of those rows, so a unit test plants any input it likes
and the page for a real tree is the same function over real inputs. ASH is imported only
inside ``read_scanner_inputs`` and the second source, never at module level, so loading
this file costs nothing and a unit test of the pure parts needs no ASH.

A limit: a scanner class that declares no operational facets, that no plugin package
registers, or whose refusal cannot be read from its class alone (an override that needs
``self``) is refused rather than shown with a guessed cell.
"""

from __future__ import annotations

import contextlib
import importlib.util
import os
import re
import sys
import types
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from _support_model import (
    DOCS,
    NAME,
    OS_NAMES,
    README,
    STATE,
    VALUE,
    CollectContext,
    Column,
    Matrix,
    ModelError,
    Row,
    SecondSource,
    platform_refusal,
)

MATRIX_NAME = "scanners"

#: The tiers a manifest can carry, with the position each takes in the table:
#: supported scanners first, then the ones being retired, then the alpha ones.
TIER_ORDER = {"supported": 0, "deprecated": 1, "alpha": 2}

#: How the note for ``loads only when its module is listed`` words a scanner of each
#: tier. The manifest model keeps maturity (the tier) apart from loading
#: (``default_enabled``): a maintained scanner that is opt-in is ``supported``, and
#: calling it alpha would misstate its maturity. So an alpha scanner keeps the alpha
#: wording, and a scanner of any other tier is described as opt-in.
LOADING_WORDING = {"supported": "opt-in", "deprecated": "opt-in", "alpha": "alpha"}

#: How a scanner's tool reaches the machine, by runtime kind (the ``RuntimeKind`` values).
RUNTIME_ROUTES = {
    "uv_python": "Python tool run with uv",
    "pinned_binary": "pinned binary that ASH downloads",
    "ruby_gem": "Ruby gem",
    "node_subcommand": "Node.js package manager command",
    "in_process": "built into ASH",
    "user_installed_cli": "CLI you install yourself",
    "pypi_package": "PyPI package",
}

#: One platform column per ``PLATFORMS_ALL`` pair, Linux first. Each row is the pair,
#: the column key, the column header, the operating system as ``platform.system()``
#: names it, and the family and CPU words the README summary uses.
PLATFORM_COLUMNS = (
    ("linux/amd64", "linux_x86_64", "Linux x86-64", "Linux", "Linux", "x86-64"),
    ("linux/arm64", "linux_arm64", "Linux arm64", "Linux", "Linux", "arm64"),
    ("darwin/amd64", "macos_intel", "macOS Intel", "Darwin", "macOS", "Intel"),
    (
        "darwin/arm64",
        "macos_apple_silicon",
        "macOS Apple silicon",
        "Darwin",
        "macOS",
        "Apple silicon",
    ),
    (
        "windows/amd64",
        "windows_x86_64",
        "Windows x86-64",
        "Windows",
        "Windows",
        "x86-64",
    ),
    ("windows/arm64", "windows_arm64", "Windows arm64", "Windows", "Windows", "arm64"),
)

#: What the config reference calls each operating system in a per-platform default.
_CONFIG_LABELS = {"Linux": "Linux", "Darwin": "macOS", "Windows": "Windows"}

NOT_MEASURED = "not measured"
LOADS = "yes"
LOADS_WHEN_LISTED = "loads only when its module is listed"
BUILT_IN = "built in"

_BOTH = frozenset({README, DOCS})
_DOCS_ONLY = frozenset({DOCS})
_README_ONLY = frozenset({README})

_TIER_PATTERN = r"supported|alpha|deprecated, superseded by `[a-z0-9][a-z0-9-]*`"
_MODULE_PATTERN = r"built in|`[A-Za-z0-9_.]+`"
_ROUTE_PATTERN = "|".join(re.escape(word) for word in RUNTIME_ROUTES.values())
_SUMMARY_PATTERN = r"(?:Linux|macOS|Windows).+"


def _platform_column(pair: str, key: str, header: str, os_name: str) -> Column:
    return Column(
        key=key,
        header=header,
        views=_DOCS_ONLY,
        kind=STATE,
        source=(
            f"The scanner's own refusal of {os_name}, then whether the facets name a "
            f"download for {pair}, then the scanner's enabled setting on {os_name}, "
            "then the facets' provisionable platforms. The first that applies is "
            "shown."
        ),
    )


COLUMNS = (
    Column(
        key="scanner",
        header="Scanner",
        views=_BOTH,
        kind=NAME,
        source="The name in the scanner's manifest, which is its name in the config.",
    ),
    Column(
        key="tier",
        header="Tier",
        views=_BOTH,
        kind=VALUE,
        pattern=_TIER_PATTERN,
        source=(
            "The tier in the manifest. A deprecated scanner names the scanner that "
            "supersedes it."
        ),
    ),
    Column(
        key="loads",
        header="Loads on its own",
        views=_DOCS_ONLY,
        kind=STATE,
        source=(
            "The manifest: whether the scanner's module loads without being listed "
            "in ash_plugin_modules."
        ),
    ),
    Column(
        key="module",
        header="Module to list",
        views=_DOCS_ONLY,
        kind=VALUE,
        pattern=_MODULE_PATTERN,
        source=(
            "The manifest's plugin module, which ash_plugin_modules names to load a "
            "scanner that does not load on its own; a scanner that loads on its own is "
            "built in."
        ),
    ),
    Column(
        key="install",
        header="Install methods",
        views=_BOTH,
        kind=VALUE,
        pattern=_ROUTE_PATTERN,
        source=(
            "The runtime kind in the scanner class's operational facets, as the way "
            "its tool reaches the machine."
        ),
    ),
    *(
        _platform_column(pair, key, header, os_name)
        for pair, key, header, os_name, _family, _cpu in PLATFORM_COLUMNS
    ),
    Column(
        key="libc",
        header="Linux libc",
        views=_DOCS_ONLY,
        kind=STATE,
        source=(
            "Not read: the pinned downloads do not record the C library they link "
            "against, so every row says it was not measured."
        ),
    ),
    Column(
        key="os_summary",
        header="Operating systems",
        views=_README_ONLY,
        kind=VALUE,
        pattern=_SUMMARY_PATTERN,
        source="The six platform cells, with equal cells grouped.",
    ),
)

INTRO = (
    "One row for every scanner manifest: supported scanners first, then deprecated "
    "ones, then alpha ones, each group by name. A scanner that loads on its own needs "
    "no setting. Any other scanner loads only when `ash_plugin_modules` lists its "
    "module. The platform columns say what ASH declares about running the scanner on "
    "each operating system and CPU."
)

#: What each phrase of a state column means, in the order the notes list them. A phrase
#: a row uses with no entry here is refused, so the notes explain every phrase shown.
#: The entry for ``loads only when its module is listed`` is the opt-in wording, which
#: is true of a scanner of any tier; ``_loading_note`` swaps in the alpha wording when
#: every scanner that carries the phrase is alpha.
_PHRASE_NOTES = {
    LOADS: "the scanner's module loads on every scan.",
    LOADS_WHEN_LISTED: (
        "the scanner is opt-in: a scan loads its module only when "
        "`ash_plugin_modules` names the module shown under Module to list."
    ),
    "provisioned": (
        "ASH downloads a pinned release of the scanner's tool built for this "
        "operating system and CPU."
    ),
    "no asset": (
        "ASH downloads this scanner's tool, and the pinned release has no build for "
        "this operating system and CPU."
    ),
    "refused: <reason>": (
        "the scanner itself states that it cannot run on this operating system, in "
        "the words shown."
    ),
    "off by default": (
        "the scanner's configuration turns it off on this operating system until you "
        "enable it."
    ),
    "package-defined (not declared)": (
        "ASH provisions no download for this scanner, so where it runs is where the "
        "package or tool it uses runs, and ASH declares no list of those platforms."
    ),
    NOT_MEASURED: (
        "nothing in the code or the register states this fact, so the table does not "
        "guess it."
    ),
}

#: The note for ``loads only when its module is listed`` in a table where every scanner
#: that carries the phrase is alpha.
_ALPHA_LOADING_NOTE = (
    "the scanner is in an alpha module, which a scan loads only when "
    "`ash_plugin_modules` names the module shown under Module to list."
)

_PRECEDENCE_NOTE = (
    "A platform cell shows the first reading that applies, in this order: the "
    "scanner's refusal, no asset, off by default, provisioned, package-defined."
)


@dataclass(frozen=True, eq=False)
class ScannerInput:
    """Everything the matrix says about one scanner, read once from the code.

    ``refusals`` and ``enabled`` are keyed by operating system as ``platform.system()``
    names it (``OS_NAMES``): the reason the scanner refuses that system, or None, and
    whether its configuration enables it there by default. ``provisionable`` is the
    ``os/arch`` pairs the facets say ASH downloads the tool for, and ``page`` is the
    repository-relative path of the scanner's own docs page, when it has one.
    """

    name: str
    tier: str
    superseded_by: str | None
    default_enabled: bool
    plugin_module: str
    runtime_kind: str
    provisionable: tuple[str, ...]
    refusals: Mapping[str, str | None]
    enabled: Mapping[str, bool]
    page: str | None


def os_state(
    *,
    refusal: str | None,
    provisionable: Sequence[str],
    pair: str,
    enabled: bool,
) -> str:
    """The cell for one platform pair: the first reading that applies.

    The scanner's own refusal comes first, because it is the scanner stating it cannot
    run there. Then "no asset": ASH downloads the tool, and the pinned release has no
    build for this pair. Then "off by default", which hides "provisioned" for a scanner
    that has a download and is off there. Then "provisioned". A scanner the facets list
    no downloads for is "package-defined (not declared)": its platforms are its
    package's, and the register declares none.
    """
    if refusal is not None:
        return f"refused: {' '.join(refusal.split())}"
    if provisionable and pair not in provisionable:
        return "no asset"
    if not enabled:
        return "off by default"
    if pair in provisionable:
        return "provisioned"
    return "package-defined (not declared)"


def _family_words(pairs: Sequence[str]) -> str:
    """The families a group of pairs names, a CPU qualifier where only one of two is in."""
    words = []
    for family in dict.fromkeys(row[4] for row in PLATFORM_COLUMNS):
        cpus = [row for row in PLATFORM_COLUMNS if row[4] == family]
        inside = [row[5] for row in cpus if row[0] in pairs]
        if not inside:
            continue
        words.append(family if len(inside) == len(cpus) else f"{family} ({inside[0]})")
    return ", ".join(words)


def os_summary(states: Mapping[str, str]) -> str:
    """The six platform cells as one README cell, equal cells grouped.

    Each group reads "<families>: <cell>", in the order of the first pair a group
    holds, and a family is named bare when both of its CPUs are in the group and with
    the CPU in parentheses when one is: "Linux, macOS, Windows (x86-64): provisioned;
    Windows (arm64): no asset".
    """
    missing = [row[0] for row in PLATFORM_COLUMNS if row[0] not in states]
    if missing:
        raise ModelError(f"the platform cells have no state for {missing}")
    groups: dict[str, list[str]] = {}
    for row in PLATFORM_COLUMNS:
        groups.setdefault(states[row[0]], []).append(row[0])
    return "; ".join(
        f"{_family_words(pairs)}: {text}" for text, pairs in groups.items()
    )


def _tier_position(scanner: ScannerInput) -> int:
    try:
        return TIER_ORDER[scanner.tier]
    except KeyError:
        raise ModelError(
            f"scanner {scanner.name!r}: its tier {scanner.tier!r} has no position in "
            f"the table; the tiers are {sorted(TIER_ORDER)}"
        ) from None


def _tier_cell(scanner: ScannerInput, names: frozenset[str]) -> str:
    if scanner.tier != "deprecated":
        if scanner.superseded_by is not None:
            raise ModelError(
                f"scanner {scanner.name!r} is {scanner.tier} but names "
                f"{scanner.superseded_by!r} as its successor; only a deprecated "
                "scanner has one"
            )
        return scanner.tier
    if scanner.superseded_by is None:
        raise ModelError(
            f"scanner {scanner.name!r} is deprecated and names no scanner that "
            "supersedes it"
        )
    if scanner.superseded_by not in names:
        raise ModelError(
            f"scanner {scanner.name!r} is deprecated in favor of "
            f"{scanner.superseded_by!r}, which has no row"
        )
    return f"deprecated, superseded by `{scanner.superseded_by}`"


def _answer(scanner: ScannerInput, field: str, mapping: Mapping, os_name: str):
    try:
        return mapping[os_name]
    except KeyError:
        raise ModelError(
            f"scanner {scanner.name!r}: its {field} has no answer for {os_name}"
        ) from None


def _row(scanner: ScannerInput, names: frozenset[str]) -> Row:
    try:
        route = RUNTIME_ROUTES[scanner.runtime_kind]
    except KeyError:
        raise ModelError(
            f"scanner {scanner.name!r}: its runtime kind {scanner.runtime_kind!r} has "
            "no install route word in RUNTIME_ROUTES"
        ) from None
    states = {
        pair: os_state(
            refusal=_answer(scanner, "refusals", scanner.refusals, os_name),
            provisionable=scanner.provisionable,
            pair=pair,
            enabled=_answer(scanner, "enabled settings", scanner.enabled, os_name),
        )
        for pair, _key, _header, os_name, _family, _cpu in PLATFORM_COLUMNS
    }
    loads, module = (
        (LOADS, BUILT_IN)
        if scanner.default_enabled
        else (LOADS_WHEN_LISTED, f"`{scanner.plugin_module}`")
    )
    cells = {
        "scanner": scanner.name,
        "tier": _tier_cell(scanner, names),
        "loads": loads,
        "module": module,
        "install": route,
        **{key: states[pair] for pair, key, *_rest in PLATFORM_COLUMNS},
        "libc": NOT_MEASURED,
        "os_summary": os_summary(states),
    }
    return Row(key=scanner.name, cells=cells, anchor=scanner.name, page=scanner.page)


def _phrase(cell: str) -> str:
    return "refused: <reason>" if cell.startswith("refused: ") else cell


def _loading_note(scanners: Sequence[ScannerInput]) -> str:
    """The note for ``loads only when its module is listed``, worded by tier.

    The alpha wording stays when every scanner that carries the phrase is alpha. In any
    other table the note is the opt-in one, which is true of a scanner of every tier and
    says nothing about its maturity. A tier with no entry in ``LOADING_WORDING`` is
    refused, so a tier the manifest model gains is worded on purpose and never by
    default.
    """
    wordings = set()
    for scanner in scanners:
        if scanner.default_enabled:
            continue
        try:
            wordings.add(LOADING_WORDING[scanner.tier])
        except KeyError:
            raise ModelError(
                f"scanner {scanner.name!r}: its tier {scanner.tier!r} has no wording "
                "for the note on loading; the tiers with one are "
                f"{sorted(LOADING_WORDING)}"
            ) from None
    if wordings == {"alpha"}:
        return _ALPHA_LOADING_NOTE
    return _PHRASE_NOTES[LOADS_WHEN_LISTED]


def _notes(rows: Sequence[Row], scanners: Sequence[ScannerInput]) -> tuple[str, ...]:
    """The precedence sentence, then one sentence for each phrase the rows use."""
    state_keys = [column.key for column in COLUMNS if column.kind == STATE]
    used = {_phrase(row.cells[key]) for row in rows for key in state_keys}
    unexplained = sorted(used - set(_PHRASE_NOTES))
    if unexplained:
        raise ModelError(
            f"the scanners matrix uses {unexplained}, which _PHRASE_NOTES does not "
            "explain; add a sentence for each"
        )
    notes = {**_PHRASE_NOTES, LOADS_WHEN_LISTED: _loading_note(scanners)}
    return (
        _PRECEDENCE_NOTE,
        *(f"`{phrase}`: {note}" for phrase, note in notes.items() if phrase in used),
    )


def scanner_matrix(inputs: Sequence[ScannerInput]) -> Matrix:
    """The scanners matrix of ``inputs``: a row each, in tier order, then by name."""
    names = frozenset(scanner.name for scanner in inputs)
    ordered = sorted(
        inputs, key=lambda scanner: (_tier_position(scanner), scanner.name)
    )
    rows = tuple(_row(scanner, names) for scanner in ordered)
    return Matrix(
        name=MATRIX_NAME,
        title="Scanners",
        columns=COLUMNS,
        rows=rows,
        members=names,
        intro=INTRO,
        notes=_notes(rows, ordered),
    )


# --- reading the world --------------------------------------------------------------


def _enabled_by_system(plugin, name: str) -> dict[str, bool]:
    """Whether the scanner's config enables it by default, for each operating system."""
    declared = plugin.enabled
    if isinstance(declared, bool):
        return dict.fromkeys(OS_NAMES, declared)
    if isinstance(declared, (list, tuple)):
        by_label = dict(declared)
        enabled = {}
        for os_name in OS_NAMES:
            value = by_label.get(_CONFIG_LABELS[os_name])
            if not isinstance(value, bool):
                raise ModelError(
                    f"scanner {name!r}: its config default for enabled cannot be "
                    f"evaluated for {os_name}"
                )
            enabled[os_name] = value
        return enabled
    raise ModelError(f"scanner {name!r}: its config class declares no enabled default")


def _refusals(cls: type, name: str) -> dict[str, str | None]:
    """The scanner class's own refusal of each operating system, host independent."""
    probe = types.SimpleNamespace(
        unsupported_platform_reason=lambda: cls.unsupported_platform_reason(object())
    )
    refusals: dict[str, str | None] = {}
    for os_name in OS_NAMES:
        try:
            refusals[os_name] = platform_refusal(probe, os_name)
        except Exception as error:
            raise ModelError(
                f"scanner {name!r}: asking its class whether it refuses {os_name} "
                f"failed ({type(error).__name__}: {error}); a refusal the matrix "
                "shows is a fact about the class, so it may not need an instance"
            ) from error
    return refusals


@contextlib.contextmanager
def _scripts_on_path():
    """Have scripts/ on ``sys.path`` while the sibling scripts load, then leave it as found.

    The scripts import each other by plain name. This file puts its directory on the path
    when it loads, but a caller that imported it from somewhere else (a test, the docs
    gate) may have taken that directory off the path again, so the imports a collector
    makes when it runs cannot rely on what the path held at load time.
    """
    added = str(_SCRIPTS) not in sys.path
    if added:
        sys.path.insert(0, str(_SCRIPTS))
    try:
        yield
    finally:
        if added:
            with contextlib.suppress(ValueError):
                sys.path.remove(str(_SCRIPTS))


def read_scanner_inputs(docs_root: Path) -> list[ScannerInput]:
    """One ``ScannerInput`` for each scanner manifest, read from the code.

    The manifests are joined to the plugin packages by class: a manifest whose scanner
    class no plugin package registers is refused, so a manifest cannot publish a row
    for a scanner a scan would never load.
    """
    with _scripts_on_path():
        return _read_scanner_inputs(docs_root)


def _read_scanner_inputs(docs_root: Path) -> list[ScannerInput]:
    from automated_security_helper import plugin_manifests
    from automated_security_helper.base.plugin_manifest import resolve_ref
    from automated_security_helper.base.scanner_operational_facets import (
        declared_operational_facets,
    )

    from _plugin_reference import discover
    from generate_scanner_reference import scanner_page

    by_class = {plugin.cls: plugin for plugin in discover("scanner")}
    inputs = []
    for manifest in plugin_manifests.scanner_manifests():
        reference = manifest.entry_points.scanner
        cls = resolve_ref(reference)
        plugin = by_class.get(cls)
        if plugin is None:
            raise ModelError(
                f"manifest {manifest.name!r} names the scanner class {reference}, "
                "which no plugin package under plugin_modules registers"
            )
        facets = declared_operational_facets(cls)
        if facets is None:
            raise ModelError(
                f"scanner {manifest.name!r}: its class {reference} declares no "
                "operational facets, so the matrix has nothing to say about it"
            )
        page = scanner_page(
            types.SimpleNamespace(
                builtin=manifest.default_enabled,
                name=manifest.name,
                package=manifest.plugin_module,
            ),
            docs_root,
        )
        inputs.append(
            ScannerInput(
                name=manifest.name,
                tier=manifest.tier.value,
                superseded_by=manifest.superseded_by,
                default_enabled=manifest.default_enabled,
                plugin_module=manifest.plugin_module,
                runtime_kind=facets.runtime.kind.value,
                provisionable=tuple(facets.platforms.provisionable),
                refusals=_refusals(cls, manifest.name),
                enabled=_enabled_by_system(plugin, manifest.name),
                page=(
                    None
                    if page is None
                    else Path(os.path.relpath(page, docs_root)).as_posix()
                ),
            )
        )
    return inputs


def _docs_checks():
    """scripts/docs_checks.py, loaded by path once and shared by its registered name."""
    name = "_ash_docs_checks"
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, _SCRIPTS / "docs_checks.py")
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {_SCRIPTS / 'docs_checks.py'}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def config_names() -> dict[str, str]:
    """Every scanner the config models declare, by config name, with where it is declared.

    The scanner fields of the root config's scanners segment, and the scanner configs of
    the plugin modules the docs checks import. It is the inventory the other docs checks
    hold the scanner pages to, which is a different statement of the same set from the
    manifests this matrix is built from.
    """
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    names = {
        info.alias or field.replace("_", "-"): f"field {field}"
        for field, info in ScannerConfigSegment.model_fields.items()
    }
    models = _docs_checks().load_config_models()
    for name, config_cls in sorted(models.plugin_configs.get("scanners", {}).items()):
        names.setdefault(name, f"{config_cls.__module__}.{config_cls.__name__}")
    return names


class _ScannerCollector:
    """The collector the generator finds in this module."""

    name = "scanners"

    def collect(self, context: CollectContext) -> Sequence[Matrix]:
        return [scanner_matrix(read_scanner_inputs(context.docs_root))]

    def second_sources(self) -> Sequence[SecondSource]:
        return [
            SecondSource(
                label="Scanners support matrix",
                matrix=MATRIX_NAME,
                header_cell="Scanner",
                names=config_names,
            )
        ]


COLLECTOR = _ScannerCollector()
