"""How each scanner is installed, at what version, and where each one runs.

One reader for the facts several generators and checks need, so none of them keeps a
copy of the rules:

* ``routes()`` and ``route_for()`` give, for each scanner manifest, the route ASH
  installs it by, its pin, the platforms ASH provisions a release for, and the
  programs it runs;
* ``scanners_for(env)`` says which scanners an environment runs (an image, the
  pre-commit hook, a Nix shell, a host with a recipe), each one available, available
  on opt-in, or missing with its reason;
* ``scanner_set_cell()`` and ``scanner_names()`` render that answer, the cell that
  counts and the names view, so a count and a name list are never worded twice.

The route is what the plugin declares, not what its runtime kind suggests. A scanner
has an install route when ASH can install it by itself: a pinned release asset, a uv
tool, a package in ASH's own environment, or install commands the plugin declares. A
plugin that runs a tool the user installs and declares no install command has no
route. A user-installed CLI that does declare install commands has one, and a
module-local constant can pin it.

The pin of a Python tool is read from four places, in this order, and every place
that answers is listed, so a caller can see two places that disagree:

1. the scanner's PyPI pin, when its specifier is exactly ``==X``;
2. the entry for its distribution in ``THIRD_PARTY_LICENSES`` (read, never written);
3. an interim table the caller passes, ``{scanner: "module:CONSTANT"}``, read when
   the question is asked;
4. a module-local constant named in ``MODULE_LOCAL_PINS``.

A binary's pin is the release pin of its tool, from ``tool_versions()``.

Nothing here installs anything, and nothing here runs a scanner. A plugin is built
once, in a scratch context, to read what install commands it declares.
"""

from __future__ import annotations

import importlib
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest import mock

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.install_package_facets import (
    INSTALL_PACKAGE_FACETS,
)
from automated_security_helper.base.plugin_manifest import (
    PluginTier,
    ScannerManifest,
    resolve_ref,
)
from automated_security_helper.base.plugin_provisioning import tool_versions
from automated_security_helper.core import constants
from automated_security_helper.core.enums import RunMode
from automated_security_helper.plugin_manifests import scanner_manifests
from automated_security_helper.utils import tool_downloads

#: The header of the column the deploy scanner cells sit under. It is not a scanner
#: name header, so the docs checks do not read the counts under it as names.
SCANNER_SET_HEADER = "Scanner set"

#: The extra of the ASH wheel a scanner needs on a host, by scanner name.
SCANNER_EXTRAS: Mapping[str, str] = MappingProxyType({"cdk-nag": "cdk"})

#: The runtimes a host provides or lacks, as they are named in a scanner's runtime
#: facet (``RuntimeFacet.external_programs``).
HOST_RUNTIMES = frozenset({"node", "npm", "ruby"})

#: Pins that live in a module beside the code that installs the tool, by scanner
#: name, as ``module:CONSTANT``. cfn-nag's gem install names the constant below, so
#: the constant is the version its install command passes.
MODULE_LOCAL_PINS: Mapping[str, str] = MappingProxyType(
    {"cfn-nag": "automated_security_helper.utils.tool_downloads:CFN_NAG_GEM_VERSION"}
)

_PROVISION_KINDS = ("image", "precommit", "nix", "host")
_IMAGE_STAGES = ("ci", "non-root")

#: The ``PypiPin.runtime`` each route installs by.
_PIN_RUNTIME = {"uv_tool": "uv-tool", "ash_environment": "ash-environment"}

_VERSION_BODY = (
    r"[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
)
_EXACT_VERSION = re.compile(_VERSION_BODY)
_EXACT_SPECIFIER = re.compile(rf"==\s*({_VERSION_BODY})")


class RouteError(ValueError):
    """A register cannot answer, or answers in a way no route can be read from."""


class Route(str, Enum):
    """How ASH installs a scanner's tool, if it does."""

    #: A pinned release asset, downloaded and checked.
    RELEASE_ASSET = "release_asset"
    #: ``uv tool install`` into an environment of the tool's own.
    UV_TOOL = "uv_tool"
    #: A PyPI package installed into the environment ASH runs in.
    ASH_ENVIRONMENT = "ash_environment"
    #: Install commands the plugin declares (a gem, a module-local installer).
    DECLARED_COMMANDS = "declared_commands"
    #: The scanner runs inside ASH; there is nothing to install.
    IN_PROCESS = "in_process"
    #: The plugin declares no install command, so ASH has no route.
    NONE = "none"


class PinSource(str, Enum):
    """Where a pin was read from, in the order the sources are tried."""

    RELEASE_PIN = "release_pin"
    PYPI_PIN = "pypi_pin"
    DISTRIBUTION_ENTRY = "distribution_entry"
    INTERIM = "interim"
    MODULE_CONSTANT = "module_constant"


@dataclass(frozen=True)
class Pin:
    """One exact version and the source that gave it."""

    version: str
    source: PinSource
    #: What the version was read from: the distribution, or ``module:CONSTANT``.
    reference: str = ""


@dataclass(frozen=True)
class RouteRow:
    """One scanner's install route."""

    scanner: str
    module: str
    tier: PluginTier
    #: Whether the plugin loads without being listed (the manifest's default).
    builtin: bool
    runtime_kind: opsf.RuntimeKind
    route: Route
    #: The programs the route puts on the path or the scanner needs: the tool's own
    #: name for a release asset, the runtime facet's external programs otherwise.
    programs: tuple[str, ...]
    #: Every source that gave a version, in the order the sources are tried.
    pins: tuple[Pin, ...]
    #: ``os/arch`` pairs ASH provisions a release asset for; empty for a tool it does
    #: not download.
    platforms: tuple[str, ...]
    platforms_note: str
    #: ``os/arch`` pairs the plugin declares install commands for.
    declared_on: tuple[str, ...]
    #: The PyPI distribution a Python route installs; empty for the other routes.
    distribution: str
    #: Why there is no route, or nothing to install; empty otherwise.
    reason: str

    @property
    def pin(self) -> Pin | None:
        """The first source that answered."""
        return self.pins[0] if self.pins else None

    @property
    def installable(self) -> bool:
        """Whether ASH can install it at one named version."""
        return bool(self.pins) and self.route in (
            Route.RELEASE_ASSET,
            Route.UV_TOOL,
            Route.ASH_ENVIRONMENT,
            Route.DECLARED_COMMANDS,
        )


def declared_pairs(plugin: Any) -> tuple[str, ...]:
    """The ``os/arch`` pairs *plugin* declares at least one install command for.

    Each pair ASH publishes releases for (``PLATFORMS_ALL``) is asked in turn, so a
    plugin that declares commands for some platforms only is read as that.
    """
    pairs = []
    for pair in opsf.PLATFORMS_ALL:
        target_platform, _, arch = pair.partition("/")
        if plugin.get_installation_commands(target_platform, arch):
            pairs.append(pair)
    return tuple(pairs)


def _declared_on(manifest: ScannerManifest) -> tuple[str, ...]:
    """What an instance of the manifest's scanner declares, built to be described.

    The instance is built the way the reference generators build one: in a scratch
    context, as on Linux, with the plugin told it is describing its install story,
    so a plugin whose commands depend on a probe of this machine declares them as it
    would where the probe passes.
    """
    from automated_security_helper.base.plugin_base import declaring_install_story
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    scanner_class = resolve_ref(manifest.entry_points.scanner)
    with tempfile.TemporaryDirectory(prefix="ash-install-routes-") as scratch:
        source = Path(scratch) / "source"
        output = Path(scratch) / "output"
        source.mkdir()
        output.mkdir()
        context = PluginContext(
            source_dir=source, output_dir=output, config=AshConfig()
        )
        with mock.patch("platform.system", return_value="Linux"):
            with declaring_install_story():
                instance = scanner_class(context=context)
        return declared_pairs(instance)


@dataclass(frozen=True)
class Registers:
    """The registers the reader answers from, as one value a test can replace."""

    manifests: tuple[ScannerManifest, ...]
    #: Each scanner's operational facets, by scanner name.
    facets: Mapping[str, opsf.ScannerOperationalFacets]
    #: ``tool_versions()``: the release pin of each tool ASH downloads.
    release_pins: Mapping[str, str]
    #: The version of each ``THIRD_PARTY_LICENSES`` entry that names a PyPI
    #: distribution, as the entry spells it.
    distribution_pins: Mapping[str, str]
    #: The PyPI distribution each of those entries names.
    distribution_names: Mapping[str, str]
    #: ``MODULE_LOCAL_PINS``, by scanner name.
    module_pins: Mapping[str, str]
    #: Tools a Nix package row provides.
    nix_tools: frozenset[str]
    #: The ``os/arch`` pairs a manifest's plugin declares install commands for.
    declared_on: Callable[[ScannerManifest], tuple[str, ...]]

    @classmethod
    def read(cls) -> Registers:
        """The registers as the package declares them. Nothing is written."""
        manifests = scanner_manifests()
        facets = {}
        for manifest in manifests:
            ref = manifest.entry_points.scanner
            try:
                scanner_class = resolve_ref(ref)
            except (ImportError, AttributeError, ValueError) as err:
                raise RouteError(
                    f"{manifest.name}: its scanner {ref} cannot be loaded "
                    f"({type(err).__name__}: {err})"
                ) from err
            row = opsf.declared_operational_facets(scanner_class)
            if row is not None:
                facets[manifest.name] = row
        table = tool_downloads.THIRD_PARTY_LICENSES
        return cls(
            manifests=manifests,
            facets=facets,
            release_pins=tool_versions(),
            distribution_pins={
                key: entry.version for key, entry in table.items() if entry.distribution
            },
            distribution_names={
                key: entry.distribution
                for key, entry in table.items()
                if entry.distribution
            },
            module_pins=dict(MODULE_LOCAL_PINS),
            nix_tools=frozenset(
                tool
                for tool, facet in INSTALL_PACKAGE_FACETS.items()
                if facet.row_for("nix") is not None
            ),
            declared_on=_declared_on,
        )


# ---------------------------------------------------------------------------
# Routes and pins
# ---------------------------------------------------------------------------


def _bare(value: str) -> str:
    """*value* without the ``v`` an upstream tag carries before its number."""
    text = value.strip()
    if text[:1] in ("v", "V") and text[1:2].isdigit():
        return text[1:]
    return text


def _exact_version(value: object) -> str | None:
    """*value* as one exact version, or None when it is anything else."""
    if not isinstance(value, str):
        return None
    version = _bare(value)
    return version if _EXACT_VERSION.fullmatch(version) else None


def _exact_specifier(specifier: str) -> str | None:
    """The version of a specifier that is exactly ``==X``, else None."""
    match = _EXACT_SPECIFIER.fullmatch(specifier.strip())
    return match.group(1) if match else None


def _constant(scanner: str, ref: str, table: str) -> str:
    """The exact version the ``module:CONSTANT`` reference names, read now."""
    module_name, colon, attribute = ref.partition(":")
    if not (module_name and colon and attribute):
        raise RouteError(
            f"{scanner}: the {table} reference {ref!r} is not 'package.module:CONSTANT'"
        )
    try:
        module = importlib.import_module(module_name)
    except ImportError as err:
        raise RouteError(
            f"{scanner}: the {table} reference {ref!r} names a module that cannot "
            f"be imported ({err})"
        ) from err
    if not hasattr(module, attribute):
        raise RouteError(f"{scanner}: {module_name} has no {attribute} ({table})")
    value = getattr(module, attribute)
    version = _exact_version(value)
    if version is None:
        raise RouteError(
            f"{scanner}: {ref} is {value!r}, which is not one exact version ({table})"
        )
    return version


def _declared(manifest: ScannerManifest, regs: Registers) -> tuple[str, ...]:
    try:
        return tuple(regs.declared_on(manifest))
    except Exception as err:
        raise RouteError(
            f"{manifest.name}: what its plugin declares to install could not be read "
            f"({type(err).__name__}: {err})"
        ) from err


def _python_pins(
    manifest: ScannerManifest,
    route: Route,
    regs: Registers,
    interim: Mapping[str, str],
) -> tuple[tuple[Pin, ...], str]:
    """Every pin the four sources give, in order, and the distribution they name."""
    name = manifest.name
    pins: list[Pin] = []
    distribution = ""
    expected = _PIN_RUNTIME.get(route.value)
    for pypi in manifest.provisioning.pypi_pins:
        if expected is not None and pypi.runtime != expected:
            raise RouteError(
                f"{name}: its PyPI pin for {pypi.distribution} says runtime "
                f"{pypi.runtime!r}, but its runtime facet installs by {expected!r}"
            )
        distribution = distribution or pypi.distribution
        version = _exact_specifier(pypi.specifier)
        if version is not None:
            pins.append(Pin(version, PinSource.PYPI_PIN, pypi.distribution))
    entry = regs.distribution_pins.get(name)
    if entry is not None:
        pins.append(Pin(_bare(entry), PinSource.DISTRIBUTION_ENTRY, name))
        distribution = distribution or regs.distribution_names.get(name, "")
    if name in interim:
        ref = interim[name]
        pins.append(Pin(_constant(name, ref, "interim"), PinSource.INTERIM, ref))
    if name in regs.module_pins:
        ref = regs.module_pins[name]
        pins.append(
            Pin(_constant(name, ref, "module constant"), PinSource.MODULE_CONSTANT, ref)
        )
    return tuple(pins), distribution


def _route(
    manifest: ScannerManifest, regs: Registers, interim: Mapping[str, str]
) -> RouteRow:
    name = manifest.name
    facet = regs.facets.get(name)
    if facet is None:
        raise RouteError(
            f"{name}: no operational facets are declared for it (its scanner class "
            "has no operational_facets row)"
        )
    kind = facet.runtime.kind
    programs = tuple(facet.runtime.external_programs)
    declared: tuple[str, ...] = ()
    pins: tuple[Pin, ...] = ()
    distribution = ""
    reason = ""
    if kind is opsf.RuntimeKind.PINNED_BINARY:
        route = Route.RELEASE_ASSET
        key = facet.runtime.tool_versions_key or name
        programs = (key,)
        release = regs.release_pins.get(key)
        if release:
            pins = (Pin(release, PinSource.RELEASE_PIN, key),)
    elif kind is opsf.RuntimeKind.UV_PYTHON:
        route = Route.UV_TOOL
        pins, distribution = _python_pins(manifest, route, regs, interim)
    elif kind is opsf.RuntimeKind.PYPI_PACKAGE:
        route = Route.ASH_ENVIRONMENT
        pins, distribution = _python_pins(manifest, route, regs, interim)
    elif kind is opsf.RuntimeKind.IN_PROCESS:
        route = Route.IN_PROCESS
        reason = "it runs inside ASH, so there is nothing to install"
    else:
        declared = _declared(manifest, regs)
        if declared:
            route = Route.DECLARED_COMMANDS
            pins, distribution = _python_pins(manifest, route, regs, interim)
        else:
            route = Route.NONE
            reason = (
                f"{name}: its plugin declares no install command, so ASH has no "
                "install route for it"
            )
    return RouteRow(
        scanner=name,
        module=manifest.plugin_module,
        tier=manifest.tier,
        builtin=manifest.default_enabled,
        runtime_kind=kind,
        route=route,
        programs=programs,
        pins=pins,
        platforms=tuple(facet.platforms.provisionable),
        platforms_note=facet.platforms.note,
        declared_on=declared,
        distribution=distribution,
        reason=reason,
    )


def route_for(
    name: str,
    regs: Registers | None = None,
    *,
    interim: Mapping[str, str] | None = None,
) -> RouteRow:
    """The install route of the scanner called *name*."""
    registers = Registers.read() if regs is None else regs
    manifest = next((m for m in registers.manifests if m.name == name), None)
    if manifest is None:
        raise RouteError(f"{name}: no manifest declares a scanner of this name")
    return _route(manifest, registers, interim or {})


def routes(
    regs: Registers | None = None, *, interim: Mapping[str, str] | None = None
) -> tuple[RouteRow, ...]:
    """One route row per manifest, sorted by scanner name."""
    registers = Registers.read() if regs is None else regs
    return tuple(
        _route(manifest, registers, interim or {})
        for manifest in sorted(registers.manifests, key=lambda m: m.name)
    )


# ---------------------------------------------------------------------------
# Environments
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllTools:
    """Every tool is present: the image counts as providing every built-in tool.

    It stands for the tool of an alpha scanner too, so an environment that provides
    ``ALL_TOOLS`` runs every alpha scanner whose own row does not leave it out (an
    image row that names the reason, a platform with no release asset).
    """

    def __contains__(self, tool: object) -> bool:
        return True


ALL_TOOLS = AllTools()


@dataclass(frozen=True)
class Provision:
    """What an environment provides before a scan.

    ``kind`` is how the environment is provisioned. An image names its stage (``ci``
    or ``non-root``) and counts as providing the tools its ``tools`` lists, with
    whatever its runtime and extras need already inside it; the answer does not
    depend on the stage today, because the image register has one row per scanner.
    The pre-commit hook provides the pre-commit set. A Nix shell provides what the
    flake's package rows carry, so a scanner with a Nix row needs no runtime from
    the provision. A host provides the tools, extras and runtimes its recipe
    installs; ``alpha_with_tools`` lists the alpha modules whose tools it installs
    too, so a host recipe that installs ``--tool hadolint`` lists that module.
    """

    kind: str
    image_stage: str | None = None
    #: Extras of the ASH wheel that are installed, such as ``cdk``.
    extras: frozenset[str] = frozenset()
    #: Tools installed before the scan.
    tools: frozenset[str] | AllTools = frozenset()
    #: Runtimes present: ``node``, ``npm``, ``ruby``.
    runtimes: frozenset[str] = frozenset()
    #: Alpha plugin modules whose tools are present.
    alpha_with_tools: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.kind not in _PROVISION_KINDS:
            raise ValueError(
                f"a provision kind is one of {', '.join(_PROVISION_KINDS)}, "
                f"not {self.kind!r}"
            )
        if self.kind == "image":
            if self.image_stage not in _IMAGE_STAGES:
                raise ValueError(
                    "an image provision names its stage, one of "
                    f"{', '.join(_IMAGE_STAGES)}, not {self.image_stage!r}"
                )
        elif self.image_stage is not None:
            raise ValueError(
                f"only an image provision has a stage, and this one is {self.kind}"
            )
        for field_name in ("extras", "runtimes", "alpha_with_tools"):
            object.__setattr__(self, field_name, frozenset(getattr(self, field_name)))
        if not isinstance(self.tools, AllTools):
            object.__setattr__(self, "tools", frozenset(self.tools))
        unknown = self.runtimes - HOST_RUNTIMES
        if unknown:
            raise ValueError(
                f"{', '.join(sorted(unknown))} is not a runtime the reader judges "
                f"({', '.join(sorted(HOST_RUNTIMES))})"
            )


@dataclass(frozen=True)
class Env:
    """An operating system, an architecture, a run mode and what is provisioned."""

    os: str
    arch: str
    mode: RunMode
    provision: Provision

    def __post_init__(self) -> None:
        pair = f"{self.os}/{self.arch}"
        if pair not in opsf.PLATFORMS_ALL:
            raise ValueError(
                f"{pair!r} is not an os/arch pair ASH publishes releases for "
                f"({', '.join(opsf.PLATFORMS_ALL)})"
            )
        if not isinstance(self.mode, RunMode):
            raise ValueError(f"mode is a RunMode member, not {self.mode!r}")
        if not isinstance(self.provision, Provision):
            raise ValueError("provision is a Provision")


class Status(str, Enum):
    """Whether an environment runs a scanner."""

    AVAILABLE = "available"
    #: Available once its module is listed (an alpha scanner).
    OPT_IN = "opt_in"
    MISSING = "missing"


@dataclass(frozen=True)
class ScannerAvailability:
    scanner: str
    module: str
    tier: PluginTier
    builtin: bool
    status: Status
    #: Why it is missing; empty for a scanner that is not.
    reason: str


@dataclass(frozen=True)
class Availability:
    """The scanners an environment runs, one row per manifest, sorted by name."""

    env: Env
    rows: tuple[ScannerAvailability, ...]


def _tool_of(
    manifest: ScannerManifest, facet: opsf.ScannerOperationalFacets
) -> str | None:
    """The tool an environment must provide for the scanner, or None for none.

    A scanner that runs inside ASH, or through a runtime the environment provides
    (npm), has no tool of its own.
    """
    kind = facet.runtime.kind
    if kind in (opsf.RuntimeKind.IN_PROCESS, opsf.RuntimeKind.NODE_SUBCOMMAND):
        return None
    if kind is opsf.RuntimeKind.PINNED_BINARY:
        return facet.runtime.tool_versions_key
    return manifest.name


def _needs(parts: list[str]) -> str:
    return "needs " + ", ".join(parts) if parts else ""


def _availability(
    manifest: ScannerManifest,
    env: Env,
    regs: Registers,
    precommit_set: frozenset[str],
) -> ScannerAvailability:
    name = manifest.name
    facet = regs.facets.get(name)
    if facet is None:
        raise RouteError(
            f"{name}: no operational facets are declared for it (its scanner class "
            "has no operational_facets row)"
        )
    provision = env.provision
    builtin = manifest.default_enabled
    present = Status.AVAILABLE if builtin else Status.OPT_IN

    def row(status: Status, reason: str = "") -> ScannerAvailability:
        return ScannerAvailability(
            scanner=name,
            module=manifest.plugin_module,
            tier=manifest.tier,
            builtin=builtin,
            status=status,
            reason=reason,
        )

    if (
        provision.kind == "precommit" or env.mode is RunMode.precommit
    ) and name not in precommit_set:
        return row(Status.MISSING, "outside the precommit set")
    if provision.kind == "precommit":
        return row(present)

    tool = _tool_of(manifest, facet)
    wanted = frozenset(facet.runtime.external_programs) & HOST_RUNTIMES
    extra = SCANNER_EXTRAS.get(name)
    parts: list[str] = []
    tool_present = (
        tool is None
        or tool in provision.tools
        or (not builtin and manifest.plugin_module in provision.alpha_with_tools)
    )

    if provision.kind == "image":
        image = facet.image
        if image.route is opsf.ImageRoute.NOT_IN_IMAGE:
            return row(Status.MISSING, f"not in image: {image.reason}")
        if not tool_present:
            parts.append(str(tool))
    elif provision.kind == "nix":
        via_nix = tool is not None and tool in regs.nix_tools
        if tool is not None and not via_nix:
            parts.append(tool)
        if extra and extra not in provision.extras:
            parts.append(f"the {extra} extra")
        if not via_nix:
            parts.extend(sorted(wanted - provision.runtimes))
    else:
        pair = f"{env.os}/{env.arch}"
        provisionable = facet.platforms.provisionable
        if provisionable and pair not in provisionable:
            return row(Status.MISSING, f"no {pair} release asset")
        if not tool_present:
            parts.append(str(tool))
        if extra and extra not in provision.extras:
            parts.append(f"the {extra} extra")
        parts.extend(sorted(wanted - provision.runtimes))

    if parts:
        return row(Status.MISSING, _needs(parts))
    return row(present)


def scanners_for(env: Env, regs: Registers | None = None) -> Availability:
    """Which scanners *env* runs, each available, opt-in or missing with a reason.

    The pre-commit set is read from ``constants`` when the question is asked, so a
    change to it changes the answer.
    """
    registers = Registers.read() if regs is None else regs
    precommit_set = frozenset(constants.PRECOMMIT_MODE_SCANNERS)
    rows = tuple(
        _availability(manifest, env, registers, precommit_set)
        for manifest in sorted(registers.manifests, key=lambda m: m.name)
    )
    return Availability(env=env, rows=rows)


# ---------------------------------------------------------------------------
# The flake cross-check
# ---------------------------------------------------------------------------


def _camel(tool: str) -> str:
    first, *rest = tool.split("-")
    return first + "".join(word.capitalize() for word in rest)


def _scanner_list(flake: str) -> str:
    """The text of the ``scannersFor`` list in *flake*, comments removed."""
    text = re.sub(r"#[^\n]*", "", flake)
    start = re.search(r"scannersFor\s*=\s*system\s*:", text)
    opener = re.compile(r"\bin\s*\[").search(text, start.end()) if start else None
    if opener is None:
        raise RouteError("flake.nix has no scannersFor list to read")
    depth = 1
    for index in range(opener.end(), len(text)):
        if text[index] == "[":
            depth += 1
        elif text[index] == "]":
            depth -= 1
            if depth == 0:
                return text[opener.end() : index]
    raise RouteError("the scannersFor list in flake.nix is not closed")


def nix_rows_missing_from_flake(flake: str, regs: Registers | None = None) -> list[str]:
    """Tools with a Nix package row that the flake's scanner list does not carry."""
    registers = Registers.read() if regs is None else regs
    listed = _scanner_list(flake)
    missing = []
    for tool in sorted(registers.nix_tools):
        spellings = (tool, f"{_camel(tool)}For")
        if not any(
            re.search(rf"(?<![\w-]){re.escape(spelling)}(?![\w-])", listed)
            for spelling in spellings
        ):
            missing.append(tool)
    return missing


# ---------------------------------------------------------------------------
# The scanner-set cell
# ---------------------------------------------------------------------------


def builtin_count(availability: Availability) -> tuple[int, int]:
    """(built-in scanners available, built-in scanners)."""
    builtin = [row for row in availability.rows if row.builtin]
    return sum(row.status is Status.AVAILABLE for row in builtin), len(builtin)


def scanner_set_cell(availability: Availability) -> str:
    """The scanner-set cell of a deploy table: a count, never a name.

    "all built-in" when every built-in scanner is available, "N of M built-in"
    otherwise, and "<n> (the precommit set)" for the pre-commit hook. Alpha scanners
    read "alpha opt-in" with no count, so admitting one changes no count.
    """
    available, total = builtin_count(availability)
    if availability.env.provision.kind == "precommit":
        return f"{available} (the precommit set)"
    if total == 0:
        raise RouteError("the availability has no built-in scanner row to count")
    cell = "all built-in" if available == total else f"{available} of {total} built-in"
    if any(not r.builtin and r.status is not Status.MISSING for r in availability.rows):
        cell += ", alpha opt-in"
    return cell


@dataclass(frozen=True)
class Names:
    """The names view: built-in scanners, each missing one with its reason, and the
    alpha scanners available on opt-in."""

    builtin: tuple[str, ...]
    alpha: tuple[str, ...]


def _plain(text: str) -> str:
    """*text* with nothing that could end a parenthetical or a table cell."""
    return " ".join(re.sub(r"[()|]", " ", text).split())


def _item(row: ScannerAvailability) -> str:
    notes = []
    if row.tier is PluginTier.DEPRECATED:
        notes.append("deprecated")
    if row.status is Status.MISSING:
        reason = _plain(row.reason)
        notes.append(f"missing: {reason}" if reason else "missing")
    name = f"`{row.scanner}`"
    return f"{name} ({'; '.join(notes)})" if notes else name


def scanner_names(availability: Availability) -> Names:
    """The names of the scanners an environment runs, for the reference page.

    Every built-in scanner is named, a missing one with its reason and a deprecated
    one marked, so ``check_scanner_names`` reads each name. An alpha scanner is
    named only when the environment can run it.
    """
    builtin = []
    alpha = []
    for row in availability.rows:
        if row.builtin:
            builtin.append(_item(row))
        elif row.status is not Status.MISSING:
            alpha.append(_item(row))
    return Names(builtin=tuple(builtin), alpha=tuple(alpha))
