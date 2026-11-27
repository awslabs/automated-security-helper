#!/usr/bin/env python3
"""The alpha scanners the docs job installs, and a check that each is where sessions look.

The docs job installs every alpha scanner ASH can install by itself, each at one exact
version, so a page that runs one finds it. Three subcommands read the registers
through ``scripts/_install_routes.py`` and print one answer each:

``plan``    one row per alpha scanner: its module, runtime kind, install route,
            version, where that version came from, and whether the job installs it.
            Tab-separated for a step summary, or JSON with ``--json``.
``args``    the ``ash dependencies install`` arguments for the rows that install,
            one token per line.
``verify``  after the install, that each installed tool is on the PATH a docs session
            gets, at its pin.

A scanner the job does not install is named, with its reason, in one of two tables:
``EXEMPT`` for a scanner ASH has no install path for, and ``HELD`` for one the plan
could install and a maintainer's decision holds back. ``INTERIM_PINS`` gives a Python
tool a version until a permanent source for it exists. Every run checks each table
against the registers it describes, so a row that stops describing them is an error
and never a silent gap.

Exit status: 0; 2 when the plan cannot be made (a message that starts
``alpha-doctest-installs:`` on stderr and nothing on stdout); 1 when ``verify`` finds a
tool that is missing or at another version.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import shutil
import subprocess  # nosec B404 - runs `uv tool list` and `<tool> --version`, fixed argv
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from automated_security_helper.base.plugin_manifest import PluginTier
from automated_security_helper.base.plugin_provisioning import normalize_distribution

REPO_ROOT = Path(__file__).resolve().parents[2]
ROUTES = REPO_ROOT / "scripts" / "_install_routes.py"
INSTALLER = (
    REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
)
DOCS_RUNNER = REPO_ROOT / "tests" / "integration" / "docs" / "docs_runner.py"

#: The platform the docs job runs on.
PLATFORM = "linux/amd64"

#: Alpha scanners ASH has no install path for, with the reason. A row for a scanner
#: that has no manifest, is not alpha, or that the plan could install is an error.
EXEMPT: dict[str, str] = {
    "snyk-code": (
        "no ASH install path (USER_INSTALLED_CLI); it uploads the source to Snyk "
        "with a token and is NOT_RUN offline, so no docs session can run it"
    ),
}

#: Alpha scanners the plan could install and a maintainer's decision holds back, with
#: the reason. Empty. A row for a scanner the plan could not install anyway belongs in
#: EXEMPT, and a row for one it could is still checked on every run.
HELD: dict[str, str] = {}

#: Python tools with no permanent pin yet, as ``module:CONSTANT``. ferret-scan's PyPI
#: pin is a range and no table entry names its distribution, so the job installs the
#: version its plugin recommends, read from the plugin when the plan is made. A
#: permanent source (a PyPI pin that is exactly ``==X``, or a table entry) makes the
#: row stale, and the plan refuses it, which forces its removal.
INTERIM_PINS: dict[str, str] = {
    "ferret-scan": (
        "automated_security_helper.plugin_modules.ash_ferret_plugins."
        "ferret_scanner:RECOMMENDED_VERSION"
    ),
}

#: The columns of a plan row, in the order ``plan`` prints them.
COLUMNS = (
    "scanner",
    "module",
    "runtime",
    "route",
    "version",
    "pin_source",
    "status",
    "reason",
)


def _load_by_path(name: str, path: Path):
    """The module at *path*, loaded under *name* once and registered first."""
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


#: scripts/_install_routes.py, the one reader of install routes.
install_routes = _load_by_path("_install_routes", ROUTES)


class PlanError(Exception):
    """The registers and tables cannot give a usable plan."""


class _NoInstall(Exception):
    """The plan cannot install a scanner; the message says why."""


@dataclass(frozen=True)
class PlanRow:
    scanner: str
    module: str
    runtime: str
    route: str
    #: The version the job installs; empty for a row that installs nothing.
    version: str
    #: Where the version was read from (see ``PinSource``); empty with no version.
    pin_source: str
    #: ``install``, ``exempt``, ``held`` or ``nothing`` (it runs inside ASH).
    status: str
    reason: str
    #: Not printed: what ``verify`` looks for.
    programs: tuple[str, ...] = ()
    distribution: str = ""

    def columns(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in COLUMNS}


def _text(value: str) -> str:
    """*value* on one line, so a cell never holds a tab or a line break."""
    return " ".join(str(value).split())


def _installation(row) -> tuple[str, str, str] | None:
    """(version, pin source, reference) the plan installs *row*'s scanner at.

    None when the scanner runs inside ASH and has nothing to install. Raises
    ``_NoInstall`` when ASH cannot install it at one named version on the docs job's
    platform.
    """
    routes = install_routes
    name = row.scanner
    if row.route is routes.Route.IN_PROCESS:
        return None
    if row.route is routes.Route.NONE:
        raise _NoInstall(
            f"{name}: no ASH install path (its plugin declares no install command); "
            "add an EXEMPT row that says so, or give the plugin an install route"
        )
    if not row.pins:
        if row.route is routes.Route.RELEASE_ASSET:
            raise _NoInstall(
                f"{name}: no release pin for its tool {row.programs[0]!r}; "
                "tool_versions() names none"
            )
        raise _NoInstall(
            f"{name}: unpinned; no PyPI pin, distribution entry, interim row or "
            "module constant gives one exact version"
        )
    if len({pin.version for pin in row.pins}) > 1:
        listed = "; ".join(f"{p.version} from {p.source.value}" for p in row.pins)
        raise _NoInstall(f"{name}: its pins disagree ({listed})")
    if row.route is routes.Route.RELEASE_ASSET and PLATFORM not in row.platforms:
        raise _NoInstall(
            f"{name}: its release table has no {PLATFORM} asset, the platform the "
            f"docs job runs on (it has {', '.join(row.platforms) or 'none'})"
        )
    if row.route is routes.Route.DECLARED_COMMANDS and PLATFORM not in row.declared_on:
        raise _NoInstall(
            f"{name}: its plugin declares install commands for "
            f"{', '.join(row.declared_on)}, none for {PLATFORM}, the platform the "
            "docs job runs on"
        )
    pin = row.pins[0]
    return pin.version, pin.source.value, pin.reference


def _check_named(table: str, name: str, manifests: Mapping[str, object]) -> None:
    manifest = manifests.get(name)
    if manifest is None:
        raise PlanError(f"{table} names {name}, which has no manifest")
    if manifest.tier is not PluginTier.ALPHA:
        raise PlanError(
            f"{table} names {name}, which is not an alpha scanner (the plan covers "
            "alpha scanners only)"
        )


def _plan(regs, exempt, held, interim) -> list[PlanRow]:
    routes = install_routes
    registers = routes.Registers.read() if regs is None else regs
    manifests = {m.name: m for m in registers.manifests}
    alpha = sorted(
        (m for m in registers.manifests if m.tier is PluginTier.ALPHA),
        key=lambda m: m.name,
    )

    for table, rows in (("EXEMPT", exempt), ("HELD", held)):
        for name, reason in rows.items():
            _check_named(table, name, manifests)
            if not str(reason).strip():
                raise PlanError(f"{table} row for {name} gives no reason")
    for name in sorted(set(exempt) & set(held)):
        raise PlanError(
            f"{name} is in both EXEMPT and HELD; EXEMPT is for a scanner with no "
            "ASH install path, HELD for one a maintainer's decision holds back"
        )
    for name in sorted(interim):
        _check_named("INTERIM_PINS", name, manifests)

    found = {
        m.name: routes.route_for(m.name, registers, interim=interim) for m in alpha
    }

    permanent = (routes.PinSource.PYPI_PIN, routes.PinSource.DISTRIBUTION_ENTRY)
    for name in sorted(interim):
        row = found[name]
        if row.route not in (routes.Route.UV_TOOL, routes.Route.ASH_ENVIRONMENT):
            raise PlanError(
                f"INTERIM_PINS names {name}, whose route is {row.route.value}; an "
                "interim pin is for a Python tool"
            )
        sources = [pin.source.value for pin in row.pins if pin.source in permanent]
        if sources:
            raise PlanError(
                f"INTERIM_PINS names {name}, which now has a permanent pin "
                f"({', '.join(sources)}); remove the row"
            )

    installs: dict[str, tuple[str, str, str] | None] = {}
    failures: dict[str, str] = {}
    for name, row in found.items():
        try:
            installs[name] = _installation(row)
        except _NoInstall as err:
            failures[name] = str(err)

    for name in sorted(exempt):
        if name not in failures:
            what = (
                "has nothing to install"
                if installs[name] is None
                else "the plan could install"
            )
            raise PlanError(f"EXEMPT names {name}, which {what}; remove the row")
    for name in sorted(held):
        if name in failures:
            raise PlanError(
                f"HELD names {name}, which the plan could not install anyway; a "
                "scanner with no install path belongs in EXEMPT"
            )
        if installs[name] is None:
            raise PlanError(f"HELD names {name}, which has nothing to install")

    result = []
    for manifest in alpha:
        name = manifest.name
        row = found[name]
        shared = {
            "scanner": name,
            "module": manifest.plugin_module,
            "runtime": row.runtime_kind.value,
            "route": row.route.value,
            "programs": row.programs,
            "distribution": row.distribution,
        }
        if name in exempt:
            result.append(
                PlanRow(
                    **shared,
                    version="",
                    pin_source="",
                    status="exempt",
                    reason=_text(exempt[name]),
                )
            )
        elif name in held:
            result.append(
                PlanRow(
                    **shared,
                    version="",
                    pin_source="",
                    status="held",
                    reason=_text(held[name]),
                )
            )
        elif name in failures:
            raise PlanError(failures[name])
        elif installs[name] is None:
            result.append(
                PlanRow(
                    **shared,
                    version="",
                    pin_source="",
                    status="nothing",
                    reason=_text(row.reason),
                )
            )
        else:
            version, source, reference = installs[name]
            result.append(
                PlanRow(
                    **shared,
                    version=version,
                    pin_source=source,
                    status="install",
                    reason=(
                        f"interim pin, read from {reference}"
                        if source == "interim"
                        else ""
                    ),
                )
            )
    return result


def plan(
    regs=None,
    *,
    exempt: Mapping[str, str] | None = None,
    held: Mapping[str, str] | None = None,
    interim: Mapping[str, str] | None = None,
) -> list[PlanRow]:
    """One row per alpha manifest, sorted by scanner name.

    The tables default to ``EXEMPT``, ``HELD`` and ``INTERIM_PINS`` as they are when
    the plan is made. A scanner with no way to be installed and no table row is an
    error, and so is a table row that no longer describes the registers.
    """
    try:
        return _plan(
            regs,
            EXEMPT if exempt is None else exempt,
            HELD if held is None else held,
            INTERIM_PINS if interim is None else interim,
        )
    except install_routes.RouteError as err:
        raise PlanError(str(err)) from err


def install_args(rows: Sequence[PlanRow]) -> list[str]:
    """The ``ash dependencies install`` arguments for the rows that install.

    One ``--config-overrides ash_plugin_modules+=[<module>]`` pair per distinct
    module, one ``--tool <name>`` per row, then the version override of each Python
    tool, spelled as ``install-pinned-tool --uv-tool-pins`` spells it.
    """
    install = [row for row in rows if row.status == "install"]
    if not install:
        raise PlanError(
            "the alpha install plan installs no scanner (each is exempt, held or "
            "runs inside ASH)"
        )
    routes = install_routes
    args: list[str] = []
    for module in dict.fromkeys(row.module for row in install):
        args += ["--config-overrides", f"ash_plugin_modules+=[{module}]"]
    for row in install:
        args += ["--tool", row.scanner]
    for row in install:
        if row.route in (
            routes.Route.UV_TOOL.value,
            routes.Route.ASH_ENVIRONMENT.value,
        ):
            args += [
                "--config-overrides",
                f"scanners.{row.scanner}.options.tool_version==={row.version}",
            ]
    return args


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Probes:
    """What ``verify`` asks of the machine, so a test can answer without one."""

    #: ``shutil.which``: the path of a program on a search path, or None.
    which: Callable[..., str | None]
    #: The text ``<executable> --version`` prints.
    version_text: Callable[[str], str]
    #: The text ``uv tool list`` prints.
    uv_tool_list: Callable[[], str]
    #: The installed version of a distribution, or None when it is not installed.
    distribution_version: Callable[[str], str | None]


def _installer():
    """assets/install-pinned-tool.py, which owns the version matcher."""
    return _load_by_path("_install_pinned_tool", INSTALLER)


def _uv_tool_list() -> str:
    uv = shutil.which("uv")
    if uv is None:
        return ""
    result = subprocess.run(  # nosec B603 - fixed argv, uv resolved on PATH
        [uv, "tool", "list"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=120,
        check=False,
    )
    return result.stdout


def _distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def default_probes() -> Probes:
    return Probes(
        which=shutil.which,
        version_text=_installer().version_output,
        uv_tool_list=_uv_tool_list,
        distribution_version=_distribution_version,
    )


def docs_runner_module():
    """tests/integration/docs/docs_runner.py, which knows the PATH a session gets."""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    return _load_by_path("_ash_docs_runner", DOCS_RUNNER)


def session_path() -> str:
    """The PATH the docs sessions run with, from the environment this runs in."""
    return docs_runner_module().session_path()


def _bare(version: str) -> str:
    return version[1:] if version[:1] in ("v", "V") else version


def _first_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[0][:100] if lines else "nothing"


def _lists_tool(listing: str, distribution: str, version: str) -> bool:
    """Whether ``uv tool list`` names *distribution* at *version*."""
    wanted = normalize_distribution(distribution)
    for line in listing.splitlines():
        parts = line.split()
        if (
            len(parts) >= 2
            and normalize_distribution(parts[0]) == wanted
            and _bare(parts[1]) == version
        ):
            return True
    return False


def _verify_row(row: PlanRow, path: str, probes: Probes) -> list[str]:
    routes = install_routes
    name = row.scanner
    version = _bare(row.version)
    programs = row.programs or (name,)
    problems = []
    found = {}
    for program in programs:
        location = probes.which(program, path=path)
        if location is None:
            problems.append(f"{name}: {program} is not on the session PATH")
        else:
            found[program] = location
    if problems:
        return problems
    distribution = row.distribution or name
    if row.route == routes.Route.RELEASE_ASSET.value:
        text = probes.version_text(found[programs[0]])
        if not _installer().reports_version(text, version):
            problems.append(
                f"{name}: {programs[0]} reports {_first_line(text)!r}, not {row.version}"
            )
    elif row.route == routes.Route.UV_TOOL.value:
        if not _lists_tool(probes.uv_tool_list(), distribution, version):
            problems.append(
                f"{name}: `uv tool list` does not show {distribution} {version}"
            )
    elif row.route == routes.Route.ASH_ENVIRONMENT.value:
        installed = probes.distribution_version(distribution)
        if installed != version:
            problems.append(
                f"{name}: the installed {distribution} is "
                f"{installed or 'not installed'}, not {version}"
            )
    return problems


def verify(
    rows: Sequence[PlanRow], *, path: str, probes: Probes | None = None
) -> list[str]:
    """What is wrong with the installed tools, one line each; empty when nothing is.

    Each row that installs is looked up on *path*, the PATH a docs session gets. A
    binary must report its pin, a uv tool must be listed by ``uv tool list`` at its
    pin, and a package installed into ASH's environment must be at its pin.
    """
    active = default_probes() if probes is None else probes
    problems = []
    for row in rows:
        if row.status == "install":
            problems.extend(_verify_row(row, path, active))
    return problems


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def _render_tsv(rows: Sequence[PlanRow]) -> str:
    lines = ["\t".join(COLUMNS)]
    for row in rows:
        lines.append("\t".join(_text(value) for value in row.columns().values()))
    return "\n".join(lines)


def _render_json(rows: Sequence[PlanRow]) -> str:
    return json.dumps([row.columns() for row in rows], indent=2)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="alpha-doctest-installs", description=__doc__.split("\n\n")[0]
    )
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan", help="one row per alpha scanner")
    plan_parser.add_argument(
        "--json", action="store_true", help="print the rows as JSON"
    )
    commands.add_parser("args", help="the ash dependencies install arguments")
    commands.add_parser("verify", help="check the installed tools on the session PATH")
    namespace = parser.parse_args(argv)
    try:
        rows = plan()
        if namespace.command == "plan":
            print(_render_json(rows) if namespace.json else _render_tsv(rows))
            return 0
        if namespace.command == "args":
            print("\n".join(install_args(rows)))
            return 0
        problems = verify(rows, path=session_path(), probes=default_probes())
    except PlanError as err:
        print(f"alpha-doctest-installs: {err}", file=sys.stderr)
        return 2
    if problems:
        for problem in problems:
            print(f"alpha-doctest-installs: {problem}", file=sys.stderr)
        return 1
    for row in rows:
        if row.status == "install":
            print(f"verified {row.scanner} {row.version} ({row.route})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
