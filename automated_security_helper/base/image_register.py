"""The container image's own facts: what no single scanner owns.

A scanner's route into the image is the ``image`` row of its operational facets
(``base/scanner_operational_facets.py``). This register holds what the Dockerfile says
about the image as a whole, so a generator, a checker and a documentation page read one
declaration instead of the Dockerfile's text:

- ``IMAGE_STAGES``: the build stages, and which one prefixes its pinned-tool install with
  the pins directory instead of setting it once for the stages built on it.
- ``OS_FAMILIES``: the operating-system families the image is built on, each with the
  hosts it covers and the package manager it uses.
- ``ENGINE_IMAGE_STEPS``: the tools the build installs before any scanner (uv, which runs
  the Python scanners, and crane, which resolves an image tag to a digest).
- ``PROVISIONED_BY_DEPENDENCIES_INSTALL``: pinned tools the image gets through
  ``ash dependencies install`` and not through the pinned-tool installer.
- ``HAND_WRITTEN_PROVIDES``: programs a step written by hand in the Dockerfile provides.
- ``SYSTEM_PACKAGES`` and ``BUILD_STEPS``: the operating-system packages the image
  installs, and the build steps that install and purge build-time packages. Declared here
  and empty: the rows arrive with the generator that renders them.

This module imports only the standard library, and nothing from the ``automated_security_helper``
package, because a checker loads it by file path before ASH is installed. Registering the
module in ``sys.modules`` before executing it, as the other by-path loaders in the tree do,
is what lets the dataclasses below resolve their annotations. ``HostMatch`` is declared here
in the shape of ``install_package_facets.HostMatch`` for that reason; a test holds the two
to one table of hosts, so they cannot drift apart.

The register checks itself when it is imported (``check_register``) and refuses a
contradiction, naming the row.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


class ImageRegisterError(ValueError):
    """The declared rows contradict each other."""


@dataclass(frozen=True)
class HostMatch:
    """The hosts a row covers, in the shape of ``install_package_facets.HostMatch``.

    ``ids`` are exact os-release ``ID`` values and are never read from ``ID_LIKE``.
    ``versions`` are release prefixes: a ``VERSION_ID`` matches when it equals one or
    starts with it plus a dot, so ``12.12`` matches ``12`` and ``123`` does not. Empty
    ``versions`` means every version. ``arches`` is recorded for a read that covered one
    architecture and is not matched.
    """

    ids: tuple[str, ...]
    versions: tuple[str, ...] = ()
    arches: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.ids or any(not value.strip() for value in self.ids):
            raise ValueError("a host match names at least one id, and no id is blank")

    def matches(self, os_id: str, version_id: str = "") -> bool:
        if os_id not in self.ids:
            return False
        if not self.versions:
            return True
        return any(
            version_id == prefix or version_id.startswith(prefix + ".")
            for prefix in self.versions
        )


@dataclass(frozen=True)
class ImageStage:
    """One build stage of the Dockerfile.

    ``pins_dir_inline`` is true for the stage that prefixes its pinned-tool install with
    ``ASH_PINS_DIR=/ash-pins``; the other stages get the directory from an ``ENV`` set
    once, in ``core``, for itself and the stages built on it.
    """

    name: str
    pins_dir_inline: bool = False


@dataclass(frozen=True)
class OsFamily:
    """An operating-system family the image is built on."""

    #: The family's name, which a system package's ``rows`` are keyed by.
    name: str
    #: The package manager's install-provider name (``apt``).
    package_manager: str
    #: The hosts the family is: ``HostMatch(ids=("debian",), versions=("12",))``.
    host: HostMatch
    #: The release's suite name, as the base image's tag spells it (``bookworm``).
    suite: str = ""


@dataclass(frozen=True)
class PackageSource:
    """Where an operating-system package comes from.

    ``distro`` is the family's own index. ``nodesource`` is the NodeSource repository for
    one Node.js major, with the key and the apt source line it is added by.
    """

    kind: str = "distro"
    major: str = ""
    key_url: str = ""
    list_line: str = ""

    def __post_init__(self) -> None:
        if self.kind == "distro":
            if self.major or self.key_url or self.list_line:
                raise ValueError("a distro source carries no nodesource field")
        elif self.kind == "nodesource":
            if any(not v.strip() for v in (self.major, self.key_url, self.list_line)):
                raise ValueError(
                    "a nodesource source names its major, key_url and list_line"
                )
        else:
            raise ValueError(
                f"unknown source kind {self.kind!r}; a source is 'distro' or "
                "'nodesource'"
            )


@dataclass(frozen=True)
class OsPackage:
    """One package in one family's index.

    ``name`` is the name that family's own index spells. ``version`` is the apt pin; a
    glob such as ``20*`` is allowed, as the Dockerfile has it. Empty means the version the
    index carries.
    """

    name: str
    version: str = ""
    source: PackageSource = PackageSource()


@dataclass(frozen=True)
class SystemPackage:
    """An operating-system package the image installs, with one row per family."""

    key: str
    #: ``{family name: the package that provides it there}``.
    rows: Mapping[str, OsPackage]
    #: The stages it is installed in.
    stages: tuple[str, ...]
    #: ``runtime``, or ``build:<step>`` for a package a build step installs and purges.
    phase: str = "runtime"
    #: The executables the package provides, which a scanner's ``external_programs``
    #: name (nodejs provides ``node`` and ``npm``).
    provides: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class BuildStep:
    """A Dockerfile step that installs build-time packages, runs commands and purges them.

    The renderer installs ``build_packages``, runs ``after``, and purges the packages in
    the same ``RUN``, so a compiler never lands in a layer.
    """

    key: str
    stage: str
    build_packages: tuple[str, ...]
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()


@dataclass(frozen=True)
class EngineImageStep:
    """A tool the build installs before any scanner, with the pinned-tool installer."""

    #: The ``TOOL_VERSIONS`` key.
    tool: str
    #: The directory the installer puts it in (``-b``).
    bin_dir: str
    #: The stages that install it.
    stages: tuple[str, ...]
    #: The argv the build runs after the install.
    version_check: tuple[str, ...]
    #: Comment lines the Dockerfile carries directly above the install, copied as they are.
    dockerfile_note: tuple[str, ...] = ()


IMAGE_STAGES: tuple[ImageStage, ...] = (
    ImageStage("uv-reqs", pins_dir_inline=True),
    ImageStage("core"),
    ImageStage("ci"),
    ImageStage("non-root"),
)

#: The Dockerfile's base image is ``python:3.12-slim-bookworm``, which is Debian 12.
OS_FAMILIES: tuple[OsFamily, ...] = (
    OsFamily(
        "debian-bookworm",
        "apt",
        HostMatch(ids=("debian",), versions=("12",)),
        suite="bookworm",
    ),
)

SYSTEM_PACKAGES: tuple[SystemPackage, ...] = ()

BUILD_STEPS: tuple[BuildStep, ...] = ()

ENGINE_IMAGE_STEPS: tuple[EngineImageStep, ...] = (
    EngineImageStep(
        "uv",
        "/root/.local/bin",
        ("uv-reqs", "core"),
        ("uv", "--version"),
    ),
    EngineImageStep(
        "crane",
        "/usr/local/bin",
        ("core",),
        ("crane", "version"),
        dockerfile_note=(
            "# crane resolves a tag-only image reference to its digest at scan time, without a",
            "# container engine (utils/image_digest_resolver.py). Same pinned-asset path as grype.",
        ),
    ),
)

#: Pinned tools the image does not install with the pinned-tool installer, and why.
PROVISIONED_BY_DEPENDENCIES_INSTALL: Mapping[str, str] = MappingProxyType(
    {
        "opengrep": (
            "the image gets it through `ash dependencies install`, which resolves it from "
            "the same pinned table through the scanner's own install commands; installing "
            "it a second time with the pinned-tool installer would add a copy of about "
            "42 MB to /usr/local/bin for no gain"
        ),
    }
)

#: Programs a step written by hand in the Dockerfile provides, and which step.
HAND_WRITTEN_PROVIDES: Mapping[str, str] = MappingProxyType(
    {
        "yarn": "the corepack step",
        "pnpm": "the corepack step",
    }
)


def check_register(
    stages: tuple[ImageStage, ...] = IMAGE_STAGES,
    families: tuple[OsFamily, ...] = OS_FAMILIES,
    packages: tuple[SystemPackage, ...] = SYSTEM_PACKAGES,
    build_steps: tuple[BuildStep, ...] = BUILD_STEPS,
    engine_steps: tuple[EngineImageStep, ...] = ENGINE_IMAGE_STEPS,
    provisioned: Mapping[str, str] = PROVISIONED_BY_DEPENDENCIES_INSTALL,
    hand_written: Mapping[str, str] = HAND_WRITTEN_PROVIDES,
) -> None:
    """Refuse a contradiction between rows, naming the row."""
    stage_names: set[str] = set()
    for stage in stages:
        if not stage.name.strip():
            raise ImageRegisterError("a stage has no name")
        if stage.name in stage_names:
            raise ImageRegisterError(f"stage {stage.name!r} is declared twice")
        stage_names.add(stage.name)

    family_names: set[str] = set()
    for family in families:
        if not family.name.strip():
            raise ImageRegisterError("a family has no name")
        if family.name in family_names:
            raise ImageRegisterError(f"family {family.name!r} is declared twice")
        family_names.add(family.name)
        if not family.package_manager.strip():
            raise ImageRegisterError(f"family {family.name!r} names no package manager")

    step_keys: set[str] = set()
    for step in build_steps:
        if step.key in step_keys:
            raise ImageRegisterError(f"build step {step.key!r} is declared twice")
        step_keys.add(step.key)
        if step.stage not in stage_names:
            raise ImageRegisterError(
                f"build step {step.key!r} names the unknown stage {step.stage!r}"
            )
        if not step.build_packages:
            raise ImageRegisterError(f"build step {step.key!r} lists no build package")

    tools: set[str] = set()
    for engine in engine_steps:
        if engine.tool in tools:
            raise ImageRegisterError(f"engine step {engine.tool!r} is declared twice")
        tools.add(engine.tool)
        if not engine.stages:
            raise ImageRegisterError(f"engine step {engine.tool!r} names no stage")
        for stage_name in engine.stages:
            if stage_name not in stage_names:
                raise ImageRegisterError(
                    f"engine step {engine.tool!r} names the unknown stage "
                    f"{stage_name!r}"
                )
        if not engine.bin_dir.startswith("/"):
            raise ImageRegisterError(
                f"engine step {engine.tool!r} has the relative bin_dir "
                f"{engine.bin_dir!r}"
            )
        if not engine.version_check:
            raise ImageRegisterError(
                f"engine step {engine.tool!r} has no version check"
            )
        if any(not word.strip() for word in engine.version_check):
            raise ImageRegisterError(
                f"engine step {engine.tool!r} has a blank word in its version check"
            )
        for line in engine.dockerfile_note:
            if not line.startswith("#"):
                raise ImageRegisterError(
                    f"engine step {engine.tool!r} has the note line {line!r}, which "
                    "is not a comment"
                )

    package_keys: set[str] = set()
    provided_by: dict[str, str] = {}
    for package in packages:
        if package.key in package_keys:
            raise ImageRegisterError(
                f"system package {package.key!r} is declared twice"
            )
        package_keys.add(package.key)
        for family_name in package.rows:
            if family_name not in family_names:
                raise ImageRegisterError(
                    f"system package {package.key!r} has a row for the unknown "
                    f"family {family_name!r}"
                )
        for stage_name in package.stages:
            if stage_name not in stage_names:
                raise ImageRegisterError(
                    f"system package {package.key!r} names the unknown stage "
                    f"{stage_name!r}"
                )
        if package.phase.startswith("build:"):
            step_key = package.phase[len("build:") :]
            if step_key not in step_keys:
                raise ImageRegisterError(
                    f"system package {package.key!r} names the unknown build step "
                    f"{step_key!r}"
                )
        elif package.phase != "runtime":
            raise ImageRegisterError(
                f"system package {package.key!r} has the phase {package.phase!r}; a "
                "phase is 'runtime' or 'build:<step>'"
            )
        if not package.reason.strip():
            raise ImageRegisterError(f"system package {package.key!r} gives no reason")
        for program in package.provides:
            if program in hand_written:
                raise ImageRegisterError(
                    f"the program {program!r} is provided by both {package.key!r} and "
                    "a hand-written step"
                )
            if program in provided_by:
                raise ImageRegisterError(
                    f"the program {program!r} is provided by both "
                    f"{provided_by[program]!r} and {package.key!r}"
                )
            provided_by[program] = package.key

    for tool, reason in provisioned.items():
        if not reason.strip():
            raise ImageRegisterError(
                f"{tool!r} is provisioned by dependencies install without a reason"
            )
    for program, reason in hand_written.items():
        if not reason.strip():
            raise ImageRegisterError(
                f"{program!r} is provided by a hand-written step without a reason"
            )


check_register()
