# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install-package facet: which package provides each tool in each ecosystem.

``ash dependencies install`` builds one install command per tool from the plugin's
own declaration (``uv tool install``, a pinned release download, ``gem install``).
``--providers`` lets the operator ask for a different route, so something has to say
what the same tool is called elsewhere: ``checkov`` is ``checkov`` to Homebrew, the
``ash-scanners`` flake output to Nix, and a pinned release asset to the downloader.
This module is that table, a register in the family of
:mod:`automated_security_helper.base.scanner_operational_facets`: ASH-declared data,
frozen, read by the installer and never supplied by the tree being scanned.

What a row is:

- ``ecosystem`` is the name of an install provider (``brew``, ``nix``, ``apt`` ...),
  the same names ``--providers`` takes.
- ``package`` is the upstream package name in that ecosystem.
- ``caveat``, when set, is a sentence the installer prints beside the command: the
  system package manager installs the version it carries, not the range the plugin
  declares (distro packages lag), and a Nix row installs what the flake pins. A row
  never hides that; a command built from a row says so.
- ``hosts`` names the hosts the row was read on and is declared for. A row with no
  hosts serves every host its ecosystem's manager runs on, which is what every row
  declared today does.
- ``repository`` names a non-default repository the package comes from (EPEL, a
  distribution's community repository). The caveat then says how the operator enables
  it; ASH never enables one.
- ``upstream`` is the homepage the ecosystem's index records for the package. It is
  the identity of the package: a row whose upstream is not the scanner's own upstream
  names another tool.
- ``source`` and ``read_on`` are the index URL a name was read from and the ISO 8601
  date of the read. ``version_read`` is the version the index carried on that date.
- ``hint_only`` marks a package that hints and documentation name and that ASH does
  not install; a provider must not build a command from such a row. No declared row
  sets it today.

Matching a host. ``HostMatch.ids`` are exact os-release ``ID`` values, and ``ID_LIKE``
is never consulted: Rocky, AlmaLinux, RHEL and Amazon Linux 2023 all carry ``fedora``
there, so a row read on Fedora would otherwise route onto hosts the package does not
exist for. ``versions`` are the release prefixes a row was read on. A ``VERSION_ID``
matches a prefix when it equals it or starts with it plus a dot, so ``3.24.4`` matches
``3.24`` and ``3.240`` does not. No versions means every version, which is for rolling
releases. ``arches`` records that a read covered one architecture and is not matched.
``InstallPackageFacet.row_for`` returns the first row of an ecosystem whose host match
fits, then the first row of it that names no host, then None. Two rows of one ecosystem
overlap when one host can match both, and a row with no hosts overlaps every row of its
ecosystem, so the register holds no two overlapping rows of one ecosystem for a tool.

What a row is not: a promise the package exists at every version, or on every
platform. A package name that does not resolve fails the install command loudly, and
the failure counts against the run. Only names read from the ecosystem's own index
are declared here; an ecosystem with no row for a tool is absent from the table
rather than guessed, so ``--providers apt`` for a tool with no apt row is refused
naming the missing row.

``preference`` is the order the installer tries ecosystems in for a tool when
``--providers`` is not given, after the provider the tool's command was declared
for and then ``uv`` (``candidate_order`` in ``utils/install_providers.py``: the
native provider first, so the declared command stays the identity of the default
run, then ``uv``, then this list). The operator's own ``--providers`` list
replaces all of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Tuple

#: The flake output that realizes the whole toolchain as one store path
#: (``flake.nix``, ``packages.ash-scanners``).
NIX_FLAKE_OUTPUT = "ash-scanners"

_NIX_CAVEAT = (
    "Nix realizes the whole ASH toolchain the repository flake pins; the version "
    "of this tool is the one the flake lock provides, not the plugin's declared range"
)
_BREW_CAVEAT = (
    "Homebrew installs the version its formula carries, not the plugin's declared range"
)

#: The order ecosystems are tried in for a tool when ``--providers`` is not given
#: (the tool's native provider and then ``uv`` are tried first, before this list;
#: ``candidate_order`` in ``utils/install_providers.py``). A provider that cannot
#: serve the tool, or has no row for it, is skipped with its reason printed.
DEFAULT_PREFERENCE: Tuple[str, ...] = (
    "release-download",
    "pipx",
    "pip",
    "brew",
    "nix",
)


@dataclass(frozen=True)
class OsRelease:
    """A host's os-release identity: the fields a row can be matched against.

    ``id_like`` is kept so a refusal can print it. Nothing matches on it.
    """

    id: str
    version_id: str = ""
    id_like: Tuple[str, ...] = ()


def _version_covers(prefix: str, version_id: str) -> bool:
    """Whether *version_id* equals *prefix* or starts with it plus a dot."""
    return version_id == prefix or version_id.startswith(prefix + ".")


@dataclass(frozen=True)
class HostMatch:
    """The hosts a row is declared for.

    ``ids`` are exact os-release ``ID`` values. ``versions`` are release prefixes that
    were read; empty means every version. ``arches`` is set only when the read covered
    one architecture, and is recorded without being matched.
    """

    ids: Tuple[str, ...]
    versions: Tuple[str, ...] = ()
    arches: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.ids or any(not os_id.strip() for os_id in self.ids):
            raise ValueError("a host match names at least one id, and no id is blank")

    def matches(self, host: OsRelease) -> bool:
        if host.id not in self.ids:
            return False
        if not self.versions:
            return True
        return any(_version_covers(prefix, host.version_id) for prefix in self.versions)

    def overlaps(self, other: HostMatch) -> bool:
        """Whether one host can match both: a shared id and versions that agree."""
        if not set(self.ids) & set(other.ids):
            return False
        if not self.versions or not other.versions:
            return True
        return any(
            _version_covers(mine, theirs) or _version_covers(theirs, mine)
            for mine in self.versions
            for theirs in other.versions
        )


@dataclass(frozen=True)
class EcosystemPackage:
    """One tool's package in one ecosystem, optionally for specific hosts."""

    ecosystem: str
    package: str
    caveat: Optional[str] = None
    #: The hosts the row is declared for; empty means every host the manager runs on.
    hosts: Tuple[HostMatch, ...] = ()
    #: A non-default repository the package comes from.
    repository: Optional[str] = None
    #: The homepage the ecosystem's index records for the package.
    upstream: Optional[str] = None
    #: The index URL the name was read from, and the ISO 8601 date of the read.
    source: Optional[str] = None
    read_on: Optional[str] = None
    #: The version the index carried on that date.
    version_read: Optional[str] = None
    #: The package is named in hints and documentation; no command is built from it.
    hint_only: bool = False

    def matches(self, host: Optional[OsRelease]) -> bool:
        """Whether the row names *host*. A row with no hosts names none."""
        return host is not None and any(match.matches(host) for match in self.hosts)

    def overlaps(self, other: EcosystemPackage) -> bool:
        """Whether one host can be served by both rows.

        Rows of two ecosystems never compete. A row with no hosts serves every host,
        so it overlaps every other row of its ecosystem.
        """
        if self.ecosystem != other.ecosystem:
            return False
        if not self.hosts or not other.hosts:
            return True
        return any(
            mine.overlaps(theirs) for mine in self.hosts for theirs in other.hosts
        )


@dataclass(frozen=True)
class InstallPackageFacet:
    """The packages that provide one tool, and the order to prefer them in."""

    tool: str
    rows: Tuple[EcosystemPackage, ...]
    preference: Tuple[str, ...]

    def row_for(
        self, ecosystem: str, host: Optional[OsRelease] = None
    ) -> Optional[EcosystemPackage]:
        """The row that serves *ecosystem* on *host*.

        The first row of the ecosystem whose host match fits *host*, then the first row
        of it that names no host, then None. A host that was not read (None) is served
        only by a row that names no host. ``ID_LIKE`` is never consulted.
        """
        rows = [row for row in self.rows if row.ecosystem == ecosystem]
        for row in rows:
            if row.matches(host):
                return row
        for row in rows:
            if not row.hosts:
                return row
        return None


def _facet(tool: str, *, brew: bool, nix: bool) -> InstallPackageFacet:
    rows = []
    if brew:
        rows.append(EcosystemPackage("brew", tool, _BREW_CAVEAT))
    if nix:
        rows.append(EcosystemPackage("nix", NIX_FLAKE_OUTPUT, _NIX_CAVEAT))
    return InstallPackageFacet(
        tool=tool, rows=tuple(rows), preference=DEFAULT_PREFERENCE
    )


#: Tools whose Homebrew formula exists (read from formulae.brew.sh/api/formula/<name>
#: .json on 2026-11-25: 200 for every name below with ``brew=True``, 404 for
#: cfn-guard, opengrep and cfn-nag, which therefore have no brew row) and that the
#: repository flake's ``ash-scanners`` output carries (``flake.nix``, ``scannersFor``).
INSTALL_PACKAGE_FACETS: Mapping[str, InstallPackageFacet] = {
    f.tool: f
    for f in (
        _facet("actionlint", brew=True, nix=True),
        _facet("bandit", brew=True, nix=True),
        _facet("betterleaks", brew=True, nix=True),
        _facet("cfn-guard", brew=False, nix=True),
        _facet("cfn-lint", brew=True, nix=True),
        _facet("cfn-nag", brew=False, nix=True),
        _facet("checkov", brew=True, nix=True),
        _facet("detect-secrets", brew=True, nix=True),
        _facet("gitleaks", brew=True, nix=True),
        _facet("grype", brew=True, nix=True),
        _facet("hadolint", brew=True, nix=True),
        _facet("opengrep", brew=False, nix=True),
        _facet("semgrep", brew=True, nix=True),
        _facet("syft", brew=True, nix=True),
        _facet("trivy", brew=True, nix=True),
        _facet("zizmor", brew=True, nix=True),
    )
}


@dataclass(frozen=True)
class PackageCollision:
    """A package name that exists in an ecosystem's index and is a different tool.

    A name read from an index is not evidence that it is the tool the name suggests.
    Each collision records one measured case, so that no row can declare it.
    """

    ecosystem: str
    package: str
    reason: str
    #: The hosts the collision was measured on; empty means every host.
    hosts: Tuple[HostMatch, ...] = ()


#: The measured collisions no row may declare. Empty until a collision is measured.
KNOWN_COLLISIONS: Tuple[PackageCollision, ...] = ()

#: The packages that provide a runtime a tool needs and ASH does not install (git, a
#: Ruby with headers, a compiler toolchain, node and npm), keyed by program name, one
#: row per ecosystem and host. Every such row is ``hint_only``. Empty until a row is
#: read from an ecosystem's index.
RUNTIME_PACKAGES: Mapping[str, Tuple[EcosystemPackage, ...]] = {}


def install_package_facet(tool: Optional[str]) -> Optional[InstallPackageFacet]:
    """The facet for ``tool`` (a plugin's command name), or None when undeclared."""
    if not tool:
        return None
    return INSTALL_PACKAGE_FACETS.get(tool)
