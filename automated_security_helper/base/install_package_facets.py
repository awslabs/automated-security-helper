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

What a row is not: a promise the package exists at every version, or on every
platform. A package name that does not resolve fails the install command loudly, and
the failure counts against the run. Only names read from the ecosystem's own index
are declared here; an ecosystem with no row for a tool is absent from the table
rather than guessed, so ``--providers apt`` for a tool with no apt row is refused
naming the missing row.

``preference`` is the order the installer tries ecosystems in for a tool when
``--providers`` is not given (after ``uv``, which is always first). The operator's
own ``--providers`` list replaces it.
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
#: (``uv`` is always tried first, before this list). A provider that cannot serve the
#: tool, or has no row for it, is skipped with its reason printed.
DEFAULT_PREFERENCE: Tuple[str, ...] = (
    "release-download",
    "pipx",
    "pip",
    "brew",
    "nix",
)


@dataclass(frozen=True)
class EcosystemPackage:
    """One tool's package in one ecosystem."""

    ecosystem: str
    package: str
    caveat: Optional[str] = None


@dataclass(frozen=True)
class InstallPackageFacet:
    """The packages that provide one tool, and the order to prefer them in."""

    tool: str
    rows: Tuple[EcosystemPackage, ...]
    preference: Tuple[str, ...]

    def row_for(self, ecosystem: str) -> Optional[EcosystemPackage]:
        for row in self.rows:
            if row.ecosystem == ecosystem:
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


def install_package_facet(tool: Optional[str]) -> Optional[InstallPackageFacet]:
    """The facet for ``tool`` (a plugin's command name), or None when undeclared."""
    if not tool:
        return None
    return INSTALL_PACKAGE_FACETS.get(tool)
