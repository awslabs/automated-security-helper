# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What each plugin provisions: its pinned tool, its content databases, its offline environment.

A plugin's manifest (``plugin_manifest.ScannerManifest``) says what the plugin is. This
module holds what the engine needs to PROVISION it, as data the plugin declares and the
engine iterates: the release pin of the tool it runs (``ToolPin``), the content databases
it reads and the age bound each is held to (``ContentDatabase``), the environment
variables that keep its tool off the network in offline mode (``OfflineEnvRow``), and the
PyPI distribution an alpha scanner installs, with the reason it is kept out of the
``alpha`` extra when it is (``PypiPin``, ``Exclusion``). One
:class:`Provisioning` block per scanner, in :data:`PROVISIONING`; the manifest of a scanner
carries its block as ``ScannerManifest.provisioning``.

Before this module the same facts were three module-level tables owned by the engine and
edited whenever a plugin changed: ``tool_downloads.TOOL_VERSIONS``,
``content_databases.CONTENT_DATABASES`` and ``offline_tool_env.OFFLINE_TOOL_ENVIRONMENT``.
Those names still exist, so no consumer changes, but each is now DERIVED from the blocks
below by :func:`tool_versions`, :func:`content_databases` and
:func:`offline_tool_environment`. Adding or retiring a plugin's pin, database or variable is
an edit to that plugin's block, and nothing else lists it.

Why this is one standard-library-only module and not one data module per plugin next to the
manifests: three consumers of these tables run before ASH's dependencies exist, and the
manifests are pydantic models.

* ``python -m automated_security_helper.utils.content_databases`` runs in CI with the
  runner's Python, and ``.github/scripts/assert-content-db-caches.py`` loads it by path;
* ``assets/install-pinned-tool.py`` loads ``utils/tool_downloads.py`` by path inside the
  container build, before the ASH wheel is installed, from the handful of files copied into
  ``/ash-pins`` (and from the flat copies the shipped Dockerfile stages into ``assets/``).
  This file is one of those files, laid out as ``base/plugin_provisioning.py`` there.

So this file imports only the standard library, and the manifest modules in
``plugin_manifests`` import their blocks from here. Splitting it per plugin package is a
packaging change (more staged files), not a design one; the blocks are already separate
constants, one per plugin.

Registry rules, enforced when the tables are first read (:func:`check_registry`):

* a tool is pinned by one scanner (two scanners that run one tool name the pin once, in the
  scanner that owns the tool) and by the engine at most once, and never by both;
* a content database name is declared once;
* two scanners may declare the same offline variable only with the same value;
* a PyPI distribution is pinned once, compared by its PEP 503 normalized name;
* a pin is a member of a known extra or is excluded from it: one of the two, never both
  and never neither;
* a pin's specifier is non-empty and holds no ``;`` (a marker has its own field);
* a cooldown exclusion carries the date the pin leaves the window.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from types import MappingProxyType
from typing import Mapping

# ---------------------------------------------------------------------------
# The declaration types.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolPin:
    """The upstream release a scanner's tool is pinned to.

    ``tool`` is the key ``tool_downloads`` looks the tool up by (``supported_platforms``,
    ``get_asset``, the installer), which is the tool's own name and not always the
    scanner's. ``version`` is the upstream release tag spelled exactly as upstream
    spells it, including a leading ``v`` or the lack of one. The asset filenames and
    SHA256 digests that go with the version stay in ``tool_downloads``, which checks
    that they agree with this pin.
    """

    tool: str
    version: str
    note: str = ""


@dataclass(frozen=True)
class OfflineEnvRow:
    """One environment variable that keeps a tool off the network in offline mode."""

    variable: str
    value: str
    #: What the variable turns off, and the evidence where it was measured.
    reason: str


#: Written next to an offline ruleset when it is downloaded, holding the download time as an
#: RFC 3339 UTC timestamp. A rules file carries no build time of its own, and its mtime is
#: reset by an ordinary ``cp``, so the download records the time explicitly. No extension, so
#: neither semgrep nor opengrep tries to load it as a rule file from the ``--config`` directory.
RULESET_FETCHED_AT_FILE = ".ash-rules-fetched-at"


@dataclass(frozen=True)
class ContentDatabase:
    """One scanner content database, and the bound ASH holds it to."""

    name: str
    scanner: str
    cache_path: str
    max_age: timedelta
    # Where the number comes from: a citation to the tool's source at the pinned version, or,
    # when ``bound_is_tool_default`` is False, ASH's reasoning for choosing it.
    bound_source: str
    bound_is_tool_default: bool
    # What timestamp the age is measured from, and how it is read.
    age_source: str
    # What an operator does to get a fresh copy. Shown in the staleness message.
    refresh: str
    # Environment variables that tell the tool the bound, with the values they must carry. Empty
    # when the tool has no such control.
    bound_env: dict[str, str] = field(default_factory=dict)
    how_enforced: str = ""
    # The verb for the timestamp ``age_source`` reads, as the staleness message prints it:
    # a vulnerability database is built, an offline ruleset is downloaded.
    timestamp_label: str = "built"
    # Whether CI may cache this database. Only grype's is, because only grype's has the CI
    # restore and save guards (`check-age`) the bucket argument on ``bucket_width`` relies on.
    # A declared max age alone is not enough: it bounds what a SCAN accepts, not what a cache
    # hands out, and the drift gate refuses a CI cache of anything not marked here.
    cacheable_in_ci: bool = False
    # Other scanners that read the same database, by config name. ``scanner`` is the one
    # the database is declared for; a scanner named here is held to the same bound, and
    # its measurements are recorded under its own name. The trivy database is read by
    # both scanners of the Trivy plugin, ``trivy-repo`` and ``trivy``.
    also_read_by: tuple[str, ...] = ()
    # The environment variable that moves the directory this database is read from,
    # for a row where ASH reads or sets it. None means no read has been recorded, not
    # that the tool has no such variable. ``cache_path`` is the default the tool reads
    # when the variable is not set.
    cache_env: str | None = None

    @property
    def readers(self) -> tuple[str, ...]:
        """Every scanner config name that reads this database, ``scanner`` first."""
        return (self.scanner, *self.also_read_by)

    @property
    def cacheable(self) -> bool:
        """Only a database with an enforced bound AND the CI age guards may be cached in CI."""
        return self.cacheable_in_ci


class ExclusionReason(str, Enum):
    """Why a PyPI pin is kept out of the ``alpha`` extra."""

    #: A requirement ASH's core also has, at a range that does not overlap.
    CORE_PIN_CONFLICT = "core_pin_conflict"
    #: The pin conflicts with the ``cdk`` or ``symbols`` extra.
    EXTRA_CONFLICT = "extra_conflict"
    #: On some platform it would install on, the install builds from source.
    NEEDS_BUILD = "needs_build"
    #: A dependency publishes neither a wheel nor a source distribution for a
    #: supported platform.
    NO_WHEELS = "no_wheels"
    #: The pin is younger than the project's ``exclude-newer`` window.
    COOLDOWN = "cooldown"
    #: Membership waits on a decision that is not the code's to make.
    OWNER_HOLD = "owner_hold"


@dataclass(frozen=True)
class Exclusion:
    """The recorded reason a pin is not a member of the ``alpha`` extra."""

    reason: ExclusionReason
    #: The cause, in the words of whoever measured it.
    detail: str
    #: When and how the cause was measured, or that it was not a measurement.
    measured: str
    #: ``COOLDOWN`` only: the UTC date the pin leaves the window.
    until: str = ""


#: The extras a pin can be a member of. The register holds the PyPI pins of the alpha
#: scanners, which the ``alpha`` extra installs, so that is the only one.
PIN_EXTRAS: frozenset[str] = frozenset({"alpha"})


@dataclass(frozen=True)
class PypiPin:
    """The PyPI distribution a scanner installs, and the range ASH holds it to.

    ``specifier`` is the scanner's own default constraint, verbatim, so the table and
    the scanner say one thing. Markers that restrict where the pin applies go in
    ``python_marker`` and ``platform_marker``, never into the specifier. ``runtime``
    is ``"uv-tool"`` for a scanner that installs into a uv tool environment of its own
    and ``"ash-environment"`` for one that installs into the environment ASH runs in.
    A pin is a member of the extra named by ``extra`` (one of :data:`PIN_EXTRAS`) or
    is ``excluded`` from it. The registry refuses a pin that is both, a pin that is
    neither, and an extra it does not know.
    """

    distribution: str
    specifier: str
    runtime: str
    #: Extra requirements installed with the tool (``uv tool install --with``).
    with_requirements: tuple[str, ...] = ()
    python_marker: str = ""
    platform_marker: str = ""
    extra: str = ""
    excluded: Exclusion | None = None
    note: str = ""


def normalize_distribution(name: str) -> str:
    """A distribution name as PEP 503 compares it: runs of ``-``, ``_`` and ``.``
    are one ``-``, in lower case."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Provisioning:
    """Everything one scanner declares for the engine to provision it."""

    #: Release pins of the tools this scanner OWNS (a tool two scanners run is owned
    #: by one of them).
    tool_pins: tuple[ToolPin, ...] = ()
    #: Content databases declared for this scanner (``ContentDatabase.scanner``).
    content_databases: tuple[ContentDatabase, ...] = ()
    #: Variables the engine adds to every child's environment in offline mode so the
    #: scanner's tool makes no network call of its own.
    offline_env: tuple[OfflineEnvRow, ...] = ()
    #: The PyPI distributions this scanner installs (an alpha scanner whose tool is a
    #: Python package). Not release pins: ``tool_versions`` does not list them.
    pypi_pins: tuple[PypiPin, ...] = ()


NO_PROVISIONING = Provisioning()


def go_duration(value: timedelta) -> str:
    """A Go ``time.Duration`` string, which is what grype parses the bound from."""
    seconds = int(value.total_seconds())
    sign = "-" if seconds < 0 else ""
    hours, rest = divmod(abs(seconds), 3600)
    minutes, secs = divmod(rest, 60)
    if minutes == 0 and secs == 0:
        return f"{sign}{hours}h"
    return f"{sign}{hours}h{minutes}m{secs}s"


GRYPE_DB_MAX_AGE = timedelta(hours=120)
TRIVY_DB_MAX_AGE = timedelta(hours=24)
# ASH's own choice for both offline rulesets; see OFFLINE_RULESET_BOUND_REASON.
OFFLINE_RULESET_MAX_AGE = timedelta(days=30)

OFFLINE_RULESET_BOUND_REASON = (
    "ASH's own choice, not a tool default: neither semgrep nor opengrep has any notion of a "
    "local rules file going stale, so there is no tool number to adopt. 30 days because a "
    "ruleset encodes code patterns rather than advisories, and ages more slowly than a "
    "vulnerability feed: holding it to grype's 5 days would fail every air-gapped image "
    "within a week over content that changes over weeks. But the registry packs keep "
    "gaining new and corrected rules, and with no bound at all an image can scan with "
    "rules years old while every report reads as current. A month bounds an offline image "
    "to a monthly rebuild for its rules; its grype database, if it has one, needs a rebuild "
    "far sooner anyway."
)

# ---------------------------------------------------------------------------
# The engine's own pin.
# ---------------------------------------------------------------------------

#: Pins no scanner owns: tools the ENGINE provisions. ``uv`` runs every ``uv_python``
#: scanner, so it belongs to none of them. Tagged without a leading "v" upstream, so the
#: release URL has none either. ``crane`` is the registry client that resolves a tag-only
#: image reference to its digest (``utils/image_digest_resolver.py``); the scan, not any one
#: scanner, runs it, so it belongs to none of them either.
ENGINE_TOOL_PINS: tuple[ToolPin, ...] = (
    ToolPin("crane", "v0.22.1"),
    ToolPin("uv", "0.13.9"),
)

# ---------------------------------------------------------------------------
# One block per scanner that provisions anything. A scanner that provisions nothing
# (bandit, cfn-lint, detect-secrets, ...) has no entry and reads NO_PROVISIONING.
#
# Pins are the same versions the container image already builds with (the Dockerfile's
# ARG lines), so a scan run from a container, from nix and from a bare
# ``ash dependencies install`` all execute the same tool versions. opengrep is not in the
# Dockerfile's ARG lines: the image installs it through ``ash dependencies install``,
# which resolves it from its pin. Its version is the default of
# ``OpengrepScannerConfigOptions.version``, which is also what nix/opengrep.nix pins.
# ---------------------------------------------------------------------------

_ACTIONLINT = Provisioning(tool_pins=(ToolPin("actionlint", "v1.7.12"),))

_BETTERLEAKS = Provisioning(
    tool_pins=(
        ToolPin(
            "betterleaks",
            "v1.10.1",
            note=(
                "The v1 maintenance line. v2.0.0 is a release candidate (2.0.0-rc.9 on "
                "2026-11-17), and ASH pins no prerelease."
            ),
        ),
    )
)

_CFN_GUARD = Provisioning(tool_pins=(ToolPin("cfn-guard", "3.3.0"),))

_CHECKOV = Provisioning(
    offline_env=(
        OfflineEnvRow(
            "CKV_SKIP_PACKAGE_UPDATE_CHECK",
            "true",
            "checkov asks pypi.org for its newest release when "
            "checkov.common.util.banner is imported, which every command does, "
            "--version included.",
        ),
    )
)

#: ferret-scan is a PyPI package installed into the environment ASH runs in. The
#: specifier is the plugin's default version constraint (a test holds the two equal).
#: Membership in an extra is held for a maintainer decision, so the pin is excluded.
_FERRET_SCAN = Provisioning(
    pypi_pins=(
        PypiPin(
            distribution="ferret-scan",
            specifier=">=2.4.5,<2.7.0",
            runtime="ash-environment",
            excluded=Exclusion(
                reason=ExclusionReason.OWNER_HOLD,
                detail="membership in an extra waits on a maintainer decision",
                measured="not a measurement: the pin is held for that decision",
            ),
            note="the specifier is the plugin's default version constraint",
        ),
    )
)

_GITLEAKS = Provisioning(tool_pins=(ToolPin("gitleaks", "v8.30.1"),))

# The Go toolchain syft or grype may run: no module proxy, no toolchain download. On a Go
# module, syft (golang.use-packages-lib, on by default) and grype run the Go toolchain found
# on PATH (``go list``; measured with a fake ``go``). A real toolchain resolves missing
# modules from GOPROXY and, for a ``go`` or ``toolchain`` line newer than itself, downloads
# a toolchain. syft's setting is turned off, and for grype, which has none, GOPROXY=off and
# GOTOOLCHAIN=local keep that toolchain from downloading anything. Both scanners declare the
# rows, because either may run without the other.
_GO_TOOLCHAIN_REASON = (
    "The Go toolchain syft or grype may run resolves modules from GOPROXY and downloads a "
    "newer toolchain; off in offline mode (measured with a fake `go` on PATH)."
)
_GO_TOOLCHAIN_ROWS = (
    OfflineEnvRow("GOPROXY", "off", _GO_TOOLCHAIN_REASON),
    OfflineEnvRow("GOTOOLCHAIN", "local", _GO_TOOLCHAIN_REASON),
)
# git run by a tool (trivy's Terraform module sources, syft's vcpkg registries) reaches no
# remote; only local paths are allowed.
_GIT_PROTOCOL_ROW = OfflineEnvRow(
    "GIT_ALLOW_PROTOCOL",
    "file",
    "git run by a tool (trivy's Terraform module sources, syft's vcpkg registries) reaches "
    "no remote; only local paths are allowed.",
)

_GRYPE = Provisioning(
    tool_pins=(ToolPin("grype", "v0.122.1"),),
    content_databases=(
        ContentDatabase(
            name="grype-db",
            scanner="grype",
            cache_path="~/.cache/grype/db",
            # ASH sets this variable for every grype scan, so grype reads the directory
            # ASH refreshes and checks, and reads it when it decides whether an offline
            # scan has a database; the image sets it.
            cache_env="GRYPE_DB_CACHE_DIR",
            max_age=GRYPE_DB_MAX_AGE,
            bound_source=(
                "grype's own default, `time.Hour * 24 * 5` "
                "(grype/db/v6/installation/curator.go:58 at v0.120.1)"
            ),
            bound_is_tool_default=True,
            age_source="`built` in `grype db status -o json`, the database's own build time",
            refresh=(
                "run `grype db update` with network access, or rebuild the offline image "
                "(`ash container build --offline`) so it downloads a current database"
            ),
            bound_env={
                "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": go_duration(GRYPE_DB_MAX_AGE),
                "GRYPE_DB_VALIDATE_AGE": "true",
            },
            how_enforced=(
                "grype refuses a database built longer ago than db.max-allowed-built-age while "
                "db.validate-age is true: it downloads a newer one, and fails the scan if it "
                "cannot (grype/db/v6/installation/curator.go:221-225,605-615 at v0.120.1). "
                "Offline, validate-age is off, and ASH's scan-time check holds the same bound"
            ),
            cacheable_in_ci=True,
        ),
    ),
    offline_env=(
        # grype: update checks, and the external sources a .grype.yaml can turn on.
        OfflineEnvRow(
            "GRYPE_CHECK_FOR_APP_UPDATE",
            "false",
            "grype checks for a newer release of itself.",
        ),
        OfflineEnvRow(
            "GRYPE_DB_AUTO_UPDATE",
            "false",
            "grype updates its vulnerability database on its own.",
        ),
        OfflineEnvRow(
            "GRYPE_EXTERNAL_SOURCES_ENABLE",
            "false",
            "the external sources (maven lookups) a .grype.yaml can turn on.",
        ),
        *_GO_TOOLCHAIN_ROWS,
    ),
)

#: GuardDog installs as a uv tool with an environment of its own. The specifier is the
#: plugin's default version constraint. The two markers record where that version is
#: known not to install: no CPython 3.14 wheels for two of its dependencies, and no
#: Windows build of a third (the scanner's runtime-compatibility row and its
#: ``unsupported_platform_reason`` say the same, and a test holds them equal).
#: Membership in an extra is held for a maintainer decision, so the pin is excluded.
_GUARDDOG = Provisioning(
    pypi_pins=(
        PypiPin(
            distribution="guarddog",
            specifier="==3.2.0",
            runtime="uv-tool",
            python_marker="python_version < '3.14'",
            platform_marker="sys_platform != 'win32'",
            excluded=Exclusion(
                reason=ExclusionReason.OWNER_HOLD,
                detail="membership in an extra waits on a maintainer decision",
                measured="not a measurement: the pin is held for that decision",
            ),
            note=(
                "the specifier is the plugin's default version constraint; the "
                "markers record where that version is known not to install"
            ),
        ),
    )
)

_HADOLINT = Provisioning(tool_pins=(ToolPin("hadolint", "v2.15.1"),))

_NPM_AUDIT = Provisioning(
    offline_env=(
        OfflineEnvRow(
            "npm_config_update_notifier",
            "false",
            "npm 10.9 runs its update notifier against registry.npmjs.org in "
            "`npm audit --offline`.",
        ),
    )
)

_OPENGREP = Provisioning(
    tool_pins=(ToolPin("opengrep", "v2.0.0"),),
    content_databases=(
        ContentDatabase(
            name="opengrep-offline-rules",
            scanner="opengrep",
            cache_path="/deps/.opengrep",
            # The scanner names this variable as its offline rule cache and ASH reads it
            # before an offline scan; the image sets it.
            cache_env="OPENGREP_RULES_CACHE_DIR",
            max_age=OFFLINE_RULESET_MAX_AGE,
            bound_source=OFFLINE_RULESET_BOUND_REASON,
            bound_is_tool_default=False,
            timestamp_label="downloaded",
            age_source=(
                f"the download time in `{RULESET_FETCHED_AT_FILE}` in the cache directory, "
                "else the oldest rules file's mtime"
            ),
            refresh=(
                "rebuild the offline image (`ash container build --offline`), which downloads the "
                "rulesets again, or download them into $OPENGREP_RULES_CACHE_DIR and record the "
                f"time in {RULESET_FETCHED_AT_FILE}"
            ),
            how_enforced=(
                "none in opengrep: a local rules file has no staleness check. ASH's scan-time "
                "check holds it to the bound in offline mode, the only mode that uses it"
            ),
        ),
    ),
)

_SEMGREP = Provisioning(
    content_databases=(
        ContentDatabase(
            name="semgrep-offline-rules",
            scanner="semgrep",
            cache_path="/deps/.semgrep",
            # The scanner names this variable as its offline rule cache and ASH reads it
            # before an offline scan; the image sets it.
            cache_env="SEMGREP_RULES_CACHE_DIR",
            max_age=OFFLINE_RULESET_MAX_AGE,
            bound_source=OFFLINE_RULESET_BOUND_REASON,
            bound_is_tool_default=False,
            timestamp_label="downloaded",
            age_source=(
                f"the download time in `{RULESET_FETCHED_AT_FILE}` in the cache directory, "
                "else the oldest rules file's mtime"
            ),
            refresh=(
                "rebuild the offline image (`ash container build --offline`), which downloads the "
                "rulesets again, or download them into $SEMGREP_RULES_CACHE_DIR and record the "
                f"time in {RULESET_FETCHED_AT_FILE}"
            ),
            how_enforced=(
                "none in semgrep: a local rules file has no staleness check. ASH's scan-time "
                "check holds it to the bound in offline mode, the only mode that uses it"
            ),
        ),
    ),
    offline_env=(
        OfflineEnvRow(
            "SEMGREP_ENABLE_VERSION_CHECK",
            "0",
            "semgrep 1.180 checks semgrep.dev for a newer version in `semgrep scan` and in "
            "`semgrep --version`.",
        ),
        OfflineEnvRow(
            "SEMGREP_SEND_METRICS",
            "off",
            "semgrep usage metrics; a different switch from --metrics off.",
        ),
    ),
)

_SYFT = Provisioning(
    tool_pins=(ToolPin("syft", "v1.57.2"),),
    offline_env=(
        # syft: update check, and the lookups a .syft.yaml or `enrich` can turn on. Setting
        # them false in the environment overrides the file (measured for the Go license
        # search).
        OfflineEnvRow(
            "SYFT_CHECK_FOR_APP_UPDATE",
            "false",
            "syft checks for a newer release of itself.",
        ),
        OfflineEnvRow(
            "SYFT_GOLANG_SEARCH_REMOTE_LICENSES",
            "false",
            "syft's remote Go license search, which a .syft.yaml can turn on.",
        ),
        OfflineEnvRow(
            "SYFT_JAVA_USE_NETWORK",
            "false",
            "syft's maven lookups, which a .syft.yaml can turn on.",
        ),
        OfflineEnvRow(
            "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES",
            "false",
            "syft's remote JavaScript license search.",
        ),
        OfflineEnvRow(
            "SYFT_PYTHON_SEARCH_REMOTE_LICENSES",
            "false",
            "syft's remote Python license search.",
        ),
        OfflineEnvRow(
            "SYFT_CPP_VCPKG_ALLOW_GIT_CLONE",
            "false",
            "syft's vcpkg git clones.",
        ),
        OfflineEnvRow(
            "SYFT_GOLANG_USE_PACKAGES_LIB",
            "false",
            "syft runs the Go toolchain on PATH for a Go module (`go list`) by default.",
        ),
        *_GO_TOOLCHAIN_ROWS,
        _GIT_PROTOCOL_ROW,
    ),
)

_TRIVY = Provisioning(
    tool_pins=(ToolPin("trivy", "v0.76.2"),),
    offline_env=(
        # trivy 0.75 contacts check.trivy.dev for its version check and its telemetry.
        OfflineEnvRow(
            "TRIVY_SKIP_VERSION_CHECK",
            "true",
            "trivy's version check against check.trivy.dev (--skip-version-check).",
        ),
        OfflineEnvRow(
            "TRIVY_DISABLE_TELEMETRY",
            "true",
            "trivy's telemetry to check.trivy.dev (--disable-telemetry).",
        ),
        _GIT_PROTOCOL_ROW,
    ),
)

_TRIVY_REPO = Provisioning(
    content_databases=(
        ContentDatabase(
            name="trivy-db",
            scanner="trivy-repo",
            also_read_by=("trivy",),
            cache_path="~/.cache/trivy",
            # trivy reads this directory from TRIVY_CACHE_DIR when it is set (the
            # trivy plugin's README, "Permission errors"), and the image sets it.
            cache_env="TRIVY_CACHE_DIR",
            max_age=TRIVY_DB_MAX_AGE,
            bound_source=(
                "trivy's own rule: a database is current until its NextUpdate "
                "(pkg/db/db.go:172-183 at v0.75.0), and the published database's NextUpdate is "
                "its UpdatedAt plus `--update-interval 24h` (trivy-db Makefile:94 and "
                "pkg/vulndb/db.go:90 at 650c4091)"
            ),
            bound_is_tool_default=True,
            age_source=(
                "`VulnerabilityDB.UpdatedAt` in `trivy version --format json`, the database's "
                "own build time"
            ),
            refresh=(
                "run `trivy image --download-db-only` with network access, or copy a current "
                "trivy database into the cache directory trivy reads"
            ),
            how_enforced=(
                "no max-age option exists; trivy refreshes on its own NextUpdate metadata unless "
                "--skip-db-update is passed (pkg/db/db.go:145-174 at v0.75.0). ASH's scan-time "
                "check holds it to the bound in both modes"
            ),
        ),
    )
)

#: ``{scanner name: its provisioning block}`` for every scanner that provisions
#: anything. The ORDER is the order the derived tables list their rows in: the content
#: databases keep the order they were first declared in (grype, trivy, semgrep,
#: opengrep). A scanner not listed provisions nothing.
PROVISIONING: Mapping[str, Provisioning] = MappingProxyType(
    {
        "actionlint": _ACTIONLINT,
        "betterleaks": _BETTERLEAKS,
        "cfn-guard": _CFN_GUARD,
        "checkov": _CHECKOV,
        "ferret-scan": _FERRET_SCAN,
        "gitleaks": _GITLEAKS,
        "grype": _GRYPE,
        "guarddog": _GUARDDOG,
        "hadolint": _HADOLINT,
        "npm-audit": _NPM_AUDIT,
        "opengrep": _OPENGREP,
        "semgrep": _SEMGREP,
        "syft": _SYFT,
        "trivy": _TRIVY,
        "trivy-repo": _TRIVY_REPO,
    }
)

#: The order the derived content-database table lists its entries in.
_DATABASE_ORDER = ("grype", "trivy-repo", "semgrep", "opengrep")


def provisioning_for(scanner: str) -> Provisioning:
    """The block *scanner* declares; :data:`NO_PROVISIONING` when it provisions nothing."""
    return PROVISIONING.get(scanner, NO_PROVISIONING)


class ProvisioningRegistryError(ValueError):
    """The declared provisioning blocks contradict each other."""


def check_registry(
    blocks: Mapping[str, Provisioning] = PROVISIONING,
    engine_pins: tuple[ToolPin, ...] = ENGINE_TOOL_PINS,
) -> None:
    """Refuse a contradiction between blocks, naming the scanners involved."""
    pinned_by: dict[str, str] = {pin.tool: "the engine" for pin in engine_pins}
    if len(pinned_by) != len(engine_pins):
        raise ProvisioningRegistryError("the engine pins a tool twice")
    databases: dict[str, str] = {}
    variables: dict[str, tuple[str, str]] = {}
    distributions: dict[str, str] = {}
    for scanner, block in blocks.items():
        for pin in block.tool_pins:
            if pin.tool in pinned_by:
                raise ProvisioningRegistryError(
                    f"{pin.tool!r} is pinned by both {pinned_by[pin.tool]!r} and "
                    f"{scanner!r}; pin it where the tool is owned"
                )
            pinned_by[pin.tool] = scanner
        for database in block.content_databases:
            if database.scanner != scanner:
                raise ProvisioningRegistryError(
                    f"content database {database.name!r} is declared by {scanner!r} "
                    f"but names {database.scanner!r} as its scanner"
                )
            if database.name in databases:
                raise ProvisioningRegistryError(
                    f"content database {database.name!r} is declared by both "
                    f"{databases[database.name]!r} and {scanner!r}"
                )
            databases[database.name] = scanner
        for row in block.offline_env:
            seen = variables.get(row.variable)
            if seen is not None and seen[1] != row.value:
                raise ProvisioningRegistryError(
                    f"{row.variable} is {seen[1]!r} for {seen[0]!r} and {row.value!r} "
                    f"for {scanner!r}"
                )
            variables[row.variable] = (scanner, row.value)
        for pypi_pin in block.pypi_pins:
            key = normalize_distribution(pypi_pin.distribution)
            if key in distributions:
                raise ProvisioningRegistryError(
                    f"distribution {pypi_pin.distribution!r} is pinned twice, by "
                    f"{distributions[key]!r} and by {scanner!r}"
                )
            distributions[key] = scanner
            if pypi_pin.extra and pypi_pin.excluded is not None:
                raise ProvisioningRegistryError(
                    f"{scanner!r} pins {pypi_pin.distribution!r} as a member of the "
                    f"{pypi_pin.extra!r} extra and also excludes it; a pin is one "
                    "or the other"
                )
            if not pypi_pin.extra and pypi_pin.excluded is None:
                raise ProvisioningRegistryError(
                    f"{scanner!r} pins {pypi_pin.distribution!r} as neither a member "
                    "of an extra nor excluded from one; a pin is one or the other"
                )
            if pypi_pin.extra and pypi_pin.extra not in PIN_EXTRAS:
                raise ProvisioningRegistryError(
                    f"{scanner!r} pins {pypi_pin.distribution!r} as a member of the "
                    f"unknown extra {pypi_pin.extra!r}; the extras are "
                    f"{', '.join(sorted(PIN_EXTRAS))}"
                )
            if not pypi_pin.specifier.strip() or ";" in pypi_pin.specifier:
                raise ProvisioningRegistryError(
                    f"{scanner!r} pins {pypi_pin.distribution!r} with the specifier "
                    f"{pypi_pin.specifier!r}, which must be non-empty and hold no "
                    "';' (a marker has its own field)"
                )
            if (
                pypi_pin.excluded is not None
                and pypi_pin.excluded.reason is ExclusionReason.COOLDOWN
                and not pypi_pin.excluded.until.strip()
            ):
                raise ProvisioningRegistryError(
                    f"{scanner!r}: the cooldown exclusion of {pypi_pin.distribution!r} "
                    "carries no 'until' date"
                )


# ---------------------------------------------------------------------------
# The derived tables. Each iterates the declarations; none lists a row itself.
# ---------------------------------------------------------------------------


def tool_versions() -> dict[str, str]:
    """``{tool: pinned release}`` for every declared pin, sorted by tool name."""
    pins = [*ENGINE_TOOL_PINS]
    for block in PROVISIONING.values():
        pins.extend(block.tool_pins)
    return {pin.tool: pin.version for pin in sorted(pins, key=lambda p: p.tool)}


def content_databases() -> tuple[ContentDatabase, ...]:
    """Every declared content database, in the order of :data:`_DATABASE_ORDER`."""
    ordered = [name for name in _DATABASE_ORDER if name in PROVISIONING]
    ordered += [
        name
        for name, block in PROVISIONING.items()
        if name not in ordered and block.content_databases
    ]
    return tuple(
        database
        for name in ordered
        for database in PROVISIONING[name].content_databases
    )


def offline_tool_environment() -> dict[str, str]:
    """The variable -> value map every child gets in offline mode."""
    environment: dict[str, str] = {}
    for block in PROVISIONING.values():
        for row in block.offline_env:
            environment[row.variable] = row.value
    return environment


check_registry()
