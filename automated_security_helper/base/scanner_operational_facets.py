# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner operational facets register: how each scanner runs, not what it maps.

:mod:`automated_security_helper.base.scanner_facets` classifies what a scanner's
native output can map into the shared pipeline. This module is its companion
for the operational side: network behavior, output types, scan-target types,
runtime dependency, platform support, the route into the container image,
severity fidelity, suppression surfaces, finding-identity stability, rules
extensibility, exit-code semantics, provenance, and input prerequisites (the
tier is the manifest's, not this register's). Every scanner class declares a
:class:`ScannerOperationalFacets` under :data:`OPERATIONAL_FACETS_ATTR`, read
from the class's own ``vars()`` exactly as the mapping register is.

Why a second descriptor and not more fields on ``ScannerFacets``: the mapping
facets already number twenty; adding the operational dimensions would put well
over thirty required fields in one class, past what a reviewer can read as one
declaration. Both are required class attributes, one registry-totality test
covers both, and each model has its own vocabulary meta-test.

The fold rule, and why most fields here are references and not new facts: ASH
already declares most operational properties in production code -- the
``offline_strategy`` class attribute, ``SandboxRequirements`` (network, env
prefixes), ``OFFLINE_TOOL_ENVIRONMENT``, ``CONTENT_DATABASES`` and
``SCANNERS_WITHOUT_CONTENT_DATABASE``, ``covers``, ``tool_type``,
``python_only``, ``use_uv_tool``, ``external_executables``,
``success_exit_codes``, and the pinned-asset tables in ``utils/tool_downloads``.
Those have live consumers (the sandbox builds its policy from
``SandboxRequirements``; the executor and the MCP inventory read
``offline_strategy``; CI keys come from ``content_databases``), so this module
does not move or replace them. Each field that restates one is a MIRROR, and
``tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py``
fails when a mirror contradicts the production declaration it names. What this
module adds is what no existing declaration says: what is fetched and why
(``grype`` and ``semgrep`` are both ``CACHE_FLAGS`` while fetching entirely
different things), a typed target vocabulary (``covers`` is free text at three
grains and cannot be totality-tested), output formats, and the dimensions that
were declared nowhere.

Declaration rules, fail closed:

- Every field is required, and a model that carries a state needing evidence
  (a degraded offline outcome, a dropped native severity field, an unconfirmed
  silencing layer) refuses to construct without it. "Not read" is representable
  as an explicit unconfirmed state with its reason, never as a default.
- ``OfflineStrategy.UNKNOWN`` is refused in a declaration, and the registry
  totality test also fails on a scanner whose class attribute is still the
  base default, so a new scanner cannot rest on the enum's honest-ignorance
  value.
- The upstream license is not recorded from recall. The field carries the
  literal ``"not read"`` until a pinned upstream LICENSE read supplies a value
  with a ``(source: ...)`` citation.
"""

from __future__ import annotations

import re
import warnings
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from automated_security_helper.core.enums import (
    OfflineStrategy,
    ScanCategory,
    ScannerToolType,
    categories_of_tool_type,
)

if TYPE_CHECKING:
    from automated_security_helper.core.asset import AssetKind

#: The class attribute a scanner declares its operational row under. Read from
#: ``vars(cls)``, so an inherited declaration never satisfies it.
OPERATIONAL_FACETS_ATTR = "operational_facets"

#: The literal an unread upstream license carries.
LICENSE_NOT_READ = "not read"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def _blank(value: Optional[str]) -> bool:
    return not (value or "").strip()


# --------------------------------------------------------------------------
# A. Network behavior
# --------------------------------------------------------------------------


class FetchKind(str, Enum):
    """What the scanner reaches the network for, as ASH invokes it."""

    #: Nothing found at the adapter's bytes.
    NONE = "none"
    #: Only the tool's own update check or telemetry, which ASH kills by
    #: environment (``OFFLINE_TOOL_ENVIRONMENT``).
    TOOL_UPDATES_ONLY = "tool_updates_only"
    #: Rulesets, vulnerability databases, advisories, package metadata,
    #: policies, module sources, issuer verification.
    CONTENT_FETCH = "content_fetch"
    #: The scanned source itself leaves the host. Never to be read as a mere
    #: ruleset fetch.
    SERVICE_UPLOAD = "service_upload"


class Fetched(str, Enum):
    """The named artifacts a content fetch or an upload moves."""

    RULESET_REGISTRY = "ruleset_registry"
    VULN_DB = "vuln_db"
    CHECKS_BUNDLE = "checks_bundle"
    ADVISORY_FEED = "advisory_feed"
    PACKAGE_METADATA = "package_metadata"
    PACKAGE_DOWNLOADS = "package_downloads"
    PLATFORM_POLICIES = "platform_policies"
    MODULE_SOURCES = "module_sources"
    ISSUER_VERIFICATION = "issuer_verification"
    SOURCE_UPLOAD = "source_upload"
    #: A registry read for the digest a tag-only image reference points at
    #: (``crane digest``, ``utils/image_digest_resolver.py``): the manifest's
    #: digest, no layer. Declared by the scanners that read images, whose scan
    #: it keys the finding ids of.
    IMAGE_DIGEST = "image_digest"


class Prefetch(str, Enum):
    """How the fetched content can be obtained before an offline scan."""

    IMAGE_BUILD = "image_build"
    CONTENT_DB_REFRESH = "content_db_refresh"
    CI_CACHE = "ci_cache"


class OfflineOutcome(str, Enum):
    """What an offline run does."""

    #: The scanner needs nothing from the network; offline changes nothing.
    UNCHANGED = "unchanged"
    #: It runs, with less (or from a cache): the reason says what.
    DEGRADED = "degraded"
    #: It does not run; the reason says why.
    NOT_RUN = "not_run"


class SandboxNetwork(str, Enum):
    """The scanner's ``SandboxRequirements`` network declaration, as a value."""

    NONE = "none"
    #: ``network=True``: granted online, never under ``--offline``.
    ONLINE = "online"
    #: ``network_requires_grant=True``: the need follows repository-writable
    #: settings, so only the operator's ``sandbox.network_scanners`` grants it.
    VERIFYING = "verifying"


class NetworkFacet(_Frozen):
    """One scanner's network row (design section A)."""

    fetch_kind: FetchKind
    fetches: tuple[Fetched, ...]
    prefetch: tuple[Prefetch, ...]
    offline_outcome: OfflineOutcome
    #: Required for DEGRADED and NOT_RUN.
    offline_reason: Optional[str] = None
    #: Mirror of the ``offline_strategy`` class attribute.
    offline_strategy: OfflineStrategy
    #: Mirror of ``SandboxRequirements.network`` / ``network_requires_grant``.
    sandbox_network: SandboxNetwork
    #: Name of the ``CONTENT_DATABASES`` entry this scanner reads, if any.
    content_database: Optional[str] = None
    #: Required when the scanner fetches content yet its sandbox declaration
    #: grants no network (checkov; guarddog's verify mode): the two runs can
    #: differ, and the register says so instead of hiding it.
    sandbox_tension: Optional[str] = None
    #: Where the row is read from (file and symbol).
    source: str
    #: An open question about this row, stated, not guessed.
    unconfirmed: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "NetworkFacet":
        if self.offline_strategy is OfflineStrategy.UNKNOWN:
            raise ValueError(
                "offline_strategy UNKNOWN is the honest-ignorance value of the "
                "enum and cannot be declared; read the scanner and classify it"
            )
        fetching = self.fetch_kind in (
            FetchKind.CONTENT_FETCH,
            FetchKind.SERVICE_UPLOAD,
        )
        if fetching and not self.fetches:
            raise ValueError(f"{self.fetch_kind.value} must name what it fetches")
        if not fetching and self.fetches:
            raise ValueError(
                f"{self.fetch_kind.value} fetches nothing the register names; "
                "a named artifact means content_fetch or service_upload"
            )
        if (Fetched.SOURCE_UPLOAD in self.fetches) != (
            self.fetch_kind is FetchKind.SERVICE_UPLOAD
        ):
            raise ValueError(
                "source_upload and service_upload name each other: a scanner "
                "that uploads the source is a service upload, and only it"
            )
        if self.offline_outcome is not OfflineOutcome.UNCHANGED and _blank(
            self.offline_reason
        ):
            raise ValueError(
                f"an offline outcome of {self.offline_outcome.value} needs a reason"
            )
        if (self.offline_outcome is OfflineOutcome.NOT_RUN) != (
            self.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        ):
            raise ValueError(
                "offline outcome not_run and offline_strategy skip_offline are "
                "one fact; the declaration contradicts itself"
            )
        if self.sandbox_network is not SandboxNetwork.NONE and not fetching:
            raise ValueError(
                "a sandbox network grant needs a fetch that uses it; declare "
                "content_fetch or service_upload, or drop the network need"
            )
        if (
            self.fetch_kind is FetchKind.CONTENT_FETCH
            and self.sandbox_network is SandboxNetwork.NONE
            and _blank(self.sandbox_tension)
        ):
            raise ValueError(
                "a scanner that fetches content while its sandbox grants no "
                "network must say what differs between the two runs "
                "(sandbox_tension)"
            )
        if self.content_database is not None and (
            self.fetch_kind is not FetchKind.CONTENT_FETCH
        ):
            raise ValueError("a content database means content_fetch")
        if Prefetch.CI_CACHE in self.prefetch and self.content_database is None:
            raise ValueError("a CI cache needs the content database it caches")
        if _blank(self.source):
            raise ValueError("a network row cites its source")
        return self


# --------------------------------------------------------------------------
# B. Output types
# --------------------------------------------------------------------------


class OutputFormat(str, Enum):
    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"
    TOOL_JSON = "tool_json"
    PYTHON_API = "python_api"
    SYNTHESIZED = "synthesized"


class OutputFacet(_Frozen):
    """The tool's output as ASH invokes it (design section B)."""

    native_formats: tuple[OutputFormat, ...]
    #: Extra files the same run writes and ASH reads.
    side_reports: tuple[str, ...]
    #: Products consumed outside the flat findings path (syft's SBOM).
    non_finding_artifacts: tuple[str, ...]
    #: Only where the consumer path deviates from SarifReport -> flat path.
    consumed_by_deviation: Optional[str] = None
    note: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "OutputFacet":
        if not self.native_formats:
            raise ValueError("a scanner has at least one native output format")
        return self


# --------------------------------------------------------------------------
# C. Scan-target types
# --------------------------------------------------------------------------


class TargetKind(str, Enum):
    SOURCE_CODE = "source_code"
    IAC_CLOUDFORMATION = "iac_cloudformation"
    IAC_TERRAFORM = "iac_terraform"
    IAC_KUBERNETES = "iac_kubernetes"
    IAC_OTHER = "iac_other"
    DEPENDENCY_LOCKFILES = "dependency_lockfiles"
    PACKAGE_SOURCES = "package_sources"
    PACKAGE_INVENTORY = "package_inventory"
    SECRETS_CONTENTS = "secrets_contents"  # pragma: allowlist secret
    SECRETS_GIT_HISTORY = "secrets_git_history"  # pragma: allowlist secret
    DOCKERFILES = "dockerfiles"
    GITHUB_ACTIONS_WORKFLOWS = "github_actions_workflows"
    COMPOSITE_ACTIONS = "composite_actions"
    CONTAINER_IMAGE = "container_image"
    SBOM_DOCUMENT = "sbom_document"


#: Target kinds NO scanner wires today, each with the reason. A roadmap cell,
#: not a bug: a scanner that claims one must be wired for it, and the
#: consistency test refuses a claim of a kind listed here.
UNCLAIMED_TARGET_KINDS: dict[TargetKind, str] = {
    TargetKind.SECRETS_GIT_HISTORY: (
        "gitleaks and betterleaks run `dir` mode only (history scanning "
        "'answers a different question', gitleaks_scanner module header), and "
        "no other secrets scanner reads git history"
    ),
    # CONTAINER_IMAGE left this list with the asset-targets wiring: grype,
    # syft and trivy claim it on their rows and override the image dispatch
    # (_execute_image_scan / scan_image), which the iff-test holds together.
    TargetKind.SBOM_DOCUMENT: (
        "no scanner consumes an SBOM document as input; syft produces one and "
        "grype scans the directory, so syft-to-grype is a potential pipeline, "
        "not current behavior"
    ),
}

#: The target kinds whose content can carry a finding of each scan category (for
#: ``sbom``, the artifact). Every shipped scanner's every declared category is
#: served by at least one of the target kinds its row declares (the consistency
#: test asserts it), and every ``TargetKind`` is in some row or in
#: ``UNCLAIMED_TARGET_KINDS``. ``secrets`` holds every kind: a literal credential
#: present in content is a secrets finding, whatever the artifact. ``binary`` and
#: ``posture`` name the nearest kinds (compiled code ships inside installed
#: packages and images; a deployed environment's posture is declared by its
#: IaC). ``dast`` and ``other`` are empty: no target kind ASH scans serves them.
CATEGORY_SERVED_BY: dict[ScanCategory, frozenset[TargetKind]] = {
    ScanCategory.SAST: frozenset(
        {
            TargetKind.SOURCE_CODE,
            TargetKind.GITHUB_ACTIONS_WORKFLOWS,
            TargetKind.COMPOSITE_ACTIONS,
        }
    ),
    ScanCategory.SECRETS: frozenset(TargetKind),
    ScanCategory.PII: frozenset(
        {
            TargetKind.SOURCE_CODE,
            TargetKind.SECRETS_CONTENTS,
            TargetKind.SECRETS_GIT_HISTORY,
        }
    ),
    ScanCategory.SCA: frozenset(
        {
            TargetKind.DEPENDENCY_LOCKFILES,
            TargetKind.PACKAGE_SOURCES,
            TargetKind.PACKAGE_INVENTORY,
            TargetKind.CONTAINER_IMAGE,
            TargetKind.GITHUB_ACTIONS_WORKFLOWS,
            TargetKind.COMPOSITE_ACTIONS,
        }
    ),
    ScanCategory.CONTAINER: frozenset({TargetKind.CONTAINER_IMAGE}),
    ScanCategory.IAC: frozenset(
        {
            TargetKind.SOURCE_CODE,
            TargetKind.IAC_CLOUDFORMATION,
            TargetKind.IAC_TERRAFORM,
            TargetKind.IAC_KUBERNETES,
            TargetKind.IAC_OTHER,
            TargetKind.DOCKERFILES,
            TargetKind.GITHUB_ACTIONS_WORKFLOWS,
            TargetKind.CONTAINER_IMAGE,
        }
    ),
    ScanCategory.CI: frozenset(
        {
            TargetKind.SOURCE_CODE,
            TargetKind.IAC_OTHER,
            TargetKind.GITHUB_ACTIONS_WORKFLOWS,
            TargetKind.COMPOSITE_ACTIONS,
        }
    ),
    ScanCategory.SUPPLY_CHAIN: frozenset(
        {
            TargetKind.SOURCE_CODE,
            TargetKind.DEPENDENCY_LOCKFILES,
            TargetKind.PACKAGE_SOURCES,
            TargetKind.GITHUB_ACTIONS_WORKFLOWS,
            TargetKind.COMPOSITE_ACTIONS,
        }
    ),
    ScanCategory.MALWARE: frozenset(
        {
            TargetKind.PACKAGE_SOURCES,
            TargetKind.PACKAGE_INVENTORY,
            TargetKind.CONTAINER_IMAGE,
        }
    ),
    ScanCategory.MAINTENANCE: frozenset(
        {
            TargetKind.DEPENDENCY_LOCKFILES,
            TargetKind.PACKAGE_SOURCES,
            TargetKind.PACKAGE_INVENTORY,
            TargetKind.CONTAINER_IMAGE,
        }
    ),
    ScanCategory.LICENSE: frozenset(
        {
            TargetKind.SOURCE_CODE,
            TargetKind.DEPENDENCY_LOCKFILES,
            TargetKind.PACKAGE_SOURCES,
            TargetKind.PACKAGE_INVENTORY,
            TargetKind.CONTAINER_IMAGE,
        }
    ),
    ScanCategory.QUALITY: frozenset(
        {
            TargetKind.SOURCE_CODE,
            TargetKind.DOCKERFILES,
            TargetKind.GITHUB_ACTIONS_WORKFLOWS,
            TargetKind.COMPOSITE_ACTIONS,
        }
    ),
    ScanCategory.COMPLEXITY: frozenset({TargetKind.SOURCE_CODE}),
    ScanCategory.API: frozenset({TargetKind.SOURCE_CODE, TargetKind.IAC_OTHER}),
    ScanCategory.AGENT: frozenset({TargetKind.SOURCE_CODE}),
    ScanCategory.BINARY: frozenset(
        {TargetKind.PACKAGE_INVENTORY, TargetKind.CONTAINER_IMAGE}
    ),
    ScanCategory.POSTURE: frozenset(
        {
            TargetKind.IAC_CLOUDFORMATION,
            TargetKind.IAC_TERRAFORM,
            TargetKind.IAC_KUBERNETES,
            TargetKind.IAC_OTHER,
        }
    ),
    ScanCategory.DAST: frozenset(),
    ScanCategory.SBOM: frozenset(
        {
            TargetKind.DEPENDENCY_LOCKFILES,
            TargetKind.PACKAGE_INVENTORY,
            TargetKind.CONTAINER_IMAGE,
        }
    ),
    ScanCategory.OTHER: frozenset(),
}


def _categories_from_tool_type(data: dict[str, Any]) -> tuple[ScanCategory, ...]:
    """The categories a targets row that omits ``categories`` derives: the one
    its ``tool_type`` stands for, or none for UNKNOWN.

    pydantic passes the fields validated so far; ``tool_type`` is declared
    before ``categories``, so it is among them when it validated."""
    return categories_of_tool_type(data.get("tool_type"))


class TargetsFacet(_Frozen):
    """What the scanner scans (design section C)."""

    kinds: tuple[TargetKind, ...]
    #: The legacy scanner type, the one the scanner sets in ``model_post_init``.
    #: The plugin base then writes it onto the instance, so the row is the last
    #: writer.
    tool_type: ScannerToolType
    #: The scan categories this scanner can serve, in canonical order (the
    #: declaration order of ``ScanCategory``). A row that omits it derives the
    #: one category its ``tool_type`` stands for, and building such a row warns
    #: once per scanner name; 4.0 removes that derivation.
    categories: tuple[ScanCategory, ...] = Field(
        default_factory=_categories_from_tool_type
    )
    #: One line naming the selection mechanism, citing the adapter.
    selection: str
    #: Where ``covers`` (the display string) understates or overstates the
    #: wired truth, if it does. The register declares the wired truth.
    covers_note: Optional[str] = None
    #: Why this ``tool_type`` is what it is, where two scanners over the same
    #: target kind disagree or a value was corrected.
    tool_type_note: Optional[str] = None
    #: Why ``categories`` is what it is, where the kinds do not show it: a
    #: category served only under a condition (an optional integration, a mode
    #: that is off by default), or one served through the nearest target kind
    #: rather than a kind of its own.
    categories_note: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "TargetsFacet":
        if not self.kinds:
            raise ValueError("a scanner scans at least one kind of target")
        if _blank(self.selection):
            raise ValueError("a targets row cites its selection mechanism")
        claimed = [k for k in self.kinds if k in UNCLAIMED_TARGET_KINDS]
        if claimed:
            raise ValueError(
                f"{[k.value for k in claimed]} is wired by no scanner today "
                "(UNCLAIMED_TARGET_KINDS); wire it before claiming it"
            )
        return self

    @model_validator(mode="after")
    def _categories_are_canonical(self) -> "TargetsFacet":
        """A written ``categories`` names at least one category, each once, in
        canonical order. An omitted one, derived from ``tool_type``, is not
        checked here; ``ash plugin verify`` refuses a row that derives none."""
        if "categories" not in self.model_fields_set:
            return self
        if not self.categories:
            raise ValueError("categories is empty: name at least one category")
        seen: set[ScanCategory] = set()
        for category in self.categories:
            if category in seen:
                raise ValueError(f"categories names {category.value} more than once")
            seen.add(category)
        canonical = tuple(category for category in ScanCategory if category in seen)
        if canonical != self.categories:
            raise ValueError(
                "categories are not in canonical order: write "
                + ", ".join(category.value for category in canonical)
            )
        return self


# --------------------------------------------------------------------------
# F. Runtime dependency and invocation
# --------------------------------------------------------------------------


class RuntimeKind(str, Enum):
    UV_PYTHON = "uv_python"
    PINNED_BINARY = "pinned_binary"
    RUBY_GEM = "ruby_gem"
    NODE_SUBCOMMAND = "node_subcommand"
    IN_PROCESS = "in_process"
    USER_INSTALLED_CLI = "user_installed_cli"
    PYPI_PACKAGE = "pypi_package"


class Invocations(str, Enum):
    ONE = "one"
    PER_TARGET = "per_target"
    MULTI_PASS = "multi_pass"


class RuntimeFacet(_Frozen):
    """The scanner's own runtime needs (design section F)."""

    kind: RuntimeKind
    #: Programs the scanner needs on the host beyond its tool.
    external_programs: tuple[str, ...]
    invocations: Invocations
    invocation_note: Optional[str] = None
    #: Key into ``tool_downloads.TOOL_VERSIONS`` for a pinned binary.
    tool_versions_key: Optional[str] = None
    #: Mirrors of the ``python_only`` ClassVar and the ``use_uv_tool`` default
    #: the scanner sets at construction.
    python_only: bool
    use_uv_tool: bool
    #: A build property of the runtime that decides whether the tool runs at
    #: all (cfn-nag's portable-Ruby build dependency).
    build_dependency: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "RuntimeFacet":
        if self.kind is RuntimeKind.PINNED_BINARY and _blank(self.tool_versions_key):
            raise ValueError("a pinned binary names its TOOL_VERSIONS key")
        if self.kind is not RuntimeKind.PINNED_BINARY and self.tool_versions_key:
            raise ValueError("only a pinned binary has a TOOL_VERSIONS key")
        if self.kind is RuntimeKind.RUBY_GEM and _blank(self.build_dependency):
            raise ValueError("a Ruby gem states its interpreter build dependency")
        if self.kind is RuntimeKind.UV_PYTHON and not self.use_uv_tool:
            raise ValueError("a uv_python scanner runs through uv (use_uv_tool)")
        if self.use_uv_tool and self.kind is not RuntimeKind.UV_PYTHON:
            raise ValueError("use_uv_tool means the uv_python runtime kind")
        if self.invocations is not Invocations.ONE and _blank(self.invocation_note):
            raise ValueError("per-target and multi-pass invocation need a note")
        return self


# --------------------------------------------------------------------------
# G. Platform and architecture
# --------------------------------------------------------------------------


#: The platform sets ``tool_downloads`` publishes, in ``supported_platforms``
#: order, so a declaration says ``PLATFORMS_ALL`` instead of restating six
#: strings. The consistency test derives each declared set from
#: ``supported_platforms`` and fails when the table moves.
PLATFORMS_ALL: tuple[str, ...] = (
    "darwin/amd64",
    "darwin/arm64",
    "linux/amd64",
    "linux/arm64",
    "windows/amd64",
    "windows/arm64",
)
#: grype, hadolint, opengrep and trivy publish no windows/arm64 asset.
PLATFORMS_NO_WINDOWS_ARM64: tuple[str, ...] = PLATFORMS_ALL[:-1]


class PlatformsFacet(_Frozen):
    """Where ASH can provision the scanner's tool (design section G)."""

    #: ``os/arch`` pairs ``tool_downloads.supported_platforms`` returns for
    #: the scanner's ``tool_versions_key``; empty for a tool ASH does not
    #: download.
    provisionable: tuple[str, ...]
    #: Why ``provisionable`` is empty, or what it leaves out. The register's
    #: honest cell for everything the tree is silent on is "unread".
    note: str

    @model_validator(mode="after")
    def _shape(self) -> "PlatformsFacet":
        if _blank(self.note):
            raise ValueError("a platforms row carries its note")
        return self


# --------------------------------------------------------------------------
# H. Severity fidelity
# --------------------------------------------------------------------------


class SeverityClass(str, Enum):
    #: The tool's own per-finding scale is mapped.
    NATIVE = "native"
    #: One severity for every finding.
    CONSTANT = "constant"
    #: Computed by ASH from other fields.
    DERIVED = "derived"
    #: A finer native signal exists and is dropped.
    DEGRADED = "degraded"
    #: The scanner has no findings.
    NOT_APPLICABLE = "not_applicable"


class SeverityFacet(_Frozen):
    severity_class: SeverityClass
    note: str
    #: The native field dropped, required for DEGRADED.
    dropped_native: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "SeverityFacet":
        if _blank(self.note):
            raise ValueError("a severity row carries its note")
        if (self.severity_class is SeverityClass.DEGRADED) != bool(
            (self.dropped_native or "").strip()
        ):
            raise ValueError(
                "a degraded severity names the native field it drops, and only "
                "a degraded severity does"
            )
        return self


# --------------------------------------------------------------------------
# I. Suppression and ignore surfaces
# --------------------------------------------------------------------------


class SilencingLayerKind(str, Enum):
    INLINE_COMMENT = "inline_comment"
    IGNORE_FILE = "ignore_file"
    TOOL_DEFAULT_FILTER = "tool_default_filter"


class SilencingWriter(str, Enum):
    #: The scanned repository can write the silencing input.
    REPOSITORY = "repository"
    OPERATOR = "operator"
    TOOL_DEFAULT = "tool_default"


class Honored(str, Enum):
    YES = "yes"
    NO = "no"
    UNCONFIRMED = "unconfirmed"


class SilencingLayer(_Frozen):
    """One tool-side layer through which a finding can disappear."""

    layer: SilencingLayerKind
    writer: SilencingWriter
    honored: Honored
    surface: str
    #: Where it is read from; required, and the reason for UNCONFIRMED.
    cite: str
    reason: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "SilencingLayer":
        if _blank(self.surface) or _blank(self.cite):
            raise ValueError("a silencing layer names its surface and cites it")
        if self.honored is Honored.UNCONFIRMED and _blank(self.reason):
            raise ValueError("an unconfirmed layer states what read would settle it")
        return self


#: The ASH-side suppression layer is uniform across scanners and reported and
#: counted rather than silent: suppression entries scoped by
#: resource_id/resource_type/engines and package fields, ``ignore_paths`` with
#: the operator/client split (a client-supplied ignore path keeps findings as
#: marked-suppressed results), and ``--ignore-suppressions``, which lifts every
#: suppression for every scanner. Declared once here, not per scanner.
ASH_SIDE_SUPPRESSION_NOTE = (
    "models/core.py suppression entries and ignore_paths; uniform across scanners"
)


class SilencingFacet(_Frozen):
    tool_side: tuple[SilencingLayer, ...]
    #: Required when ``tool_side`` is empty: why no tool-side layer applies.
    none_reason: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "SilencingFacet":
        if not self.tool_side and _blank(self.none_reason):
            raise ValueError("no tool-side silencing layer needs a reason")
        return self


# --------------------------------------------------------------------------
# J. Finding-identity stability
# --------------------------------------------------------------------------


class FingerprintClass(str, Enum):
    STABLE_NATIVE = "stable_native"
    STABLE_COMPUTED = "stable_computed"
    #: The tool carries a hash that ASH deliberately never lets into the SARIF.
    DROPPED_BY_POLICY = "dropped_by_policy"
    #: Identity is file and line through the shared floor; a suppression
    #: breaks on an edit above the finding.
    POSITIONAL_ONLY = "positional_only"
    #: Not read at a committed fixture yet; reads as positional-only until it is.
    UNCONFIRMED = "unconfirmed"
    #: The scanner has no findings to identify (syft).
    NOT_APPLICABLE = "not_applicable"


class IdentityFacet(_Frozen):
    fingerprint_class: FingerprintClass
    note: str

    @model_validator(mode="after")
    def _shape(self) -> "IdentityFacet":
        if _blank(self.note):
            raise ValueError("an identity row carries its note")
        return self


# --------------------------------------------------------------------------
# K. Config and rules extensibility
# --------------------------------------------------------------------------


class CustomRules(str, Enum):
    NONE = "none"
    OPERATOR_PATHS = "operator_paths"
    REGISTRY_REFS = "registry_refs"
    BOTH = "both"


class ExtensibilityFacet(_Frozen):
    custom_rules: CustomRules
    #: Mirror of ``SandboxRequirements.env_prefixes``.
    env_prefixes: tuple[str, ...]
    #: The options the user feeds in, or why there is no rules surface.
    options_surface: str

    @model_validator(mode="after")
    def _shape(self) -> "ExtensibilityFacet":
        if _blank(self.options_surface):
            raise ValueError("an extensibility row names its options surface")
        return self


# --------------------------------------------------------------------------
# L. Exit-code semantics
# --------------------------------------------------------------------------


class ExitCodesFacet(_Frozen):
    #: Mirror of the ``success_exit_codes`` class attribute.
    success_exit_codes: tuple[int, ...]
    semantics: str

    @model_validator(mode="after")
    def _shape(self) -> "ExitCodesFacet":
        if not self.success_exit_codes:
            raise ValueError("a scanner has at least one success exit code")
        if tuple(sorted(set(self.success_exit_codes))) != self.success_exit_codes:
            raise ValueError("success exit codes are listed sorted and unique")
        if _blank(self.semantics):
            raise ValueError("an exit-code row states its semantics")
        return self


# --------------------------------------------------------------------------
# M. Tool provenance
# --------------------------------------------------------------------------


#: The maturity tier and the default-enablement of a scanner are NOT declared
#: here: they are the ``tier`` and ``default_enabled`` fields of its manifest
#: (``base/plugin_manifest.py``, data in ``plugin_manifests/``), the one place
#: they are declared, readable without importing the scanner.


class ProvenanceSource(str, Enum):
    PINNED_RELEASE_BINARY = "pinned_release_binary"
    GEMFILE_LOCK = "gemfile_lock"
    PYPI_VIA_UV = "pypi_via_uv"
    PYPI_PINNED_DEPENDENCY = "pypi_pinned_dependency"
    USER_INSTALLED = "user_installed"


class ProvenanceFacet(_Frozen):
    source: ProvenanceSource
    #: Switches below the tier: sub-scanners, opt-in modes.
    selection_surfaces: tuple[str, ...]
    #: ``"not read"`` or ``"<spdx> (source: <pinned upstream LICENSE>)"``.
    upstream_license: str

    @model_validator(mode="after")
    def _shape(self) -> "ProvenanceFacet":
        value = self.upstream_license.strip()
        if value != LICENSE_NOT_READ and "(source: " not in value:
            raise ValueError(
                "an upstream license is either 'not read' or carries a "
                "'(source: ...)' citation of a pinned upstream LICENSE read; "
                "a recalled license name is the unmeasured value this "
                "register exists to refuse"
            )
        return self


# --------------------------------------------------------------------------
# N. Input prerequisites
# --------------------------------------------------------------------------


class Prerequisite(str, Enum):
    NONE = "none"
    LOCKFILE = "lockfile"
    MANIFEST = "manifest"
    TEMPLATE = "template"
    GIT_CHECKOUT = "git_checkout"
    AUTH_TOKEN = "auth_token"
    NODE_RUNTIME = "node_runtime"


class PrerequisitesFacet(_Frozen):
    kinds: tuple[Prerequisite, ...]
    note: str
    #: An open question, stated; the declared kinds are then the conservative
    #: reading.
    unconfirmed: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "PrerequisitesFacet":
        if not self.kinds:
            raise ValueError("declare (none,) for a scanner with no prerequisite")
        if Prerequisite.NONE in self.kinds and len(self.kinds) > 1:
            raise ValueError("'none' excludes every other prerequisite")
        if _blank(self.note):
            raise ValueError("a prerequisites row carries its note")
        return self


# --------------------------------------------------------------------------
# O. Runtime compatibility
# --------------------------------------------------------------------------


class RuntimeName(str, Enum):
    """The language runtime a compatibility row constrains.

    The value is the key :mod:`automated_security_helper.utils.runtime_compat_ranges`
    selects a range grammar by: one filter interface, the grammar native to
    each runtime (PEP 440 for python, node-semver for node).
    """

    PYTHON = "python"
    NODE = "node"


class CompatResolution(str, Enum):
    """How a declared incompatibility is resolved at install and launch."""

    #: Constrain the interpreter request (``uv tool install --python``). The
    #: preferred resolution: overriding what runs is simpler and more honest
    #: than patching what runs.
    PIN = "pin"
    #: A shim applied over {runtime range x tool range} at tool launch. Valid
    #: only with ``pin_insufficient``, the reason a pin cannot serve.
    POLYFILL = "polyfill"


class RuntimeCompatRow(_Frozen):
    """One runtime-compatibility fact: a tool range against a runtime range."""

    runtime: RuntimeName
    #: The tool versions the row covers, in the runtime's range grammar. ``""``
    #: is every version of the tool, stated and never defaulted.
    tool_versions: str
    #: PIN: the interpreter request handed to ``uv tool install --python``;
    #: it must carry no whitespace, because the stored install command is one
    #: string split on whitespace. POLYFILL: the runtime range the shim covers
    #: (the shim does nothing outside it).
    runtime_request: str
    resolution: CompatResolution
    #: The incompatibility and its measurement. Always required.
    reason: str
    #: The upstream issue, URL-shaped. An ``open_ended`` row carries this or a
    #: ``recheck_note``.
    upstream_issue: Optional[str] = None
    #: An UNSOLVED upstream incompatibility: the row declares only the bounds it
    #: can prove (an upper runtime bound with the tool side open, or a lower
    #: bound only) and is re-read whenever the tool's version constraint moves.
    #: The re-check is :meth:`recheck_fires`: the row records the scanner's
    #: default tool constraint as of row-write time
    #: (``recorded_default_constraint``), and the consistency gate goes red the
    #: moment the live default no longer equals it -- the tool bumped, so read
    #: the row's upstream issue (or recheck_note) and close or re-bound the row.
    #: A membership test alone could never red here: an open-ended row's tool
    #: range is typically blank (applies everywhere) and a default constraint
    #: is typically a range (kept the safe side by :meth:`applies_to`).
    open_ended: bool = False
    #: Open-ended only, in place of an ``upstream_issue`` when none exists to
    #: cite: what was searched and found absent, so the re-check reader knows
    #: where to look. A gap with no upstream issue is still an unsolved one.
    recheck_note: Optional[str] = None
    #: Open-ended only, required there: the scanner's default tool-version
    #: constraint as of row-write time (``""`` when the scanner had none), in
    #: the row's range grammar. The re-check gate's record.
    recorded_default_constraint: Optional[str] = None
    #: POLYFILL only: the shim directory under
    #: ``automated_security_helper/assets/polyfills/``.
    polyfill: Optional[str] = None
    #: POLYFILL only: why pinning cannot serve (no compatible interpreter is
    #: installable, floors conflict). The prefer-PIN policy's enforcement point.
    pin_insufficient: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "RuntimeCompatRow":
        from automated_security_helper.utils.runtime_compat_ranges import (
            RangeError,
            parse_range,
        )

        if _blank(self.reason):
            raise ValueError("a runtime-compat row carries its reason")
        if _blank(self.runtime_request):
            raise ValueError("a runtime-compat row names its runtime_request")
        if any(c.isspace() for c in self.runtime_request):
            raise ValueError(
                "runtime_request carries no whitespace: the stored uv install "
                "command is one string split on whitespace"
            )
        try:
            parse_range(self.runtime.value, self.tool_versions)
            parse_range(self.runtime.value, self.runtime_request)
        except RangeError as exc:
            raise ValueError(str(exc)) from exc
        if (
            self.open_ended
            and _blank(self.upstream_issue)
            and _blank(self.recheck_note)
        ):
            raise ValueError(
                "an open-ended row records an unsolved upstream issue and "
                "carries its upstream_issue URL, or a recheck_note where no "
                "upstream issue exists to cite"
            )
        if not self.open_ended and self.recheck_note is not None:
            raise ValueError("recheck_note belongs to an open-ended row")
        if self.upstream_issue is not None and _blank(self.upstream_issue):
            raise ValueError(
                "upstream_issue is its URL or None, never blank: a blank "
                "string is truthy to the reference renderer, which would emit "
                "a broken whitespace link and drop the recheck_note"
            )
        if not _blank(self.upstream_issue) and not (
            self.upstream_issue or ""
        ).startswith(("https://", "http://")):
            raise ValueError("upstream_issue is a URL")
        if self.open_ended and self.recorded_default_constraint is None:
            raise ValueError(
                "an open-ended row records the scanner's default tool "
                "constraint as of row-write time (recorded_default_constraint, "
                '"" when the scanner has none), so the re-check gate can red '
                "when the default moves"
            )
        if not self.open_ended and self.recorded_default_constraint is not None:
            raise ValueError(
                "recorded_default_constraint is the open-ended re-check's "
                "record; a closed row carries none"
            )
        if self.recorded_default_constraint is not None:
            try:
                parse_range(self.runtime.value, self.recorded_default_constraint)
            except RangeError as exc:
                raise ValueError(str(exc)) from exc
        if self.resolution is CompatResolution.PIN:
            if self.polyfill is not None or self.pin_insufficient is not None:
                raise ValueError("a PIN row carries no polyfill or pin_insufficient")
        else:
            if _blank(self.polyfill):
                raise ValueError("a POLYFILL row names its shim directory")
            if not re.fullmatch(r"[a-z][a-z0-9_]*", self.polyfill or ""):
                raise ValueError("polyfill is a directory name: [a-z][a-z0-9_]*")
            if _blank(self.pin_insufficient):
                raise ValueError(
                    "prefer a PIN: a POLYFILL row states why pinning the "
                    "interpreter cannot serve (pin_insufficient)"
                )
        return self

    def applies_to(self, tool_constraint: Optional[str]) -> bool:
        """Whether the row governs the tool at *tool_constraint*.

        Decidable and conservative; no range intersection is attempted
        (``packaging`` has none, and ``npm_audit_scanner`` documents why
        pretending otherwise is wrong):

        1. ``tool_versions == ""`` applies at every tool version.
        2. A constraint naming exactly one version (``==3.4.11``) is a
           membership test against the row's tool range.
        3. Any other constraint (a range, or None) applies: a range that in
           fact excludes the row's range still gets the row, the safe side
           (an unnecessary interpreter constraint, never a missing one).
        """
        from automated_security_helper.utils.runtime_compat_ranges import (
            exact_version,
            parse_range,
        )

        if not self.tool_versions.strip():
            return True
        version = exact_version(tool_constraint)
        if version is None:
            return True
        return parse_range(self.runtime.value, self.tool_versions).contains(version)

    def recheck_fires(self, default_tool_constraint: Optional[str]) -> bool:
        """Whether the open-ended re-check fires at *default_tool_constraint*.

        The re-check is an equality against the default constraint recorded at
        row-write time, so it is decidable for every constraint shape -- a
        blank tool range and a range constraint included, where
        :meth:`applies_to` alone can never go red (a blank ``tool_versions``
        applies everywhere, and a range constraint keeps the row the safe
        side). A moved default IS the event the gate exists for: the tool
        bumped, so re-read the row's upstream issue (or recheck_note) and
        close or re-bound the row. Never fires for a closed row.
        """
        if not self.open_ended:
            return False
        return (default_tool_constraint or "") != (
            self.recorded_default_constraint or ""
        )


class RuntimeCompatFacet(_Frozen):
    """A scanner's runtime-compatibility rows.

    Empty means no known incompatibility between this tool's versions and its
    runtime's versions: the honest common state, not an unread one, so it needs
    no reason (unlike a silencing layer, where absence is the unread state).
    """

    rows: tuple[RuntimeCompatRow, ...]

    @model_validator(mode="after")
    def _shape(self) -> "RuntimeCompatFacet":
        keys = [
            (r.runtime, r.tool_versions, r.runtime_request, r.resolution)
            for r in self.rows
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("a runtime-compat row is declared once")
        return self

    def pin_request(
        self, runtime: RuntimeName, tool_constraint: Optional[str]
    ) -> Optional[str]:
        """The interpreter request the applicable PIN rows ask for, or None.

        Several applicable rows combine (every clause must hold), in
        declaration order. This is the one derivation point the installers
        read: ``UVToolMixin._get_tool_python_request``.
        """
        from automated_security_helper.utils.runtime_compat_ranges import parse_range

        combined = None
        for row in self.rows:
            if (
                row.runtime is runtime
                and row.resolution is CompatResolution.PIN
                and row.applies_to(tool_constraint)
            ):
                predicate = parse_range(row.runtime.value, row.runtime_request)
                combined = (
                    predicate if combined is None else combined.combined(predicate)
                )
        return combined.as_request() if combined is not None else None

    def polyfills(self, tool_constraint: Optional[str]) -> tuple[RuntimeCompatRow, ...]:
        """The POLYFILL rows that govern the tool at *tool_constraint*."""
        return tuple(
            row
            for row in self.rows
            if row.resolution is CompatResolution.POLYFILL
            and row.applies_to(tool_constraint)
        )


# --------------------------------------------------------------------------
# G2. Container image route
# --------------------------------------------------------------------------
#
# Declared after the sections above it although the design numbers it after G: a
# line-pinned suppression in .ash/.ash_alpha_plugins.yaml names one line of this
# module by number, so code inserted above that line would move it.


class ImageRoute(str, Enum):
    """How a scanner's tool gets into the image the Dockerfile builds."""

    #: A pinned release asset, installed with ``install-pinned-tool <tool>``.
    RELEASE_ASSET = "release_asset"
    #: ``ash dependencies install`` puts it in place during the build.
    DEPENDENCIES_INSTALL = "dependencies_install"
    #: The Gemfile and Bundler build step.
    GEM_BUNDLE = "gem_bundle"
    #: The base operating system's package manager, one package per family.
    OS_PACKAGE = "os_package"
    #: Nothing beyond the ASH wheel and the system programs it already needs.
    ASH_WHEEL = "ash_wheel"
    #: Another scanner's tool: the scanner runs a tool a different row installs.
    SHARED_TOOL = "shared_tool"
    #: The image does not carry it, and the row says why.
    NOT_IN_IMAGE = "not_in_image"


class ImageFacet(_Frozen):
    """The scanner's route into the container image (design section G2)."""

    route: ImageRoute
    #: ``RELEASE_ASSET`` and ``SHARED_TOOL``: the ``tool_downloads.TOOL_VERSIONS`` key
    #: of the tool.
    tool: Optional[str] = None
    #: ``OS_PACKAGE``: the key of a system package in ``base/image_register.py``.
    package: Optional[str] = None
    #: The argv the build runs after the install to prove the tool answers; empty
    #: when the Dockerfile runs none for this scanner.
    version_check: tuple[str, ...] = ()
    #: Comment lines the Dockerfile carries directly above the scanner's install
    #: lines, copied as they are. A comment about licensing is not copied.
    dockerfile_note: tuple[str, ...] = ()
    #: ``NOT_IN_IMAGE``: why the image leaves the scanner out.
    reason: Optional[str] = None

    @model_validator(mode="after")
    def _shape(self) -> "ImageFacet":
        if self.route is ImageRoute.NOT_IN_IMAGE:
            if _blank(self.reason):
                raise ValueError("a not_in_image image row states its reason")
            if self.tool is not None or self.version_check:
                raise ValueError(
                    "a not_in_image image row names no tool and no version check"
                )
        if self.route in (ImageRoute.RELEASE_ASSET, ImageRoute.SHARED_TOOL):
            if _blank(self.tool):
                raise ValueError(f"a {self.route.value} image row names its tool")
        if self.route is ImageRoute.OS_PACKAGE and _blank(self.package):
            raise ValueError("an os_package image row names its package")
        for line in self.dockerfile_note:
            if not line.startswith("#"):
                raise ValueError(
                    f"an image note line is a Dockerfile comment, not {line!r}"
                )
        if any(_blank(word) for word in self.version_check):
            raise ValueError("an image version check holds no blank word")
        return self


# --------------------------------------------------------------------------
# The whole row
# --------------------------------------------------------------------------

#: The dimension names, in the model's field order. The vocabulary meta-test
#: pins ``ScannerOperationalFacets.model_fields`` to this tuple.
OPERATIONAL_FACET_NAMES: tuple[str, ...] = (
    "scanner_name",
    "network",
    "output",
    "targets",
    "runtime",
    "runtime_compat",
    "platforms",
    "image",
    "severity",
    "silencing",
    "identity",
    "extensibility",
    "exit_codes",
    "provenance",
    "prerequisites",
)


class ScannerOperationalFacets(_Frozen):
    """A scanner's whole operational register row."""

    #: The scanner's configuration name; the consistency test checks it
    #: against the name the scanner's own config model carries, and keys the
    #: ``CONTENT_DATABASES`` and ``SCANNERS_WITHOUT_CONTENT_DATABASE`` joins.
    scanner_name: str
    network: NetworkFacet
    output: OutputFacet
    targets: TargetsFacet
    runtime: RuntimeFacet
    runtime_compat: RuntimeCompatFacet
    platforms: PlatformsFacet
    image: ImageFacet
    severity: SeverityFacet
    silencing: SilencingFacet
    identity: IdentityFacet
    extensibility: ExtensibilityFacet
    exit_codes: ExitCodesFacet
    provenance: ProvenanceFacet
    prerequisites: PrerequisitesFacet

    @model_validator(mode="after")
    def _record_categories(self) -> "ScannerOperationalFacets":
        """Record the row's categories under its scanner name, and warn once per
        name when the row derives them from ``tool_type`` (it writes no
        ``targets.categories``)."""
        targets = self.targets
        _ROW_CATEGORIES[self.scanner_name] = tuple(targets.categories)
        if (
            "categories" not in targets.model_fields_set
            and self.scanner_name not in _ROW_DERIVATION_WARNED
        ):
            _ROW_DERIVATION_WARNED.add(self.scanner_name)
            derived = ", ".join(category.value for category in targets.categories)
            warnings.warn(
                f"scanner '{self.scanner_name}': its operational row names no "
                "categories, so they are derived from tool_type "
                f"{targets.tool_type.value} as {derived or 'nothing'}; declare "
                "targets.categories (deriving categories from tool_type is "
                "removed in 4.0)",
                DeprecationWarning,
                stacklevel=2,
            )
        return self


# --------------------------------------------------------------------------
# Asset routing: which asset kinds a declaration serves
# --------------------------------------------------------------------------

#: Every target kind a scanner reads out of a filesystem tree.
#: ``CONTAINER_IMAGE`` is the one kind whose subject is not presented as files
#: under the source directory, so the filesystem side is its complement:
#: ``SECRETS_GIT_HISTORY`` reads the tree's ``.git`` and ``SBOM_DOCUMENT`` a
#: document in the tree, both files under the root.
FILESYSTEM_SIDE_KINDS: frozenset[TargetKind] = frozenset(TargetKind) - {
    TargetKind.CONTAINER_IMAGE
}


def declared_operational_facets(
    scanner_class: type,
) -> Optional[ScannerOperationalFacets]:
    """*scanner_class*'s own register row, or None where it declares none.

    Read from the class's own ``vars()`` exactly as the registry-totality test
    reads it, so an inherited declaration never answers for a subclass. A
    third-party plugin predating the register has no row; its caller decides
    what that means (for asset routing below: filesystem-only, today's
    behavior).
    """
    facets = vars(scanner_class).get(OPERATIONAL_FACETS_ATTR)
    return facets if isinstance(facets, ScannerOperationalFacets) else None


def declared_runtime_compat(scanner_class: type) -> Optional[RuntimeCompatFacet]:
    """The runtime-compatibility rows *scanner_class* answers with, or None.

    Unlike :func:`declared_operational_facets`, a subclass answers with the
    nearest declaring base class: the interpreter request used to be a method
    a subclass inherited, and the installers that derive it from the rows keep
    that behavior. A class with no declaration anywhere in its MRO (a
    third-party plugin predating the register) answers None and derives
    nothing, which is what it did before the register had rows.
    """
    for klass in scanner_class.__mro__:
        facets = declared_operational_facets(klass)
        if facets is not None:
            return facets.runtime_compat
    return None


def serves_container_images(scanner_class: type) -> bool:
    """Whether *scanner_class* declares container-image targets.

    :func:`serves_asset_kind` for ``AssetKind.CONTAINER_IMAGE``, under a name
    that needs no ``AssetKind``: the helpers in ``utils`` ask this, because the
    layer order keeps them from importing ``core``, where ``AssetKind`` lives
    (tests/unit/test_layer_dag_boundaries.py). No declaration means no claim.
    """
    facets = declared_operational_facets(scanner_class)
    return facets is not None and TargetKind.CONTAINER_IMAGE in facets.targets.kinds


def serves_asset_kind(scanner_class: type, kind: "AssetKind") -> bool:
    """Whether *scanner_class* declares that it scans assets of *kind*.

    The register is the one place capability lives, so routing asks the
    declaration rather than a scattered conditional:

    - ``AssetKind.CONTAINER_IMAGE`` is served iff the declared target kinds
      include :attr:`TargetKind.CONTAINER_IMAGE`. No declaration means no
      claim, so an undeclared scanner is never handed an image.
    - ``AssetKind.FILESYSTEM`` is served by every scanner that declares any
      filesystem-side kind -- all of them today -- and by a scanner with no
      declaration at all, which keeps today's behavior for third-party
      plugins the register has never seen.
    """
    from automated_security_helper.core.asset import AssetKind

    if kind == AssetKind.CONTAINER_IMAGE:
        return serves_container_images(scanner_class)
    facets = declared_operational_facets(scanner_class)
    if facets is None:
        return True
    return any(k in FILESYSTEM_SIDE_KINDS for k in facets.targets.kinds)


# --------------------------------------------------------------------------
# Scan categories: the by-name record and the mode maps
# --------------------------------------------------------------------------

#: The categories each operational row built in this process declares, by
#: scanner name. ``ScannerOperationalFacets`` records them when it is built; a
#: later row with the same name replaces the earlier one, and ``model_copy``
#: (which runs no validator) records nothing.
_ROW_CATEGORIES: dict[str, tuple[ScanCategory, ...]] = {}

#: The categories each scanner instance declared, by its config name
#: (``ScannerPluginBase.model_post_init`` records them on every instance).
_INSTANCE_CATEGORIES: dict[str, tuple[ScanCategory, ...]] = {}

#: The scanner names whose row has raised the derivation warning in this
#: process: the warning is raised once per name.
_ROW_DERIVATION_WARNED: set[str] = set()

#: The ``json_schema_extra`` key under which a mode option carries its map.
CATEGORY_MAP_KEY = "x-ash-categories"

#: The map key that stands for every value the map does not name.
CATEGORY_MAP_ANY = "*"


def row_categories(scanner_name: str) -> Optional[tuple[ScanCategory, ...]]:
    """The categories the row named *scanner_name* declared when it was built in
    this process, or None when no row of that name was built."""
    return _ROW_CATEGORIES.get(scanner_name)


def instance_categories(scanner_name: str) -> Optional[tuple[ScanCategory, ...]]:
    """The categories an instance with this config name declared when it was
    built in this process, or None when none was recorded."""
    return _INSTANCE_CATEGORIES.get(scanner_name)


def record_instance_categories(
    scanner_name: str, categories: Iterable[ScanCategory]
) -> None:
    """Record the categories a scanner instance with this config name declares."""
    _INSTANCE_CATEGORIES[scanner_name] = tuple(categories)


def nearest_operational_facets(
    scanner_class: type,
) -> Optional[ScannerOperationalFacets]:
    """The operational row of *scanner_class* or of its nearest declaring base, or
    None when no class in its MRO declares one.

    Each class is read from its own namespace, as
    :func:`declared_operational_facets` reads it; unlike that function, a
    subclass answers with an inherited row, the way
    :func:`declared_runtime_compat` walks the MRO.
    """
    for klass in scanner_class.__mro__:
        facets = declared_operational_facets(klass)
        if facets is not None:
            return facets
    return None


def category_map(
    options_model: type[BaseModel], field_name: str
) -> dict[str, tuple[ScanCategory, ...]]:
    """The category map option *field_name* of *options_model* carries.

    Read from the field's ``json_schema_extra`` under ``CATEGORY_MAP_KEY``: each
    mode value with its categories in canonical order, repeats dropped. A value
    that names no category raises ValueError. ``{}`` when the field does not
    exist, has no ``json_schema_extra``, has a callable one, or holds no dict
    under the key.
    """
    field = getattr(options_model, "model_fields", {}).get(field_name)
    extra = getattr(field, "json_schema_extra", None)
    if not isinstance(extra, dict):
        return {}
    published = extra.get(CATEGORY_MAP_KEY)
    if not isinstance(published, dict):
        return {}
    mapping: dict[str, tuple[ScanCategory, ...]] = {}
    for key, values in published.items():
        named = {ScanCategory(value) for value in values}
        mapping[str(key)] = tuple(
            category for category in ScanCategory if category in named
        )
    return mapping


def category_mapped_fields(options_model: type[BaseModel]) -> tuple[str, ...]:
    """The names of *options_model*'s fields that carry a category map, in
    declaration order; ``()`` when none does."""
    return tuple(
        field_name
        for field_name in getattr(options_model, "model_fields", {})
        if category_map(options_model, field_name)
    )
