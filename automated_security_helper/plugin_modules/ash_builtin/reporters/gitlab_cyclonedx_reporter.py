# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GitLab CycloneDX reporter.

Enriches the Syft-produced CycloneDX SBOM with GitLab's property taxonomy
so that GitLab's Dependency List can ingest it without the
"Required GitLab CycloneDX properties are missing" error.

This reporter does NOT modify the existing ``cyclonedx`` reporter — it produces
a separate artifact (``gl-dependency-scanning-report.cdx.json``) intended to be
uploaded as ``artifacts:reports:cyclonedx`` in GitLab CI.

Reference:
  https://docs.gitlab.com/ee/development/sec/cyclonedx_property_taxonomy.html
"""

import json
from typing import Literal, Optional, TYPE_CHECKING

from pydantic import Field
from typing import Annotated

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITLAB_SCHEMA_VERSION = "1"
"""The only supported schema version as of GitLab 17.x (May 2026)."""

# Mapping from Syft's ``syft:package:type`` values to GitLab's expected
# (package_manager, language) pair.
SYFT_TYPE_TO_GITLAB: dict[str, tuple[str, str]] = {
    "npm": ("npm", "JavaScript"),
    "python": ("pip", "Python"),
    "gem": ("bundler", "Ruby"),
    "go-module": ("go", "Go"),
    "java-archive": ("maven", "Java"),
    "maven": ("maven", "Java"),
    "gradle": ("gradle", "Java"),
    "cargo": ("cargo", "Rust"),
    "composer": ("composer", "PHP"),
    "nuget": ("nuget", "C#"),
    "pub": ("pub", "Dart"),
    "cocoapods": ("cocoapods", "Swift"),
    "hex": ("mix", "Elixir"),
    "hackage": ("cabal", "Haskell"),
    "apk": ("apk", ""),
    "deb": ("apt", ""),
    "rpm": ("yum", ""),
}

# Fallback mapping from PURL type prefix to GitLab values.
# Used when ``syft:package:type`` is absent (e.g. non-Syft CycloneDX sources).
PURL_TYPE_TO_GITLAB: dict[str, tuple[str, str]] = {
    "npm": ("npm", "JavaScript"),
    "pypi": ("pip", "Python"),
    "gem": ("bundler", "Ruby"),
    "golang": ("go", "Go"),
    "maven": ("maven", "Java"),
    "cargo": ("cargo", "Rust"),
    "composer": ("composer", "PHP"),
    "nuget": ("nuget", "C#"),
    "pub": ("pub", "Dart"),
    "cocoapods": ("cocoapods", "Swift"),
    "hex": ("mix", "Elixir"),
    "hackage": ("cabal", "Haskell"),
    "apk": ("apk", ""),
    "deb": ("apt", ""),
    "rpm": ("yum", ""),
}

# Default lockfile/manifest names per ecosystem, used as a last-resort fallback
# for the metadata-level ``input_file:path`` when Syft doesn't report a location.
_DEFAULT_LOCKFILES: dict[str, str] = {
    "npm": "package-lock.json",
    "pypi": "requirements.txt",
    "gem": "Gemfile.lock",
    "golang": "go.sum",
    "maven": "pom.xml",
    "cargo": "Cargo.lock",
    "composer": "composer.lock",
    "nuget": "packages.lock.json",
    "pub": "pubspec.lock",
    "cocoapods": "Podfile.lock",
    "hex": "mix.lock",
    "python": "requirements.txt",
    "go-module": "go.sum",
}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class GitLabCycloneDXReporterConfigOptions(ReporterOptionsBase):
    """Options for the gitlab-cyclonedx reporter."""

    category: Annotated[
        str,
        Field(
            description=(
                "Default dependency category injected as "
                "gitlab:dependency_scanning:category. "
                "Typically 'production' or 'development'."
            ),
        ),
    ] = "production"

    package_manager_override: Annotated[
        Optional[str],
        Field(
            description=(
                "If set, overrides the auto-detected package manager name "
                "for ALL components. Useful for single-ecosystem repos."
            ),
        ),
    ] = None

    language_override: Annotated[
        Optional[str],
        Field(
            description=(
                "If set, overrides the auto-detected language name for ALL components."
            ),
        ),
    ] = None

    input_file_path_override: Annotated[
        Optional[str],
        Field(
            description=(
                "If set, overrides the auto-detected input file path "
                "for ALL components. Useful when Syft reports absolute "
                "container paths that don't match the repo layout."
            ),
        ),
    ] = None


class GitLabCycloneDXReporterConfig(ReporterPluginConfigBase):
    name: Literal["gitlab-cyclonedx"] = "gitlab-cyclonedx"
    extension: str = "gl-dependency-scanning-report.cdx.json"
    enabled: bool = True
    options: GitLabCycloneDXReporterConfigOptions = (
        GitLabCycloneDXReporterConfigOptions()
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_component_property(component_dict: dict, property_name: str) -> str | None:
    """Extract a named property value from a component's properties list."""
    for prop in component_dict.get("properties") or []:
        if prop.get("name") == property_name:
            return prop.get("value")
    return None


def _extract_purl_type(purl: str | None) -> str | None:
    """Extract the type segment from a PURL string.

    Example: ``pkg:npm/%40antfu/install-pkg@1.0.0`` → ``npm``
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    remainder = purl[4:]  # strip "pkg:"
    slash_idx = remainder.find("/")
    if slash_idx == -1:
        return remainder or None
    return remainder[:slash_idx] or None


def _normalize_input_file_path(raw_path: str | None) -> str | None:
    """Attempt to make a Syft location path repo-relative.

    Syft often reports absolute paths from inside containers
    (e.g. ``/.venv/lib/python3.12/.../yarn.lock``). We try to extract
    just the manifest filename which is what GitLab displays.

    Returns None if we can't produce something useful.
    """
    if not raw_path:
        return None

    # Strip leading slash
    path = raw_path.lstrip("/")

    # If the path contains common virtual-env or site-packages segments,
    # extract just the filename (the lockfile/manifest).
    # This is a heuristic — better than showing a container-internal path.
    segments_to_skip = (
        ".venv/",
        "venv/",
        "site-packages/",
        "node_modules/",
        "vendor/",
    )
    for segment in segments_to_skip:
        idx = path.find(segment)
        if idx != -1:
            # Find the last path component that looks like a manifest
            # e.g. "yarn.lock", "package-lock.json", "go.sum", "requirements.txt"
            parts = path.split("/")
            # Return the last component (the actual file)
            return parts[-1] if parts else None

    return path


def _resolve_package_manager_and_language(
    component_dict: dict,
    options: GitLabCycloneDXReporterConfigOptions,
) -> tuple[str | None, str | None]:
    """Resolve (package_manager, language) for a component.

    Resolution order:
    1. Config overrides (if set)
    2. ``syft:package:type`` property → SYFT_TYPE_TO_GITLAB mapping
    3. PURL type → PURL_TYPE_TO_GITLAB mapping
    4. None (omit the property)
    """
    # Config overrides win unconditionally
    if options.package_manager_override and options.language_override:
        return options.package_manager_override, options.language_override

    # Try syft:package:type first
    syft_type = _get_component_property(component_dict, "syft:package:type")
    if syft_type and syft_type in SYFT_TYPE_TO_GITLAB:
        pm, lang = SYFT_TYPE_TO_GITLAB[syft_type]
        return (
            options.package_manager_override or pm,
            options.language_override or lang,
        )

    # Fallback to PURL type
    purl_type = _extract_purl_type(component_dict.get("purl"))
    if purl_type and purl_type in PURL_TYPE_TO_GITLAB:
        pm, lang = PURL_TYPE_TO_GITLAB[purl_type]
        return (
            options.package_manager_override or pm,
            options.language_override or lang,
        )

    return options.package_manager_override, options.language_override


def _resolve_input_file_path(
    component_dict: dict,
    options: GitLabCycloneDXReporterConfigOptions,
) -> str | None:
    """Resolve the input file path for a component.

    Resolution order:
    1. Config override (if set)
    2. ``syft:location:0:path`` property (normalized)
    3. None (omit the property)
    """
    if options.input_file_path_override:
        return options.input_file_path_override

    raw_path = _get_component_property(component_dict, "syft:location:0:path")
    return _normalize_input_file_path(raw_path)


def _build_gitlab_properties_for_component(
    component_dict: dict,
    options: GitLabCycloneDXReporterConfigOptions,
) -> list[dict[str, str]]:
    """Build the list of GitLab taxonomy properties to inject on a component."""
    props: list[dict[str, str]] = []

    # Category (always injected)
    props.append(
        {"name": "gitlab:dependency_scanning:category", "value": options.category}
    )

    # Package manager and language
    pm, lang = _resolve_package_manager_and_language(component_dict, options)
    if pm:
        props.append(
            {"name": "gitlab:dependency_scanning:package_manager:name", "value": pm}
        )
    if lang:
        props.append(
            {"name": "gitlab:dependency_scanning:language:name", "value": lang}
        )

    # Input file path
    input_file = _resolve_input_file_path(component_dict, options)
    if input_file:
        props.append(
            {"name": "gitlab:dependency_scanning:input_file:path", "value": input_file}
        )

    return props


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


@ash_reporter_plugin
class GitLabCycloneDXReporter(ReporterPluginBase[GitLabCycloneDXReporterConfig]):
    """Enriches CycloneDX SBOM with GitLab dependency scanning properties.

    Produces ``gl-dependency-scanning-report.cdx.json`` suitable for upload as
    ``artifacts:reports:cyclonedx`` in GitLab CI pipelines.
    """

    def model_post_init(self, context):
        if self.config is None:
            self.config = GitLabCycloneDXReporterConfig()
        return super().model_post_init(context)

    def _resolve_dominant_type(
        self,
        components: list[dict],
        options: GitLabCycloneDXReporterConfigOptions,
    ) -> str | None:
        """Determine the dominant ecosystem type across all components.

        Uses config override if set, otherwise counts PURL types and
        syft:package:type values to find the most common one.
        """
        if options.package_manager_override:
            # Find the matching type key for the override
            for purl_type, (pm, _) in PURL_TYPE_TO_GITLAB.items():
                if pm == options.package_manager_override:
                    return purl_type
            for syft_type, (pm, _) in SYFT_TYPE_TO_GITLAB.items():
                if pm == options.package_manager_override:
                    return syft_type

        from collections import Counter

        types: Counter[str] = Counter()
        for component in components:
            # Try syft:package:type first
            syft_type = _get_component_property(component, "syft:package:type")
            if syft_type and syft_type in SYFT_TYPE_TO_GITLAB:
                types[syft_type] += 1
                continue
            # Fallback to PURL type
            purl_type = _extract_purl_type(component.get("purl"))
            if purl_type and purl_type in PURL_TYPE_TO_GITLAB:
                types[purl_type] += 1

        return types.most_common(1)[0][0] if types else None

    def _dominant_input_file(self, components: list[dict]) -> str | None:
        """Find the most common input file path across components."""
        from collections import Counter

        files: Counter[str] = Counter()
        for component in components:
            raw_path = _get_component_property(component, "syft:location:0:path")
            normalized = _normalize_input_file_path(raw_path)
            if normalized:
                files[normalized] += 1
        return files.most_common(1)[0][0] if files else None

    def _build_minimal_empty_sbom(self) -> dict:
        """Build a minimal valid GitLab-flavored CycloneDX document.

        Used when no components are detected (e.g., infrastructure-only repos).
        Always emitting an artifact ensures GitLab pipelines that require the
        ``gl-dependency-scanning-report.cdx.json`` artifact don't fail when a
        repo legitimately has no software dependencies.

        The minimal document includes the CycloneDX envelope and the GitLab
        schema version metadata property required by GitLab's parser.
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "properties": [
                    {
                        "name": "gitlab:meta:schema_version",
                        "value": GITLAB_SCHEMA_VERSION,
                    }
                ],
            },
            "components": [],
        }

    def report(self, model: "AshAggregatedResults") -> str | None:
        """Enrich CycloneDX with GitLab properties and serialize.

        When no CycloneDX data or components are present, emit a minimal valid
        GitLab-compatible CycloneDX document instead of skipping. This ensures
        downstream GitLab pipelines that require the artifact to exist (e.g.,
        for policy validation) don't fail on repos with no dependencies.
        """

        # Guard: emit a minimal empty SBOM when no CycloneDX data is present
        if not model.cyclonedx:
            ASH_LOGGER.debug(
                "gitlab-cyclonedx: No CycloneDX model present, "
                "emitting minimal empty SBOM."
            )
            return json.dumps(self._build_minimal_empty_sbom(), separators=(",", ":"))

        # Serialize to dict for manipulation
        doc = model.cyclonedx.model_dump(
            by_alias=True,
            exclude_unset=True,
            exclude_none=True,
            mode="json",
        )

        components = doc.get("components")
        if not components:
            ASH_LOGGER.debug(
                "gitlab-cyclonedx: CycloneDX model has no components, "
                "emitting minimal empty SBOM."
            )
            return json.dumps(self._build_minimal_empty_sbom(), separators=(",", ":"))

        # --- Inject metadata-level schema version property ---
        metadata = doc.setdefault("metadata", {})
        metadata_props = metadata.setdefault("properties", [])
        metadata_props.append(
            {"name": "gitlab:meta:schema_version", "value": GITLAB_SCHEMA_VERSION}
        )

        # --- Inject metadata-level dependency_scanning source properties ---
        # GitLab's CycloneDX parser resolves the report-level source from
        # metadata.properties ONLY. Without these, the parser returns nil for
        # the source and fires "Required GitLab CycloneDX properties are missing".
        options = self.config.options
        dominant_type = self._resolve_dominant_type(components, options)
        if dominant_type:
            pm, lang = (None, None)
            if dominant_type in PURL_TYPE_TO_GITLAB:
                pm, lang = PURL_TYPE_TO_GITLAB[dominant_type]
            elif dominant_type in SYFT_TYPE_TO_GITLAB:
                pm, lang = SYFT_TYPE_TO_GITLAB[dominant_type]

            input_file = (
                options.input_file_path_override
                or self._dominant_input_file(components)
                or _DEFAULT_LOCKFILES.get(dominant_type)
            )

            metadata_props.append(
                {
                    "name": "gitlab:dependency_scanning:category",
                    "value": options.category,
                }
            )
            if options.package_manager_override or pm:
                metadata_props.append(
                    {
                        "name": "gitlab:dependency_scanning:package_manager:name",
                        "value": options.package_manager_override or pm,
                    }
                )
            if options.language_override or lang:
                metadata_props.append(
                    {
                        "name": "gitlab:dependency_scanning:language:name",
                        "value": options.language_override or lang,
                    }
                )
            if input_file:
                metadata_props.append(
                    {
                        "name": "gitlab:dependency_scanning:input_file:path",
                        "value": input_file,
                    }
                )

        # --- Inject per-component properties ---
        enriched_count = 0

        for component in components:
            gitlab_props = _build_gitlab_properties_for_component(component, options)
            if gitlab_props:
                component.setdefault("properties", []).extend(gitlab_props)
                enriched_count += 1

        ASH_LOGGER.info(
            f"gitlab-cyclonedx: Enriched {enriched_count}/{len(components)} "
            f"components with GitLab dependency scanning properties."
        )

        return json.dumps(doc, separators=(",", ":"))
