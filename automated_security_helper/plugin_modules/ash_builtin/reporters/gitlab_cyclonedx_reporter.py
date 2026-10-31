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
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
    conforming_bom,
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
# Every type key of the two tables above has an entry: a type without one left
# the report with no ``input_file:path``, the one property GitLab requires. The
# OS package types name the database Syft reads for them.
_DEFAULT_LOCKFILES: dict[str, str] = {
    "npm": "package-lock.json",
    "pypi": "requirements.txt",
    "gem": "Gemfile.lock",
    "golang": "go.sum",
    "maven": "pom.xml",
    "java-archive": "pom.xml",
    "gradle": "build.gradle",
    "cargo": "Cargo.lock",
    "composer": "composer.lock",
    "nuget": "packages.lock.json",
    "pub": "pubspec.lock",
    "cocoapods": "Podfile.lock",
    "hex": "mix.lock",
    "hackage": "cabal.project",
    "python": "requirements.txt",
    "go-module": "go.sum",
    "apk": "lib/apk/db/installed",
    "deb": "var/lib/dpkg/status",
    "rpm": "var/lib/rpm/Packages",
}

# The package manager a lockfile's name says declared a component, where the
# ecosystem tables can only say the ecosystem's generic manager. GitLab's
# taxonomy gives ``package_manager:name`` by example (npm, bundler, go) and
# fixes no list, and its own analyzers name yarn, pnpm, poetry and pipenv. Keyed
# by basename; a component whose location is one of these gets that manager.
_LOCKFILE_PACKAGE_MANAGERS: dict[str, str] = {
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "poetry",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "uv.lock": "uv",
    "pdm.lock": "pdm",
}

# The managers a lockfile can refine, by the generic manager the ecosystem tables
# give. A lockfile refines only within its own ecosystem: a yarn.lock never turns
# a Python component's ``pip`` into ``yarn``, nor a poetry.lock an npm one into
# ``poetry``.
_REFINEMENTS: dict[str, frozenset[str]] = {
    "npm": frozenset({"yarn", "pnpm"}),
    "pip": frozenset({"poetry", "pipenv", "uv", "pdm"}),
}

# The basenames of the manifests and lockfiles a declared dependency comes from.
# A location inside a vendored tree is reported by its basename only when it is
# one of these: the basename of any other file there (a wheel's METADATA, an
# installed package's own package.json, a binary) is not an input file GitLab
# can show a reader, and was shown as one.
_MANIFEST_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
        "pyproject.toml",
        "setup.py",
        "Gemfile",
        "Gemfile.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "Cargo.toml",
        "Cargo.lock",
        "composer.json",
        "composer.lock",
        "packages.lock.json",
        "pubspec.yaml",
        "pubspec.lock",
        "Podfile",
        "Podfile.lock",
        "mix.exs",
        "mix.lock",
        "cabal.project",
    }
)


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


#: Path segments that mark a component as a vendored or installed copy rather
#: than a dependency the repository declares: a virtual environment, an installed
#: site-packages tree, a node_modules tree, a vendor directory.
_VENDORED_SEGMENTS = (
    ".venv/",
    "venv/",
    "site-packages/",
    "node_modules/",
    "vendor/",
)


_VENDORED_DIRECTORY_NAMES = frozenset(
    segment.rstrip("/") for segment in _VENDORED_SEGMENTS
)


def _is_vendored(component_dict: dict) -> bool:
    """Whether the component's recorded location lies inside a vendored tree.

    The test is on whole directory names along the path, so ``vendor/`` marks
    ``/vendor/x.lock`` and ``/src/vendor/x.lock`` but not ``/src/myvendor/x.lock``;
    a plain substring test matched the latter.
    """
    raw_path = _get_component_property(component_dict, "syft:location:0:path")
    if not raw_path:
        return False
    directories = raw_path.strip("/").split("/")[:-1]
    return any(directory in _VENDORED_DIRECTORY_NAMES for directory in directories)


def _declared_components(components: list[dict]) -> list[dict]:
    """The components that vote for the report-level source.

    Components found inside a virtual environment, site-packages, node_modules
    or vendor directory describe what is installed under the repository, not
    what the repository declares: with them in the vote ASH's own repository
    (a Python project whose .venv holds a documentation toolchain) was labelled
    an npm project with input file yarn.lock. They are left out of the vote
    when any component outside such a tree exists; an inventory that is all
    vendored copies keeps voting as before, so the metadata is never empty for
    a repository that has only vendored dependencies.
    """
    declared = [c for c in components if not _is_vendored(c)]
    return declared or list(components)


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

    # If a directory on the path is a virtual-env, site-packages, node_modules
    # or vendor directory, show just the filename (the lockfile/manifest).
    # This is a heuristic — better than showing a container-internal path.
    # The test is on whole directory names, the same as _is_vendored: a
    # repository's own "src/myvendor/" keeps its path. Only a manifest or
    # lockfile name is shown: a wheel's METADATA or an installed dependency's
    # own package.json is where Syft found the component, not a file that
    # declares it, and naming it as the input file told a reader to edit it.
    parts = path.split("/")
    if any(directory in _VENDORED_DIRECTORY_NAMES for directory in parts[:-1]):
        # e.g. "yarn.lock", "package-lock.json", "go.sum", "requirements.txt"
        return parts[-1] if parts[-1] in _MANIFEST_NAMES else None

    return path


def _lockfile_package_manager(path: str | None) -> str | None:
    """The package manager the lockfile at *path* names, or None."""
    if not path:
        return None
    return _LOCKFILE_PACKAGE_MANAGERS.get(path.rsplit("/", 1)[-1])


def _refined_package_manager(pm: str | None, path: str | None) -> str | None:
    """*pm*, or the manager the lockfile at *path* names when *pm* is only the
    ecosystem's generic one (``npm`` for a yarn.lock, ``pip`` for a poetry.lock).

    The tables map an ecosystem to one manager, so every JavaScript component
    was labelled ``npm`` and every Python one ``pip`` whatever lockfile
    declared it; the lockfile's name says which manager did. Only a manager of
    *pm*'s own ecosystem refines it (see ``_REFINEMENTS``): a Python component
    whose location is a yarn.lock stays ``pip``.
    """
    if pm is None:
        return None
    refined = _lockfile_package_manager(path)
    if refined is not None and refined in _REFINEMENTS.get(pm, frozenset()):
        return refined
    return pm


def _walk_components(components: list[dict]) -> list[dict]:
    """*components* and every component nested under them, depth first.

    A CycloneDX component can carry its own ``components`` (an assembly, a
    bundled dependency's dependencies); they are part of the inventory and vote
    for the report-level source with the rest.

    The walk is linear: *pending* is a stack whose top is the next component,
    so a component's children are pushed in reverse and popped in document
    order, with no list copied per step.
    """
    out: list[dict] = []
    pending = [c for c in reversed(components) if isinstance(c, dict)]
    while pending:
        component = pending.pop()
        out.append(component)
        nested = component.get("components")
        if isinstance(nested, list):
            pending.extend(c for c in reversed(nested) if isinstance(c, dict))
    return out


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

    The manager an ecosystem table gives is refined by the component's lockfile
    (:func:`_refined_package_manager`): a component declared by a yarn.lock is
    ``yarn``, not ``npm``. The lockfile is the one the component reports as its
    input file (:func:`_resolve_input_file_path`), the operator's override
    included, so the manager and the input file written on one component always
    agree.
    """
    # Config overrides win unconditionally
    if options.package_manager_override and options.language_override:
        return options.package_manager_override, options.language_override

    pm, lang = _ecosystem_of(component_dict)
    if pm is not None:
        input_file = _resolve_input_file_path(component_dict, options)
        return (
            options.package_manager_override
            or _refined_package_manager(pm, input_file),
            options.language_override or lang,
        )

    return options.package_manager_override, options.language_override


def _ecosystem_of(component_dict: dict) -> tuple[str | None, str | None]:
    """The (package_manager, language) the tables give for a component, from its
    ``syft:package:type`` first and its PURL type second, else (None, None)."""
    syft_type = _get_component_property(component_dict, "syft:package:type")
    if syft_type and syft_type in SYFT_TYPE_TO_GITLAB:
        return SYFT_TYPE_TO_GITLAB[syft_type]
    purl_type = _extract_purl_type(component_dict.get("purl"))
    if purl_type and purl_type in PURL_TYPE_TO_GITLAB:
        return PURL_TYPE_TO_GITLAB[purl_type]
    return None, None


def _generic_manager(pm: str) -> str:
    """The ecosystem's generic manager for a refined one (``pip`` for ``poetry``,
    ``npm`` for ``yarn``); any other name is returned as it is."""
    for generic, refined in _REFINEMENTS.items():
        if pm in refined:
            return generic
    return pm


def _type_key_for_manager(pm: str) -> str | None:
    """A type key of the two tables whose manager is *pm*, PURL types first.

    A refined manager (``poetry``, ``yarn``) is looked up as its ecosystem's
    generic one, since the tables name only the generic managers.
    """
    pm = _generic_manager(pm)
    for purl_type, (manager, _) in PURL_TYPE_TO_GITLAB.items():
        if manager == pm:
            return purl_type
    for syft_type, (manager, _) in SYFT_TYPE_TO_GITLAB.items():
        if manager == pm:
            return syft_type
    return None


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

    Workspace mode: per project, for both of the reasons its two parents have. It
    is an SBOM, so N deliverables are N documents (see ``cyclonedx_reporter``);
    and it is a GitLab CI report artefact resolved against one project's
    repository root (see ``gitlab_sast_reporter``).

    The GitLab taxonomy this reporter injects makes merging worse rather than
    just wrong. ``_resolve_dominant_type`` and ``_dominant_input_file`` pick a
    single ecosystem and a single manifest path by majority vote across
    components. Across N projects the majority is whichever project has the most
    dependencies, so a merged document would label a Python project's components
    with a JavaScript project's ``package_manager`` and point at its lockfile --
    plausible-looking metadata that is simply false.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

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

        Uses config override if set, otherwise counts the ecosystem of every
        declared component, nested ones included, to find the most common one.
        The vote is by the (package_manager, language) pair the tables give,
        not by the raw type key: a Syft type and a PURL type that name one
        ecosystem (``python`` and ``pypi``, ``go-module`` and ``golang``) were
        counted apart, so one ecosystem's components split across two keys and
        a smaller ecosystem could win. The winning pair is returned as one of
        the table keys, which is what the callers look up.

        *components* is the flat list :func:`_walk_components` returns, nested
        components included; ``report`` walks the document once and passes the
        same list here and to :meth:`_dominant_input_file`.
        """
        if options.package_manager_override:
            override_type = _type_key_for_manager(options.package_manager_override)
            if override_type is not None:
                return override_type

        from collections import Counter

        pairs: Counter[tuple[str, str]] = Counter()
        for component in _declared_components(components):
            pm, lang = _ecosystem_of(component)
            if pm is not None:
                pairs[(pm, lang or "")] += 1

        if not pairs:
            return None
        pm, _ = pairs.most_common(1)[0][0]
        return _type_key_for_manager(pm)

    def _dominant_input_file(
        self, components: list[dict], dominant_type: str | None = None
    ) -> str | None:
        """Find the most common input file path across components.

        Counted over the components of the dominant ecosystem when there is
        one, so the report-level ``input_file:path`` names a file of the same
        ecosystem as the report-level package manager. Counted over every
        declared component, as it was, the metadata could pair ``pip`` with
        ``package-lock.json`` when a Python project vendored more JavaScript
        files than it declared Python ones. When the dominant ecosystem has
        no component with a usable location the result is None, and the caller
        falls back to that ecosystem's default lockfile; another ecosystem's
        file is never returned. Every declared component votes only when no
        ecosystem was found at all.

        *components* is the flat list :func:`_walk_components` returns.
        """
        from collections import Counter

        dominant_pm = None
        if dominant_type in PURL_TYPE_TO_GITLAB:
            dominant_pm = PURL_TYPE_TO_GITLAB[dominant_type][0]
        elif dominant_type in SYFT_TYPE_TO_GITLAB:
            dominant_pm = SYFT_TYPE_TO_GITLAB[dominant_type][0]

        declared = _declared_components(components)
        if dominant_pm is not None:
            voters = [c for c in declared if _ecosystem_of(c)[0] == dominant_pm]
        else:
            voters = declared

        files: Counter[str] = Counter()
        for component in voters:
            raw_path = _get_component_property(component, "syft:location:0:path")
            normalized = _normalize_input_file_path(raw_path)
            if normalized:
                files[normalized] += 1
        if files:
            return files.most_common(1)[0][0]
        return None

    def _build_minimal_empty_sbom(
        self,
        inventory_known: bool = False,
        options: GitLabCycloneDXReporterConfigOptions | None = None,
    ) -> dict:
        """Build a minimal valid GitLab-flavored CycloneDX document.

        Used when no components are detected (e.g., infrastructure-only repos).
        Always emitting an artifact ensures GitLab pipelines that require the
        ``gl-dependency-scanning-report.cdx.json`` artifact don't fail when a
        repo legitimately has no software dependencies.

        The minimal document includes the CycloneDX envelope and the GitLab
        schema version metadata property required by GitLab's parser.

        *inventory_known* is False when no SBOM scanner produced an inventory
        (it was missing, skipped or failed), and then the document carries a
        ``compositions`` entry with aggregate ``unknown``, as the ``cyclonedx``
        reporter does for the same case: an empty component list is not a
        statement that the project has no dependencies, and without the marker
        this document was byte-identical to the one a dependency-free repository
        gets.

        With *options* the document also carries the report-level source
        properties the full document carries: the category, which is always
        known, and the package manager, language and input file an operator
        set as overrides. The minimal document carried the schema version alone,
        so an operator who had told the reporter the repository's source saw it
        say nothing about the source whenever the inventory came back empty.
        """
        properties: list[dict[str, str]] = [
            {"name": "gitlab:meta:schema_version", "value": GITLAB_SCHEMA_VERSION}
        ]
        if options is not None:
            properties.append(
                {
                    "name": "gitlab:dependency_scanning:category",
                    "value": options.category,
                }
            )
            for name, value in (
                ("package_manager:name", options.package_manager_override),
                ("language:name", options.language_override),
                ("input_file:path", options.input_file_path_override),
            ):
                if value:
                    properties.append(
                        {"name": f"gitlab:dependency_scanning:{name}", "value": value}
                    )
        document: dict = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {"properties": properties},
            "components": [],
        }
        if not inventory_known:
            document["compositions"] = [{"aggregate": "unknown"}]
        return document

    def report(self, model: "AshAggregatedResults") -> str | None:
        """Enrich CycloneDX with GitLab properties and serialize.

        When no CycloneDX data or components are present, emit a minimal valid
        GitLab-compatible CycloneDX document instead of skipping. This ensures
        downstream GitLab pipelines that require the artifact to exist (e.g.,
        for policy validation) don't fail on repos with no dependencies.
        """

        # Guard: emit a minimal empty SBOM when no CycloneDX data is present.
        # No model means no SBOM scanner produced an inventory, so the document
        # says the inventory is unknown rather than empty.
        if not model.cyclonedx:
            ASH_LOGGER.debug(
                "gitlab-cyclonedx: No CycloneDX model present, "
                "emitting minimal empty SBOM."
            )
            return json.dumps(
                self._build_minimal_empty_sbom(
                    inventory_known=False, options=self.config.options
                ),
                separators=(",", ":"),
            )

        # Serialize to dict for manipulation. The BOM is first reduced to the
        # license lists CycloneDX 1.6 allows, as the ``cyclonedx`` reporter
        # does: a stored results file can hold an entry the lenient load kept,
        # and GitLab refuses a document that repeats it.
        doc = conforming_bom(model.cyclonedx).model_dump(
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
            # Every SBOM a scanner writes has metadata or a serial number; the
            # default model, and its dump read back from a results file, have
            # neither (the ``cyclonedx`` reporter's test for the same case).
            inventory_known = bool(doc.get("metadata") or doc.get("serialNumber"))
            return json.dumps(
                self._build_minimal_empty_sbom(
                    inventory_known=inventory_known, options=self.config.options
                ),
                separators=(",", ":"),
            )

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
        #
        # Not gated on a dominant ecosystem being found. The category is always
        # known, and an operator's package_manager_override, language_override
        # and input_file_path_override are set exactly for the repository whose
        # components map to no ecosystem in the tables; gating on the dominant
        # type dropped every one of these and left the report with no source
        # properties at all, the case the overrides exist to cure.
        options = self.config.options
        every_component = _walk_components(components)
        dominant_type = self._resolve_dominant_type(every_component, options)
        pm, lang = (None, None)
        if dominant_type in PURL_TYPE_TO_GITLAB:
            pm, lang = PURL_TYPE_TO_GITLAB[dominant_type]
        elif dominant_type in SYFT_TYPE_TO_GITLAB:
            pm, lang = SYFT_TYPE_TO_GITLAB[dominant_type]

        input_file = (
            options.input_file_path_override
            or self._dominant_input_file(every_component, dominant_type)
            or (_DEFAULT_LOCKFILES.get(dominant_type) if dominant_type else None)
        )
        # The lockfile the report names says which manager declared it: a
        # poetry.lock is poetry's, where the ecosystem table could only say pip.
        pm = _refined_package_manager(pm, input_file)

        if pm is None and not options.package_manager_override:
            ASH_LOGGER.warning(
                "gitlab-cyclonedx: no component maps to a known ecosystem, so the "
                "report names no package manager or language; set the reporter's "
                "package_manager_override, language_override and "
                "input_file_path_override options for this repository."
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
        # Top-level components only: GitLab's taxonomy says of components that
        # nest that properties "may only have properties applied to the
        # top-level object", so a nested component is described by its parent's.
        # Nested components still vote for the report-level source above.
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
