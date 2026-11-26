"""Module containing the Grype security scanner implementation."""

import logging
import os
import re
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Final,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
)

import yaml
from pydantic import Field, model_validator
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.models.vocab import SeverityThresholdText, TargetType
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.constants import SHIPPED_SEVERITY_LEVEL
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.link_exclusions import syft_excludes
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.redacted_model import value_tuple
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    identity_properties,
    install_path,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.content_db_refresh import (
    GRYPE_PREPARED_ENV,
    default_cache_dir,
    prepare_content_db,
    sandboxed_online,
    scan_id_for,
)

#: grype configuration keys that remove matches from the report.
#:
#: A discovered grype config is passed straight through as ``--config``, so a key
#: like ``only-fixed`` narrows ASH's own results. Until these keys were named here
#: nothing in the run said the report had been filtered, and the only record was
#: the config file itself -- which nobody opens while reading a clean scan.
#: Warning on the key rather than fixing one config file is the general form: any
#: adopter can point ASH at a config that quietly withholds their own findings.
#:
#: Key names and effects are from grype's configuration reference at
#: https://oss.anchore.com/docs/reference/grype/configuration/ (generated for
#: grype 0.110.0):
#:
#: * ``only-fixed`` -- "ignore matches for vulnerabilities that are not fixed"
#: * ``only-notfixed`` -- "ignore matches for vulnerabilities that are fixed"
#: * ``ignore-wontfix`` -- "ignore matches for vulnerabilities with specified
#:   comma separated fix states"
#: * ``ignore`` -- "A list of vulnerability ignore rules"
#: * ``exclude`` -- "a list of globs to exclude from scanning"
#: * ``vex-add`` -- "VEX statuses to consider as ignored rules"
#: * ``vex-documents`` -- "a list of VEX documents to consider when producing
#:   scanning results"; with one loaded, matches a document marks ``not_affected``
#:   or ``fixed`` leave the report by default (``vex-add`` only widens the set of
#:   statuses that do), so the documents are the filter and the key is named.
#:
#: ``fail-on-severity`` is excluded deliberately: it sets the return code and
#: removes nothing from the report, so warning about it would train a reader to
#: ignore the warning. ``show-suppressed`` is the inverse of a filter -- it
#: reveals matches that were dropped rather than dropping them.
#:
#: The keys are matched case-insensitively: grype reads its config through viper,
#: which lowercases keys, so ``Only-Fixed: true`` filters as ``only-fixed`` does.
OUTPUT_RESTRICTING_GRYPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "only-fixed",
        "only-notfixed",
        "ignore-wontfix",
        "ignore",
        "exclude",
        "vex-add",
        "vex-documents",
    }
)

# The per-result message grype's SARIF presenter writes for a package match.
#: Where the register's mapped grype cells were observed. ASH runs grype on a
#: directory (``dir:``); the committed capture is grype 0.122.1 over a syft SBOM,
#: so locations, the line and column values, the fingerprint distribution and the
#: rule help link are read from that mode and a ``dir:`` run is not yet captured.
_SBOM_CAPTURE_NOTE = (
    "observed in the committed grype 0.122.1 capture over a syft SBOM, not in a "
    "dir: scan, the mode ASH wires; a dir: capture would settle any difference"
)

_GRYPE_PACKAGE_MESSAGE = re.compile(
    r"vulnerability in \S+ package: (?P<name>[^,\s]+), version (?P<version>\S+) "
    r"was found at: "
)

#: One ``Key: value`` line of the help text grype's SARIF presenter writes on each
#: rule ("Vulnerability <id>\nSeverity: ...\nPackage: ...\nVersion: ...\nFix
#: Version: ...\nType: ...").
_GRYPE_HELP_LINE = re.compile(
    r"^(?P<key>Package|Version|Fix Version):[ \t]*(?P<value>.*?)[ \t]*$"
)


def _rule_fix_statements(run) -> dict[str, tuple[str, str, str]]:
    """Each rule's ``(package, version, fix versions)`` from its help text.

    Only a rule whose id is unique in the run and whose help text names exactly
    one ``Package``, one ``Version`` and one ``Fix Version`` line is read; the
    fix versions are the (possibly empty) text after ``Fix Version:``. A rule
    with a repeated id, a repeated or missing line, or no help text is left out,
    so a result naming it gets nothing attached.
    """
    driver = run.tool.driver if run.tool else None
    rules = (driver.rules if driver else None) or []
    seen: dict[str, int] = {}
    for rule in rules:
        seen[rule.id] = seen.get(rule.id, 0) + 1
    statements: dict[str, tuple[str, str, str]] = {}
    for rule in rules:
        if seen[rule.id] != 1 or rule.help is None:
            continue
        found: dict[str, list[str]] = {}
        for line in rule.help.text.splitlines():
            line_match = _GRYPE_HELP_LINE.match(line)
            if line_match:
                found.setdefault(line_match.group("key"), []).append(
                    line_match.group("value")
                )
        if any(
            len(found.get(key, [])) != 1
            for key in ("Package", "Version", "Fix Version")
        ):
            continue
        statements[rule.id] = (
            found["Package"][0],
            found["Version"][0],
            found["Fix Version"][0],
        )
    return statements


#: What grype writes for a file-name byte that is not UTF-8: Go strings hold the
#: replacement character (U+FFFD) where such a byte sits, so grype's SARIF cannot
#: spell the name.
_GRYPE_REPLACEMENT = "�"

#: One file-name character Python lists for a byte that is not UTF-8: a lone
#: surrogate, from os.fsdecode's surrogateescape.
_ONE_UNDECODABLE_CHARACTER = "[\ud800-\udfff]"


def _holds_a_database(cache: Path) -> bool:
    """Whether *cache* holds a grype database: ``<schema version>/vulnerability.db``.

    grype keeps one directory per schema version under its cache, so the version
    is not named here. A cache that cannot be listed holds none that can be read.
    """
    try:
        versions = os.listdir(cache)
    except OSError:
        return False
    return any(
        os.path.isfile(os.path.join(cache, version, "vulnerability.db"))
        for version in versions
    )


def _name_grype_garbled(root: Path, uri: str, separators: Optional[str] = None) -> str:
    """The name under *root* that *uri* garbles, or *uri* as grype wrote it.

    Each path component holding the replacement character is matched against the
    directory's own entries, with each replacement character standing for exactly
    one character the directory listing shows as a lone surrogate (the form a
    file-name byte that is not UTF-8 takes). A component is replaced only when no
    entry is literally named with the replacement character and exactly one entry
    matches; anything else, two matches included, is left as grype wrote it,
    since the output does not say which file it means.

    *separators* are the characters that split the URI into components, kept in
    place when it is joined back: ``/`` and, on Windows, the backslash too, since
    grype writes the relative part of a path there with backslashes (see
    ``_attach_package_identity``). On other hosts a backslash is a character of a
    name and is never a separator.

    A URI that begins with *root* itself (grype's Windows spelling, the scan root
    followed by the backslashed relative path) keeps those leading components as
    written, and only what follows them is read from the directory; walked from
    *root* again, the root's own components named a directory that does not exist.
    """
    if _GRYPE_REPLACEMENT not in uri:
        return uri
    if separators is None:
        separators = "/\\" if os.sep == "\\" else "/"
    # On Windows grype writes the scan root, then the relative path with backslashes
    # ("D:/a/r/r/\\deploy\\..."; see ``_attach_package_identity``). The walk starts
    # at *root*, so the root's own components are not walked again: they are kept as
    # written, and only what follows them is read from the directory.
    prefix = ""
    fold = str.casefold if "\\" in separators else str
    root_text = root.as_posix().rstrip("/")
    spelled = uri.replace("\\", "/") if "\\" in separators else uri
    if root_text and fold(spelled).startswith(fold(root_text) + "/"):
        rest = uri[len(root_text) :]
        relative = rest.lstrip(separators)
        prefix = uri[: len(uri) - len(relative)]
        uri = relative
    parts = re.split(f"([{re.escape(separators)}])", uri)
    current = root
    components: List[str] = []
    for component in parts:
        if component in separators and component:
            components.append(component)
            continue
        # os.path.lexists, not Path.exists: inside a directory the process
        # cannot list, Path.exists raises PermissionError on Python 3.10-3.13
        # (only 3.14 answers False), and os.path.lexists answers False on any
        # OSError. A file literally named with the replacement character is
        # found either way and left as grype wrote it.
        if _GRYPE_REPLACEMENT in component and not os.path.lexists(current / component):
            pattern = re.compile(
                "".join(
                    _ONE_UNDECODABLE_CHARACTER
                    if character == _GRYPE_REPLACEMENT
                    else re.escape(character)
                    for character in component
                )
            )
            try:
                entries = os.listdir(current)
            except OSError:
                entries = []
            matches = [entry for entry in entries if pattern.fullmatch(entry)]
            if len(matches) == 1:
                component = matches[0]
        components.append(component)
        if component:
            current = current / component
    return prefix + "".join(components)


def _lowercase_keys(document: Any) -> dict:
    """*document* as a mapping with its keys lowercased, as viper reads grype's
    config; an empty mapping when it is not one."""
    if not isinstance(document, dict):
        return {}
    return {str(key).lower(): value for key, value in document.items()}


class GrypeScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Grype configuration file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory."
            f" {SET_BY_THE_OPERATOR}"
            " ASH does not look for one by name. Without one, grype gets an empty config, so it does not read `.grype.yaml` from the scanned tree.",
        ),
    ] = None
    severity_threshold: Annotated[
        SeverityThresholdText | None,
        Field(
            description=f"Minimum severity level to consider findings as failures. This is a scanner-level override of the default severity-level within ASH of {SHIPPED_SEVERITY_LEVEL}."
        ),
    ] = None
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, disabling database updates and validation. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]


class GrypeScannerConfig(ScannerPluginConfigBase):
    name: Literal["grype"] = "grype"
    enabled: bool = True
    options: Annotated[
        GrypeScannerConfigOptions, Field(description="Configure Grype scanner")
    ] = GrypeScannerConfigOptions()


def _with_path_spellings(values: Iterable[str]) -> list[str]:
    """*values*, each also as Path() writes it ("a/./b" as "a/b").

    The scanner names its config through Path(), which collapses "." segments
    and doubled or trailing slashes, and redaction finds only a spelling it is
    given. On Windows Path() also respells forward slashes with backslashes, so
    the native spelling is a needle too, and it collapses the same "." segments
    and doubled separators in a value written with backslashes, so every
    non-empty value is respelled, not only one holding a slash. Elsewhere the
    respelling of a value without a slash is the value itself, and a repeat is
    dropped.
    """
    values = list(value_tuple(values))
    spelled = [
        spelling
        for value in values
        if value
        for spelling in (Path(value).as_posix(), str(Path(value)))
    ]
    return list(dict.fromkeys([*values, *spelled]))


def _declared_grype_db_bound(
    environ: Mapping[str, str],
    grype_config: Path | None,
    values: Iterable[str] = (),
    *,
    shown: Path | None = None,
) -> dict[str, str]:
    """The grype-db bound from the registry, minus anything the user set themselves.

    *grype_config* is the file as grype will read it (``~`` expanded, a relative
    value taken from the source directory, links resolved): the path as configured
    read ``<cwd>/~/...`` or a planted ``<source>/~/...`` instead of the operator's
    home file, so the operator's own ``db`` settings went unseen and ASH's bound
    was exported over them. *shown*, the path as configured, names the file in the
    DEBUG line; *values*, the config's environment values, are redacted from it:
    the config's path can come from the environment, and ash.log keeps DEBUG lines
    under --debug.
    """
    from automated_security_helper.utils.content_databases import get
    from automated_security_helper.utils.error_text import text_without_values

    user_config_keys: set[str] = set()
    if grype_config is not None:
        try:
            import yaml

            loaded = yaml.safe_load(grype_config.read_text(encoding="utf-8")) or {}
            # Lowercased, as viper reads them: a differently cased key in the
            # user's file is the same setting to grype.
            db_section = _lowercase_keys(loaded).get("db")
            user_config_keys = set(_lowercase_keys(db_section))
        except Exception as exc:  # nosec B110 - an unreadable config is grype's to report
            named = shown if shown is not None else grype_config
            ASH_LOGGER.debug(
                text_without_values(
                    f"Could not read {named} for db settings: {exc}", values
                )
            )
    config_key_for_env = {
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "max-allowed-built-age",
        "GRYPE_DB_VALIDATE_AGE": "validate-age",
    }
    return {
        name: value
        for name, value in get("grype-db").bound_env.items()
        if name not in environ and config_key_for_env.get(name) not in user_config_keys
    }


@ash_scanner_plugin
class GrypeScanner(ScannerPluginBase[GrypeScannerConfig]):
    """GrypeScanner implements IaC scanning using Grype."""

    display_name = "Grype"
    docs_summary = "Vulnerability matching"
    covers = ("Packages and dependency files",)

    #: grype is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        # Every place content_db_refresh.default_cache_dir can put grype's
        # database: ~/.cache on Linux, ~/Library/Caches on macOS, XDG_CACHE_HOME
        # when set, and GRYPE_DB_CACHE_DIR. Caches rather than read paths: a cache
        # is read-only on every backend but bwrap, whose overlay throws writes
        # away, and sandbox-exec runs no program from one, where it runs programs
        # from read paths. The database is updated outside the sandbox before an
        # online scan (utils/content_db_refresh.py), and grype only reads it.
        cache_paths=(
            "~/.cache/grype",
            "~/Library/Caches/grype",
            "$XDG_CACHE_HOME/grype",
            "$GRYPE_DB_CACHE_DIR",
        ),
        env_prefixes=("GRYPE_",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    #: The facets register row (base/scanner_facets.py). Declaration only.
    #: grype is a package-vulnerability matcher: its findings are packages, and
    #: the one place a finding names where it was found is the manifest, a
    #: locator and not a resource, so resource_id is n/a and the register's
    #: must-not row holds the adapter to never writing ``ash_resource_id``.
    #: Native fields are quoted from the committed native JSON
    #: (tests/test_data/scanners/grype/grype.src.json) and from ASH's own
    #: reading of grype's SARIF in this module (``_GRYPE_PACKAGE_MESSAGE``).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field="SARIF result ruleId (the vulnerability id plus the "
            "package name)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field='SARIF rule properties "security-severity" (CVSS), '
            'else the result "level"',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field="SARIF locations[].physicalLocation.artifactLocation."
            "uri (the manifest or lockfile)",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field="SARIF region.startLine (grype writes line 1 of the manifest)",
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field="SARIF region.startColumn / region.endColumn (always "
            "1 in the capture, as the finding is the manifest's line 1)",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field="SARIF result message.text",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="LOCATOR-ONLY: grype reports packages; the only location "
            "is the manifest at line 1, a file locator and package identity "
            "(artifact.purl), not a resource with its own lifecycle",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="grype output names no resource; artifact.type is a "
            "package ecosystem (gem, npm), not a resource type",
        ),
        package_name=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field='SARIF message "package: <name>, version <version> '
            'was found at:" parsed by _GRYPE_PACKAGE_MESSAGE',
        ),
        package_version=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field='SARIF message "package: <name>, version <version> '
            'was found at:" parsed by _GRYPE_PACKAGE_MESSAGE',
        ),
        package_path=FacetDecl(
            state=FacetState.UNCONFIRMED,
            reason="UNCONFIRMED: the adapter resolves an npm lockfile entry "
            "by name and version beside the manifest (set only when exactly "
            "one copy matches), pinned over the conformance tests' presenter "
            "shape only; no grype SARIF fixture from a real run (over a "
            "committed npm tree) is committed, so a `grype -o sarif` capture "
            "settles it",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.UNCONFIRMED,
            reason="UNCONFIRMED: the SARIF result ruleId is the vulnerability "
            "id (matches[].vulnerability.id, a CVE or GHSA id; the committed "
            "native JSON's eight matches are all GHSA ids, which the flat CVE "
            "column never reads); no grype SARIF fixture from a real run with "
            "a CVE-named match is committed, so a `grype -o sarif` capture "
            "settles it",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the committed native grype JSON (vulnerability keys "
            "advisories, cvss, dataSource, description, epss, fix, id, "
            "namespace, severity, urls) carries no CWE, and the captured SARIF "
            "rule properties hold only purls and security-severity",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field="SARIF result partialFingerprints."
            "primaryLocationLineHash (a hash of the manifest line, so findings "
            "at one manifest line share a value; 6 distinct values over 21 "
            "results in the capture)",
        ),
        fix_available=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field='the SARIF rule help.text line "Fix Version: '
            "<versions>\" (grype's rendering of "
            "matches[].vulnerability.fix.versions); fix_available=True is "
            "written only for a non-empty list on a uniquely named rule whose "
            "Package and Version lines match the result's own message",
        ),
        remediation_text=FacetDecl(
            state=FacetState.UNCONFIRMED,
            reason="UNCONFIRMED: not classified by the survey; the flat "
            "model has no remediation column, and matchDetails[].fix."
            "suggestedVersion is a version, not text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a package match has no source code snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="tool.driver.rules[].helpUri, read into the flat "
            "references by the shared rule read when the result carries "
            "none of its own",
            reason="grype writes the advisory dataSource as the rule helpUri; "
            "the native match urls (matches[].vulnerability.urls, "
            "relatedVulnerabilities[].urls) are still never read; "
            + _SBOM_CAPTURE_NOTE,
        ),
        tags=FacetDecl(
            state=FacetState.UNCONFIRMED,
            reason="UNCONFIRMED: the survey reads SARIF rule properties.tags "
            "off the conformance tests' presenter shape (rule-level, which "
            "the flat reader takes as the tags column only when the result "
            "itself carries none); no grype SARIF fixture from a real run is "
            "committed, so a `grype -o sarif` capture settles whether results "
            "carry tags",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            reason=_SBOM_CAPTURE_NOTE,
            native_field="SARIF result properties bag (package identity keys "
            "this adapter writes) passed through to the flat properties",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="grype",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                # IMAGE_DIGEST: the one-manifest registry read that keys this
                # scanner's image finding ids (utils/image_digest_resolver).
                fetches=(opsf.Fetched.VULN_DB, opsf.Fetched.IMAGE_DIGEST),
                prefetch=(
                    opsf.Prefetch.CONTENT_DB_REFRESH,
                    opsf.Prefetch.CI_CACHE,
                ),
                offline_outcome=opsf.OfflineOutcome.DEGRADED,
                offline_reason=(
                    "GRYPE_DB_AUTO_UPDATE=false and GRYPE_DB_VALIDATE_AGE=false against a "
                    "pre-checked local database; the scan-time staleness check holds the "
                    "database to the age bound declared in utils/content_databases.py "
                    "after the scan"
                ),
                offline_strategy=OfflineStrategy.CACHE_FLAGS,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                content_database="grype-db",
                source=(
                    "grype_scanner.py offline_strategy and sandbox_requirements; "
                    "utils/content_databases.py grype-db; utils/content_db_refresh.py "
                    "refreshes it outside the sandbox before an online scan"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(
                    opsf.TargetKind.PACKAGE_INVENTORY,
                    opsf.TargetKind.DEPENDENCY_LOCKFILES,
                    opsf.TargetKind.CONTAINER_IMAGE,
                ),
                tool_type=ScannerToolType.SCA,
                selection=(
                    "a dir: scan of the source tree, with a lockfile join for "
                    "locations; a container-image asset through a stereoscope "
                    "target (_execute_image_scan: docker-archive:/oci-archive: "
                    "by the tar's own format, oci-dir: for a layout, "
                    "docker:/podman:/registry: for a reference by the detected "
                    "engine), with the ignore paths as --exclude globs"
                ),
                covers_note=(
                    "the display string reads 'Packages and dependency files'; "
                    "container images are scanned when the submission names one "
                    "(the asset routing), which the display string understates"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key="grype",
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_NO_WINDOWS_ARM64,
                note="no windows/arm64 asset (tool_downloads.py docstring)",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the generic CVSS path; the per-result severity word is a dropped cell in the mapping register",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.UNCONFIRMED,
                        surface="a grype configuration file with ignore rules in the scanned tree",
                        cite="tool feature; grype_scanner.py was not read for whether ASH passes a config that stops it",
                        reason=(
                            "whether a repository-written grype config can silence "
                            "findings under ASH was not read; one adapter read settles it"
                        ),
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="read at tests/test_data/scanners/grype/captured/grype-0.122.1-from-syft-sbom.sarif: "
                "every result carries partialFingerprints.primaryLocationLineHash, which grype writes "
                "per manifest line (6 distinct values over 21 results), so findings at one line share "
                "a value; it is not a per-finding hash, so identity is the position",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("GRYPE_",),
                options_surface="typed options only; the tool's vulnerability database is not operator-replaceable through ASH",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 2),
                semantics="per the adapter's own comment at the success_exit_codes declaration",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=(),
                upstream_license=(
                    "Apache-2.0 (source: utils/tool_downloads.py "
                    "THIRD_PARTY_LICENSES['grype'], pinned commit 8f3dded)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note=(
                    "a directory, or a container image (a reference needs an "
                    "engine or the registry, a saved archive or OCI layout "
                    "needs neither); no SBOM document input is wired"
                ),
            ),
        )
    )

    check_conf: str = "NOT_PROVIDED"
    # Env vars to layer onto the subprocess. Populated by
    # _process_config_options (e.g. offline-mode flags). Kept local to the
    # scanner instance so concurrent scanners don't race on os.environ.
    extra_env: Annotated[dict, Field(default_factory=dict)]

    def model_post_init(self, context):
        if self.config is None:
            self.config = GrypeScannerConfig()
        self.command = "grype"
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--file",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "GrypeScanner":
        """Set up custom installation commands for grype.

        grype had no install path inside ASH at all before this. It was one of
        three scanners (with syft and trivy) that could only arrive from the
        container image, a package manager or the nix toolchain -- so a
        ``python-local`` run on a machine without it scanned without it, reported
        the scanner as not having run, and still exited 0.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("grype"))
        return self

    def validate_plugin_dependencies(self) -> bool:
        """The base check, then grype's own warning when the binary is simply absent.

        ``ScannerPluginBase.validate_plugin_dependencies`` reads a recorded
        ``dependency_unavailable_reason`` first (a construction-time refusal is not
        outvoted by a PATH probe), then probes PATH, and records the in-tree
        refusal when the only copy found sits inside the scanned tree, so the
        MISSING row says so rather than "not installed". This override used to
        probe PATH itself and skip both, so a recorded reason was ignored. The
        warning is kept for the case the base leaves unworded: no binary, no
        reason.
        """
        if super().validate_plugin_dependencies():
            return True
        if not self.dependency_unavailable_reason:
            ASH_LOGGER.warning(
                "Grype executable not found in PATH. Please ensure grype is installed."
            )
        return False

    @staticmethod
    def _strip_leading_slash_from_uri(location, root: Path) -> None:
        """Strip leading slashes from the artifact location URI, if present, and
        read a name grype could not spell back from the directory."""
        if (
            location.physicalLocation
            and location.physicalLocation.root
            and location.physicalLocation.root.artifactLocation
        ):
            uri = location.physicalLocation.root.artifactLocation.uri
            if uri:
                location.physicalLocation.root.artifactLocation.uri = (
                    _name_grype_garbled(root, uri.lstrip("/"))
                )

    def _normalize_result_uris(self, result, root: Path) -> None:
        """Strip leading slashes from all URIs in a single SARIF result."""
        try:
            for loc in result.locations or []:
                self._strip_leading_slash_from_uri(loc, root)

            for rel in getattr(result, "relatedLocations", None) or []:
                self._strip_leading_slash_from_uri(rel, root)

            if result.analysisTarget and result.analysisTarget.uri:
                result.analysisTarget.uri = _name_grype_garbled(
                    root, result.analysisTarget.uri.lstrip("/")
                )
        except Exception as e:
            ASH_LOGGER.warning(f"Error processing Grype result: {e}")

    @staticmethod
    def _output_restricting_keys(config_path: Path | str) -> List[str]:
        """Which keys in the grype config at *config_path* drop matches.

        Returns the matching key names sorted, and an empty list when the file
        removes nothing, cannot be read, or is not a YAML mapping.

        Deliberately does not raise. grype owns the verdict on its own config
        file, and turning a document ASH merely passes through into an ASH-side
        failure would replace grype's precise parse error with a worse one, on a
        scan grype itself might have run.

        A key present with a falsy value is not reported: ``only-fixed: false``
        is the documented default written out, and warning about it would train a
        reader to ignore the warning. Keys are read case-insensitively, as grype
        reads them (``OUTPUT_RESTRICTING_GRYPE_KEYS``).

        A file that cannot be decoded (not UTF-8: a ``UnicodeDecodeError`` is a
        ``ValueError``), or that PyYAML refuses with a ``ValueError`` of its own,
        is unreadable like one that cannot be opened, and reports nothing.

        Args:
            config_path: The grype config file ASH is about to pass as
                ``--config``.

        Returns:
            Sorted names of the keys that restrict grype's output.
        """
        document = GrypeScanner._read_config(config_path)
        if not isinstance(document, dict):
            return []
        lowered = _lowercase_keys(document)
        return sorted(key for key in OUTPUT_RESTRICTING_GRYPE_KEYS if lowered.get(key))

    @staticmethod
    def _read_config(config_path: Path | str) -> Any:
        """The parsed grype config at *config_path*, or None when it cannot be read.

        Never raises: grype owns the judgment of its own config file (see
        ``_output_restricting_keys``), and a raise here would leave the scanner's
        construction, which runs this, for a file ASH only passes through.
        """
        try:
            with open(config_path, "r", encoding="utf-8") as config_file:
                return yaml.safe_load(config_file)
        except (OSError, ValueError, yaml.YAMLError):
            return None

    def _warn_if_config_moves_the_database(
        self,
        config_path: Path,
        values: Iterable[str] = (),
        shown: Optional[Path] = None,
    ) -> None:
        """Say so when the grype config sets ``db.cache-dir``, which ASH overrides.

        The scan reads the database from ``default_cache_dir("grype")``, passed as
        ``GRYPE_DB_CACHE_DIR``, so the refresh and the staleness check read the same
        one; that variable beats the config file. Never raises, like
        ``_output_restricting_keys``. The path is redacted with *values*, the
        config's environment values, as the sibling restricting-keys warning is: a
        configured option can come from the environment. The file is read at
        *config_path*; the warning names it as *shown*, the configured spelling
        (default: *config_path*), because redaction finds only that spelling.
        """
        document = self._read_config(config_path)
        db = _lowercase_keys(_lowercase_keys(document).get("db"))
        if db.get("cache-dir"):
            self._plugin_log(
                text_without_values(
                    f"The grype config at {shown or config_path} sets db.cache-dir, which ASH "
                    "does not use: grype reads its database from the directory ASH "
                    "refreshes and checks the age of. Set GRYPE_DB_CACHE_DIR to move "
                    "it.",
                    values,
                ),
                level=logging.WARNING,
            )

    def _use_empty_config(self) -> None:
        """Hand grype an empty config file ASH writes.

        Given no ``--config``, grype runs from the source directory and reads
        ``.grype.yaml`` from it, which would put the repository's file where the
        operator's refused or missing one was. An explicit ``--config`` ends
        the discovery.
        """
        self.args.extra_args.append(
            ToolExtraArg(
                key="--config",
                value=self._neutral_tool_file("grype-config-empty.yaml", "{}\n"),
            )
        )

    def _process_config_options(self) -> None:
        # Grype config path
        # Only the operator's config file. A config file inside the scanned tree
        # does not choose it (config/tool_config_trust.py), and ASH no longer looks
        # for .grype.yaml or .grype/config.yaml by name: their ignore and
        # only-fixed would let the repository decide what its scan reports. With
        # none, the scan passes grype an empty one (_execute_scan), so grype does
        # not read one from its working directory on its own.
        # A blank value names no file: Path("") joined to the source directory is
        # the source directory itself, which exists, so grype would be handed
        # --config <source_dir> and fail. Blank reads as unset.
        possible_config_paths = [
            item
            for item in [self.config.options.config_file]
            if item is not None and str(item).strip()
        ]

        # Resolve config candidates against source_dir, not the process working
        # directory, and hand grype an absolute path. Same fix, same reason, as
        # checkov_scanner._process_config_options.
        #
        # The subprocess runs with cwd=context.source_dir (see
        # PluginBase._run_subprocess), so probing with a bare Path(...).exists()
        # asked a different question than the one grype would answer: it tested the
        # directory ASH happens to be invoked from. Scanning ASH's own checkout,
        # the probe matched the tracked ".ash/.grype.yaml" and passed it through
        # get_shortest_name, which relativises against the process cwd. grype then
        # exited 1 in under 100ms with "invalid application config: file does not
        # exist: .ash/.grype.yaml", producing no SARIF -- so the scanner reported
        # EXECUTION FAILED with zero findings while grype itself was fine.
        source_dir = Path(self.context.source_dir)
        # The config's environment values, each also as Path() spells it: the
        # lines below name the config through Path().
        environment_values = _with_path_spellings(self._environment_values())
        resolved_config: Path | None = None
        # The path as configured, for anything that NAMES the config: a symlink
        # in the configured path changes the resolved spelling, and redaction
        # can only find the spelling the config (and _environment_values) carry.
        configured_config: Path | None = None
        # The operator's config as the database refresh may read it: set below
        # only for an accepted config that lies outside the scanned tree. The
        # refresh runs outside the sandbox (utils/content_db_refresh.py,
        # "Isolation"), so a file the scanned repository could have written is
        # never handed to it; such a config still reaches the scan.
        self._content_db_operator_config = None
        # A config the scan derived from the repository being scanned (under
        # the output or work directory) is not handed to grype unless the
        # operator's own configuration names it; see config/path_trust.py. The
        # checkout's own in-tree configs stay accepted as before, so only the
        # derived-directory clause applies here. A refused configured value
        # drops the ``--config`` rather than falling through to discovery: the
        # option named one file, and discovery would silently replace it.
        from automated_security_helper.config.operator_only_options import (
            operator_wrote_value,
        )
        from automated_security_helper.config.path_trust import (
            derived_roots,
            in_scanned_tree,
            refused_derived_product,
            resolved_path,
        )

        context_config = getattr(self.context, "config", None)
        for index, conf_path in enumerate(possible_config_paths):
            configured = index == 0 and self.config.options.config_file is not None
            # As grype will read it: "~" expanded, a relative path taken from the
            # source directory, symlinks resolved (path_trust.resolved_path, the
            # resolution refused_derived_product checks). Joining the value as
            # written under the source directory read a "~/..." path as a file
            # below the scanned tree: the operator's home config was judged
            # missing and an empty one passed, or a same-named file the
            # repository planted at <source>/~/... was handed to grype.
            candidate = resolved_path(conf_path, source_dir)
            # os.path.exists, not Path.exists: under a directory this process
            # cannot search, Path.exists raises PermissionError on Python
            # 3.10-3.13, out of the scanner's construction; os.path.exists
            # answers False on any OSError, which takes the missing-file path.
            if os.path.exists(candidate):
                if refused_derived_product(
                    candidate,
                    source_dir=source_dir,
                    key="scanners.grype.options.config_file"
                    if configured
                    else f"grype config file {conf_path}",
                    config=context_config,
                    derived_dirs=derived_roots(self.context),
                    operator_written=configured
                    and operator_wrote_value(
                        context_config,
                        "scanner",
                        "grype",
                        ("options", "config_file"),
                        conf_path,
                        config_from_context=self._config_from_context,
                    ),
                ):
                    if configured:
                        self._use_empty_config()
                        ASH_LOGGER.warning(
                            "Configured grype config file was not used because "
                            "it is a work product derived from the scanned "
                            "repository. Grype will run with an empty config "
                            "file that ASH writes; no config file is "
                            "discovered from the scanned tree in its place."
                        )
                        break
                    continue
                # Say so when the config narrows the report. Without this the
                # only record that matches were withheld is the config file
                # itself, which nobody reads while looking at a clean scan.
                restricting_keys = self._output_restricting_keys(candidate)
                if restricting_keys:
                    # Redacted: the config path is configured, and a configured
                    # option can come from the environment. Named as configured,
                    # not as resolved: redaction finds only the configured
                    # spelling, and the resolved path of "~/..." or a symlink is
                    # another string.
                    self._plugin_log(
                        text_without_values(
                            f"The grype config at {Path(conf_path)} sets "
                            f"{', '.join(restricting_keys)}, which restricts which "
                            "matches reach the report. Vulnerabilities grype detected "
                            "may be absent from these results, and the scan can pass "
                            "with findings withheld.",
                            environment_values,
                        ),
                        level=logging.WARNING,
                    )
                self._warn_if_config_moves_the_database(
                    candidate, environment_values, shown=Path(conf_path)
                )
                resolved_config = candidate
                configured_config = Path(conf_path)
                # A database mirror or CA the operator's config names applies to
                # the update as it does to the scan, when the file is the
                # operator's own and outside the scanned tree. One inside it
                # (the checkout's own grype config, accepted for the scan) is
                # not: the update runs unsandboxed and reads what the config
                # says, so it keeps the empty config ASH writes.
                if in_scanned_tree(candidate, source_dir):
                    ASH_LOGGER.debug(
                        "The grype config is inside the scanned tree, so the "
                        "database update runs with an empty config instead of it"
                    )
                else:
                    self._content_db_operator_config = candidate
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config",
                        value=resolved_config.as_posix(),
                    )
                )
                break
            elif configured:
                # A configured file that does not exist takes no discovered
                # replacement (config/path_trust.py, "Configured tool inputs
                # that are refused or missing").
                self._use_empty_config()
                ASH_LOGGER.warning(
                    text_without_values(
                        f"Configured grype config file does not exist: "
                        f"{self.config.options.config_file}. Grype will run "
                        "with an empty config file that ASH writes; no config "
                        "file is discovered from the scanned tree in its place.",
                        environment_values,
                    )
                )
                break

        # Online, the database's age bound is DECLARED rather than inherited: the
        # value comes from utils/content_databases.py, the same entry the CI cache
        # key and its freshness guard are computed from, so the cache window and
        # the bound grype enforces are one number. It equals grype's own default
        # today (the registry cites where), so this changes no verdict; it makes
        # the equality something a test can hold rather than a coincidence.
        #
        # An explicit choice still wins. A user who exported one of these, or
        # set `db.max-allowed-built-age` / `db.validate-age` in the grype config
        # ASH passes above, asked for that bound; grype puts the environment
        # above the config file, so setting the variable here regardless would
        # silently override their file.
        offline = self._scanner_offline()
        if not offline:
            self.extra_env.update(
                _declared_grype_db_bound(
                    snapshot_environ(),
                    resolved_config,
                    environment_values,
                    shown=configured_config,
                )
            )

        # Handle offline mode. Stash offline-mode env vars on the instance
        # rather than writing to os.environ — scanners run concurrently
        # in thread pools and would race on the shared parent env.
        #
        # GRYPE_DB_VALIDATE_AGE=false stays: with it true, grype answers a stale
        # database by trying to download a new one, which an air-gapped host
        # cannot do. The bound is held instead by ASH's own check after the scan
        # (utils/content_db_staleness.py), which reads `built` from
        # `grype db status` the same way online and offline, and fails the scan
        # by default once the database is past the registry's bound.
        if offline:
            self.extra_env.update(
                {
                    "GRYPE_DB_VALIDATE_AGE": "false",
                    "GRYPE_DB_AUTO_UPDATE": "false",
                    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                }
            )

            self._check_offline_cache()

            ASH_LOGGER.info(
                "Running Grype in offline mode - database updates and validation disabled"
            )

        return super()._process_config_options()

    def _check_offline_cache(self) -> None:
        """Offline: look at the cache the scan will read, before the scan.

        ``utils/offline_mode_validator.validate_grype_offline_mode`` judges the
        cache ``GRYPE_DB_CACHE_DIR`` names and nothing else, so with the variable
        unset it reported "GRYPE_DB_CACHE_DIR environment variable not set" about
        every offline scan, including one whose default cache
        (``default_cache_dir("grype")``, the XDG or platform directory the scan is
        pointed at in ``_execute_scan``) holds a current database. The validator
        runs only when the variable is set, where it reads the right directory;
        otherwise the resolved default cache is checked for existence here, with the
        directory named. The authoritative check stays the post-scan staleness
        check (``utils/content_db_staleness.py``).
        """
        if snapshot_environ().get("GRYPE_DB_CACHE_DIR"):
            from automated_security_helper.utils.offline_mode_validator import (
                validate_grype_offline_mode,
            )

            offline_valid, offline_messages = validate_grype_offline_mode()
            if not offline_valid:
                for msg in offline_messages:
                    self._plugin_log(msg, level=logging.WARNING)
            return
        cache = default_cache_dir("grype", snapshot_environ())
        # os.path.isdir, not Path.is_dir: under a directory this process cannot
        # search, Path.is_dir raises PermissionError on Python 3.10-3.13, out of
        # the scanner's construction, where os.path.isdir answers False.
        if not os.path.isdir(cache):
            self._plugin_log(
                f"Grype offline mode: the database directory {cache.as_posix()} "
                "does not exist, so grype has no vulnerability database to read. "
                "Download one with network access, or set GRYPE_DB_CACHE_DIR to a "
                "cache that holds one.",
                level=logging.WARNING,
            )
        elif not _holds_a_database(cache):
            self._plugin_log(
                f"Grype offline mode: the database directory {cache.as_posix()} "
                "holds no vulnerability database (no <schema version>/"
                "vulnerability.db under it), so grype has none to read. "
                "Download one with network access, or set GRYPE_DB_CACHE_DIR to a "
                "cache that holds one.",
                level=logging.WARNING,
            )

    # Grype exits with 2 when vulnerabilities are found above threshold,
    # not 1 like most scanners. Override the template-method default.
    success_exit_codes: ClassVar[set] = {0, 2}

    def _execute_scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        """Resolve final argv, results path, and subprocess env for Grype."""
        # Absolute, as the syft scanner does: grype runs with the scanned source
        # as its working directory (PluginBase._run_subprocess), so a relative
        # output directory (``ash --output-dir out``) would put results_sarif.sarif
        # under the scanned tree, where the scan reads it as source and the
        # results file ASH then opens does not exist.
        target_results_dir = Path(os.path.abspath(self.results_dir)).joinpath(
            target_type
        )
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # The target too: a relative one would be read from grype's working
        # directory, the scanned source, not from where ASH was given it.
        scanned = Path(os.path.abspath(target))
        # Each link leaving the target, and each path the global ignore paths
        # ignore, for this resolution only (extra_args persists across scan()
        # calls, and the next target has links of its own). grype follows none of
        # the links; see utils/link_exclusions.py. A new list: the one extra_args
        # holds is put back as it was, unchanged, whatever raises between the swap
        # and the resolution (writing the empty config included), so the next
        # target never inherits this target's --exclude values.
        original_extra_args = self.args.extra_args
        try:
            self.args.extra_args = [
                *original_extra_args,
                *(
                    ToolExtraArg(key="--exclude", value=pattern)
                    for pattern in syft_excludes(
                        target, self.context.source_dir, global_ignore_paths
                    )
                ),
            ]
            if not any(arg.key == "--config" for arg in self.args.extra_args):
                empty = empty_tool_config(
                    "grype-empty.yaml", "{}\n", context=self.context
                )
                self.args.extra_args.append(
                    ToolExtraArg(key="--config", value=empty.as_posix())
                )
            final_args = self._resolve_arguments(
                # Grype expects directory scans to have the target begin with `dir:`
                target=f"dir:{scanned.as_posix()}",
                results_file=results_file,
            )
        finally:
            self.args.extra_args = original_extra_args
        scan_env = {**snapshot_environ(), **self.extra_env}
        # The database's directory, resolved once as grype resolves it on this host
        # and named to the scan, the refresh and the staleness check alike: the
        # sandbox drops XDG_CACHE_HOME, and GRYPE_DB_CACHE_DIR beats a db.cache-dir
        # in any grype config, the scanned repository's included. See "Which
        # cache" in utils/content_db_refresh.py.
        cache = default_cache_dir("grype", scan_env)
        scan_env["GRYPE_DB_CACHE_DIR"] = cache.as_posix()
        self._content_db_cache_dir = cache
        if sandboxed_online(self._scanner_offline()):
            # The sandbox mounts grype's cache read-only, so its database is updated
            # first, outside the sandbox, and grype only reads it. See
            # utils/content_db_refresh.py.
            prepare_content_db(
                "grype",
                cache,
                offline=False,
                source_dir=self.context.source_dir,
                results_dir=self.results_dir or results_file.parent,
                config=getattr(self.context, "config", None),
                scan_id=scan_id_for(self.context),
                # The operator's config, outside the scanned tree, when there is
                # one (_process_config_options): its database settings reach the
                # update as they reach the scan. None keeps the empty config.
                config_file=getattr(self, "_content_db_operator_config", None),
                values=self._values_to_redact(),
            )
            scan_env.update(GRYPE_PREPARED_ENV)
        return final_args, results_file, scan_env

    def _execute_image_scan(self, image):
        """Resolve argv, results path and env for a container-image scan.

        The dir: scan's resolution with the image differences and nothing
        else: the target is a stereoscope string built from the locator and
        the detected engine (utils/image_tool_targets.py: a payload needs no
        engine; a reference prefers the daemon's content store, else the
        tool's own registry client), the ``--exclude`` patterns are the
        IMAGE's ignore paths (absolute in-image globs; nothing of the source
        tree is scanned, so no source-tree exclude applies), and the empty
        config and the database cache are exactly the dir: scan's, so the
        offline database posture carries over unchanged.
        """
        from automated_security_helper.utils.image_tool_targets import (
            stereoscope_target,
        )

        engine = self._image_engine
        engine_socket = self._image_engine_socket
        if engine is None:
            # A direct call outside scan_image (a test driving this hook
            # alone); the template detects once per target otherwise.
            from automated_security_helper.core.container_engine import (
                detect_engine_socket,
            )

            engine, engine_socket = detect_engine_socket()

        target_results_dir = Path(os.path.abspath(self.results_dir)).joinpath("image")
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)

        original_extra_args = self.args.extra_args
        try:
            self.args.extra_args = list(original_extra_args)
            if not any(arg.key == "--config" for arg in self.args.extra_args):
                empty = empty_tool_config(
                    "grype-empty.yaml", "{}\n", context=self.context
                )
                self.args.extra_args.append(
                    ToolExtraArg(key="--config", value=empty.as_posix())
                )
            # The ignore paths grype can be told to leave uncataloged (measured
            # on grype 0.122.1: an absolute in-image glob is honored on an
            # image source; utils/image_ignore_paths).
            self.args.extra_args.extend(
                ToolExtraArg(key="--exclude", value=glob)
                for glob in self._image_exclude_globs()
            )
            final_args = self._resolve_arguments(
                target=stereoscope_target(
                    image,
                    engine=engine,
                    # Declared in the environment with no local socket: the
                    # schemeless target keeps stereoscope's source fallback.
                    # Only read when the engine is docker or podman, so the
                    # always-socketless NONE case is unaffected.
                    remote_daemon=engine_socket is None,
                ),
                results_file=results_file,
            )
        finally:
            self.args.extra_args = original_extra_args

        scan_env = {**snapshot_environ(), **self.extra_env}
        cache = default_cache_dir("grype", scan_env)
        scan_env["GRYPE_DB_CACHE_DIR"] = cache.as_posix()
        self._content_db_cache_dir = cache
        if sandboxed_online(self._scanner_offline()):
            prepare_content_db(
                "grype",
                cache,
                offline=False,
                source_dir=self.context.source_dir,
                results_dir=self.results_dir or results_file.parent,
                config=getattr(self.context, "config", None),
                scan_id=scan_id_for(self.context),
                config_file=getattr(self, "_content_db_operator_config", None),
                values=self._values_to_redact(),
            )
            scan_env.update(GRYPE_PREPARED_ENV)
        return final_args, results_file, scan_env

    def _invocation_extras(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> dict:
        """Attach the run's tool to the invocation's properties bag."""
        if not sarif_report.runs:
            return {}
        return {"properties": PropertyBag(tool=sarif_report.runs[0].tool)}

    def _resolve_arguments(
        self, target: str | Path, results_file: str | Path | None = None
    ) -> List[str]:
        """The base arguments plus an ``--exclude`` per ASH output directory.

        Added for this resolution only: the patterns depend on the target, and
        extra_args persists across scan() calls. *target* is the ``dir:`` source
        _execute_scan builds. A new list: the one extra_args holds is put back as
        it was, unchanged.
        """
        from automated_security_helper.utils.scan_output_dirs import (
            output_dir_exclude_globs,
        )

        if self._image_scan_in_progress:
            # An image target is a stereoscope string, not a dir: source, and
            # nothing of the host tree is scanned: no output directory can be
            # inside the image, so no --exclude patterns are built.
            return super()._resolve_arguments(target=target, results_file=results_file)

        directory = str(target).removeprefix("dir:")
        original_extra_args = self.args.extra_args
        self.args.extra_args = [
            *original_extra_args,
            *(
                ToolExtraArg(key="--exclude", value=pattern)
                for pattern in output_dir_exclude_globs(
                    self._ash_output_dirs_inside(Path(directory))
                )
            ),
        ]
        try:
            return super()._resolve_arguments(target=target, results_file=results_file)
        finally:
            self.args.extra_args = original_extra_args

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Strip leading slashes from artifact URIs and attach package identity.

        The HOST-TREE steps are skipped for an image scan: an in-image path
        stays as grype wrote it (absolute; no host root may rebase it), and
        joining image packages to the HOST's lockfiles would attribute a copy
        the image does not hold. The package NAME and VERSION are not
        host-tree work -- they come from grype's own result message, which has
        the same shape for an image -- so they are attached for images too
        (``correlation_id_for`` builds the ``dep/`` key from them, which is
        how a grype image finding correlates with trivy's on the same CVE,
        and package-scoped suppressions match on them). Only the lockfile
        join, which yields ``package_path``, is skipped. ``fix_available`` is
        read from the report itself and holds for images too.

        The in-progress flag is read with a default: the facets corpus
        harness replays captured reports through ``cls.__new__(cls)``
        skeletons, which have no pydantic private state, and a skeleton is
        never mid-image-scan.
        """
        in_image = bool(getattr(self, "_image_scan_in_progress", False))
        lock_index = None if in_image else NpmLockIndex(target)
        for run in sarif_report.runs or []:
            fixes = _rule_fix_statements(run)
            for result in run.results or []:
                if not in_image:
                    self._normalize_result_uris(result, target)
                self._attach_package_identity(result, lock_index)
                self._attach_fix_available(result, run, fixes)
        return sarif_report

    @staticmethod
    def _attach_fix_available(
        result, run, fixes: Mapping[str, tuple[str, str, str]]
    ) -> None:
        """Record ``fix_available = True`` for a result grype says has a fix.

        grype's presenter writes the vulnerability's native ``fix.versions`` into
        the rule's help text as ``Fix Version: <versions>``, one rule per
        (vulnerability, package) pair; ``fixes`` holds each uniquely named rule's
        statement (see ``_rule_fix_statements``). Only a non-empty list is
        written, and only as True: an empty ``Fix Version:`` is what grype writes
        for every non-``fixed`` state (``not-fixed``, ``wont-fix``, ``unknown``),
        so it cannot say that no fix exists and nothing is attached.

        The result must match its rule, or nothing is attached: the rule is the
        one the result's ``ruleId`` names, any ``ruleIndex`` points at that same
        rule, and the package and version the rule's help names are the ones the
        result's own message names. grype keys a rule by vulnerability and
        package name alone, so a second copy of the package at another version
        shares the rule and would carry the first copy's statement.
        """
        rule_id = result.ruleId
        statement = fixes.get(rule_id) if rule_id else None
        if statement is None:
            return
        index = result.ruleIndex
        if index is not None and index >= 0:
            rules = run.tool.driver.rules or []
            if index >= len(rules) or rules[index].id != rule_id:
                return
        message = result.message.root.text if result.message else None
        match = _GRYPE_PACKAGE_MESSAGE.search(message or "")
        if not match:
            return
        name, version, fix_versions = statement
        if (name, version) != (match.group("name"), match.group("version")):
            return
        if not fix_versions:
            return
        if result.properties is None:
            result.properties = PropertyBag(fix_available=True)
        else:
            setattr(result.properties, "fix_available", True)

    @staticmethod
    def _attach_package_identity(result, lock_index: Optional[NpmLockIndex]) -> None:
        """Record which package copy a grype result is about.

        grype's SARIF puts every dependency finding at line 1 of the manifest,
        and its rule's ``purls`` list is per rule, not per result, so the only
        per-result statement of the package is the message grype writes:
        ``A <sev> vulnerability in <type> package: <name>, version <version>
        was found at: <path>``. When the message has another shape nothing is
        attached, and a package-scoped suppression will not match the result.

        For an npm lockfile the name and version are looked up among the
        lockfile's entries; exactly one match gives ``package_path``. Two or
        more (the same version installed at two places) give no path, because
        grype's output does not say which copy it found. An image scan passes
        ``lock_index=None``: the name and version still attach, and no host
        lockfile is consulted for a path.
        """
        message = result.message.root.text if result.message else None
        match = _GRYPE_PACKAGE_MESSAGE.search(message or "")
        if not match:
            return
        name, version = match.group("name"), match.group("version")

        path = None
        uri = None
        if result.locations:
            physical = result.locations[0].physicalLocation
            if physical and physical.root and physical.root.artifactLocation:
                uri = physical.root.artifactLocation.uri
        # grype's URI is not scan-root-relative on Windows: it is the scan root
        # followed by a backslashed relative path, "D:/a/r/r/\\deploy\\cdk\\...".
        # sanitize_sarif_paths fixes the location later, but package_path is
        # built here, so the lockfile is relativized here too. None (outside
        # the scan root, or an image scan with no lockfile index) claims no path.
        lock_rel = (
            lock_index.relative(uri) if (lock_index is not None and uri) else None
        )
        if lock_rel:
            entry = lock_index.unique_by_name_version(lock_rel, name, version)
            if entry is not None:
                path = install_path(lock_rel, entry.key)

        identity = identity_properties(name, version, path)
        if result.properties is None:
            result.properties = PropertyBag(**identity)
        else:
            for key, value in identity.items():
                setattr(result.properties, key, value)
