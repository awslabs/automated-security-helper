"""Module containing the Syft security scanner implementation."""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Set

from pydantic import Field, PrivateAttr, ValidationError, model_validator
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.models.vocab import TargetType
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
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
from automated_security_helper.base.uv_tool_mixin import guarded_values_read
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.config.path_trust import (
    cwd_outside_scanned_tree,
    honored_path,
    resolved_path,
)
from automated_security_helper.utils.link_exclusions import syft_excludes
from automated_security_helper.utils.error_text import (
    text_without_values,
    traceback_text,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.redacted_model import RedactedSection
from automated_security_helper.utils.suppression_matcher import active_ignore_paths

#: The CycloneDX version syft is asked to write. Without ``@<version>`` syft writes
#: the latest it supports, which moves with syft (its formats guide lists 1.2 to 1.7),
#: while ``CycloneDXReport`` models version 1.6 and refuses any field outside it, so
#: a syft that moved on would have every SBOM refused whole. See
#: ``schemas/cyclonedx_bom_1_6_schema``.
CYCLONEDX_SPEC_VERSION = "1.6"


class SdistHarvestOptions(RedactedSection):
    """Options for the cross-toolchain sdist lockfile harvest.

    The harvest itself runs in the convert phase (the ``sdist-lock-harvester``
    converter), because the syft subprocess's declared sandbox allows it no
    network and the harvested lockfiles must sit where grype and trivy also
    read; the OPTIONS live here because this is the surface where the operator
    configures SBOM behavior. See ``utils/sdist_harvest.py`` for the mechanism.
    """

    enabled: Annotated[
        bool,
        Field(
            description="Harvest embedded lockfiles from the hash-pinned sdists of resolved dependencies whose wheels carry a platform tag (compiled native extensions with no artifact audit data), so the SBOM covers cross-toolchain packages such as a compiled wheel's statically linked Rust crates. On by default in online mode; inert in offline mode, where each skipped package is a visible informational record. The only network it adds is a GET of bytes the project's own lockfile already pins by sha256, verified before extraction; nothing fetched is executed.",
        ),
    ] = True
    ecosystems: Annotated[
        List[Literal["cargo", "gomod", "npm"]],
        Field(
            description="Which embedded lockfiles are harvested from a pinned sdist: cargo reads Cargo.lock, gomod reads go.sum, npm reads package-lock.json. The vocabulary is the GitLab CycloneDX reporter's existing ecosystem mapping.",
        ),
    ] = ["cargo", "gomod", "npm"]
    max_sdist_mb: Annotated[
        int,
        Field(
            gt=0,
            description="The largest sdist, in megabytes, the harvest will fetch. Checked against the lockfile's own recorded size before any fetch, and enforced on the bytes actually streamed during it: a transfer that passes the bound is aborted on the wire, so a lying size claim cannot buy an unbounded download. Either way the package is skipped with an informational record rather than stalling the scan.",
        ),
    ] = 100
    cache_dir: Annotated[
        Path | str | None,
        Field(
            description="Where verified harvests are cached, keyed by each sdist's sha256 and with each cached file's digest recorded and re-verified before it is served, so an entry can never serve different bytes than the lock pins; a warmed cache serves entries offline with no network. Defaults to ash/sdist-harvest under the user-level cache directory (XDG_CACHE_HOME, or ~/.cache), never a directory under the scanned tree, whose content the scanned repository could ship."
            f" {SET_BY_THE_OPERATOR}",
        ),
    ] = None
    lockfiles: Annotated[
        List[Literal["uv.lock"]],
        Field(
            description="The Python lockfiles walked for resolved packages to flag. uv.lock only today: it pins each sdist by URL and sha256, which is what authorizes a fetch. The list exists so other hash-and-URL-pinned formats can be added without a schema change.",
        ),
    ] = ["uv.lock"]


class SyftScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Syft configuration file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory."
            f" {SET_BY_THE_OPERATOR}"
            " ASH does not look for one by name. Without one, syft gets an empty config, so it does not read `.syft.yaml` from the scanned tree.",
        ),
    ] = None
    exclude: Annotated[
        List[IgnorePathWithReason],
        Field(
            description='Paths (files or directories) to skip, each a glob relative to the scanned directory and passed to syft as one --exclude. A glob must start with "./", "*/" or "**/", and syft fails the scan on any other. "*" does not match across "/" and "**" does: "./dir1/**" skips the top-level "dir1", and "**/dir1/**" skips every directory named "dir1".',
        ),
    ] = []
    additional_outputs: Annotated[
        List[
            Literal[
                "cyclonedx-json",
                "cyclonedx-xml",
                "github-json",
                "spdx-json",
                "spdx-tag-value",
                "syft-json",
                "syft-table",
                "syft-text",
                # "template",
            ]
        ],
        Field(
            description="List of additional formats to output. Defaults to syft-table."
        ),
    ] = ["syft-table"]
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, disabling update checks. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]
    sdist_harvest: Annotated[
        SdistHarvestOptions,
        Field(
            description="Configure the cross-toolchain sdist lockfile harvest, which completes the SBOM for compiled dependencies whose artifacts carry no audit data. The harvest runs in the convert phase; offline mode disables its fetches whatever these options say.",
        ),
    ] = SdistHarvestOptions()


class SyftScannerConfig(ScannerPluginConfigBase):
    name: Literal["syft"] = "syft"
    enabled: bool = True
    options: Annotated[
        SyftScannerConfigOptions, Field(description="Configure Syft scanner")
    ] = SyftScannerConfigOptions()  # type: ignore[call-arg]


@ash_scanner_plugin
class SyftScanner(ScannerPluginBase[SyftScannerConfig]):
    """SyftScanner implements IaC scanning using Syft."""

    display_name = "Syft"
    docs_summary = "Software inventory"
    covers = ("SBOM generation",)

    #: syft is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        cache_paths=("~/.cache/syft",),
        env_prefixes=("SYFT_",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    #: The facets register row (base/scanner_facets.py). Declaration only.
    #: syft is an SBOM generator: it returns a CycloneDXReport and writes no
    #: SARIF Result at all, so no finding facet exists. The component
    #: inventory is the package identity, carried in the CycloneDX document
    #: outside the flat-vulnerability path. Every other cell is n/a because
    #: there are no findings to carry it.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no rule id",
        ),
        severity=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no severity",
        ),
        file_path=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist; component locations are "
            "inventory evidence, not a finding location",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no line range",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no column",
        ),
        message=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no message",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="no findings exist; the SBOM names packages (package "
            "identity), not infrastructure resources, and writes no "
            "ash_resource_id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="no findings exist; component types (library, "
            "application) are package kinds, not resource types",
        ),
        package_name=FacetDecl(
            state=FacetState.DROPPED,
            native_field="CycloneDX components[].name",
            reason="carried in the CycloneDX document the scanner returns, "
            "outside the flat-vulnerability path: syft writes no SARIF "
            "result, so no flat row ever holds it",
        ),
        package_version=FacetDecl(
            state=FacetState.DROPPED,
            native_field="CycloneDX components[].version",
            reason="carried in the CycloneDX document the scanner returns, "
            "outside the flat-vulnerability path: syft writes no SARIF "
            "result, so no flat row ever holds it",
        ),
        package_path=FacetDecl(
            state=FacetState.UNCONFIRMED,
            reason="UNCONFIRMED: syft's native artifacts[].locations[].path "
            "(fixture syft.src.json) has a CycloneDX counterpart this "
            "adapter has not been read against; a cyclonedx-json run "
            "settles it",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: inventory only, no vulnerability matching",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: inventory only, no vulnerability matching",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist to fingerprint",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no vulnerabilities, so no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no remediation",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no snippet",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no references",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no tags",
        ),
        extras=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no SARIF property bag; the CycloneDX "
            "document is passed through whole outside the flat path",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="syft",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.TOOL_UPDATES_ONLY,
                # An IMAGE scan by reference pulls manifests and layers (the
                # engine's store where one is present, else syft's own
                # registry client) -- network use this row owns in its source
                # text below. Not Fetched.IMAGE_DIGEST: syft reports no
                # findings, so no id keys on the digest ladder and the scan
                # phase must not count syft as a reason to ask a registry.
                # The vocabulary has no member yet for the image pull itself
                # (grype's and trivy's rows carry the same gap); adding one to
                # all three rows together is the register owner's edit. A
                # reference is skipped offline (the base template's skip), so
                # offline_outcome stays UNCHANGED for what actually runs.
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.CACHE_FLAGS,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "syft_scanner.py offline_strategy and sandbox_requirements; "
                    "utils/content_databases.py SCANNERS_WITHOUT_CONTENT_DATABASE['syft']: "
                    "it catalogs packages and matches nothing against advisories; the "
                    "remote license, maven and vcpkg lookups are forced off by "
                    "OFFLINE_TOOL_ENVIRONMENT; scan_image with a reference pulls the "
                    "image through the engine or syft's own registry client"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.CYCLONEDX,),
                side_reports=(),
                non_finding_artifacts=("CycloneDXReport (the SBOM)",),
                consumed_by_deviation="no SARIF Result exists; the SBOM is consumed outside the flat findings path",
            ),
            targets=opsf.TargetsFacet(
                kinds=(
                    opsf.TargetKind.PACKAGE_INVENTORY,
                    opsf.TargetKind.CONTAINER_IMAGE,
                ),
                tool_type=ScannerToolType.SBOM,
                selection=(
                    "the whole directory, cataloged into an SBOM; a "
                    "container-image asset through a stereoscope target "
                    "(scan_image: oci-archive:/docker-archive: by the tar's "
                    "own format, oci-dir: for a layout, "
                    "docker:/podman:/registry: for a reference by the "
                    "detected engine), with the ignore paths as --exclude globs"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key="syft",
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_ALL,
                note="asset table lists all six platform/arch pairs",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NOT_APPLICABLE,
                note="an SBOM has no findings",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="syft produces an SBOM, not findings; there is nothing to silence",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.NOT_APPLICABLE,
                note="no findings to identify",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("SYFT_",),
                options_surface="typed options only; no rules surface",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="a completed run exits 0; syft installs no findings-found exit",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=(),
                upstream_license=(
                    "Apache-2.0 (source: utils/tool_downloads.py "
                    "THIRD_PARTY_LICENSES['syft'], pinned commit 1a72047)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note=(
                    "a directory; or a container image (a reference needs an "
                    "engine or the registry, a saved archive or OCI layout "
                    "needs neither)"
                ),
            ),
        )
    )

    # syft exits 0 for a completed run; cmd/syft/main.go runs clio, whose Run exits 1
    # on any error, and syft installs no other exit-code mapping. An SBOM has no
    # "findings found" code.
    success_exit_codes: ClassVar[Set[int]] = {0}

    # Env vars to layer onto the subprocess. Populated in model_post_init when
    # offline mode is active. Kept local to the scanner instance so concurrent
    # scanners don't race on os.environ.
    extra_env: Annotated[dict, Field(default_factory=dict)]

    # The config-file warnings already given: _process_config_options runs at
    # construction and again on every scan() (the ToolArgs rebuild there drops
    # what it added), and the same missing or refused file need be said once.
    _config_warnings_given: Set[str] = PrivateAttr(default_factory=set)

    def model_post_init(self, context):
        if self.config is None:
            self.config = SyftScannerConfig()
        self.command = "syft"
        self.tool_type = ScannerToolType.SBOM

        if self._scanner_offline():
            self.extra_env.update(
                {
                    "SYFT_CHECK_FOR_APP_UPDATE": "false",
                    "SYFT_LOG_QUIET": "true",
                }
            )
            ASH_LOGGER.info("Running Syft in offline mode - update checks disabled")

        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "SyftScanner":
        """Set up custom installation commands for Syft.

        Every platform previously mapped to an empty list, so the table looked
        populated while ``get_installation_commands`` returned nothing. syft had no
        install path at all: on a machine without it the scan ran without syft,
        reported syft as not having run, and still exited 0.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("syft"))
        return self

    def _use_empty_config(self) -> None:
        """Hand syft an empty config file ASH writes.

        Given no ``--config``, syft runs from the source directory and reads
        ``.syft.yaml`` from it, which would put the repository's file where the
        operator's refused or missing one was. An explicit ``--config`` ends
        the discovery.
        """
        self.args.extra_args.append(
            ToolExtraArg(
                key="--config",
                value=self._neutral_tool_file("syft-config-empty.yaml", "{}\n"),
            )
        )

    def _process_config_options(self):
        # Syft config path
        # Only the operator's config file. A config file inside the scanned tree
        # does not choose it (config/tool_config_trust.py), and ASH no longer looks
        # for .syft.yaml by name: its exclude would let the repository decide what
        # the SBOM lists. With none, scan() passes syft an empty one, so syft does
        # not read one from its working directory on its own.
        # A blank value names no file: Path("") joined to the source directory is
        # the source directory itself, which exists, so the probe below would read
        # it as a configured file (refused, with no refusal line to point at).
        # Blank reads as unset.
        possible_config_paths = [
            item
            for item in [self.config.options.config_file]
            if item is not None and str(item).strip()
        ]

        # Resolve config candidates against source_dir, not the process working
        # directory, and hand syft an absolute path. Same fix, same reason, as
        # checkov_scanner._process_config_options.
        #
        # The subprocess runs with cwd=context.source_dir (see
        # PluginBase._run_subprocess), so probing with a bare Path(...).exists()
        # asked a different question than the one syft would answer: it tested the
        # directory ASH happens to be invoked from, then passed the match through
        # get_shortest_name, which relativises against the process cwd.
        #
        # Latent here rather than observed, because this repository has no
        # .syft.yaml for the probe to find. It is the same defect grype hit -- and
        # fixing grype while leaving the identical probe here is how the bug comes
        # back the first time anyone adds a syft config.
        #
        # A config inside the scanned tree is never passed (see
        # config/path_trust.py), and syft runs from outside the tree so it does not
        # find one there itself (_working_directory): a .syft.yaml can turn on remote
        # license and package lookups, which contacted proxy.golang.org and
        # github.com in an offline scan, and change what is reported.
        source_dir = Path(self.context.source_dir)
        # A refused configured value drops the ``--config`` rather than falling
        # through to discovery: the option named one file, and discovery would
        # silently replace it. Whether a candidate may be used is honored_path's
        # call (config/path_trust.py), which weighs who named the path. Whether
        # the operator wrote the configured value is operator_wrote_value's
        # answer, as for checkov, bandit and grype: a work product the scan
        # derived from the repository reaches syft only when it is.
        from automated_security_helper.config.operator_only_options import (
            operator_wrote_value,
        )

        context_config = getattr(self.context, "config", None)
        for index, conf_path in enumerate(possible_config_paths):
            configured = index == 0 and self.config.options.config_file is not None
            # As syft will read it: "~" expanded, a relative path taken from the
            # source directory (path_trust.resolved_path, the resolution
            # honored_path checks). Joining the value as written under the
            # source directory read a "~/..." path as a file below the scanned
            # tree, so the operator's home config was judged missing and an
            # empty one passed in its place.
            candidate = resolved_path(conf_path, source_dir)
            # os.path.exists, not Path.exists: under a directory this process
            # cannot search, Path.exists raises PermissionError on Python
            # 3.10-3.13, out of the scanner's construction; os.path.exists
            # answers False on any OSError, which takes the missing-file path.
            if os.path.exists(candidate):
                honored = honored_path(
                    conf_path,
                    source_dir=source_dir,
                    config=context_config,
                    key="scanners.syft.options.config_file"
                    if configured
                    else f"syft config file {conf_path}",
                    operator_written=configured
                    and operator_wrote_value(
                        context_config,
                        "scanner",
                        "syft",
                        ("options", "config_file"),
                        conf_path,
                        config_from_context=self._config_from_context,
                    ),
                )
                if honored is None:
                    if configured:
                        # honored_path has logged why (inside the scanned tree,
                        # delivered by an MCP client, or a work product derived
                        # from the repository), but it logs each refusal once per
                        # process while this line is given once per scanner
                        # instance: in a long-lived process (the MCP server) a
                        # later scan's instance gives this line with that one
                        # long past. So this line names the key and the three
                        # reasons itself and does not point at another line.
                        self._use_empty_config()
                        self._warn_once(
                            "Configured syft config file was not used "
                            "(scanners.syft.options.config_file): it is inside "
                            "the scanned tree, was delivered by an MCP client, or "
                            "was derived from the repository, and the first scan "
                            "in this process to meet it logged which. Syft will "
                            "run with an empty config file that ASH writes; no "
                            "config file is discovered from the scanned tree in "
                            "its place."
                        )
                        break
                    continue
                self.args.extra_args.append(
                    ToolExtraArg(key="--config", value=honored.as_posix())
                )
                break
            elif configured:
                # A configured file that does not exist takes no discovered
                # replacement (config/path_trust.py, "Configured tool inputs
                # that are refused or missing").
                self._use_empty_config()
                self._warn_once(
                    text_without_values(
                        f"Configured syft config file does not exist: "
                        f"{self.config.options.config_file}. Syft will run "
                        "with an empty config file that ASH writes; no config "
                        "file is discovered from the scanned tree in its place.",
                        self._environment_values(),
                    )
                )
                break

        for item in active_ignore_paths(
            self.config.options.exclude, where="scanners.syft.options.exclude"
        ):
            # NO_MARKUP: the path and the reason are the config's text, and a
            # "[/" in either is a closing Rich tag that raises instead of printing.
            # Redacted: a configured value can come from the environment, and
            # ash.log keeps DEBUG lines under --debug.
            ASH_LOGGER.debug(
                text_without_values(
                    f"Path '{item.path}' excluded from {self.config.name} scan "
                    f"for reason: {item.reason}",
                    self._environment_values(),
                ),
                extra=NO_MARKUP,
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--exclude",
                    value=item.path,
                )
            )

        return super()._process_config_options()

    def _warn_once(self, message: str) -> None:
        """Log ``message`` as a warning the first time it is given, and not on the
        later ``_process_config_options`` runs that every ``scan()`` makes."""
        if message in self._config_warnings_given:
            return
        self._config_warnings_given.add(message)
        ASH_LOGGER.warning(message)

    def _base_path(self, target: Path) -> Path:
        """What syft gets as ``--base-path``: the source directory for a target
        inside it, else the target itself.

        syft reports paths relative to the base path and follows no link above
        it. The source target is the source directory. The converted target lives
        under the output directory, which is inside the source tree by default
        (``.ash/ash_output``) but is wherever ``--output-dir`` put it, and a base
        path that does not contain the scanned directory would make syft spell
        every path from a directory the scan is not under.
        """
        source_dir = Path(os.path.abspath(self.context.source_dir))
        scanned = Path(os.path.abspath(target))
        if scanned == source_dir or source_dir in scanned.parents:
            return source_dir
        return scanned

    def _working_directory(self, target: Path, results_dir: Path) -> Path:
        """A working directory outside the scanned tree, online and offline.

        syft reads ``.syft.yaml`` (and ``.syft/config.yaml``) from its working
        directory. See _process_config_options for why that matters.
        """
        return cwd_outside_scanned_tree(
            target,
            results_dir=results_dir,
            source_dir=self.context.source_dir,
            config=getattr(self.context, "config", None),
        )

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — SyftScanner overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: SyftScannerConfig | None = None,
    ) -> CycloneDXReport | bool:
        """Execute Syft scan and return results.

        Args:
            target: Path to scan

        Returns:
            CycloneDXReport: containing the SBOM findings and metadata.

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        # Per target; see ScannerPluginBase.scan(). The tool lines too, so a
        # failed converted-target run does not quote the source target's stderr.
        self.exit_code = 0
        self.output = []
        self._reset_errors()
        # Check if the target directory is empty or doesn't exist
        if self._target_is_empty(target):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            # No tool runs for this target, so its record starts and ends now: a
            # start time left from the previous target would give it that
            # target's duration.
            self.start_time = None
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return True

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        # The refusal ScannerPluginBase._refuse_flagged_response raises for a run the
        # subprocess layer flagged, once it has. Its text was shaped through the
        # one guarded read of the values hook, so the handler below re-raises it
        # as it is instead of building a second message from it.
        flagged_refusal: ScannerError | None = None
        try:
            # Absolute, because syft runs from outside the source directory
            # (_working_directory), where a relative path names something else.
            target = Path(os.path.abspath(target))
            target_results_dir = Path(os.path.abspath(self.results_dir)).joinpath(
                target_type
            )
            target_results_dir.mkdir(parents=True, exist_ok=True)
            results_file = target_results_dir.joinpath("syft.cdx.json")
            self.args = ToolArgs(
                format_arg="--output",
                format_arg_value=(
                    f"cyclonedx-json@{CYCLONEDX_SPEC_VERSION}={results_file.as_posix()}"
                ),
                scan_path_arg=None,
                extra_args=[
                    ToolExtraArg(
                        key="--base-path",
                        value=self._base_path(target).as_posix(),
                    ),
                ],
            )
            # Re-apply config options (exclude paths, config file) that were
            # set during model_post_init but lost by the ToolArgs rebuild above.
            self._process_config_options()
            if not any(arg.key == "--config" for arg in self.args.extra_args):
                empty = empty_tool_config(
                    "syft-empty.yaml", "{}\n", context=self.context
                )
                self.args.extra_args.append(
                    ToolExtraArg(key="--config", value=empty.as_posix())
                )
            # Each link leaving this target (syft follows none of them), and each
            # path the global ignore paths ignore. Rebuilt with the arguments above
            # for every target. See utils/link_exclusions.py.
            self.args.extra_args.extend(
                ToolExtraArg(key="--exclude", value=pattern)
                for pattern in syft_excludes(
                    target, self.context.source_dir, global_ignore_paths
                )
            )
            conf: SyftScannerConfig = self.config
            opts: SyftScannerConfigOptions = conf.options
            for out in opts.additional_outputs:
                out_ext = "txt"
                if "json" in out:
                    out_ext = "json"
                elif "xml" in out:
                    out_ext = "xml"
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--output",
                        value=f"{out}={results_file.as_posix()}.{out}.{out_ext}",
                    )
                )

            # ASH's own output directories inside the target. Rebuilt with the
            # ToolArgs above on every call, so nothing accumulates.
            from automated_security_helper.utils.scan_output_dirs import (
                output_dir_exclude_globs,
            )

            self.args.extra_args.extend(
                ToolExtraArg(key="--exclude", value=pattern)
                for pattern in output_dir_exclude_globs(
                    self._ash_output_dirs_inside(target)
                )
            )
            final_args = self._resolve_arguments(
                target=target,
            )
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                cwd=self._working_directory(target, target_results_dir),
                env=subprocess_env,
                timeout=effective_timeout,
            )

            self._post_scan(
                target=target,
                target_type=target_type,
            )
            try:
                self._refuse_flagged_response(response, effective_timeout)
            except ScannerError as refusal:
                flagged_refusal = refusal
                raise
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            syft_results = {}
            with open(results_file, mode="r", encoding="utf-8") as f:
                syft_results = json.load(f)
            try:
                sbom_report = CycloneDXReport.model_validate(syft_results)
            except ValidationError as e:
                # Not returned as it is: the declared result is a CycloneDXReport
                # or a bool, and a raw dict reaches the executor as a result it
                # cannot grade, reported as "not SARIF and carries no status",
                # which names neither syft nor the cause. The error's count, not
                # its text: the text quotes the document's values.
                raise ScannerError(
                    f"{self.__class__.__name__} wrote a results file that is not "
                    f"CycloneDX ASH can read ({e.error_count()} validation "
                    "error(s)), so its SBOM could not be recorded"
                )

            if target_type == TargetType.CONVERTED:
                # Components the sdist-lock-harvester materialized carry their
                # provenance (the sdist's sha256 pin, the parent package's purl,
                # the source URL) as CycloneDX properties, read from the harvest
                # manifests beside the lockfiles. An enrichment, never a gate: a
                # failure here costs the properties, not the SBOM.
                from automated_security_helper.utils.sdist_harvest import (
                    stamp_harvested_components,
                )

                try:
                    stamped = stamp_harvested_components(sbom_report, target)
                    if stamped:
                        ASH_LOGGER.debug(
                            f"stamped harvest provenance onto {stamped} "
                            "component(s) under sdist-locks/"
                        )
                except Exception as stamp_error:
                    ASH_LOGGER.debug(
                        "could not stamp harvest provenance properties: "
                        f"{type(stamp_error).__name__}"
                    )

            return sbom_report

        except Exception as e:
            # The run is over for this target, however it ended: the executor
            # records end_time, and one left from the previous target would give
            # this one an end before its start.
            self.end_time = datetime.now(timezone.utc)
            # A flagged run is reported as the base method worded it: building a
            # message from it here would read the values hook a second time, and a
            # hook that raises would replace "timed out" with its own failure.
            if e is flagged_refusal:
                raise
            # Redacted, as the module's other error paths are: the text can quote
            # a path the configuration read from the environment. Through the one
            # guarded read of the values hook, so a hook that raises does not
            # replace this error with its own; with no usable answer nothing can
            # be redacted, and the error text is not shown.
            read = guarded_values_read(self)
            if read.values is None:
                failure = (
                    f"{self.__class__.__name__} scan failed (the error text is not "
                    f"shown: the plugin's values hook {read.failure()})"
                )
                ASH_LOGGER.debug(
                    f"{self.__class__.__name__} scan failed; the original traceback "
                    f"is not shown: the plugin's values hook {read.failure()}",
                    extra=NO_MARKUP,
                )
            else:
                failure = text_without_values(
                    f"{self.__class__.__name__} scan failed: {str(e)}", read.values
                )
                # The new error carries no traceback (below), so a bug inside the
                # try (an AttributeError in ASH's own code, say) would leave only
                # the one-line message. The stack goes to the debug log, redacted
                # the way the message is.
                ASH_LOGGER.debug(
                    f"{self.__class__.__name__} scan failed; the original "
                    "traceback:\n" + traceback_text(e, values=read.values),
                    extra=NO_MARKUP,
                )
        # Raised outside the except block, so the original exception, whose text
        # is not redacted, is attached to the new one neither as __context__ nor
        # as __cause__: `raise ... from None` would only hide it from the default
        # traceback while leaving it readable on the object.
        raise ScannerError(failure)

    def scan_image(
        self,
        image,
        config: SyftScannerConfig | None = None,
        *args,
        global_ignore_paths=None,
        **kwargs,
    ) -> CycloneDXReport | bool:
        """Catalog a container image into an SBOM.

        syft overrides the whole image dispatch, as it overrides ``scan()``:
        its result is a CycloneDX document, which the base image template
        would try to grade as SARIF. The flow is this scanner's own scan flow
        with the image differences and nothing else -- the target is a
        stereoscope string (utils/image_tool_targets.py) instead of a
        directory, there is no --base-path and no exclude set because nothing
        of the source tree is read, and the results land under the scanner's
        ``image`` results directory.
        """
        image_target_type = "image"
        anchor = Path(os.path.abspath(self.context.source_dir))

        self.exit_code = 0
        self.start_time = None
        self.end_time = None
        self.output = []
        self._reset_errors()
        self._nothing_scanned_reason = None
        self._image_ignore_paths = list(global_ignore_paths or [])

        # One engine reading for the whole target, as the base template takes
        # it: the skip decision and the stereoscope target must agree. The
        # socket half says whether the daemon is local or only DECLARED.
        self._image_engine, self._image_engine_socket = self._detect_image_engine()

        not_scanned = self._image_not_scanned_reason(image)
        if not_scanned is not None:
            self._nothing_scanned_reason = not_scanned
            self._plugin_log(
                f"{not_scanned}. Not running the tool.",
                target_type=image_target_type,
                level=logging.WARNING,
                append_to_stream="stderr",
            )
            self._post_scan(target=anchor, target_type=image_target_type)
            return True

        validated = self._pre_scan(
            target=anchor,
            target_type=image_target_type,
            config=config,
        )
        if not validated:
            self._post_scan(target=anchor, target_type=image_target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=anchor, target_type=image_target_type)
            return False

        flagged_refusal: ScannerError | None = None
        try:
            from automated_security_helper.utils.image_tool_targets import (
                stereoscope_sources,
                stereoscope_target,
            )

            # Declared in the environment with no local socket: the
            # schemeless target keeps a source fallback. Only read when the
            # engine is docker or podman, so the always-socketless NONE case
            # is unaffected.
            remote_daemon = self._image_engine_socket is None
            target_results_dir = Path(os.path.abspath(self.results_dir)).joinpath(
                image_target_type
            )
            target_results_dir.mkdir(parents=True, exist_ok=True)
            results_file = target_results_dir.joinpath("syft.cdx.json")
            self.args = ToolArgs(
                format_arg="--output",
                format_arg_value=(
                    f"cyclonedx-json@{CYCLONEDX_SPEC_VERSION}={results_file.as_posix()}"
                ),
                scan_path_arg=None,
                extra_args=[],
            )
            # Re-apply config options (config file, additional outputs) that
            # the ToolArgs rebuild above dropped, as scan() re-applies them.
            self._process_config_options()
            # ... except the exclude set: options.exclude globs are paths
            # relative to the scanned DIRECTORY, and handing them to syft here
            # would filter in-image paths that happen to match a source-tree
            # glob. This is what makes the docstring's "no exclude set" true.
            # The in-image excludes are added below, from the ignore paths.
            # Said here because _process_config_options just logged each
            # entry as "excluded from syft scan", which this removal makes
            # untrue for THIS scan.
            removed_excludes = sum(
                1 for arg in self.args.extra_args if arg.key == "--exclude"
            )
            if removed_excludes:
                self._plugin_log(
                    f"The {removed_excludes} configured exclude pattern(s) are "
                    "directory-relative and do not apply to an image scan; the "
                    "image's ignore paths are passed instead.",
                    level=logging.DEBUG,
                )
            self.args.extra_args = [
                arg for arg in self.args.extra_args if arg.key != "--exclude"
            ]
            if not any(arg.key == "--config" for arg in self.args.extra_args):
                empty = empty_tool_config(
                    "syft-empty.yaml", "{}\n", context=self.context
                )
                self.args.extra_args.append(
                    ToolExtraArg(key="--config", value=empty.as_posix())
                )
            conf: SyftScannerConfig = self.config
            opts: SyftScannerConfigOptions = conf.options
            for out in opts.additional_outputs:
                out_ext = "txt"
                if "json" in out:
                    out_ext = "json"
                elif "xml" in out:
                    out_ext = "xml"
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--output",
                        value=f"{out}={results_file.as_posix()}.{out}.{out_ext}",
                    )
                )
            # The ignore paths syft can be told to leave uncataloged (measured
            # on syft 1.57.2: an absolute in-image glob is honored on an image
            # source, the "./" form is not; utils/image_ignore_paths).
            self.args.extra_args.extend(
                ToolExtraArg(key="--exclude", value=glob)
                for glob in self._image_exclude_globs()
            )
            # A schemeless target names its sources (the declared daemon, then
            # the registry): left to itself syft reads a local path that
            # spells the reference first (utils/image_tool_targets).
            self.args.extra_args.extend(
                ToolExtraArg(key="--from", value=source)
                for source in stereoscope_sources(
                    image, engine=self._image_engine, remote_daemon=remote_daemon
                )
            )
            final_args = self._resolve_arguments(
                target=stereoscope_target(
                    image, engine=self._image_engine, remote_daemon=remote_daemon
                ),
            )
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                cwd=self._working_directory(anchor, target_results_dir),
                env=subprocess_env,
                timeout=effective_timeout,
            )

            self._post_scan(target=anchor, target_type=image_target_type)
            try:
                self._refuse_flagged_response(response, effective_timeout)
            except ScannerError as refusal:
                flagged_refusal = refusal
                raise
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            with open(results_file, mode="r", encoding="utf-8") as f:
                syft_results = json.load(f)
            try:
                sbom_report = CycloneDXReport.model_validate(syft_results)
            except ValidationError as e:
                raise ScannerError(
                    f"{self.__class__.__name__} wrote a results file that is not "
                    f"CycloneDX ASH can read ({e.error_count()} validation "
                    "error(s)), so its SBOM could not be recorded"
                )

            return sbom_report

        except Exception as e:
            # The mirror of scan()'s handler: the run is over, a flagged run is
            # reported as the base method worded it, and everything else is
            # redacted through the one guarded read of the values hook.
            self.end_time = datetime.now(timezone.utc)
            if e is flagged_refusal:
                raise
            read = guarded_values_read(self)
            if read.values is None:
                failure = (
                    f"{self.__class__.__name__} image scan failed (the error text "
                    f"is not shown: the plugin's values hook {read.failure()})"
                )
                ASH_LOGGER.debug(
                    f"{self.__class__.__name__} image scan failed; the original "
                    f"traceback is not shown: the plugin's values hook "
                    f"{read.failure()}",
                    extra=NO_MARKUP,
                )
            else:
                failure = text_without_values(
                    f"{self.__class__.__name__} image scan failed: {str(e)}",
                    read.values,
                )
                ASH_LOGGER.debug(
                    f"{self.__class__.__name__} image scan failed; the original "
                    "traceback:\n" + traceback_text(e, values=read.values),
                    extra=NO_MARKUP,
                )
        raise ScannerError(failure)


def _demo_main(source_dir: Path, output_dir: Path) -> Path:
    """Scan ``source_dir`` with syft and write the SBOM under ``output_dir``.

    What ``python -m`` on this module does: a scanner with the plugin context the
    executor would give it, one source scan, and the CycloneDX document written as
    ``syft.cdx.json`` (the name the scanner writes). A result that is not a report
    (True for an empty target, False when syft cannot run) is written as JSON too.
    Returns the file written.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config

    context = PluginContext(
        source_dir=source_dir, output_dir=output_dir, config=get_default_config()
    )
    scanner = SyftScanner(context=context)
    report: Any = scanner.scan(target=source_dir, target_type=TargetType.SOURCE)
    if hasattr(report, "model_dump_json"):
        report_json = report.model_dump_json(
            indent=2, by_alias=True, exclude_unset=True
        )
    else:
        report_json = json.dumps(report, indent=2)
    destination = output_dir.joinpath("syft.cdx.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open_for_write(destination, encoding=None, errors=None) as f:
        f.write(report_json)
    return destination


if __name__ == "__main__":
    _demo_main(Path.cwd(), Path.cwd().joinpath(".ash", "ash_output"))
