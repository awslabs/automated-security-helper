# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Dockle, a container image linter (CIS Docker Benchmark and best practices).

An alpha scanner plugin: listing this module in ``ash_plugin_modules`` is the
opt-in, and a scan that does not list it is unchanged.

What it runs
------------
``dockle`` over ONE container image, never over the scanned source tree. Dockle
reads an image by reference (from a registry or a Docker daemon) or a saved image
tarball (``--input``). ASH's directory scan target is not an input to it, so the
image comes from one of two places:

* an image scan (``ash scan --image``, ``--image-archive`` or ``--image-layout``),
  whose asset the scan phase hands to every scanner whose register row claims
  ``container_image``; ``scan_image`` drives ``_execute_image_scan`` (see
  "Container image scans");
* in a directory scan, the operator's ``image`` or ``image_tarball`` option; with
  neither set the scanner does nothing and says so (see "Gate").

Invocation (flags read from the Dockle source, pkg/app.go, 2026-11-18)::

    dockle --format=sarif --output=<results>/<source|image>/dockle.sarif \\
        --no-color [--input=<tarball>] [--] [<image>]

* ``--format=sarif`` and ``--output`` write SARIF 2.1.0 to a file
  (pkg/report/sarif.go).
* ``--exit-code`` is NOT passed. Without it Dockle exits 0 whether or not it found
  anything, and a non-zero exit means it failed (a missing image, an unreachable
  daemon). ``success_exit_codes`` is therefore ``{0}``.
* ``--input`` is used for a tarball. When it is set Dockle does not read the image
  argument (pkg/run.go: the image name is taken only when ``--input`` is empty).
* The image reference follows ``--`` so a name is never read as a flag.
* ``--ignore``, ``--accept-*`` and ``--sensitive-*`` are not passed; ASH
  suppressions are the one place findings are tuned.
* Dockle reads ``.dockleignore`` and ``DOCKLE_IGNORES`` to drop checkpoints. The
  subprocess working directory is the results directory (``_subprocess_cwd``), not
  the scanned tree, so a ``.dockleignore`` in the scanned repository is not read
  from there. ``DOCKLE_*`` variables of the operator's environment pass the
  sandbox's env filter (credential-shaped names such as ``DOCKLE_PASSWORD`` do
  not).

Gate
----
No ``image`` and no ``image_tarball`` option set by the operator: the scanner logs
an INFO line, records a "nothing scanned" reason and returns without starting
Dockle (``scan()``). Only the ``source`` target runs it; the ``converted`` target
is the same image and is skipped. An option written by a config inside the scanned
tree, or by an MCP client, is ignored with a warning, as for the other scanners'
operator-only options, because it would let a scanned repository make ASH pull an
image from a registry of its choosing.

Container image scans
---------------------
The image asset's locator gives the argv (``_execute_image_scan``): a reference
follows ``--``, checked as ``options.image`` is, and a saved archive is passed with
``--input``. ``dockle --input`` reads a ``docker save`` archive only (pkg/scanner/
scan.go at v0.4.15 opens it with deckoder's docker-archive extractor), so two
shapes are a reported clean skip rather than a tool failure
(``_unsupported_image_shape_reason``): an OCI image-layout directory, and an
OCI-layout tarball that holds no ``manifest.json`` (``archive_scheme`` reads member
names only). Dockle has no path-exclusion option, so the scan's ignore paths are
not handed to it; ASH applies them to its findings after the scan, as it does for
every scanner.

Severity
--------
Dockle writes the SARIF level itself (pkg/report/writer.go, ``sarifAlertLabels``):
FATAL -> ``error``, WARN -> ``warning``, INFO -> ``note``, and PASS, SKIP and
IGNORE -> ``none``. ASH rates them FATAL -> HIGH, WARN -> MEDIUM, INFO -> LOW,
none -> INFO, and sets the SARIF level to match. ``error`` is HIGH and not
CRITICAL because the checkpoints are configuration lint (a root user, a ``latest``
tag, a sensitive-looking file name), as for hadolint. A result with no level is
MEDIUM (SARIF's own default); a level this table does not know is HIGH, so nothing
is under-reported.

Exit status and output
----------------------
Any exit code other than 0 fails the scan, even when a report is on disk. A report
that is not JSON, not SARIF, or holds no run fails it too: an empty run is a scan
that found nothing, a missing run is no scan. A report left by an earlier run is
removed before each run. Dockle's stderr can quote image content and is not copied
into the scan's errors.

Offline
-------
Scanning a saved tarball needs no network. Scanning an image by name pulls from a
registry or talks to a Docker daemon. ``offline_strategy`` is ``SKIP_OFFLINE``: an
offline scan does not run it.

Sandbox
-------
The sandbox is declared with a network need that follows the operator's option
(``network_requires_grant``), so the network is granted only where the operator's
trusted configuration names the scanner in ``sandbox.network_scanners``.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import Field, model_validator

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.confinement_remedy import (
    KEEP_A_SETTING,
    SET_BY_THE_OPERATOR,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.models.vocab import TargetType
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.config_trust import (
    LEADS_OUT_OF_THE_TREE,
    operator_path,
    refusal_warning,
    set_by_operator,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import downloadable_tools

if TYPE_CHECKING:
    from automated_security_helper.core.asset import ImageLocator

#: The ``TOOL_VERSIONS`` key and download-table row of the pinned Dockle release.
DOCKLE_TOOL_NAME = "dockle"

#: Dockle's SARIF level for each result -> (ASH severity, SARIF level).
DOCKLE_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
    "none": ("INFO", Level.none),
}

#: A name Dockle can be handed as an image: a registry reference, with a tag or digest.
#: It cannot start with ``-`` and holds no whitespace or control character.
_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+\-]*$")


def _level_name(level: Any) -> Optional[str]:
    if level is None:
        return None
    return str(getattr(level, "value", level))


class DockleScannerConfigOptions(ScannerOptionsBase):
    image: Annotated[
        str | None,
        Field(
            description=(
                "The container image Dockle scans, as a registry reference "
                "(`alpine:3.20`, `registry.example.com/team/app@sha256:...`). Dockle "
                "pulls it from a registry or reads it from a Docker daemon, so the "
                "scan needs a network or a daemon. Unset, and with no "
                "`image_tarball`, the scanner does nothing and says so. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with "
                "a warning."
            ),
        ),
    ] = None
    image_tarball: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a saved image (`docker save`) that Dockle scans with "
                "`--input`. Needs no network. A relative path is taken from the "
                "directory of the config file that sets it, or from the working "
                "directory for --config-overrides. Setting both `image` and "
                f"`image_tarball` fails the scan. {SET_BY_THE_OPERATOR} "
                "Set by such a config, it is ignored with a warning."
            ),
        ),
    ] = None


class DockleScannerConfig(ScannerPluginConfigBase):
    name: Literal["dockle"] = "dockle"
    enabled: bool = True
    options: Annotated[
        DockleScannerConfigOptions,
        Field(description="Configure the dockle scanner"),
    ] = DockleScannerConfigOptions()


@ash_scanner_plugin
class DockleScanner(ScannerPluginBase[DockleScannerConfig]):
    """Container image lint over one image or saved image tarball using Dockle."""

    #: Not Python-only: Dockle is a native binary, installed from its pinned release.
    python_only: ClassVar[bool | None] = False

    # Scanning by name pulls the image; the tarball route does not. Either way an
    # offline scan does not run it.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name Dockle's own SARIF (pkg/report/sarif.go,
    #: writer.go sarifAlertLabels, read from upstream source 2026-11-18).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (the Dockle checkpoint code, CIS-DI-0001 etc.)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (error, warning, note, none), mapped by '
            "DOCKLE_LEVEL_MAP in _post_process_sarif to HIGH, MEDIUM, LOW, INFO",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri "
            "(an in-image path such as app/id_rsa, or the word metadata; never "
            "a file in the scanned tree; captured/positive.sarif)",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="image findings have no source line",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="image findings have no source column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="the image reference is the one scanned object and is an "
            "image locator, not an infrastructure resource id; the SARIF "
            "carries a checkpoint code and message only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries no resource type; every finding is about "
            "the one container image",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="checkpoints are configuration lint, not package findings",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="checkpoints are configuration lint, not package findings",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="checkpoints are configuration lint, not package findings",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="Dockle reports no CVEs; vulnerability scanning is out of its scope",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="Dockle checkpoints carry no CWE taxonomy in the SARIF",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries no fingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="checkpoints carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry the checkpoint code and description only",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="image findings carry no code snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rules[] "helpUri" (the CHECKPOINT.md anchor of each rule), '
            "read into the flat references when the result carries no "
            "relatedLocations",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="Dockle's SARIF carries no tags (0 of 10 results in "
            "captured/*.sarif); the container-image and security tags are "
            "added by _post_process_sarif, not read from the output",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="dockle",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.PACKAGE_DOWNLOADS,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason="scanning by image name pulls from a registry or "
                "reads a Docker daemon; ASH skips the scanner offline, tarball "
                "route included",
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.VERIFYING,
                source=(
                    "dockle_scanner.py offline_strategy, sandbox_requirements "
                    "(network_requires_grant); module header Offline and Sandbox"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.CONTAINER_IMAGE,),
                tool_type=ScannerToolType.CONTAINER,
                selection="a container-image asset through _execute_image_scan "
                "(a reference after --, --input for a docker save archive; an OCI "
                "layout directory or an OCI-layout tarball is a reported clean "
                "skip), or in a directory scan one image from options.image or a "
                "saved tarball from options.image_tarball; the scanned tree is "
                "never an input (module header Gate and Container image scans)",
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key=DOCKLE_TOOL_NAME,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for Dockle.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(
                    "darwin/amd64",
                    "darwin/arm64",
                    "linux/amd64",
                    "linux/arm64",
                ),
                note="the v0.4.15 release publishes Linux and macOS archives for "
                "amd64 and arm64 and no Windows build (plus 32-bit, ARM and "
                "loong64 Linux, which ASH does not install); derived from "
                "tool_downloads",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="Dockle's FATAL, WARN and INFO levels map to HIGH, MEDIUM "
                "and LOW; PASS, SKIP and IGNORE map to INFO",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.OPERATOR,
                        honored=opsf.Honored.YES,
                        surface=".dockleignore in the working directory and "
                        "DOCKLE_IGNORES in the environment",
                        cite="dockle_scanner.py module header (Invocation): the "
                        "subprocess runs in the results directory, so a file in "
                        "the scanned repository is not read; DOCKLE_ variables "
                        "pass the sandbox env filter",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the SARIF results carry no fingerprints (captured/*.sarif); "
                "identity is rule and in-image path through the shared floor, "
                "with no line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("DOCKLE_",),
                options_surface="the image asset of an image scan, or "
                "options.image and options.image_tarball set by the operator; "
                "--ignore, --accept-* and --sensitive-* are never passed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="without --exit-code Dockle exits 0 whether or not it "
                "found anything; any other exit means it failed",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=(
                    "ash_dockle_plugins in ash_plugin_modules",
                    "an image scan (--image, --image-archive, --image-layout)",
                    "options.image",
                    "options.image_tarball",
                ),
                upstream_license=(
                    "Apache-2.0 (source: LICENSE in dockle_0.4.15_Linux-64bit.tar.gz, "
                    "sha256 c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4, "
                    "byte-identical to the repository LICENSE at the v0.4.15 tag "
                    "commit 54368575)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="an image: the asset of an image scan, or in a directory "
                "scan an image reference or saved tarball set by the operator; "
                "without one the scanner skips cleanly",
            ),
        )
    )

    # Without --exit-code Dockle exits 0 with findings; anything else is a failure.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # Fetching an image by name needs a network, and the option that names the image
    # is the operator's, so the scanner's own declaration does not grant it.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        network_requires_grant=True,
        env_prefixes=("DOCKLE_",),
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = DockleScannerConfig()
        self.command = "dockle"
        self.tool_type = ScannerToolType.CONTAINER
        # The argv is assembled in _build_arguments.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "DockleScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``.

        The pin (version, four asset names, archive and executable digests,
        license entry) lives in that shared table. A table without the row would
        make ``pinned_tool_install_commands`` raise for an unknown tool and the
        scanner impossible to construct, so the install table then stays empty
        instead: no install command is offered, and ``validate_plugin_dependencies``
        says so. The unpinned install path is never a ``curl | sh`` or an
        unverified download.
        """
        if DOCKLE_TOOL_NAME in downloadable_tools():
            self.custom_install_commands.update(
                pinned_tool_install_commands(DOCKLE_TOOL_NAME)
            )
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> DockleScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, DockleScannerConfigOptions):
            return options
        return DockleScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("DockleScanner has no plugin context")
        return Path(self.context.source_dir)

    def _operator_image(self) -> Optional[str]:
        """``options.image`` when the operator set it, else None (with a warning)."""
        value = self._options().image
        if not value:
            return None
        config = self.context.config if self.context is not None else None
        if not set_by_operator(config, "scanners.dockle.options.image", value):
            self._plugin_log(
                "Ignoring scanners.dockle.options.image: it is set in a config "
                "inside a git checkout or the scanned directory, or by an MCP "
                "client, and the scanned repository does not choose which image "
                f"ASH pulls. {KEEP_A_SETTING}",
                level=logging.WARNING,
            )
            return None
        if not _IMAGE_REFERENCE.match(value):
            raise ScannerError(
                f"scanners.dockle.options.image is {value!r}, which is not an image "
                "reference (letters, digits and ._/:@+- only, not starting with a "
                "dash). Dockle is not run."
            )
        return value

    def _operator_tarball(self) -> Optional[Path]:
        """``options.image_tarball`` when the operator set it, else None."""
        value = self._options().image_tarball
        if not value:
            return None
        config = self.context.config if self.context is not None else None
        chosen = operator_path(
            config,
            "scanners.dockle.options.image_tarball",
            value,
            self._source_dir(),
            outside_tree=False,
        )
        if chosen.refusal == LEADS_OUT_OF_THE_TREE:
            raise ScannerError(
                f"scanners.dockle.options.image_tarball is {str(value)!r}, a path "
                "inside the scanned tree that resolves outside it through a symbolic "
                "link. Dockle is not run."
            )
        if chosen.path is None:
            self._plugin_log(
                refusal_warning(
                    f"Ignoring scanners.dockle.options.image_tarball "
                    f"({str(value)!r}): {chosen.refusal}.",
                    chosen.refusal,
                ),
                level=logging.WARNING,
            )
            return None
        if not chosen.path.is_file():
            raise ScannerError(
                f"scanners.dockle.options.image_tarball is {str(value)!r}, which is "
                f"not a file (resolved to {chosen.path.as_posix()}). Dockle is not "
                "run."
            )
        return chosen.path

    def _resolve_input(self) -> Tuple[Optional[str], Optional[Path]]:
        """``(image, tarball)``; at most one is set, both None means nothing to scan."""
        image = self._operator_image()
        tarball = self._operator_tarball()
        if image is not None and tarball is not None:
            raise ScannerError(
                "scanners.dockle.options.image and image_tarball are both set; "
                "Dockle scans one image, so set one of them. Dockle is not run."
            )
        return image, tarball

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def scan(  # type: ignore[override]
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """The template scan, behind the gate described in the module docstring."""
        reason: Optional[str] = None
        if target_type != "source":
            reason = (
                "dockle scans one image, not files; the converted target is not "
                "scanned again"
            )
        else:
            # Raises ScannerError for a bad option, before anything runs.
            image, tarball = self._resolve_input()
            if image is None and tarball is None:
                reason = (
                    "dockle needs a container image: set "
                    "scanners.dockle.options.image or image_tarball. Nothing was "
                    "scanned"
                )
        if reason is None:
            return super().scan(
                target, target_type, global_ignore_paths, config, *args, **kwargs
            )
        # The clean skip the template takes for an empty target.
        self.exit_code = 0
        self.start_time = None
        self.end_time = None
        self.output = []
        self._reset_errors()
        self._nothing_scanned_reason = reason
        self._plugin_log(
            f"{reason}.",
            target_type=target_type,
            level=logging.INFO,
            append_to_stream="stderr",
        )
        self._post_scan(target=target, target_type=target_type)
        return True

    def _subprocess_cwd(self, results_dir: Path) -> Path | None:
        """The results directory, so a ``.dockleignore`` in the scanned tree is not read."""
        return results_dir

    def _build_arguments(
        self, results_file: Path, image: Optional[str], tarball: Optional[Path]
    ) -> List[str]:
        """The full Dockle argv: one ``--flag=value`` token each, the image after ``--``."""
        args: List[str] = [
            self.command or "dockle",
            "--format=sarif",
            f"--output={results_file.as_posix()}",
            "--no-color",
        ]
        if tarball is not None:
            args.append(f"--input={tarball.as_posix()}")
        if image is not None:
            args.extend(["--", image])
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for the one Dockle run.

        ``target`` is the source directory and is not given to Dockle, which scans an
        image. ``global_ignore_paths`` is applied to the SARIF by ASH.
        """
        if self.results_dir is None:
            raise ScannerError("DockleScanner has no results directory")
        self.exit_code = 0
        image, tarball = self._resolve_input()
        if image is None and tarball is None:
            raise ScannerError("DockleScanner was run with no image to scan")
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "dockle.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(results_file, image, tarball)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    # ------------------------------------------------------------------
    # Container image scans (the image asset; see "Container image scans")
    # ------------------------------------------------------------------

    def _unsupported_image_shape_reason(self, image: "ImageLocator") -> Optional[str]:
        """Dockle reads a reference or a ``docker save`` archive, nothing else.

        ``dockle --input`` opens the file with deckoder's docker-archive extractor
        (pkg/scanner/scan.go at v0.4.15), which needs the ``manifest.json`` a
        ``docker save`` tarball carries, and Dockle has no input mode for an OCI
        image-layout directory. Either shape is then a reported clean skip rather
        than a tool failure, and the other image scanners still read it.
        """
        if image.oci_layout is not None:
            return (
                f"container image at {image.shown()} was not scanned by dockle: "
                "dockle reads a reference or a docker save archive (--input), "
                "not an OCI image-layout directory"
            )
        if image.oci_archive is not None:
            from automated_security_helper.utils.image_tool_targets import (
                archive_scheme,
            )

            if archive_scheme(Path(image.oci_archive)) == "oci-archive":
                return (
                    f"container image at {image.shown()} was not scanned by "
                    "dockle: it is an OCI-layout tarball with no manifest.json, "
                    "and dockle --input reads only a docker save archive"
                )
        return None

    def _execute_image_scan(
        self, image: "ImageLocator"
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one image run.

        The directory scan's argv with the image asset's locator in place of the
        operator's options: a saved archive is ``--input=<absolute path>``, and a
        reference follows ``--``, checked as ``options.image`` is. No exclude is
        passed: Dockle has no path-exclusion option, and ASH applies the scan's
        ignore paths to its findings after the scan.
        """
        if self.results_dir is None:
            raise ScannerError("DockleScanner has no results directory")
        results_file = (
            Path(self.results_dir).absolute().joinpath("image", "dockle.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        if image.oci_archive is not None:
            tarball = Path(image.oci_archive).absolute()
            final_args = self._build_arguments(results_file, None, tarball)
        else:
            reference = image.ref or ""
            if not _IMAGE_REFERENCE.match(reference):
                raise ScannerError(
                    f"the image to scan is {reference!r}, which is not an image "
                    "reference (letters, digits and ._/:@+- only, not starting "
                    "with a dash). Dockle is not run."
                )
            final_args = self._build_arguments(results_file, reference, None)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=TargetType.IMAGE,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run that did not exit 0, then read it as JSON."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"dockle exited {self.exit_code}; without --exit-code it exits 0 "
                "whether or not it found anything, so this run failed"
            )
        try:
            return super()._read_results_file(results_file)
        except json.JSONDecodeError as exc:
            raise ScannerError(f"its report is not JSON: {exc.msg}") from exc

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep Dockle's stderr, which can quote the image, out of errors."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate each result from the level Dockle wrote, and make the SARIF agree."""
        for result in sarif_report.get_all_results():
            # A result with no level arrives as the SARIF model's default, warning
            # (MEDIUM). A level the table does not know is read as error, so nothing
            # is under-reported.
            name = _level_name(result.level) or "warning"
            severity, level = DOCKLE_LEVEL_MAP.get(name, DOCKLE_LEVEL_MAP["error"])
            result.level = level
            if level is not Level.none:
                result.kind = Kind.fail
            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("container-image", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "dockle")
        if not found:
            ASH_LOGGER.warning(
                "dockle executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_dockle_plugins\"]' --tool dockle`."
            )
        return found is not None


__all__ = [
    "DOCKLE_LEVEL_MAP",
    "DockleScanner",
    "DockleScannerConfig",
    "DockleScannerConfigOptions",
]
