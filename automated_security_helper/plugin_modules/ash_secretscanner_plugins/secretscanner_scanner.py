# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SecretScannerScanner: finds secrets in a container image with Deepfence SecretScanner.

What it runs
------------
``SecretScanner -output=json -image-name=<image> -temp-directory=<dir>`` (the
binary Deepfence's repository builds, https://github.com/deepfence/SecretScanner,
MIT). SecretScanner unpacks the image through the local Docker daemon and matches
its files against its secret rules. It is an image-layer scanner: the scan target
ASH hands every scanner (the source tree) is not what it reads.

Opt-in gate
-----------
The scanner does nothing until ``scanners.secretscanner.options.image_name`` names
an image. With no image
it logs one INFO line, runs nothing and the row is SKIPPED. The option is the
operator's: set from a config file inside the scanned tree or by an MCP client it
is ignored with a warning, because it makes ASH read an image through the Docker
daemon and write what it matched into the report.

Flags (read from the tool's source, core/options.go at v2.5.8)
--------------------------------------------------------------
Every flag is a Go ``flag`` flag, so ``-name=value`` is one token and a value
that starts with a dash is not read as another flag.

``-output=json``       the default is ``table``. JSON is printed to stdout; the
                       tool's log lines go to stderr.
``-image-name=<ref>``  the image, with its tag.
``-temp-directory=``   where the image is unpacked (default: the system temp
                       directory); ASH points it into its own results directory.

Never passed, and pinned by a test: ``-local`` (scans a directory, not an image),
``-enable-updater`` (downloads rules at run time: network), ``-config-path`` and
``-rules-path`` (read files the scanned tree could supply), ``-console-url``,
``-deepfence-key`` (publish to a Deepfence console), ``-socket-path``,
``-http-port`` and ``-standalone-http-port`` (start a server), ``-container-id``.
The ``-fail-on-*-count`` flags are left at their default of -1 so the tool's exit
status says only whether it ran.

Output
------
One JSON object: ``{"Timestamp", "Image Name", "Image ID", "Container ID",
"IOC": [...]}`` (``"Secrets"`` in releases before the YaraHunter-based runner).
Each entry carries ``Matched Rule Name``, ``Severity`` (``high``, ``medium`` or
``low``), ``Severity Score``, ``Full File Name`` (the path inside the image),
``Image Layer ID`` and ``matches`` (``Offset`` and ``Data``). ``Data`` is the
matched text, that is the secret. It is never copied into the SARIF.

There is no line number: a finding is a file in an image layer, so its SARIF
location is that path with no region.

Severity
--------
The tool's own severity decides it: ``high`` -> HIGH / ``error``, ``medium`` ->
MEDIUM / ``warning``, ``low`` -> LOW / ``note``. A finding with no severity is
MEDIUM; one with a severity this plugin does not know is HIGH, so nothing is
under-reported. ``issue_severity`` and the SARIF level always agree.

Exit status
-----------
0 is the only status that means the scan ran. The tool logs fatal errors (no
Docker daemon, image not found) and exits 1. A timeout, a non-zero exit, empty
output or output that is not the JSON object above fails the scan. stderr is
never copied into an error message: it can quote the image's contents.

Installing
----------
Deepfence publishes no release binaries (the GitHub releases of v2.5.8 list no
assets). The tool is built from source (``make``, needs Hyperscan and YARA) or run
from the ``quay.io/deepfenceio/deepfence_secret_scanner_ce`` image. ASH expects an
executable named ``SecretScanner`` on PATH, with its rules where the tool looks by
default (``/home/deepfence/usr/secret.yar``).

Sandbox
-------
The strict default. Reading an image needs the Docker socket, which a sandbox does
not grant yet; grants derived from options wait for the sandbox grant gates.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Set, Tuple

from pydantic import AnyUrl, Field

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
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.config_trust import set_by_operator
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The executable the tool's Makefile builds.
COMMAND = "SecretScanner"

#: SecretScanner severity -> (ASH severity, SARIF level). See the module docstring.
SECRETSCANNER_SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("LOW", "note"),
}

#: A finding that states no severity; one the map lacks is rated HIGH.
_MISSING_SEVERITY = ("MEDIUM", "warning")
_UNKNOWN_SEVERITY = ("HIGH", "error")

#: An image reference: no leading dash, no whitespace, no control characters.
_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]*$")

#: Keys the tool's JSON holds the findings under: the current runner, then older ones.
_FINDING_KEYS = ("IOC", "Secrets")

_RULES_DIR_HINT = "/home/deepfence/usr/secret.yar"


class SecretScannerConfigOptions(ScannerOptionsBase):
    image_name: Annotated[
        str | None,
        Field(
            description=(
                "The container image to scan, with its tag (for example "
                "'registry.example.com/team/app:1.2.3'), read through the local "
                "Docker daemon. Unset, the scanner does nothing and its row is "
                f"SKIPPED. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning."
            ),
        ),
    ] = None


class SecretScannerConfig(ScannerPluginConfigBase):
    name: Literal["secretscanner"] = "secretscanner"
    enabled: bool = True
    options: Annotated[
        SecretScannerConfigOptions, Field(description="Configure secretscanner")
    ] = SecretScannerConfigOptions()


@ash_scanner_plugin
class SecretScannerScanner(ScannerPluginBase[SecretScannerConfig]):
    """Scans a container image for secrets with Deepfence SecretScanner."""

    # The rules are files next to the binary; nothing is fetched at scan time.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # A native binary, not Python.
    python_only: ClassVar[bool | None] = False

    #: The facets register row (base/scanner_facets.py). Native fields name the
    #: tool's JSON as ``_result`` reads it; the sample is
    #: tests/test_data/scanners/secretscanner/captured/positive.json, which is
    #: written by hand from the tool's output structs, not captured from a run
    #: (the tool publishes no binary), and the SARIF beside it is what
    #: ``convert_output`` writes for it.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "Matched Rule Name"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "Severity" (high, medium, low), mapped by '
            "SECRETSCANNER_SEVERITY_MAP to issue_severity and the SARIF level",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "Full File Name" (the path inside the image)',
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="a finding is a file in an image layer; the tool reports a "
            "byte offset into the matched text, not a line",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="a finding is a file in an image layer; no column is reported",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='synthesized by _result from finding "Matched Rule '
            'Name" and "Full File Name"; the tool writes no message',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="a path inside an image layer is a file locator, not a "
            "deployable resource; the image layer id is kept as a property, not "
            "as a resource id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file in an image, not a resource type",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the tool's rules carry no CWE taxonomy in its JSON",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the tool emits no fingerprint; a hash of the matched text "
            "would be derived from the secret and is never computed",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the tool's JSON carries no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.DROPPED,
            native_field='finding "matches"[].Data',
            reason="the matched text is the secret; it is deliberately never "
            "copied into the SARIF",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the tool's JSON carries no reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="the converter writes no tags; the tool's JSON carries none",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "image_name", "image_layer_id" '
            '(finding "Image Layer ID"), "secretscanner_severity" and '
            '"issue_severity", written by _result',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="secretscanner",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "secretscanner_scanner.py _argv and offline_strategy; module "
                    "header: -enable-updater (rules fetched at run time) is never "
                    "passed and the image is read through the local Docker daemon"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="-output=json prints one JSON object to stdout; convert_output "
                "writes the SARIF",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SECRETS_CONTENTS,),
                tool_type=ScannerToolType.SECRETS,
                selection="the image named by the operator's options.image_name, "
                "once, on the source target; unset, the scanner does nothing "
                "(_image, scan)",
                covers_note=(
                    "the community scanners declare no covers display string. The "
                    "scanned object is a container image, which UNCLAIMED_TARGET_"
                    "KINDS (container_image) refuses to name until a central edit "
                    "lists it as wired; secrets_contents is the nearest kind"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="ASH provisions nothing: the vendor publishes no release "
                "binary, so the tool is built from source or taken from the "
                "vendor's image; a reachable Docker daemon is also required",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the tool's own high, medium and low map to HIGH, MEDIUM and "
                "LOW; no severity is MEDIUM and an unknown one is HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="the tool reads an image, not the scanned tree, and "
                "ASH passes neither -config-path nor -rules-path, so no file in "
                "the tree can silence a finding",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="no tool-written fingerprint and no captured run: identity "
                "is the rule id and the in-image path through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="options.image_name (operator only) and the "
                "common scan_timeout; no rules or config path is passed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="the tool logs fatal errors (no Docker daemon, image not "
                "found) and exits 1; no -fail-on-*-count flag is passed",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_secretscanner_plugins in ash_plugin_modules",
                    "options.image_name",
                ),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no repository file is required; the operator names an image "
                "and a Docker daemon must be reachable",
            ),
        )
    )

    # No -fail-on-*-count flag is passed, so 0 is the only status of a run that
    # completed; the tool's fatal errors exit 1.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default: no network and the baseline environment. Reading an image
    # needs the Docker socket and DOCKER_HOST, which wait for the sandbox grant gates.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SecretScannerConfig()
        self.command = COMMAND
        self.tool_type = ScannerToolType.SECRETS
        # Empty: nothing from the base resolver may add a token the tool would read
        # as one of its flags.
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: SecretScanner overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _options(self) -> SecretScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, SecretScannerConfigOptions):
            return options
        return SecretScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _image(self) -> str | None:
        """The image to scan, or None when the gate is closed.

        Closed when no image is set, and when the setting is not the operator's
        (it names what ASH reads through the Docker daemon).
        """
        configured = self._options.image_name
        if configured is None or not str(configured).strip():
            return None
        image = str(configured).strip()
        if not set_by_operator(
            getattr(self.context, "config", None),
            "scanners.secretscanner.options.image_name",
            configured,
        ):
            self._plugin_log(
                "Ignoring scanners.secretscanner.options.image_name: it came from a "
                "config file inside a git checkout or the scanned directory, or from "
                "an MCP client. Set it with --config-overrides or a config file "
                "outside the scanned tree. SecretScanner does not run.",
                level=logging.WARNING,
            )
            return None
        if not _IMAGE_REFERENCE.fullmatch(image):
            raise ScannerError(
                "scanners.secretscanner.options.image_name is not an image "
                "reference (letters, digits and . _ / : @ + - only, not starting "
                "with a dash)."
            )
        return image

    def _argv(self, image: str, temp_dir: Path) -> List[str]:
        return [
            self.command or COMMAND,
            "-output=json",
            f"-image-name={image}",
            f"-temp-directory={temp_dir.as_posix()}",
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(self) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="SecretScanner",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://github.com/deepfence/SecretScanner"
                            ),
                        )
                    ),
                    results=[],
                )
            ],
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: SecretScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Scan the configured image once, on the source target."""
        # Reset at the top, above every early return, so a second target never
        # inherits the first target's counts.
        self.targets_attempted = 0
        self.targets_failed = 0

        if target_type != "source":
            # The image is not part of either tree: one run is the whole scan.
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()

        image = self._image()
        if image is None:
            self._plugin_log(
                "SecretScanner scans a container image and "
                "scanners.secretscanner.options.image_name is not set (by the "
                "operator), so nothing was scanned.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        try:
            results_dir = Path(self.results_dir or self.context.output_dir).joinpath(
                target_type
            )
            temp_dir = results_dir.joinpath("secretscanner-tmp")
            temp_dir.mkdir(parents=True, exist_ok=True)

            argv = self._argv(image, temp_dir)
            timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=argv,
                results_dir=results_dir,
                stdout_preference="return",
                stderr_preference="write",
                timeout=timeout,
            )
            if not isinstance(response, dict):
                response = {}
            self._post_scan(target=target, target_type=target_type)
            if response.get("timed_out"):
                raise ScannerError(
                    f"SecretScanner timed out after {timeout}s and was killed, so it "
                    "produced no report. Raise scanners.secretscanner.options."
                    "scan_timeout if the image legitimately needs longer."
                )
            self._record_target_exit_code(response)
            if self.exit_code not in self.success_exit_codes:
                raise ScannerError(
                    f"SecretScanner exited {self.exit_code}, which means it did not "
                    "complete (no Docker daemon, or the image was not found). Its "
                    "stderr is in the scan's log directory."
                )
            self.targets_attempted = 1
            sarif_report = self.convert_output(response.get("stdout") or "", image)
            self._inject_invocation(sarif_report, argv, target)
            return sarif_report
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, None))

    # ------------------------------------------------------------------
    # Output conversion
    # ------------------------------------------------------------------

    def convert_output(self, stdout: str, image: str) -> SarifReport:
        """SecretScanner's JSON document -> SARIF. Raises ScannerError on bad output."""
        if not stdout.strip():
            raise ScannerError("SecretScanner exited 0 but wrote no report")
        try:
            document = json.loads(stdout)
        except ValueError as e:
            raise ScannerError(f"SecretScanner's output is not JSON ({e})")
        if not isinstance(document, dict):
            raise ScannerError("SecretScanner's output is not a JSON object")
        entries: Any = []
        for key in _FINDING_KEYS:
            if key in document:
                entries = document[key]
                break
        else:
            raise ScannerError(
                "SecretScanner's output holds neither an 'IOC' nor a 'Secrets' list"
            )
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise ScannerError("SecretScanner's findings are not a list")

        results: List[Dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ScannerError(
                    "SecretScanner reported a finding that is not an object"
                )
            results.append(self._result(entry, image))

        report = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "SecretScanner",
                                "informationUri": "https://github.com/deepfence/SecretScanner",
                            }
                        },
                        "results": results,
                    }
                ],
            }
        )
        return report

    @staticmethod
    def _result(entry: Dict[str, Any], image: str) -> Dict[str, Any]:
        raw = entry.get("Severity")
        key = raw.strip().lower() if isinstance(raw, str) else ""
        if not key:
            severity, level = _MISSING_SEVERITY
        else:
            severity, level = SECRETSCANNER_SEVERITY_MAP.get(key, _UNKNOWN_SEVERITY)
        rule = entry.get("Matched Rule Name")
        rule_id = rule if isinstance(rule, str) and rule else "secret"
        filename = entry.get("Full File Name")
        uri = filename if isinstance(filename, str) and filename else image
        layer = entry.get("Image Layer ID")
        properties: Dict[str, Any] = {
            "issue_severity": severity,
            "image_name": image,
        }
        if key:
            properties["secretscanner_severity"] = key
        if isinstance(layer, str) and layer:
            properties["image_layer_id"] = layer
        # The matched text ("matches[].Data", "Matched Contents") is the secret and
        # is deliberately not copied anywhere.
        return {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"Possible secret ({rule_id}) in {uri} of image {image}"
            },
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "properties": properties,
        }

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or COMMAND)
        if not found:
            ASH_LOGGER.warning(
                "SecretScanner executable not found in PATH. Deepfence publishes "
                "no release binaries: build it from "
                "https://github.com/deepfence/SecretScanner or use the "
                "quay.io/deepfenceio/deepfence_secret_scanner_ce image's binary, "
                f"with its rules at {_RULES_DIR_HINT}."
            )
        return found is not None


__all__ = [
    "COMMAND",
    "SECRETSCANNER_SEVERITY_MAP",
    "SecretScannerConfig",
    "SecretScannerConfigOptions",
    "SecretScannerScanner",
]
