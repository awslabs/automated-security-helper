# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SBOM generation over the scan target's files using cdxgen (CycloneDX Generator).

cdxgen is an inventory tool, like syft: it lists the components a tree uses and
reports no findings. Its output is a CycloneDX document, not SARIF, so this scanner
overrides ``scan()`` and returns a ``CycloneDXReport`` the way the builtin syft
scanner does, instead of filling in the template's ``_execute_scan``.

What was read from cdxgen's CLI documentation (docs/CLI.md in the CycloneDX/cdxgen
repository) and not run on this host:

- ``--output`` is the output file (default ``bom.json``).
- ``--spec-version`` takes 1.6, 1.7 or 2.0 and defaults to 1.7. ASH models 1.6
  (``CycloneDXReport``), so ``--spec-version=1.6`` is always passed.
- ``--install-deps`` defaults to true: cdxgen installs dependencies of the scanned
  project, which runs the project's package manager over code the tree controls.
  ``--no-install-deps`` is always passed.
- Exit status: 0 success, 1 generic failure, 4 and 5 only for ``--introspect``
  runs, which ASH does not use. Only 0 is accepted.

Severity: there are no findings, so there is no SARIF level and no
``issue_severity`` to disagree. The components are inventory (INFO), as syft's are.

Working directory: cdxgen can read a ``.cdxgenrc`` or a ``package.json`` section
from its working directory, so it runs from outside the scanned tree
(``cwd_outside_scanned_tree``) and is given the scan path absolute.

Offline: with ``--no-install-deps`` ASH makes no registry call on cdxgen's behalf;
the sandbox grants no network (see ``sandbox_requirements``).
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, ClassVar, List, Literal, Set

from pydantic import Field, ValidationError, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import PluginDependency
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.path_trust import cwd_outside_scanned_tree
from automated_security_helper.core.enums import (
    OfflineStrategy,
    PackageManager,
    ScannerToolType,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The npm package that provides the ``cdxgen`` command, and the release ASH installs.
CDXGEN_NPM_PACKAGE = "@cyclonedx/cdxgen"
CDXGEN_VERSION = "12.9.2"

#: The CycloneDX version cdxgen is asked to write; ``CycloneDXReport`` models 1.6.
CYCLONEDX_SPEC_VERSION = "1.6"

#: Platform and architecture pairs the npm package runs on (Node.js decides).
INSTALL_PLATFORMS = {
    "linux": ("amd64", "arm64"),
    "darwin": ("amd64", "arm64"),
    "windows": ("amd64", "arm64"),
}


class CdxgenScannerConfigOptions(ScannerOptionsBase):
    project_type: Annotated[
        List[str],
        Field(
            description=(
                "Project types passed to cdxgen as one --type=<value> each (for "
                "example js, python, java). Empty lets cdxgen detect the types."
            ),
        ),
    ] = []
    exclude: Annotated[
        List[IgnorePathWithReason],
        Field(
            description=(
                "Glob patterns cdxgen skips, each passed as one --exclude=<glob>."
            ),
        ),
    ] = []


class CdxgenScannerConfig(ScannerPluginConfigBase):
    name: Literal["cdxgen"] = "cdxgen"
    enabled: bool = True
    options: Annotated[
        CdxgenScannerConfigOptions,
        Field(description="Configure the cdxgen scanner"),
    ] = CdxgenScannerConfigOptions()


@ash_scanner_plugin
class CdxgenScanner(ScannerPluginBase[CdxgenScannerConfig]):
    """CdxgenScanner generates a CycloneDX SBOM using cdxgen."""

    display_name = "cdxgen"
    docs_summary = "Software inventory"
    covers = ("SBOM generation",)

    #: cdxgen is a Node.js program; a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # An SBOM has no "findings found" exit code; 1 is a failure.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default: no network, baseline environment only.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context):
        if self.config is None:
            self.config = CdxgenScannerConfig()
        self.command = "cdxgen"
        self.tool_type = ScannerToolType.SBOM
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_install_commands(self) -> "CdxgenScanner":
        """Install the pinned release from npm, for every platform Node.js runs on."""
        for platform, architectures in INSTALL_PLATFORMS.items():
            for arch in architectures:
                self.dependencies.setdefault(platform, {})[arch] = [
                    PluginDependency(
                        name=CDXGEN_NPM_PACKAGE,
                        version=CDXGEN_VERSION,
                        package_manager=PackageManager.NPM,
                    )
                ]
        return self

    def _options(self) -> CdxgenScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, CdxgenScannerConfigOptions):
            return options
        return CdxgenScannerConfigOptions()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full cdxgen argv. Options are single ``--flag=value`` tokens."""
        args: List[str] = [
            self.command or "cdxgen",
            f"--output={results_file.as_posix()}",
            f"--spec-version={CYCLONEDX_SPEC_VERSION}",
            "--no-install-deps",
        ]
        options = self._options()
        for project_type in options.project_type:
            args.append(f"--type={project_type}")
        for item in options.exclude:
            args.append(f"--exclude={item.path}")
        # ASH's own output directories inside the target would be inventoried too.
        for relative in self._ash_output_dirs_inside(target):
            args.append(f"--exclude=**/{Path(relative).as_posix()}/**")
        args.append(target.as_posix())
        return args

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub: CdxgenScanner overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CdxgenScannerConfig | None = None,
    ) -> CycloneDXReport | bool:
        """Run cdxgen over ``target`` and return its SBOM.

        Returns True for an empty or missing target (nothing to inventory) and False
        when the scanner cannot run. Raises ScannerError when cdxgen fails, times
        out, or writes something that is not CycloneDX 1.6.
        """
        self.exit_code = 0
        self.output = []
        self._reset_errors()
        if self._target_is_empty(target):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self.start_time = None
            self._post_scan(target=target, target_type=target_type)
            return True

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        refusal: ScannerError | None = None
        try:
            target = Path(os.path.abspath(target))
            results_dir = Path(os.path.abspath(self.results_dir)).joinpath(target_type)
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("cdxgen.cdx.json")
            # A report left by an earlier run must not be read as this run's.
            results_file.unlink(missing_ok=True)
            final_args = self._build_arguments(target, results_file)
            timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=results_dir,
                cwd=cwd_outside_scanned_tree(
                    target,
                    results_dir=results_dir,
                    source_dir=self.context.source_dir,
                    config=getattr(self.context, "config", None),
                ),
                timeout=timeout,
            )
            self._post_scan(target=target, target_type=target_type)
            try:
                self._refuse_flagged_response(response, timeout)
            except ScannerError as flagged:
                refusal = flagged
                raise
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            try:
                with open(results_file, mode="r", encoding="utf-8") as handle:
                    document = json.load(handle)
            except (OSError, ValueError) as exc:
                raise ScannerError(
                    f"cdxgen wrote no readable JSON report ({exc.__class__.__name__})"
                )
            try:
                return CycloneDXReport.model_validate(document)
            except ValidationError as exc:
                # The count only: the text would quote the document's values.
                raise ScannerError(
                    "cdxgen wrote a report that is not CycloneDX 1.6 ASH can read "
                    f"({exc.error_count()} validation error(s))"
                )
        except Exception as exc:
            self.end_time = datetime.now(timezone.utc)
            if exc is refusal:
                raise
            failure = f"{self.__class__.__name__} scan failed: {exc}"
        raise ScannerError(failure)

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "cdxgen")
        if not found:
            ASH_LOGGER.warning(
                "cdxgen executable not found in PATH (it needs Node.js). Install it "
                "with `ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_cdxgen_plugins\"]' --tool cdxgen`."
            )
        return found is not None


__all__ = [
    "CdxgenScanner",
    "CdxgenScannerConfig",
    "CdxgenScannerConfigOptions",
]
