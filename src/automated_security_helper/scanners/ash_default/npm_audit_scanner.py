"""Module containing the NPM Audit security scanner implementation."""

import json
from pathlib import Path
import shutil
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
)
from automated_security_helper.utils.log import ASH_LOGGER


class NpmAuditScannerConfigOptions(ScannerOptionsBase):
    pass


class NpmAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["npm-audit"] = "npm-audit"
    enabled: bool = True
    options: Annotated[
        NpmAuditScannerConfigOptions, Field(description="Configure NpmAudit scanner")
    ] = NpmAuditScannerConfigOptions()


class NpmAuditScanner(ScannerPluginBase[NpmAuditScannerConfig]):
    """NpmAuditScanner implements IaC scanning using `npm/yarn/pnpm audit` based on the lock files discovered in the source directory."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = NpmAuditScannerConfig()
        self.command = "npm"
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--file",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        return shutil.which(self.command) is not None

    def _process_config_options(self):
        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: NpmAuditScannerConfig | None = None,
    ) -> SarifReport:
        """Execute NpmAudit scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        try:
            self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
        except ScannerError as exc:
            raise exc

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)
            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
            )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            npmaudit_results = {}
            Path(results_file).parent.mkdir(exist_ok=True, parents=True)
            with open(results_file, "r") as f:
                npmaudit_results = json.load(f)
            try:
                sarif_report: SarifReport = SarifReport(**npmaudit_results)
                # sarif_report.runs[0].invocations = [
                #     Invocation(
                #         commandLine=final_args[0],
                #         arguments=final_args[1:],
                #         startTimeUtc=self.start_time,
                #         endTimeUtc=self.end_time,
                #         executionSuccessful=True,
                #         exitCode=self.exit_code,
                #         exitCodeDescription="\n".join(self.errors),
                #         workingDirectory=ArtifactLocation(
                #             uri=get_shortest_name(input=target),
                #         ),
                #         properties=PropertyBag(
                #             tool=sarif_report.runs[0].tool,
                #         ),
                #     )
                # ]
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}"
                )
                self.errors.append(
                    f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}"
                )
                return

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"NpmAudit scan failed: {str(e)}")
