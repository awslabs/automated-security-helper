"""Module containing the Syft security scanner implementation."""

import json
from pathlib import Path
from typing import Annotated, List, Literal

from pydantic import Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER


class SyftScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | None,
        Field(
            description="Path to Syft configuration file, relative to current source directory. Defaults to searching for `.syft.yaml` and `.syft.yml` in the root of the source directory.",
        ),
    ] = None
    exclude: Annotated[
        List[IgnorePathWithReason],
        Field(
            description='Path (file or directory) to skip, using regular expression logic, relative to current working directory. Word boundaries are not implicit; i.e., specifying "dir1" will skip any directory or subdirectory named "dir1". Ignored with -f. Can be specified multiple times.',
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


class SyftScannerConfig(ScannerPluginConfigBase):
    name: Literal["syft"] = "syft"
    enabled: bool = True
    options: Annotated[
        SyftScannerConfigOptions, Field(description="Configure Syft scanner")
    ] = SyftScannerConfigOptions()


class SyftScanner(ScannerPluginBase[SyftScannerConfig]):
    """SyftScanner implements IaC scanning using Syft."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = SyftScannerConfig()
        self.command = "syft"
        # self.tool_version = version("syft")
        super().model_post_init(context)

    def validate(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # Syft is a dependency this Python module, if the Python import got
        # this far then we know we're in a valid runtime for this scanner.
        return True

    def _process_config_options(self):
        # Syft config path
        possible_config_paths = [
            item
            for item in [
                self.config.options.config_file,
                ".syft.yaml",
                ".syft.yml",
            ]
            if item is not None
        ]

        for conf_path in possible_config_paths:
            if Path(conf_path).exists():
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config",
                        value=get_shortest_name(input=conf_path),
                    )
                )
                break

        # for item in self.config.options.additional_formats:
        #     self.args.extra_args.append(ToolExtraArg(key="--output", value=item))
        # for item in self.config.options.frameworks:
        #     self.args.extra_args.append(ToolExtraArg(key="--framework", value=item))
        # for item in self.config.options.skip_frameworks:
        #     self.args.extra_args.append(
        #         ToolExtraArg(key="--skip-framework", value=item)
        #     )
        for item in self.config.options.exclude:
            ASH_LOGGER.debug(
                f"Path '{item.path}' excluded from {self.config.name} scan for reason: {item.reason}"
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--skip-path",
                    value=item.path,
                )
            )

        return super()._process_config_options()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: SyftScannerConfig | None = None,
    ) -> CycloneDXReport:
        """Execute Syft scan and return results.

        Args:
            target: Path to scan

        Returns:
            CycloneDXReport: containing the SBOM findings and metadata.

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
            target_results_dir = Path(self.results_dir).joinpath(target_type)
            results_file = target_results_dir.joinpath("syft.cdx.json")
            self.config.options.exclude.extend(global_ignore_paths)

            self.args = ToolArgs(
                format_arg="--output",
                format_arg_value=f"cyclonedx-json={results_file.as_posix()}",
                scan_path_arg=None,
                extra_args=[
                    ToolExtraArg(
                        key="--base-path", value=self.context.source_dir.as_posix()
                    ),
                ],
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

            final_args = self._resolve_arguments(
                target=target,
            )
            self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
            )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            syft_results = {}
            Path(results_file).parent.mkdir(exist_ok=True, parents=True)
            with open(results_file, "r") as f:
                syft_results = json.load(f)
            try:
                sbom_report = CycloneDXReport.model_validate(syft_results)
                # sbom_report.runs[0].invocations = [
                #     Invocation(
                #         commandLine=final_args[0],
                #         arguments=final_args[1:],
                #         startTimeUtc=self.start_time,
                #         endTimeUtc=self.end_time,
                #         executionSuccessful=True,
                #         exitCode=self.exit_code,
                #         exitCodeDescription="\n".join(self.errors),
                #         workingDirectory=ArtifactLocation(
                #             uri=target.as_posix(),
                #         ),
                #         properties=PropertyBag(
                #             tool=sbom_report.runs[0].tool,
                #         ),
                #     )
                # ]
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to parse {self.__class__.__name__} results as CycloneDX: {str(e)}"
                )
                sbom_report = syft_results

            return sbom_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} scan failed: {str(e)}")


if __name__ == "__main__":
    scanner = SyftScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
    )
    report = scanner.scan(target=scanner.source_dir)

    report_json = report.model_dump_json(
        indent=2,
        by_alias=True,
        exclude_unset=True,
    )
    with open(
        Path.cwd().joinpath(".ash", "ash_output").joinpath("cfn_nag_results.sarif"), "w"
    ) as f:
        f.write(report_json)
