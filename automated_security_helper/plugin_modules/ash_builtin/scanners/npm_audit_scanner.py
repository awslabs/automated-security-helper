"""Module containing the NPM Audit security scanner implementation."""

import json
import logging
import os
from pathlib import Path
from typing import Annotated, Dict, List, Literal, Any

from pydantic import Field, model_validator
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    MultiformatMessageString,
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    ArtifactLocation,
    Location,
    PhysicalLocation,
    Region,
    Message,
    PropertyBag,
    ReportingDescriptor,
    Invocation,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.subprocess_utils import find_executable


class NpmAuditScannerConfigOptions(ScannerOptionsBase):
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached data",
        ),
    ] = str(os.environ.get("ASH_OFFLINE", "NO")).upper() in ["YES", "TRUE", "1"]


class NpmAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["npm-audit"] = "npm-audit"
    enabled: bool = True
    options: Annotated[
        NpmAuditScannerConfigOptions, Field(description="Configure NpmAudit scanner")
    ] = NpmAuditScannerConfigOptions()


@ash_scanner_plugin
class NpmAuditScanner(ScannerPluginBase[NpmAuditScannerConfig]):
    """NpmAuditScanner implements IaC scanning using `npm/yarn/pnpm audit` based on the lock files discovered in the source directory."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = NpmAuditScannerConfig()
        self.command = "npm"
        self.tool_type = "SCA"
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="json",
            output_arg="--file",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "NpmAuditScanner":
        """Set up custom installation commands for NPM."""
        # Get version and linux_type from config
        # Linux
        if "linux" not in self.custom_install_commands:
            self.custom_install_commands["linux"] = {}
        self.custom_install_commands["linux"]["amd64"] = []
        self.custom_install_commands["linux"]["arm64"] = []
        # macOS
        if "darwin" not in self.custom_install_commands:
            self.custom_install_commands["darwin"] = {}
        self.custom_install_commands["darwin"]["amd64"] = []
        self.custom_install_commands["darwin"]["arm64"] = []
        # Windows
        if "windows" not in self.custom_install_commands:
            self.custom_install_commands["windows"] = {}
        self.custom_install_commands["windows"]["amd64"] = []

        return self

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        found = find_executable(self.command)
        if found:
            self.tool_version = self._run_subprocess(
                command=[self.command, "--version"],
                stderr_preference="return",
                stdout_preference="return",
            ).get("stdout", "1.0.0")

        # If not found but we have non-empty custom install commands, return True to allow installation
        if found is None and self._has_install_commands():
            return True

        return found is not None

    def _has_install_commands(self) -> bool:
        """Check if scanner has non-empty custom install commands."""
        import platform
        import struct

        system = platform.system().lower()
        arch = "amd64" if struct.calcsize("P") * 8 == 64 else "arm64"

        if system in self.custom_install_commands:
            if arch in self.custom_install_commands[system]:
                return len(self.custom_install_commands[system][arch]) > 0
        return False

    def _process_config_options(self):
        return super()._process_config_options()

    def _convert_npm_audit_to_sarif(
        self, npm_audit_results: Dict[str, Any], target_path: Path
    ) -> SarifReport:
        """Convert npm audit results to SARIF format.

        Args:
            npm_audit_results: npm audit results in JSON format
            target_path: Path to the scanned directory

        Returns:
            SarifReport: SARIF report containing the scan findings
        """
        # Create the basic SARIF structure
        tool_component = ToolComponent(
            name="npm-audit",
            version=self.tool_version,
            informationUri="https://docs.npmjs.com/cli/v8/commands/npm-audit",
            rules=[],
        )

        # Create a dictionary to track unique rules
        rules_dict = {}

        # Create results list for SARIF
        results = []

        # Process vulnerabilities
        if "vulnerabilities" in npm_audit_results:
            for pkg_name, vuln_info in npm_audit_results["vulnerabilities"].items():
                # Get severity
                severity = vuln_info.get("severity", "moderate")

                # Map npm severity to SARIF level
                level_map = {
                    "critical": "error",
                    "high": "error",
                    "moderate": "warning",
                    "low": "note",
                    "info": "note",
                }
                level = level_map.get(severity, "warning")

                # Process each vulnerability path
                via_items = vuln_info.get("via", [])
                if not isinstance(via_items, list):
                    via_items = [via_items]

                for via in via_items:
                    # Skip if it's just a string reference to another package
                    if isinstance(via, str):
                        continue

                    # Extract vulnerability details
                    vuln_id = (
                        via.get("url", "").split("/")[-1]
                        if via.get("url")
                        else f"npm-{pkg_name}"
                    )
                    title = via.get("title", f"Vulnerability in {pkg_name}")
                    description = f"Vulnerability in {pkg_name}: {title}"

                    # Create a rule for this vulnerability if it doesn't exist
                    if vuln_id not in rules_dict:
                        rule = ReportingDescriptor(
                            id=vuln_id,
                            name=f"npm-audit-{vuln_id}",
                            shortDescription=MultiformatMessageString(text=title),
                            fullDescription=MultiformatMessageString(text=description),
                            helpUri=via.get("url", ""),
                            properties=PropertyBag(
                                tags=[
                                    "security",
                                    "npm-audit",
                                    severity,
                                    f"tool_name::{self.config.name}",
                                    f"tool_type::{self.tool_type or 'UNKNOWN'}",
                                ],
                                security_severity=via.get("cvss", {}).get("score", 0),
                            ),
                        )
                        rules_dict[vuln_id] = rule

                    # Find the package location
                    package_locations = []
                    for node_path in vuln_info.get("nodes", []):
                        # Convert node_modules path to a file location
                        rel_path = str(node_path).replace("node_modules/", "")
                        package_locations.append(rel_path)

                    # Create a result for this vulnerability
                    for pkg_location in package_locations:
                        result = Result(
                            ruleId=vuln_id,
                            level=level,
                            message=Message(
                                text=f"{title} in {pkg_name} {vuln_info.get('range', '*')}. {via.get('url', '')}"
                            ),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri=f"node_modules/{pkg_location}/package.json"
                                        ),
                                        region=Region(startLine=1, startColumn=1),
                                    )
                                )
                            ],
                            properties=PropertyBag(
                                package_name=pkg_name,
                                installed_version=vuln_info.get("range", "*"),
                                vulnerable_versions=vuln_info.get("range", "*"),
                                recommendation=f"Update {pkg_name} to a non-vulnerable version",
                                severity=severity,
                                cwe=via.get("cwe", []),
                                cvss=via.get("cvss", {}),
                                fix_available=vuln_info.get("fixAvailable", False),
                            ),
                        )
                        results.append(result)

        # Add all rules to the tool component
        tool_component.rules = list(rules_dict.values())

        # Create the SARIF report
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=results,
                    invocations=[
                        Invocation(
                            commandLine="npm audit --json",
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target_path)
                            ),
                        )
                    ],
                    properties=PropertyBag(
                        metrics=npm_audit_results.get("metadata", {}).get(
                            "vulnerabilities", {}
                        )
                    ),
                )
            ],
        )

        return sarif_report

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] = [],
        config: NpmAuditScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute NpmAudit scan and return results.

        Args:
            target: Path to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        tool_component = ToolComponent(
            name="npm-audit",
            version=self.tool_version,
            informationUri="https://docs.npmjs.com/cli/v8/commands/npm-audit",
            rules=[],
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine="npm audit --json",
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=20,
                append_to_stream="stderr",  # This will add the message to self.errors
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return sarif_report

        try:
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
        except ScannerError as exc:
            raise exc

        if not self.dependencies_satisfied:
            # Logging of this has been done in the central self._pre_scan() method.
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results.json")
            results_file.parent.mkdir(exist_ok=True, parents=True)

            # Find all files to scan from the scan set
            orig_scannable = (
                [item for item in self.context.work_dir.glob("**/*.*")]
                if target_type == "converted"
                else scan_set(
                    source=self.context.source_dir,
                    output=self.context.output_dir,
                    # filter_pattern=r"\.(yaml|yml|json)$",
                )
            )

            scannable = []
            for f in orig_scannable:
                pf = Path(f)
                if pf.name == "package.json":
                    # if (
                    #     pf.name in [
                    #         "package-lock.json",
                    #         "yarn.lock",
                    #         "pnpm-lock.yaml",
                    #     ]
                    # ):
                    scannable.append(pf.as_posix())
            joined_files = "\n- ".join(scannable)
            self._plugin_log(f"Found {len(scannable)} package locks:\n- {joined_files}")

            if len(scannable) == 0:
                self._plugin_log(
                    f"No package lock files found in {target_type} directory to scan. Returning.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return sarif_report

            # Run npm audit for each package.json file
            all_results = {}
            lock_files = [
                "yarn.lock",
                "pnpm-lock.yaml",
                "package-lock.json",
            ]
            for item in scannable:
                package_file = Path(item)
                lock_file = None
                for item in lock_files:
                    lf_path = package_file.parent.joinpath(item)
                    if lf_path.exists():
                        lock_file = lf_path
                        break
                if lock_file is not None:
                    package_dir = package_file.parent

                    try:
                        # Run npm audit
                        if lock_file.name == "yarn.lock":
                            binary = "yarn"
                        elif lock_file.name == "pnpm-lock.yaml":
                            binary = "pnpm"
                        else:
                            binary = "npm"

                        cmd = [binary, "audit", "--json"]

                        # Add offline mode if enabled
                        if self.config.options.offline:
                            cmd.append("--offline")
                            ASH_LOGGER.info(
                                f"🔄 Running {binary} audit in offline mode"
                            )

                            # Validate offline mode requirements
                            from automated_security_helper.utils.offline_mode_validator import (
                                validate_npm_audit_offline_mode,
                            )

                            offline_valid, offline_messages = (
                                validate_npm_audit_offline_mode()
                            )
                            if not offline_valid:
                                ASH_LOGGER.warning(
                                    "npm audit offline mode validation failed, but continuing with scan"
                                )

                        result = self._run_subprocess(
                            command=cmd,
                            results_dir=target_results_dir,
                            stdout_preference="both",
                            stderr_preference="both",
                        )
                        ASH_LOGGER.info(result)

                        # npm audit returns non-zero exit code when vulnerabilities are found
                        # but we still want to process the output
                        if result.get("stdout", None):
                            try:
                                audit_results = json.loads(result.get("stdout", None))
                                # Merge results
                                if not all_results:
                                    all_results = audit_results
                                else:
                                    # Merge vulnerabilities
                                    if "vulnerabilities" in audit_results:
                                        all_results.setdefault(
                                            "vulnerabilities", {}
                                        ).update(audit_results["vulnerabilities"])
                                    # Update metadata
                                    if "metadata" in audit_results:
                                        for key, value in audit_results[
                                            "metadata"
                                        ].items():
                                            if key in all_results.get("metadata", {}):
                                                if isinstance(value, dict):
                                                    all_results["metadata"][key].update(
                                                        value
                                                    )
                                                elif isinstance(value, (int, float)):
                                                    all_results["metadata"][key] += (
                                                        value
                                                    )
                                            else:
                                                all_results.setdefault("metadata", {})[
                                                    key
                                                ] = value
                            except json.JSONDecodeError:
                                ASH_LOGGER.warning(
                                    f"Failed to parse npm audit output for {package_dir}"
                                )
                    except Exception as e:
                        ASH_LOGGER.warning(
                            f"Failed to run npm audit in {package_dir}: {str(e)}"
                        )

            # Save the combined results
            if all_results:
                Path(results_file).parent.mkdir(exist_ok=True, parents=True)
                Path(results_file).write_text(json.dumps(all_results, default=str))

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            # Convert npm audit results to SARIF
            if all_results:
                sarif_report = self._convert_npm_audit_to_sarif(all_results, target)

                # Save SARIF report
                sarif_file = target_results_dir.joinpath("results_sarif.sarif")
                with open(sarif_file, mode="w", encoding="utf-8") as f:
                    f.write(
                        sarif_report.model_dump_json(
                            exclude_none=True,
                            exclude_unset=True,
                        )
                    )

                return sarif_report
            else:
                # Return empty SARIF report
                return SarifReport(
                    version="2.1.0",
                    runs=[
                        Run(
                            tool=Tool(
                                driver=ToolComponent(
                                    name="npm-audit",
                                    version="1.0.0",
                                    informationUri="https://docs.npmjs.com/cli/v8/commands/npm-audit",
                                )
                            ),
                            results=[],
                            invocations=[
                                Invocation(
                                    commandLine="npm audit --json",
                                    executionSuccessful=True,
                                    workingDirectory=ArtifactLocation(
                                        uri=get_shortest_name(input=target)
                                    ),
                                )
                            ],
                        )
                    ],
                )

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"NpmAudit scan failed: {str(e)}")


if __name__ == "__main__":
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    AshConfig.model_rebuild()
    ASH_LOGGER.debug("Running NpmAuditScanner via __main__")
    scanner = NpmAuditScanner(
        context=PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        )
    )
    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    if report:
        print(
            report.model_dump_json(
                indent=2,
                by_alias=True,
                exclude_unset=True,
            )
        )
