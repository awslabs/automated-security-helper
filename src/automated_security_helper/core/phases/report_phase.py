"""Implementation of the Report phase."""

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.progress import ExecutionPhase
from automated_security_helper.utils.log import ASH_LOGGER


class ReportPhase(EnginePhase):
    """Implementation of the Report phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "report"

    def execute(self, **kwargs) -> None:
        """Execute the Report phase.

        Args:
            **kwargs: Additional arguments
        """
        ASH_LOGGER.debug("Entering: ReportPhase.execute()")

        # Initialize progress
        self.initialize_progress("Starting report generation...")

        # Update progress
        self.update_progress(10, "Preparing report data...")

        # Print progress update
        ASH_LOGGER.info("Preparing report data...")

        # Get output formats from config
        output_formats = getattr(self.config, "output_formats", [])
        if not output_formats:
            ASH_LOGGER.warning("No output formats specified in configuration")
            self.update_progress(100, "No output formats specified")
            return

        # Get the appropriate reporters
        from automated_security_helper.reporters.ash_default import (
            ASFFReporter,
            CSVReporter,
            CycloneDXReporter,
            HTMLReporter,
            JSONReporter,
            JUnitXMLReporter,
            SARIFReporter,
            SPDXReporter,
            TextReporter,
            YAMLReporter,
        )

        available_reporters = {
            "asff": {"reporter": ASFFReporter(), "name": "ASFF Reporter"},
            "csv": {"reporter": CSVReporter(), "name": "CSV Reporter"},
            "cyclonedx": {
                "reporter": CycloneDXReporter(),
                "name": "CycloneDX Reporter",
            },
            "html": {"reporter": HTMLReporter(), "name": "HTML Reporter"},
            "json": {"reporter": JSONReporter(), "name": "JSON Reporter"},
            "junitxml": {"reporter": JUnitXMLReporter(), "name": "JUnit XML Reporter"},
            "sarif": {"reporter": SARIFReporter(), "name": "SARIF Reporter"},
            "spdx": {"reporter": SPDXReporter(), "name": "SPDX Reporter"},
            "text": {"reporter": TextReporter(), "name": "Text Reporter"},
            "yaml": {"reporter": YAMLReporter(), "name": "YAML Reporter"},
        }

        # Filter reporters based on the configured output formats
        active_reporters = {}
        for fmt in output_formats:
            fmt_str = str(fmt).lower()
            if fmt_str in available_reporters:
                active_reporters[fmt_str] = available_reporters[fmt_str]

        if not active_reporters:
            ASH_LOGGER.warning(
                f"No matching reporters found for formats: {output_formats}"
            )
            self.update_progress(100, "No matching reporters found")
            return

        # Update progress
        self.update_progress(20, f"Found {len(active_reporters)} matching reporters")

        ASH_LOGGER.info(
            f"Found {len(active_reporters)} matching reporters for formats: {', '.join(output_formats)}"
        )

        # Update progress
        self.update_progress(
            30,
            f"Generating reports in formats: {', '.join([str(fmt) for fmt in output_formats])}",
        )

        ASH_LOGGER.info(
            f"Generating reports in formats: {', '.join([str(fmt) for fmt in output_formats])}"
        )

        # Generate reports
        reporter_tasks = {}
        completed_reporters = 0
        total_reporters = len(active_reporters)
        output_dir = self.output_dir.joinpath("reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt, reporter_info in active_reporters.items():
            reporter = reporter_info["reporter"]
            reporter_name = reporter_info["name"]

            # Create task for this reporter
            task_description = f"[magenta]({reporter_name}) Generating {fmt} report..."
            reporter_task = self.progress_display.add_task(
                phase=ExecutionPhase.REPORT, description=task_description, total=100
            )
            reporter_tasks[fmt] = reporter_task

            # Update reporter task to show it's starting
            self.progress_display.update_task(
                phase=ExecutionPhase.REPORT,
                task_id=reporter_task,
                completed=10,
                description=f"[blue]({reporter_name}) Starting {fmt} report generation...",
            )

            ASH_LOGGER.info(f"Starting {fmt} report generation with {reporter_name}")

            try:
                # Generate report with this reporter
                ASH_LOGGER.debug(f"Generating {fmt} report with {reporter_name}")

                # Update reporter task to show progress
                self.progress_display.update_task(
                    phase=ExecutionPhase.REPORT,
                    task_id=reporter_task,
                    completed=50,
                    description=f"[yellow]({reporter_name}) Generating {fmt} report...",
                )

                # Generate the report
                formatted = reporter.report(self.asharp_model)
                if formatted is None:
                    ASH_LOGGER.error(
                        f"Failed to format report with {fmt} reporter, returned empty string"
                    )
                    raise ValueError(f"Reporter returned empty result for {fmt}")

                # Write the report to a file
                output_filename = f"ash.{fmt}"
                if fmt == "cyclonedx":
                    output_filename = "ash.cdx.json"
                elif fmt == "junitxml":
                    output_filename = "ash.junit.xml"
                elif fmt == "sarif":
                    output_filename = "ash.sarif"
                elif fmt == "spdx":
                    output_filename = "ash.spdx.json"

                output_file = output_dir.joinpath(output_filename)
                ASH_LOGGER.info(f"Writing {fmt} report to {output_file}")
                output_file.write_text(formatted)

                # Update reporter task to show completion
                self.progress_display.update_task(
                    phase=ExecutionPhase.REPORT,
                    task_id=reporter_task,
                    completed=100,
                    description=f"[green]({reporter_name}) {fmt.upper()} report generated",
                )

                ASH_LOGGER.info(
                    f"✅ {fmt.upper()} report generated successfully with {reporter_name}"
                )

                # Update main report phase progress
                completed_reporters += 1
                progress_percent = 30 + ((completed_reporters / total_reporters) * 70)
                self.update_progress(
                    int(progress_percent),
                    f"Generated {completed_reporters}/{total_reporters} reports",
                )

            except Exception as e:
                ASH_LOGGER.error(
                    f"Error generating reports with {reporter_name}: {str(e)}"
                )
                self.progress_display.update_task(
                    phase=ExecutionPhase.REPORT,
                    task_id=reporter_task,
                    completed=100,
                    description=f"[red]({reporter_name}) Failed: {str(e)}",
                )

        # Update progress to 100%
        self.update_progress(
            100,
            f"Generated reports with {completed_reporters}/{total_reporters} reporters",
        )

        # Print completion message
        ASH_LOGGER.info(
            f"✅ Generated reports with {completed_reporters}/{total_reporters} reporters"
        )

        # Add summary row
        self.add_summary(
            "Complete",
            f"Generated reports with {completed_reporters}/{total_reporters} reporters",
        )
