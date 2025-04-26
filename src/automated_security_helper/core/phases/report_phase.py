"""Implementation of the Report phase."""

from pathlib import Path
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.core.progress import ExecutionPhase
from automated_security_helper.core.plugin_registry import PluginRegistry, PluginType
from automated_security_helper.utils.log import ASH_LOGGER


class ReportPhase(EnginePhase):
    """Implementation of the Report phase."""

    @property
    def phase_name(self) -> str:
        """Return the name of this phase."""
        return "report"

    def execute(
        self, report_dir: Path, plugin_registry: PluginRegistry = None, **kwargs
    ) -> None:
        """Execute the Report phase.

        Args:
            report_dir(Path): The directory to save reports to.
            plugin_registry: Registry of plugins to use
            **kwargs: Additional arguments
        """
        ASH_LOGGER.debug("Entering: ReportPhase.execute()")
        report_dir.mkdir(parents=True, exist_ok=True)

        # Initialize progress
        self.initialize_progress("Starting report generation...")

        # Update progress
        self.update_progress(10, "Preparing report data...")

        # Print progress update
        ASH_LOGGER.info("Preparing report data...")

        # Create plugin context
        plugin_context = PluginContext(
            source_dir=self.source_dir,
            output_dir=self.output_dir,
            work_dir=self.work_dir,
        )

        # Get all registered reporter plugins
        registered_reporters = {}
        if plugin_registry:
            registered_reporters = plugin_registry.get_plugin(
                plugin_type=PluginType.reporter
            )

        if not registered_reporters:
            ASH_LOGGER.warning("No reporter plugins registered")
            self.update_progress(100, "No reporter plugins registered")
            return

        # Filter reporters based on configuration
        active_reporters = {}

        for reporter_name, reporter_plugin in registered_reporters.items():
            if reporter_plugin.enabled:
                ASH_LOGGER.verbose(f"Enabled reporter {reporter_name} from registry")
                active_reporters[reporter_plugin.name] = reporter_plugin.plugin_class(
                    config=reporter_plugin.plugin_config,
                    context=plugin_context,
                    source_dir=self.source_dir,
                    output_dir=self.output_dir,
                )
            else:
                ASH_LOGGER.warning(
                    f"Reporter {reporter_name} is disabled in config, skipping"
                )

        # First, check the reporters block in the config
        # if hasattr(self.config, "reporters") and self.config.reporters:
        #     for reporter_name, reporter_config in self.config.reporters.model_dump(mode="json").items():
        #         reporter_name = reporter_name.lower()
        #         if reporter_name in registered_reporters and reporter_config.enabled:
        #             # Get the reporter class from the registry
        #             reporter_plugin = registered_reporters[reporter_name]
        #             reporter_class = reporter_plugin.plugin_class

        #             # Create an instance with the context
        #             reporter_instance = reporter_class(context=plugin_context)

        #             # Configure the reporter with its config from the reporters block
        #             reporter_instance.configure(reporter_config)

        #             active_reporters[reporter_name] = {
        #                 "reporter": reporter_instance,
        #                 "name": reporter_plugin.name
        #             }
        #             ASH_LOGGER.verbose(f"Enabled reporter {reporter_name} from reporters config block")

        if not active_reporters:
            ASH_LOGGER.warning("No active reporters found")
            self.update_progress(100, "No active reporters found")
            return

        # Update progress
        self.update_progress(20, f"Found {len(active_reporters)} active reporters")

        ASH_LOGGER.info(
            f"Found {len(active_reporters)} active reporters: {', '.join(active_reporters.keys())}"
        )

        # Update progress
        self.update_progress(
            30,
            f"Generating reports in formats: {', '.join(active_reporters.keys())}",
        )

        ASH_LOGGER.info(
            f"Generating reports in formats: {', '.join(active_reporters.keys())}"
        )

        # Generate reports
        reporter_tasks = {}
        completed_reporters = 0
        total_reporters = len(active_reporters)
        report_dir.mkdir(parents=True, exist_ok=True)

        reporter: ReporterPluginBase
        for reporter_class_name, reporter in active_reporters.items():
            reporter_config: ReporterPluginConfigBase = reporter.config
            reporter_name = reporter_config.name
            fmt = reporter_config.extension

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

            ASH_LOGGER.verbose(f"Starting {fmt} report generation with {reporter_name}")

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

                # Determine output filename based on reporter's extension if available
                output_filename = f"ash.{fmt}"
                if hasattr(reporter, "config") and hasattr(
                    reporter.config, "extension"
                ):
                    output_filename = f"ash.{reporter.config.extension}"

                output_file = report_dir.joinpath(output_filename)
                ASH_LOGGER.verbose(f"Writing {fmt} report to {output_file}")
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
