"""Execution engine for security scanners."""

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import platform
import time
from typing import Any, List, Literal, Mapping, Optional, Set


from automated_security_helper.base.plugin_config import (
    declared_plugin_name,
    plugin_config_key,
    section_enabled,
    split_plugin_names,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.cancellation import (
    ScanCancelled,
    raise_if_cancelled,
)
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.scanner_selection import (
    community_scanner_refusal,
    refuse_selection_matching_no_scanner,
    selection_after_exclusions,
)
from automated_security_helper.core.metrics_table import display_metrics_table
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.utils.report_path_links import ensure_reports_dir
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.scanner_selection import SelectionOrigin
from automated_security_helper.core.phases.inspect_phase import InspectPhase
from automated_security_helper.core.progress import (
    ExecutionPhaseType,
    LiveProgressDisplay,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.discovery import discover_plugins
from automated_security_helper.plugins.plugin_manager import (
    masked_module_names,
    without_masked_modules,
)
from automated_security_helper.models.core import IgnorePathWithReason

# Define valid execution phases
from automated_security_helper.config.ash_config import (
    AshConfig,
)
from automated_security_helper.config.plugin_module_trust import (
    drop_untrusted_off_host_plugins,
    plugin_modules_by_trust,
)
from automated_security_helper.config.reporter_trust import (
    confine_declared_reporter_destinations,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.utils.error_text import (
    carry_environment_values,
    config_environment_values,
    error_text,
)
from automated_security_helper.utils.log import ASH_LOGGER


class ScanExecutionEngine:
    """Manages the execution of security scanners."""

    def __init__(
        self,
        context: PluginContext,
        # enabled_scanners is the list of scanner names that were explicitly passed
        # in from the Orchestrator. This allows ASH users to specify the scanners via CLI
        # at runtime for a more focused scan (e.g. during finding remediation where
        # there is only a single scanner failing, isolating scans to just that
        # scanner will allow quicker retesting until passing and a full scan can be )
        enabled_scanners: List[str] | None = None,
        # excluded_scanners is the list of scanner names that should be excluded from running
        # This takes precedence over enabled_scanners
        excluded_scanners: List[str] | None = None,
        strategy: Optional[ExecutionStrategy] = ExecutionStrategy.PARALLEL,
        asharp_model: Optional[AshAggregatedResults] = None,
        show_progress: bool = True,
        show_summary: bool = True,
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        color_system: Literal[
            "auto", "standard", "256", "truecolor", "windows"
        ] = "auto",
        verbose: bool = False,
        debug: bool = False,
        python_based_plugins_only: bool = False,
        simple_mode: bool = False,
        ash_plugin_modules: List[str] | None = None,
        output_formats: List[str] | None = None,
        shard_index: Optional[int] = None,
        shard_count: Optional[int] = None,
        changed_files: Optional[Set[Path]] = None,
        selection_origin: SelectionOrigin = "cli",
        plugin_module_names: Optional[Mapping[str, str]] = None,
    ):
        """Initialize the execution engine.

        Args:
            plugin_module_names: How the whole run names its plugin modules, for a
                run whose modules come from more than one config (a workspace's
                projects): merged with this config's own map, the masked form
                winning, so a name another project read from the environment is
                never printed by this engine's log lines.
            enabled_scanners: The scanner names to run, the ``--scanners`` allowlist.
                None and an empty list mean the same thing, no narrowing: every
                scanner runs. Nothing can be selected by an empty list; running
                nothing is refused instead (core.scanner_selection), because a
                scan that checked nothing would report itself clean.
            shard_index: Zero-based index of this shard, when one scan is split
                across several executors. Requires shard_count. Carried verbatim to
                ScanPhase, which validates the pair and computes the partition.
            shard_count: Total number of shards. Requires shard_index.
            selection_origin: Who made the scanner selection, "cli" or "mcp".
                The selection refusals made here, and ScanPhase's SKIPPED rows, name
                the flags or the MCP tool's parameters accordingly.
            changed_files: Resolved paths changed against the base ref, from
                --changed-files-only. Findings located outside them are dropped
                from the results before the summary counts and the reports are
                written. None: no filter. An empty set matches nothing.
            strategy: Execution strategy to use for scanner execution (default: PARALLEL)
            asharp_model: Optional AshAggregatedResults to use for results
            show_progress: Whether to show progress bars
            show_summary: Whether to show metrics table and results summary after scan completion
            global_ignore_paths: List of paths to ignore globally
            color_system: Color system to use for progress display
            verbose: Whether to show verbose output
            debug: Whether to show debug output
            discover_external_plugins: Whether to discover external plugins
            color_system: Color system to use for the console
            verbose: Enable verbose logging
            debug: Enable debug logging
        """
        # Rebind mutable defaults so each instance gets its own collections.
        if enabled_scanners is None:
            enabled_scanners = []
        if excluded_scanners is None:
            excluded_scanners = []
        if global_ignore_paths is None:
            global_ignore_paths = []
        if ash_plugin_modules is None:
            ash_plugin_modules = []
        if output_formats is None:
            output_formats = []

        # Set up logging and initial state
        ASH_LOGGER.debug("Initializing ScanExecutionEngine")
        if context is None:
            raise ValueError("Context must be provided")

        # Whether this engine built its results model, which decides whether
        # ensure_initialized may stamp the run's configuration onto it: a model
        # a caller passed (one loaded from an existing results file by
        # --use-existing, a library caller's own) records the configuration of
        # the scan that produced it, which this run's is not.
        self._built_model = asharp_model is None
        if asharp_model is None:
            asharp_model = AshAggregatedResults(
                name=f"ASH Scan {datetime.now().isoformat()}",
                description="Aggregated security scan results",
                ash_config=context.config,
            )
            # The reports name the project the configuration names. Left alone,
            # metadata.project_name is the model's placeholder "ASH", which every
            # report printed whatever the config said. A workspace project's
            # label replaces this in ASHScanOrchestrator._apply_metadata.
            configured = getattr(context.config, "project_name", None)
            if isinstance(configured, str) and configured.strip():
                from automated_security_helper.config.config_validator import (
                    record_of_metadata,
                )

                # A name the configuration read from the environment is named
                # by the reference its file wrote, as the results file records
                # it, so the reports this run writes match what `ash report`
                # renders from that file and hold no value.
                asharp_model.metadata.project_name = record_of_metadata(
                    context.config, {"project_name": configured.strip()}
                )["project_name"]
        self._asharp_model = asharp_model
        self._context = context
        self._scanners = {}
        self._scan_results = {}
        self._strategy = strategy
        self.show_progress = show_progress
        self.show_summary = show_summary
        self._initialized = False  # Track initialization state
        self._init_enabled_scanners = split_plugin_names(enabled_scanners)
        self._init_excluded_scanners = split_plugin_names(excluded_scanners)
        self._enabled_scanners = []

        ASH_LOGGER.debug(f"Raw enabled_scanners: {enabled_scanners}")
        ASH_LOGGER.debug(
            f"Processed _init_enabled_scanners: {self._init_enabled_scanners}"
        )
        ASH_LOGGER.debug(f"Raw excluded_scanners: {excluded_scanners}")
        ASH_LOGGER.debug(
            f"Processed _init_excluded_scanners: {self._init_excluded_scanners}"
        )
        self._global_ignore_paths = global_ignore_paths
        self._python_only = (
            python_based_plugins_only  # Store the python_based_plugins_only flag
        )
        self._simple_mode = simple_mode  # Store the simple_mode flag
        self._output_formats = output_formats  # CLI --output-formats
        # Stored unvalidated. ScanPhase._execute_phase is the single owner of both
        # the validation and the partition, because the names a shard is expressed
        # in are only knowable after scanner instantiation; a rule duplicated here
        # could start disagreeing with the one that decides what actually runs.
        self._shard_index = shard_index
        self._shard_count = shard_count
        self._changed_files = changed_files
        self._selection_origin: SelectionOrigin = selection_origin

        # Get debug and verbose flags from environment or config
        debug_flag = debug or os.environ.get("ASH_DEBUG", "").lower() in [
            "true",
            "1",
            "yes",
        ]
        verbose_flag = verbose or os.environ.get("ASH_VERBOSE", "").lower() in [
            "true",
            "1",
            "yes",
        ]

        # Discover external plugins if enabled
        ash_plugin_manager.set_context(self._context)

        # Load internal plugins first to ensure event handlers are registered.
        # Failures land in this run's record, never a process-wide one.
        from automated_security_helper.plugins.loader import load_internal_plugins

        # __init__ raised on a None context, so it is always set here.
        run_record = self._context.plugin_load_record
        load_internal_plugins(record=run_record)

        # Combine plugin modules from config and CLI parameters, entries split on
        # commas. The operator's (the CLI's, and the config entries its trusted
        # list names) are imported first, and the rest -- what a config inside
        # the scanned tree or one an MCP client delivered added -- each inside
        # untrusted_import, so that a later scan in this process that does not
        # load one of them is not offered the classes its import registered.
        operator_plugin_modules, untrusted_plugin_modules = plugin_modules_by_trust(
            self._context.config, ash_plugin_modules
        )
        # Both lists are split on commas, stripped and de-duplicated in order
        # (plugin_module_trust.split_plugin_modules), so the refusal, the imports
        # and the scan filter all see the same names whatever source gave them.
        # CLI parameters first, then the config's, so --ash-plugin-modules
        # "a_ash_plugins, b_ash_plugins" and ASH_PLUGIN_MODULES entries arrive
        # already split rather than as one module name.
        combined_plugin_modules = operator_plugin_modules + untrusted_plugin_modules

        # How this run names its plugin modules: an entry the config read from
        # the environment by its mask. The block below fills it when the scan
        # names any module; the registry lines further down read it too.
        shown: Mapping[str, str] = {}
        if len(combined_plugin_modules) > 0:
            # Import additional plugin modules
            from automated_security_helper.plugins.loader import (
                load_additional_plugin_modules,
                refuse_failed_plugin_imports,
                refuse_plugin_modules_outside_namespace,
            )

            # Before importing any of them: a name outside the plugin namespace
            # refuses the scan with exit 3, and nothing is imported. A named
            # module that then fails to import refuses it with exit 3 too, before
            # any scanner runs. An entry the config read from the environment is
            # named by its masked form, never the variable's value -- in the log
            # line below too, which otherwise puts the resolved value on the
            # console and in ash.log.
            from automated_security_helper.config.plugin_module_trust import (
                config_module_names,
                environment_only_plugin_modules,
                merged_module_names,
            )

            # With the run's own map merged in: in a workspace, a project that
            # writes a name literally prints it here otherwise, though another
            # project read the same name from the environment.
            shown = merged_module_names(
                config_module_names(self._context.config)
                if self._context.config
                else {},
                plugin_module_names,
            )
            ASH_LOGGER.info(
                "Loading plugin modules: "
                f"{[shown.get(name, name) for name in combined_plugin_modules]}"
            )
            refuse_plugin_modules_outside_namespace(
                combined_plugin_modules, shown=shown or None
            )
            if operator_plugin_modules:
                load_additional_plugin_modules(
                    operator_plugin_modules,
                    shown=shown or None,
                    record=run_record,
                    values=config_environment_values(self._context.config),
                )
                # Discover plugins from specified modules, past the ones the
                # loader already failed (refused below on the record). With the
                # run's env-read values: a failure raised here is a new
                # exception object, carrying none of the values the loader
                # redacts with, so its warning line is redacted from these.
                discover_plugins(
                    plugin_modules=operator_plugin_modules,
                    shown=shown or None,
                    failed=run_record,
                    values=config_environment_values(self._context.config),
                )
            for module_name in untrusted_plugin_modules:
                with ash_plugin_manager.untrusted_import(module_name):
                    load_additional_plugin_modules(
                        [module_name],
                        shown=shown or None,
                        record=run_record,
                        values=config_environment_values(self._context.config),
                    )
                    discover_plugins(
                        plugin_modules=[module_name],
                        shown=shown or None,
                        failed=run_record,
                        values=config_environment_values(self._context.config),
                    )
            # A configured module that failed to import refuses the scan, as a
            # misnamed one does above: the run has none of the plugins the
            # operator asked for.
            # The scan prints str(error), so the environment remedy for an entry
            # only ASH_PLUGIN_MODULES contributed is built into the message here.
            refuse_failed_plugin_imports(
                combined_plugin_modules,
                run_record,
                shown=shown or None,
                environment_only=environment_only_plugin_modules(
                    ash_plugin_modules,
                    getattr(self._context.config, "ash_plugin_modules", None),
                ),
            )
        ash_plugin_manager.trust_plugin_modules(operator_plugin_modules)
        # Config can override environment
        if self._context.config:
            if (
                hasattr(self._context.config, "debug")
                and self._context.config.debug is not None
            ):
                debug_flag = self._context.config.debug
            if (
                hasattr(self._context.config, "verbose")
                and self._context.config.verbose is not None
            ):
                verbose_flag = self._context.config.verbose

        # Initialize progress display with debug/verbose flags
        self.progress_display = LiveProgressDisplay(
            show_progress=show_progress,
            color_system=(
                "windows" if platform.system() == "Windows" else color_system
            ),
            verbose=verbose_flag,
            debug=debug_flag,
        )

        # Phase tracking
        self.current_phase = None
        self.phase_tasks = {
            ExecutionPhase.CONVERT: None,
            ExecutionPhase.SCAN: None,
            ExecutionPhase.REPORT: None,
            ExecutionPhase.INSPECT: None,
        }

        # Initialize basic configuration

        # Convert and set up paths
        self._context.source_dir = (
            Path(self._context.source_dir) if self._context.source_dir else None
        )
        try:
            # Log directory setup
            ASH_LOGGER.debug(f"Source directory: {self._context.source_dir}")
            ASH_LOGGER.debug(f"Output directory: {self._context.output_dir}")
            ASH_LOGGER.debug(f"Work directory: {self._context.work_dir}")

        except Exception as e:
            ASH_LOGGER.error(f"Failed to setup directories: {error_text(e)}")
            raise

        # Initialize base components
        self._completed_scanners = []
        self._results = self._asharp_model
        self._progress = None
        self._max_workers = min(32, (os.cpu_count() or 1) + 4)

        # Initialize scanner components
        self._scanners = {}
        self._registered_scanners = {}
        self._initialized = False

        # This scan's plugins: ASH's built-in ones plus those of the modules this
        # scan names, not everything the process-wide registry holds. A server
        # process (MCP) runs many scans, and any of them, or a tool, may have
        # loaded modules this run's configuration never listed; the filter
        # selects this scan's share of the registry. The handler filter decides
        # which event handlers it notifies: those of the same plugins, plus
        # handlers the program running the scan subscribed from outside the
        # plugin namespace. The phases this engine builds take the same handler
        # filter as their plugin_scope, so a phase-level event (SCAN_START,
        # SCAN_COMPLETE, every *_PHASE_START and *_PHASE_COMPLETE) reaches the
        # same handlers EXECUTION_START and EXECUTION_COMPLETE reach. The
        # phases used to be given plugins_of instead, which admits only the
        # plugin namespace, so a handler the program subscribed saw the
        # execution events and never a phase event.
        from automated_security_helper.plugins.loader import (
            masked_module_scope,
            scan_handler_filter,
            scan_plugin_filter,
        )

        self._plugin_filter = scan_plugin_filter(combined_plugin_modules)
        self._handler_filter = scan_handler_filter(combined_plugin_modules)
        # The registry is the process's, so the lines its reads write name a
        # plugin's module as the plugin recorded it. A module an entry read
        # from the environment is, or sits inside or above, is named by its
        # mask there too, as the load's own lines name it, inside a longer
        # module name as well.
        masked_scope = masked_module_scope(shown)
        with masked_module_names(masked_scope):
            self.plugins = {
                "converter": ash_plugin_manager.plugin_modules(
                    "converter", self._plugin_filter
                ),
                "scanner": ash_plugin_manager.plugin_modules(
                    "scanner", self._plugin_filter
                ),
                "reporter": ash_plugin_manager.plugin_modules(
                    "reporter", self._plugin_filter
                ),
            }
        for k, v in self.plugins.items():
            ASH_LOGGER.verbose(f"Discovered {len(v)} {k} plugins at runtime")
        # Logged, because a plugin left out here otherwise leaves no trace: no row,
        # no MISSING. The usual case is a module another scan in this process named;
        # the one to notice is a plugin a named package registers from another
        # package or a subpackage without importing or listing it. The count goes
        # to INFO and the names to DEBUG: ash.log records INFO, and in a process
        # running several scans (an MCP server) the names are what other scans
        # named.
        with masked_module_names(masked_scope):
            left_out = [
                (kind, plugin)
                for kind in ("converter", "scanner", "reporter")
                for plugin in ash_plugin_manager.plugin_modules(kind)
                if plugin not in self.plugins[kind]
            ]
        if left_out:
            ASH_LOGGER.info(
                f"{len(left_out)} registered plugin(s) not used by this scan, "
                "because no module in its ash_plugin_modules defines, imports or "
                "lists them. Run with --debug to see which."
            )
            # Built and masked only for a logger that writes it: each name is a
            # full redaction pass over the forms of every masked module. The
            # registry is the process's, so a plugin can come from a module
            # that another run's scope masked when it registered: each name is
            # also hidden under the forms its registration recorded.
            if ASH_LOGGER.isEnabledFor(logging.DEBUG):
                described = []
                with masked_module_names(masked_scope):
                    for kind, plugin in left_out:
                        recorded = ash_plugin_manager.masked_forms_of_module(
                            kind, plugin.__module__
                        )
                        with masked_module_names(recorded):
                            hidden = without_masked_modules(plugin.__module__)
                        described.append(f"{kind} {plugin.__name__} ({hidden})")
                names = ", ".join(described)
                ASH_LOGGER.debug(f"Registered plugins not used by this scan: {names}")

        # The registry is the process's, so it also holds what an earlier scan's
        # untrusted config loaded, in the MCP server and across a workspace's
        # projects. The filter above already took only the classes this scan's
        # own modules bring in; this second check drops any that only another
        # scan's untrusted import registered. The cached list stays whole for the
        # next scan.
        with masked_module_names(masked_scope):
            self.plugins = ash_plugin_manager.plugins_loaded_by(
                self.plugins, combined_plugin_modules
            )

        # A class from an off-host plugin package is selected only when this
        # scan's trusted modules load it: not when only an in-tree or delivered
        # config's module brought it in, nor when an earlier scan in this process
        # did. Without a config the defaults name no module.
        self.plugins = drop_untrusted_off_host_plugins(
            self._context.config, self.plugins, ash_plugin_modules
        )

        # The plugin modules are loaded, so every reporter's declared destination
        # options are known: those a config file in the scanned tree set are
        # replaced by the trusted base's before the report phase builds any reporter.
        if self._context.config is not None:
            confine_declared_reporter_destinations(
                self._context.config, self.plugins["reporter"]
            )

        # The first point where both the loaded plugins and the config exist, and
        # nothing has been converted or scanned yet. A built-in plugin's options
        # were already checked when the config loaded.
        if self._context.config is not None:
            from automated_security_helper.config.plugin_option_check import (
                refuse_unknown_plugin_options,
            )

            refuse_unknown_plugin_options(self._context.config, self.plugins)

        self.ensure_initialized(self._context.config)

    def get_scanner(
        self, scanner_name: str, check_enabled: bool = True
    ) -> ScannerPluginBase:
        """Get a scanner instance by name.

        Args:
            scanner_name: Name of the scanner to retrieve: its declared name
                (``bandit``, the key its config is looked up by), the name its
                configured section gives it (``scanners.bandit.name``, the name
                ScanPhase selects and reports it by) or its class name
                (``BanditScanner``), compared case-insensitively.
            check_enabled: If True, refuse a scanner this engine's selection
                leaves out: one named by the exclusion list, one the allowlist
                (when there is one) does not name, or one whose configured
                section disables it (``enabled: false``), which ScanPhase
                records SKIPPED.

        Returns:
            Scanner instance configured with current engine paths

        Raises:
            ValueError: If scanner does not exist or is not enabled
        """
        # Normalize scanner name
        lookup_name = scanner_name.lower().strip()
        if not lookup_name:
            ASH_LOGGER.warning("Scanner name cannot be empty")
            raise ValueError("Scanner name cannot be empty")

        # Get all scanner plugins
        scanner_plugins = self.plugins.get("scanner", [])

        # Find the scanner by name. Every spelling is accepted: the lookup used
        # to compare the lowercased class name only, so get_scanner("bandit"),
        # the name every other surface uses, raised "not found"; and it read the
        # declared name only, so a scanner the configuration renames
        # (scanners.bandit.name: my-bandit), which ScanPhase selects and reports
        # as my-bandit and which ensure_initialized judges the selection by, was
        # "not found" under that name and judged against the wrong one.
        for scanner_class in scanner_plugins:
            names = {
                getattr(scanner_class, "__name__", "Unknown").lower(),
                plugin_config_key(scanner_class).lower(),
            }
            configured = self._selectable_scanner_name(scanner_class)
            if configured is not None:
                names.add(configured.lower().strip())
            if lookup_name in names:
                # The documented check: the parameter was accepted and never
                # read, so an excluded or unselected scanner was returned.
                if check_enabled:
                    self._refuse_unselected_scanner(scanner_name, names, scanner_class)
                # Create and return the scanner instance
                scanner = scanner_class(
                    context=self._context,
                    config=(
                        self._context.config.get_plugin_config(
                            plugin_type="scanner",
                            plugin_name=plugin_config_key(scanner_class),
                        )
                        if self._context.config
                        else None
                    ),
                )
                return scanner

        # If we get here, the scanner wasn't found
        raise ValueError(f"Scanner {lookup_name} not found")

    def _refuse_unselected_scanner(
        self, scanner_name: str, names: Set[str], scanner_class: type
    ) -> None:
        """Raise ValueError when this engine's selection leaves the scanner out.

        *names* are the lowercased spellings the scanner answers to, the
        configured name among them. The exclusion list wins, as it does in
        ScanPhase; an allowlist that was given and names none of them leaves the
        scanner out too, and so does a configured section that disables the
        scanner (ScanPhase records such a scanner SKIPPED, "disabled in the
        configuration"). An empty allowlist means every scanner.
        """
        excluded = {name.lower().strip() for name in self._init_excluded_scanners}
        if names & excluded:
            raise ValueError(
                f"Scanner {scanner_name} is not enabled: it is named by the "
                "exclusion list"
            )
        enabled = {name.lower().strip() for name in self._init_enabled_scanners}
        if enabled and not names & enabled:
            raise ValueError(
                f"Scanner {scanner_name} is not enabled: the selection does not name it"
            )
        if not section_enabled(self._scanner_section(scanner_class)):
            raise ValueError(
                f"Scanner {scanner_name} is not enabled: its configuration "
                "disables it (enabled: false)"
            )

    def _scanner_section(self, plugin_class: type) -> Any:
        """The configured section of *plugin_class*, or None when there is none.

        A section that cannot be read (a config whose lookup raises) is None
        too: it names nothing and disables nothing, so the declared name and
        the enabled default stand, as ``_selectable_scanner_name`` reads them.
        """
        config = self._context.config
        if config is None:
            return None
        try:
            return config.get_plugin_config(
                plugin_type="scanner", plugin_name=plugin_config_key(plugin_class)
            )
        except Exception:  # noqa: BLE001 -- a section that cannot be read names nothing
            return None

    def _selectable_scanner_name(self, plugin_class: type) -> Optional[str]:
        """The name ``--scanners`` selects *plugin_class* by, or None.

        ScanPhase matches the selection against ``config.name`` on each
        instance, which the operator's configuration can set to something other
        than the name the class declares. The construction-time refusal has to
        compare the same names, so the configured section's ``name`` is read
        first (a dict section as well as a model) and the declared name is the
        fallback; a class that declares none answers None, which defers the
        refusal to the phase (see ensure_initialized).
        """
        declared = declared_plugin_name(plugin_class)
        section = self._scanner_section(plugin_class)
        if section is None:
            return declared
        if isinstance(section, dict):
            name = section.get("name")
        else:
            name = getattr(section, "name", None)
        if isinstance(name, str) and name:
            return name
        return declared

    def ensure_initialized(self, config: Optional[AshConfig] = None) -> None:
        """Ensure scanner factory and scanners are properly initialized.

        Args:
            config: ASH configuration object for initialization
        """
        if not self._initialized or (
            self._context.config is None and config is not None
        ):
            ASH_LOGGER.info("Initializing execution engine")
            if config is not None:
                self._context.config = config
            if not self._context.config or self._context.config is None:
                self._context.config = AshConfig(
                    project_name="ASH Default Project Config",
                )
            if not isinstance(self._context.config, AshConfig):
                raise ValueError("Configuration must be an AshConfig instance")
            # The results model was built in __init__ with the context's config
            # as it was then. A run that had none records the configuration it
            # actually ran with, the default substituted just above, instead of
            # None beside a run that used ASH's defaults. Only the model this
            # engine built: a model a caller passed records the configuration of
            # the scan that produced it (a results file whose ash_config is null
            # loads as None), and this run's configuration is not that one.
            if (
                self._built_model
                and self._asharp_model is not None
                and getattr(self._asharp_model, "ash_config", None) is None
            ):
                self._asharp_model.ash_config = self._context.config

            # Process excluded scanners - this takes precedence over enabled scanners
            if self._init_excluded_scanners:
                ASH_LOGGER.info(f"Excluding scanners: {self._init_excluded_scanners}")
            # Take the exclusions out of the allowlist here, the only layer that
            # still holds both lists as given: after the subtraction an allowlist
            # emptied by exclusions looks like one never given. One that cancels
            # itself is refused, in the caller's own terms and in the words the
            # workspace pre-flight uses (core.scanner_selection).
            self._init_enabled_scanners = selection_after_exclusions(
                self._init_enabled_scanners,
                self._init_excluded_scanners,
                self._selection_origin,
            )

            # An allowlist that names no registered scanner, refused here as well as
            # in ScanPhase: ASHScanOrchestrator builds the engine before it asks git
            # anything or clears the output directory, so a command line refused
            # here starts no process and deletes nothing. The names compared are
            # the ones ScanPhase matches as config.name on the instance: the
            # configured section's name where the operator set one, else the
            # name each class declares (_selectable_scanner_name). Compared
            # against the declared names alone, a scanner the configuration
            # renamed was refused as a misspelling of a name the phase accepts.
            #
            # Deferred to ScanPhase in the one shape only the phase can judge:
            # when any scanner class in scope declares no name, its selectable
            # name is config.name on an instance the phase alone constructs, so a
            # check keyed on the lowercased class name would refuse the configured
            # name the phase accepts; the workspace pre-check
            # (workspace.execution.refuse_unresolvable_scanner_selection) defers
            # the same way. A request naming a community scanner whose module
            # this run did not load is refused HERE, before anything is cleared,
            # with the module to add rather than spelling advice, in the one
            # text ScanPhase's backstop also raises
            # (core.scanner_selection.community_scanner_refusal), which names
            # any misspelled name beside the module. Nothing registered means
            # nothing to judge against: deferred, as every selection refusal
            # defers that case.
            if self._init_enabled_scanners:
                scanner_classes = list(self.plugins.get("scanner", []))
                declared_names = [
                    self._selectable_scanner_name(plugin_class)
                    for plugin_class in scanner_classes
                ]
                if scanner_classes and all(name is not None for name in declared_names):
                    refusal = community_scanner_refusal(
                        self._init_enabled_scanners, declared_names, scanner_classes
                    )
                    if refusal:
                        raise ScannerSelectionError(refusal)
                    refuse_selection_matching_no_scanner(
                        self._init_enabled_scanners,
                        declared_names,
                        self._selection_origin,
                    )

            # Mark initialization complete
            self._initialized = True

    def restrict_to_changed_files(self, changed_files: Optional[Set[Path]]) -> None:
        """Set the changed-file filter after construction; ``None`` means none.

        ASHScanOrchestrator.restrict_to_changed_files calls this for a caller that
        works the set out once the engine has been built.
        """
        self._changed_files = changed_files

    def _drop_findings_outside_changed_files(self) -> None:
        """Narrow the results to the --changed-files-only set, if one was given.

        Every scanner still scanned everything; this only removes findings whose
        location is outside the changed files, with the same filter workspace
        mode uses. Applied to the one model every reporter, the summary counts
        and the exit code read, so every report and the summary leave out the
        same findings that ash.sarif, the aggregated results and the exit code
        do. Idempotent, so the scan and report phases can both call it.
        """
        if self._changed_files is None or self._results is None:
            return
        from automated_security_helper.utils.changed_files import (
            filter_results_to_changed_files,
        )
        from automated_security_helper.utils.scan_output_dirs import (
            converted_sources_of,
        )

        # A finding in a converted file (a notebook's Python, an archive member)
        # is placed by the source the converter read, which the converters
        # recorded beside their output; the converted file itself is in the
        # output directory and never in the changed set.
        self._results = filter_results_to_changed_files(
            self._results,
            self._changed_files,
            self._context.source_dir,
            converted_sources=converted_sources_of(self._context),
        )
        self._asharp_model = self._results

    def _apply_final_suppressions(self) -> None:
        """The aggregated suppression pass, then the metrics that read it.

        Final suppression pass on the merged SARIF before anything reads it: the
        per-scanner passes can miss findings whose paths only become matchable
        after merge and normalization in the aggregated context. Run once per
        execution, at the end of the last phase that shapes the findings: the
        report arm when the run reports, else the scan arm, so a run without a
        report phase writes the same suppressed results a full scan does and
        takes its exit code from them. With --ignore-suppressions the pass lifts
        suppressions and ignore paths, not the exclusion of ASH's own output
        directory.

        The --changed-files-only narrowing runs AFTER the pass, here, and not
        before it: the pass records which suppressions matched, and a finding
        outside the changed files that was dropped first left its suppression
        recorded as unused (and warned about) although it matched the finding
        the scanner reported. The metrics are then rebuilt from what is left.
        """
        if self._results and self._results.sarif:
            from automated_security_helper.utils.sarif_utils import (
                apply_suppressions_to_sarif,
                exclude_output_dir_results,
            )

            if not self._context.ignore_suppressions:
                self._results.sarif = apply_suppressions_to_sarif(
                    sarif_report=self._results.sarif,
                    plugin_context=self._context,
                    used_suppressions=getattr(self._results, "used_suppressions", None),
                )
                # After the last suppression pass, once: a suppression path
                # ending in "/" matches no file.
                from automated_security_helper.utils.suppression_matcher import (
                    warn_unmatched_directory_suppressions,
                )

                # With the config: the warning quotes a path the config read
                # from the environment by its reference, as every other
                # message about a suppression does. Without it the record was
                # never built and this one warning printed the value.
                warn_unmatched_directory_suppressions(
                    self._context.config.global_settings.suppressions or [],
                    getattr(self._results, "used_suppressions", None) or (),
                    config=self._context.config,
                )
            else:
                self._results.sarif = exclude_output_dir_results(
                    sarif_report=self._results.sarif,
                    plugin_context=self._context,
                )

        # The --changed-files-only set, after the pass has seen every finding.
        self._drop_findings_outside_changed_files()

        # Refresh metrics after the final suppression pass so the exit code
        # reflects the post-suppression state.
        self._results = populate_metrics_from_unified_source(
            aggregated_results=self._results
        )
        self._asharp_model = self._results

    def _stamp_scan_timing(
        self, scan_start_time: datetime, scan_end_time: datetime, ordered_phases
    ) -> float:
        """Record this run's start, end and duration on the results; return the duration.

        A run that scanned stamps its own timing. A report over existing
        results (--use-existing) describes a scan that already ran, whose timing
        the stored summary carries; stamping the report run's own clock over it
        lost the scan's start, end and duration when the CLI rewrote the
        aggregated results file. Called before the report phase renders the
        model as well as when the run ends: the reporters read the model as it
        is, and stamped only at the end, every report written during a scan
        recorded start None, end None and duration 0.0 while the results file
        written afterwards carried the real values. A stamp this run made is
        this run's to stamp over: the pre-report stamp sets ``start``, so
        without that the final stamp of a report-only run over fresh results
        read ``start`` as set and left the pre-report end in place.
        """
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        stats = self._results.metadata.summary_stats
        if (
            "scan" in ordered_phases
            or stats.start is None
            or getattr(self, "_run_stamped_timing", False)
        ):
            stats.start = scan_start_time
            stats.end = scan_end_time
            stats.duration = scan_duration
            self._run_stamped_timing = True
        return scan_duration

    def execute_phases(
        self,
        phases: List[ExecutionPhaseType] | None = None,
    ) -> AshAggregatedResults:
        """Execute the specified phases in the correct order.

        Args:
            phases (List[ExecutionPhaseType], optional): The phases to execute.
                Defaults to ["convert", "scan", "report"].
            config (Optional[AshConfig], optional): An override configuration to be
                provided at the start of execution.
                Defaults to None.

        Returns:
            AshAggregatedResults: The results of the scan.
        """
        if phases is None:
            phases = ["convert", "scan", "report"]
        ASH_LOGGER.debug(f"Entering: ScanExecutionEngine.execute_phases({phases})")

        # Always execute phases in the correct order, regardless of input order
        ordered_phases = []
        if "convert" in phases:
            ordered_phases.append("convert")
        if "scan" in phases:
            ordered_phases.append("scan")
        if "report" in phases:
            ordered_phases.append("report")
        if "inspect" in phases:
            ordered_phases.append("inspect")

        ASH_LOGGER.info(f"Executing phases: {ordered_phases}")

        # Log a message to show progress is happening
        ASH_LOGGER.info("===== ASH Security Scan Starting =====")
        ASH_LOGGER.info(f"Executing phases: {', '.join(ordered_phases)}")

        # Record the start time for calculating scan duration. The monotonic
        # mark beside it gives the pre-report stamp its elapsed time without a
        # second wall-clock read: the run's clock is read exactly twice, at the
        # start and in the finally block, which is the contract the duration
        # tests pin with a two-value clock.
        scan_start_time = datetime.now(timezone.utc)
        scan_start_mark = time.monotonic()
        # Whether this run has stamped its timing yet (see _stamp_scan_timing):
        # a report over existing results keeps the stored timing, a stamp this
        # run made is stamped over by the final one.
        self._run_stamped_timing = False
        # Initialize duration variables so the finally block can reference
        # them even when the try block raises before computing them.
        hours = minutes = seconds = 0
        # If we're only running the report phase (likely with existing results),
        # we don't need to set up the work directory or clean anything up
        report_only = len(ordered_phases) in [1, 2] and ordered_phases[0] == "report"

        # Only create directories if we're not in report-only mode
        if not report_only:
            # Ensure work directory exists
            if self._context.work_dir:
                self._context.work_dir.mkdir(parents=True, exist_ok=True)

        # Always ensure reports directory exists, refusing a link there first.
        ensure_reports_dir(self._context.output_dir.joinpath("reports"))

        self.progress_display.start()

        # The values this run's config read from the environment. An event
        # handler is plugin code, and its failure text can quote any of them:
        # every line below that shows such a failure is redacted with them, and
        # an error leaving this method carries them for the run's handlers.
        values = config_environment_values(self._context.config)

        # Ctrl-C: the scan did not complete, so the finally block below says
        # neither that it did nor what it found.
        interrupted = False
        # A phase that raised: the run failed, and the finally block says so
        # instead of announcing a completed scan over partial results.
        failed = False
        try:
            # Notify execution start. Inside this try, whose finally is the one
            # place the Live display started above is stopped: a Ctrl-C or a
            # cancel while a start handler ran used to escape before the try and
            # leave the display running. A handler that raises anything else is
            # logged and the run goes on, as before.
            try:
                from automated_security_helper.plugins.events import AshEventType
                from automated_security_helper.plugins import ash_plugin_manager

                ash_plugin_manager.notify(
                    AshEventType.EXECUTION_START,
                    handler_filter=self._handler_filter,
                    phase="execution",
                    phases=ordered_phases,
                    plugin_context=self._context,
                    source_dir=self._context.source_dir,
                    output_dir=self._context.output_dir,
                    enabled_scanners=self._init_enabled_scanners,
                    excluded_scanners=self._init_excluded_scanners,
                    python_based_plugins_only=self._python_only,
                    strategy=self._strategy,
                    message=f"Starting ASH execution with phases: {', '.join(ordered_phases)}",
                )
            except (KeyboardInterrupt, ScanCancelled):
                raise
            except Exception as event_error:
                ASH_LOGGER.error(
                    f"Failed to notify execution start event: "
                    f"{error_text(event_error, values)}"
                )

            # Execute each phase in order using the new phase classes
            self._results = self._asharp_model
            # Recorded on the results, not only in this run's context: under
            # --ignore-suppressions no suppression is matched in any phase, and a
            # results file re-rendered later by `ash report`, whose context
            # carries no such flag, has to read the same way (the
            # unused-suppressions reporter reads metadata.suppressions_ignored
            # beside its context). Written before the phases so a run that stops
            # at the scan phase records it too; never written False, so a saved
            # record survives a later report-only run.
            if self._context.ignore_suppressions:
                self._results.metadata.suppressions_ignored = True
            for phase_name in ordered_phases:
                # A scan cancelled during one phase does not start the next, so a
                # cancel during the scan phase writes no reports. A no-op outside
                # a cancellable scan; see core/cancellation.py.
                raise_if_cancelled()
                ASH_LOGGER.info(f"\n----- Starting phase: {phase_name.upper()} -----")

                match phase_name:
                    case "convert":
                        # Create and execute the Convert phase
                        convert_phase = ConvertPhase(
                            plugins=self.plugins["converter"],
                            plugin_filter=self._handler_filter,
                            plugin_context=self._context,
                            progress_display=self.progress_display,
                            asharp_model=self._asharp_model,
                        )
                        self._results = convert_phase.execute(
                            aggregated_results=self._results,
                            python_based_plugins_only=self._python_only,
                        )

                    case "scan":
                        # Create and execute the Scan phase
                        scan_phase = ScanPhase(
                            plugins=self.plugins["scanner"],
                            plugin_filter=self._handler_filter,
                            plugin_context=self._context,
                            progress_display=self.progress_display,
                            asharp_model=self._asharp_model,
                        )

                        # The completed scanners are stored for metrics display
                        # even when the phase ends by raising (a cancel is a
                        # ScanCancelled), so the ones that finished before the
                        # end stay recorded. ScanPhase sets the list from
                        # construction, so a phase that ended before its own run
                        # started (a SCAN_PHASE_START handler raised) reads as
                        # none, and what it raised is what propagates.
                        try:
                            self._results = scan_phase.execute(
                                aggregated_results=self._results,
                                enabled_scanners=self._init_enabled_scanners,
                                excluded_scanners=self._init_excluded_scanners,
                                parallel=(self._strategy == ExecutionStrategy.PARALLEL),
                                max_workers=self._max_workers,
                                global_ignore_paths=self._global_ignore_paths,
                                python_based_plugins_only=self._python_only,  # Pass the python_based_plugins_only flag to the scan phase
                                shard_index=self._shard_index,
                                shard_count=self._shard_count,
                                selection_origin=self._selection_origin,
                            )
                        finally:
                            self._completed_scanners = scan_phase._completed_scanners
                        # Stamp shard provenance, so `ash merge` can verify
                        # coverage from the result files alone rather than being
                        # told out of band how many shards to expect. Taken from
                        # the phase rather than from self._shard_index/_count
                        # because the phase is what resolved the actual scanner
                        # names: copying the two integers here would record that a
                        # shard existed without recording what it covered, and
                        # verify_shard_coverage's overlap check needs the names.
                        #
                        # Assigned only when the phase produced one, so a
                        # non-sharded scan leaves metadata.shard as None. Assigning
                        # unconditionally would be a no-op today and would stay
                        # correct only as long as _shard_assignment is never given
                        # a non-None default.
                        #
                        # Read as a plain attribute, not via getattr with a
                        # fallback: ScanPhase.__init__ always sets it, so a
                        # fallback would only ever hide the case where a refactor
                        # stopped setting it -- and that case must not degrade to
                        # "silently stamp nothing", which is a partial scan
                        # reporting itself as whole.
                        if scan_phase._shard_assignment is not None:
                            self._results.metadata.shard = scan_phase._shard_assignment
                        # A run without a report phase writes these results and
                        # takes its exit code from them, so they are given the
                        # aggregated suppression pass (which narrows them to the
                        # --changed-files-only set after it) here: the pass used
                        # to run only in the report arm, so a run whose phases
                        # omit report wrote a results file and took an exit code
                        # that counted findings a full scan suppresses. A run
                        # that goes on to report takes the pass there, once.
                        if "report" not in ordered_phases:
                            self._apply_final_suppressions()

                    case "report":
                        # Before the counts and the reporters, so that every
                        # report, the summary and the verdict describe one set of
                        # findings. Also here, not only after "scan", for a report
                        # run over existing results.
                        self._apply_final_suppressions()
                        # And the timing so far, so the reports the phase writes
                        # carry a start and a duration instead of None and 0.0;
                        # the finally block stamps the final values. The end so
                        # far is the start plus the monotonic elapsed time, not a
                        # second wall-clock read (see scan_start_mark).
                        self._stamp_scan_timing(
                            scan_start_time,
                            scan_start_time
                            + timedelta(seconds=time.monotonic() - scan_start_mark),
                            ordered_phases,
                        )

                        # Create and execute the Report phase
                        report_phase = ReportPhase(
                            plugins=self.plugins["reporter"],
                            plugin_filter=self._handler_filter,
                            plugin_context=self._context,
                            progress_display=self.progress_display,
                            asharp_model=self._results,
                        )
                        self._results = report_phase.execute(
                            report_dir=self._context.output_dir.joinpath("reports"),
                            cli_output_formats=self._output_formats or None,
                            aggregated_results=self._results,
                            python_based_plugins_only=self._python_only,
                        )
                        self._asharp_model = self._results

                    case "inspect":
                        # Create and execute the Inspect phase
                        inspect_phase = InspectPhase(
                            plugins=[],  # No plugin support for the Inspect phase at this time.
                            plugin_filter=self._handler_filter,
                            plugin_context=self._context,
                            progress_display=self.progress_display,
                            asharp_model=self._asharp_model,
                        )
                        self._results = inspect_phase.execute(
                            aggregated_results=self._results,
                            python_based_plugins_only=self._python_only,
                        )
                        self._asharp_model = self._results

        except Exception as e:
            failed = True
            carry_environment_values(e, values)
            ASH_LOGGER.error(f"Execution failed: {error_text(e)}")
            ASH_LOGGER.info(f"\nExecution failed: {error_text(e)}")

            # Notify execution error
            try:
                from automated_security_helper.plugins.events import AshEventType
                from automated_security_helper.plugins import ash_plugin_manager

                ash_plugin_manager.notify(
                    AshEventType.ERROR,
                    handler_filter=self._handler_filter,
                    phase="execution",
                    error=error_text(e),
                    exception=e,
                    message=f"ASH execution failed: {error_text(e)}",
                )
            except (KeyboardInterrupt, ScanCancelled):
                # A Ctrl-C or a cancel while the error handlers ran: the sibling
                # arm below does not see an interrupt raised inside this one,
                # so it is marked here, or the finally block would notify
                # EXECUTION_COMPLETE and print the closing banner.
                interrupted = True
                raise
            except Exception as event_error:
                ASH_LOGGER.error(
                    f"Failed to notify execution error event: "
                    f"{error_text(event_error, values)}"
                )

            raise
        except (KeyboardInterrupt, ScanCancelled):
            # A cancelled run did not complete either: no EXECUTION_COMPLETE,
            # the display stops as interrupted, and no final table or model
            # rebuild below.
            interrupted = True
            raise
        finally:
            # Notify execution complete (whether successful or not), unless it was
            # interrupted: then it did not complete, and the caller says so.
            try:
                from automated_security_helper.plugins.events import AshEventType
                from automated_security_helper.plugins import ash_plugin_manager

                scan_end_time = datetime.now(timezone.utc)
                scan_duration = self._stamp_scan_timing(
                    scan_start_time, scan_end_time, ordered_phases
                )
                minutes, seconds = divmod(int(scan_duration), 60)
                hours, minutes = divmod(minutes, 60)

                if not interrupted:
                    # Notified for a failed run too (the handlers see every run
                    # end), but saying so: the message read "completed" over a
                    # run whose phase raised, and nothing in the event said
                    # otherwise.
                    outcome = "failed after" if failed else "completed in"
                    ash_plugin_manager.notify(
                        AshEventType.EXECUTION_COMPLETE,
                        handler_filter=self._handler_filter,
                        phase="execution",
                        plugin_context=self._context,
                        phases=ordered_phases,
                        results=self._results,
                        duration=scan_duration,
                        succeeded=not failed,
                        completed_scanners=getattr(self, "_completed_scanners", []),
                        message=f"ASH execution {outcome} {scan_duration:.1f}s",
                    )
            except Exception as event_error:
                ASH_LOGGER.error(
                    f"Failed to notify execution complete event: "
                    f"{error_text(event_error, values)}"
                )
            finally:
                # Stop progress display
                if (
                    hasattr(self.progress_display, "live")
                    and self.progress_display.live
                ):
                    self.progress_display.stop(interrupted=interrupted)

                # The closing banner. A failed run says it failed: the banner
                # read "Completed" over a run whose phase raised.
                if not self._simple_mode and not interrupted:
                    if hours > 0:
                        duration_str = f"{hours}h {minutes}m {seconds}s"
                    elif minutes > 0:
                        duration_str = f"{minutes}m {seconds}s"
                    else:
                        duration_str = f"{seconds}s"

                    if failed:
                        ASH_LOGGER.info(
                            f"===== ASH Security Scan Failed after {duration_str} ====="
                        )
                    else:
                        ASH_LOGGER.info(
                            f"===== ASH Security Scan Completed in {duration_str} ====="
                        )

                # The final metrics table, for a run that completed: the table
                # of a failed run's partial results read as that run's outcome
                # (a scanner that never ran showed no findings), and the
                # exception that is propagating is the run's report. Guarded,
                # because this runs inside a finally: an exception from the
                # metrics rebuild or the rendering replaced the one the run was
                # propagating, and turned a completed run into a failed one.
                if self._asharp_model and not interrupted and not failed:
                    try:
                        # Populate final metrics before displaying the table
                        # This ensures the metrics table shows the correct aligned data
                        updated_asharp_model = populate_metrics_from_unified_source(
                            aggregated_results=self._asharp_model
                        )
                        self._asharp_model = updated_asharp_model

                        # Get color setting from progress display
                        use_color = True
                        if hasattr(self.progress_display, "console") and hasattr(
                            self.progress_display.console, "color_system"
                        ):
                            use_color = (
                                self.progress_display.console.color_system is not None
                            )

                        # Always display the metrics table if show_summary is True
                        if self.show_summary:
                            display_metrics_table(
                                asharp_model=self._asharp_model,
                                source_dir=os.environ.get(
                                    "ASH_ACTUAL_SOURCE_DIR",
                                    self._context.source_dir.as_posix(),
                                ),
                                output_dir=os.environ.get(
                                    "ASH_ACTUAL_OUTPUT_DIR",
                                    self._context.output_dir.as_posix(),
                                ),
                                use_color=use_color,
                            )
                    except Exception as table_error:  # noqa: BLE001 -- a summary must not fail the run
                        ASH_LOGGER.error(
                            "The final metrics table could not be built or shown: "
                            f"{error_text(table_error, values)}"
                        )

        return self._results
