# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import streamlit as st
from pathlib import Path
import pandas as pd

from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    Phases,
    RunMode,
    Strategy,
    ExportFormat,
)
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.utils.get_ash_version import get_ash_version

# Set page configuration
st.set_page_config(
    page_title="Automated Security Helper",
    page_icon="🔒",
    layout="wide",
)

# App title and description
st.title("Automated Security Helper - UI")

st.write(
    "This is a UI for the Automated Security Helper. This interface is designed to help with running security scans with ASH, "
    "exploring the results emitted by ASH, and remediating findings with help from Agentic helpers."
)

# Version information
st.sidebar.info(f"ASH Version: {get_ash_version()}")

# Create tabs for different sections
tab1, tab2 = st.tabs(["Run Scan", "View Results"])

with tab1:
    # Main visible section - Source directory and Run button in the same row
    st.header("Run ASH Scan")

    # Create two columns - one for the source directory input and one for the run button
    col1, col2 = st.columns([1, 1])
    # Default values for hidden options
    default_output_dir = Path.cwd().joinpath(".ash", "ash_output").as_posix()
    output_dir = default_output_dir

    with col1:
        source_dir = st.text_input(
            "Source Directory",
            value=Path.cwd().as_posix(),
            help="The source directory to scan",
        )

    with col2:
        output_dir = st.text_input(
            "Output Directory",
            value=default_output_dir,
            help="The directory to output results to",
        )

    # All configuration options in collapsible sections
    with st.expander("Additional Scan Options", expanded=False):
        # Scanner Configuration
        st.subheader("Scanner Configuration")

        col1, col2 = st.columns(2)

        with col1:
            scanners_input = st.text_input(
                "Scanners to Run (comma-separated)",
                value="",
                help="Specific scanner names to run. Leave empty to run all scanners.",
            )
            scanners = (
                [s.strip() for s in scanners_input.split(",")] if scanners_input else []
            )

        with col2:
            exclude_scanners_input = st.text_input(
                "Scanners to Exclude (comma-separated)",
                value="",
                help="Specific scanner names to exclude from running. Takes precedence over scanners parameter.",
            )
            exclude_scanners = (
                [s.strip() for s in exclude_scanners_input.split(",")]
                if exclude_scanners_input
                else []
            )

        ash_plugin_modules_input = st.text_input(
            "ASH Plugin Modules (comma-separated)",
            value="",
            help="List of Python modules to import containing ASH plugins and/or event subscribers.",
        )
        ash_plugin_modules = (
            [s.strip() for s in ash_plugin_modules_input.split(",")]
            if ash_plugin_modules_input
            else []
        )

        # Execution Options
        st.subheader("Execution Options")

        col1, col2 = st.columns(2)

        with col1:
            offline = st.checkbox(
                "Offline Mode",
                value=False,
                help="Run scan in offline/airgapped mode (skips NPM/PNPM/Yarn Audit checks)",
            )

            if offline:
                offline_semgrep_rulesets = st.text_input(
                    "Offline Semgrep Rulesets",
                    value="p/ci",
                    help="Specify Semgrep rulesets for use in ASH offline mode",
                )
            else:
                offline_semgrep_rulesets = "p/ci"

            strategy = st.selectbox(
                "Execution Strategy",
                options=[s.value for s in Strategy],
                index=0,
                help="Whether to run scanners in parallel or sequential",
            )

        with col2:
            available_phases = [phase.value for phase in Phases]
            default_phases = [
                Phases.convert.value,
                Phases.scan.value,
                Phases.report.value,
            ]
            phases = st.multiselect(
                "Execution Phases",
                options=available_phases,
                default=default_phases,
                help="The phases to run",
            )

            inspect = st.checkbox(
                "Enable Inspection",
                value=False,
                help="Enable inspection of SARIF fields after running",
            )

            use_existing = st.checkbox(
                "Use Existing Results",
                value=False,
                help="Use an existing ash_aggregated_results.json file in the output-dir",
            )

            cleanup = st.checkbox(
                "Cleanup After Scan",
                value=False,
                help="Clean up 'converted' directory and other temporary files after scan completes",
            )

        # Output Format Options
        st.subheader("Output Format Options")

        available_formats = [fmt.value for fmt in ExportFormat]
        output_formats = st.multiselect(
            "Output Formats",
            options=available_formats,
            default=[],
            help="The output formats to use",
        )

        # Logging and Display Options
        st.subheader("Logging and Display Options")

        col1, col2 = st.columns(2)

        with col1:
            log_level = st.selectbox(
                "Log Level",
                options=[level.value for level in AshLogLevel],
                index=3,  # Default to INFO
                help="Set the log level",
            )

            show_summary = st.checkbox(
                "Show Summary",
                value=True,
                help="Show metrics table and results summary",
            )

        with col2:
            quiet = st.checkbox("Quiet Mode", value=False, help="Hide all log output")

            verbose = st.checkbox(
                "Verbose Mode", value=False, help="Enable verbose logging"
            )

            debug = st.checkbox("Debug Mode", value=False, help="Enable debug logging")

            color = st.checkbox(
                "Colorized Output", value=True, help="Enable/disable colorized output"
            )

        # Container Options
        st.subheader("Container Options")

        col1, col2 = st.columns(2)

        with col1:
            build = st.checkbox(
                "Build Container Image",
                value=True,
                help="Whether to build the ASH container image",
            )

            run = st.checkbox(
                "Run Container Image",
                value=True,
                help="Whether to run the ASH container image",
            )

            force = st.checkbox(
                "Force Rebuild",
                value=False,
                help="Force rebuild of the ASH container image",
            )

            oci_runner = st.text_input(
                "OCI Runner",
                value="",
                help="Use the specified OCI runner instead of docker to run the containerized tools",
            )
            if not oci_runner:
                oci_runner = None

        with col2:
            build_target = st.selectbox(
                "Build Target",
                options=["", BuildTarget.NON_ROOT.value, BuildTarget.CI.value],
                index=0,
                help="Specify the target stage of the ASH image to build",
            )
            if not build_target:
                build_target = None

            container_uid = st.text_input(
                "Container UID", value="", help="UID to use for the container user"
            )
            if not container_uid:
                container_uid = None

            container_gid = st.text_input(
                "Container GID", value="", help="GID to use for the container user"
            )
            if not container_gid:
                container_gid = None

        # Advanced container options
        ash_revision_to_install = st.text_input(
            "ASH Revision to Install",
            value="",
            help="ASH branch or tag to install in the container image for usage during containerized scans",
        )
        if not ash_revision_to_install:
            ash_revision_to_install = None

        custom_containerfile = st.text_input(
            "Custom Containerfile Path",
            value="",
            help="Path to a custom container definition (e.g. Dockerfile)",
        )
        if not custom_containerfile:
            custom_containerfile = None

        custom_build_arg_input = st.text_input(
            "Custom Build Arguments (comma-separated)",
            value="",
            help="Custom build arguments to pass to the container build",
        )
        custom_build_arg = (
            [arg.strip() for arg in custom_build_arg_input.split(",")]
            if custom_build_arg_input
            else []
        )

        # Run Mode and Additional Options
        st.subheader("Run Mode and Additional Options")

        col1, col2 = st.columns(2)

        with col1:
            mode = st.selectbox(
                "Execution Mode",
                options=[mode.value for mode in RunMode],
                index=2,  # Default to local
                help="Execution mode preset",
            )

            python_based_plugins_only = st.checkbox(
                "Python-Based Plugins Only",
                value=False,
                help="Exclude execution of any plugins or tools that have dependencies external to Python",
            )

        with col2:
            config = st.text_input(
                "Config File Path", value="", help="The path to the configuration file"
            )
            if not config:
                config = None

            fail_on_findings = st.radio(
                "Fail on Findings",
                options=["Default", "Yes", "No"],
                index=0,
                help="Enable/disable throwing non-successful exit codes if any actionable findings are found",
            )
            if fail_on_findings == "Yes":
                fail_on_findings = True
            elif fail_on_findings == "No":
                fail_on_findings = False
            else:
                fail_on_findings = None

    # Run Button - Prominently displayed outside the expander
    if st.button("Run ASH Scan", type="primary", use_container_width=False):
        with st.spinner("Running ASH scan..."):
            try:
                # Convert string values back to enum objects
                strategy_enum = Strategy(strategy)
                log_level_enum = AshLogLevel(log_level)
                mode_enum = RunMode(mode)
                phases_enum = [Phases(phase) for phase in phases]
                output_formats_enum = [ExportFormat(fmt) for fmt in output_formats]

                if build_target:
                    build_target_enum = BuildTarget(build_target)
                else:
                    build_target_enum = None

                # Call run_ash_scan with all parameters
                results = run_ash_scan(
                    source_dir=source_dir,
                    output_dir=output_dir,
                    config=config,
                    offline=offline,
                    offline_semgrep_rulesets=offline_semgrep_rulesets,
                    strategy=strategy_enum,
                    scanners=scanners,
                    exclude_scanners=exclude_scanners,
                    progress=False,
                    output_formats=output_formats_enum,
                    cleanup=cleanup,
                    phases=phases_enum,
                    inspect=inspect,
                    existing_results=(
                        Path(output_dir)
                        .joinpath("ash_aggregated_results.json")
                        .as_posix()
                        if use_existing
                        else None
                    ),
                    python_based_plugins_only=python_based_plugins_only,
                    log_level=log_level_enum,
                    quiet=quiet,
                    verbose=verbose,
                    debug=debug,
                    color=color,
                    fail_on_findings=False,
                    mode=mode_enum,
                    show_summary=show_summary,
                    simple=log_level == AshLogLevel.SIMPLE.value,
                    ash_plugin_modules=ash_plugin_modules,
                    # Container-specific params
                    build=build,
                    run=run,
                    force=force,
                    oci_runner=oci_runner,
                    build_target=build_target_enum,
                    container_uid=container_uid,
                    container_gid=container_gid,
                    ash_revision_to_install=ash_revision_to_install,
                    custom_containerfile=custom_containerfile,
                    custom_build_arg=custom_build_arg,
                )

                st.success("ASH scan completed successfully!")

                # Display results path
                st.info(f"Results saved to: {output_dir}")

                # Try to display aggregated results if available
                results_file = Path(output_dir) / "ash_aggregated_results.json"
                if results_file.exists():
                    st.session_state.results_path = results_file

            except Exception as e:
                st.error(f"Error running ASH scan: {str(e)}")
                st.error("Stack trace:")
                import traceback

                st.code(traceback.format_exc())

    # Display Markdown report if available
    st.header("Latest Scan Results Summary")

    # Determine the path to the markdown summary
    markdown_summary_path = Path(output_dir) / "reports" / "ash.summary.md"

    if markdown_summary_path.exists():
        st.info(f"Displaying summary from: {markdown_summary_path}")

        # Read the markdown content
        with open(markdown_summary_path, "r") as md_file:
            markdown_content = md_file.read()

        # Display the markdown content
        st.markdown(markdown_content)

        # Add download button for the markdown file
        with open(markdown_summary_path, "rb") as file:
            st.download_button(
                label="Download Markdown Summary",
                data=file,
                file_name="ash.summary.md",
                mime="text/markdown",
            )
    else:
        st.info(
            "No markdown summary available yet. Run a scan to generate a summary report."
        )

with tab2:
    st.header("Scan Results")

    # Allow user to select results file
    results_file = st.text_input(
        "Results File Path",
        value=(
            str(Path(output_dir) / "ash_aggregated_results.json")
            if "output_dir" in locals()
            else ""
        ),
        help="Path to the ASH results file",
    )

    if results_file and Path(results_file).exists():
        try:
            import json
            from automated_security_helper.config.ash_config import AshConfig
            from automated_security_helper.models.asharp_model import (
                AshAggregatedResults,
            )

            AshConfig.model_rebuild()
            AshAggregatedResults.model_rebuild()

            # Load results using the Pydantic model
            with open(results_file, "r") as f:
                results_data = json.load(f)
            results = AshAggregatedResults.model_validate(results_data)

            # Display basic scan information
            st.subheader("Scan Information")

            # Show scan metadata
            if results.metadata:
                col1, col2 = st.columns(2)
                with col1:
                    # Check if duration is available in a different format
                    if hasattr(results.metadata, "duration"):
                        st.metric("Scan Duration", f"{results.metadata.duration}s")
                    elif hasattr(results.metadata, "execution_time"):
                        st.metric(
                            "Scan Duration", f"{results.metadata.execution_time}s"
                        )
                    else:
                        # If no duration field is available, show something else
                        st.metric(
                            "Scanners Run",
                            (
                                len(results.scanner_results)
                                if hasattr(results, "scanner_results")
                                else "N/A"
                            ),
                        )

                with col2:
                    if hasattr(results.metadata, "scan_date"):
                        st.metric("Scan Date", results.metadata.scan_date)
                    elif hasattr(results.metadata, "timestamp"):
                        st.metric("Scan Date", results.metadata.timestamp)
                    else:
                        st.metric("Scan Date", "N/A")

                if (
                    hasattr(results.metadata, "source_dir")
                    and results.metadata.source_dir
                ):
                    st.info(f"Source Directory: {results.metadata.source_dir}")

            # Display findings using to_flat_vulnerabilities
            flat_vulns = results.to_flat_vulnerabilities()

            if flat_vulns:
                st.subheader(f"Findings ({len(flat_vulns)})")

                # Create a dataframe for better display
                findings_data = []
                for vuln in flat_vulns:
                    findings_data.append(
                        vuln.model_dump(
                            exclude_unset=True, exclude_none=True, by_alias=True
                        )
                    )

                if findings_data:
                    findings_df = pd.DataFrame(findings_data)
                    st.write(findings_df)

                    # Add severity filter
                    severity_options = ["All"] + sorted(
                        findings_df["severity"].unique().tolist()
                    )
                    selected_severity = st.selectbox(
                        "Filter by Severity", severity_options
                    )

                    if selected_severity != "All":
                        filtered_df = findings_df[
                            findings_df["severity"] == selected_severity
                        ]
                    else:
                        filtered_df = findings_df

                    # Add scanner filter
                    scanner_options = ["All"] + sorted(
                        findings_df["scanner"].unique().tolist()
                    )
                    selected_scanner = st.selectbox(
                        "Filter by Scanner", scanner_options
                    )

                    if selected_scanner != "All":
                        filtered_df = filtered_df[
                            filtered_df["scanner"] == selected_scanner
                        ]

                    # Display the filtered dataframe
                    st.dataframe(filtered_df)

                    # Show finding details when clicked
                    if st.checkbox("Show Finding Details"):
                        finding_index = st.number_input(
                            "Finding Index",
                            min_value=0,
                            max_value=len(flat_vulns) - 1,
                            value=0,
                        )
                        if 0 <= finding_index < len(flat_vulns):
                            st.json(flat_vulns[finding_index].dict())
                else:
                    st.success("No findings detected!")
            else:
                st.success("No findings detected!")

            # Display summary views in expandable sections
            with st.expander("View Simple Summary"):
                st.json(results.to_simple_dict())

            with st.expander("View Scanner Results"):
                st.json(results.scanner_results)

        except Exception as e:
            st.error(f"Error loading results: {str(e)}")
            st.error("Stack trace:")
            import traceback

            st.code(traceback.format_exc())
    else:
        st.info("No results file selected or file does not exist")

# Add footer with links
st.markdown("---")
st.markdown(
    "For more information, please visit the [ASH GitHub Repository](https://github.com/awslabs/automated-security-helper)"
)
