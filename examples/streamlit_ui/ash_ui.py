# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import streamlit as st
from pathlib import Path
import pandas as pd
import json
import os
import boto3
import configparser
from typing import Dict, List, Optional, Any

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

# Initialize session state variables for global configuration
if "source_dir" not in st.session_state:
    st.session_state.source_dir = Path.cwd().as_posix()
if "output_dir" not in st.session_state:
    st.session_state.output_dir = Path.cwd().joinpath(".ash", "ash_output").as_posix()
if "results_file" not in st.session_state:
    st.session_state.results_file = (
        Path(st.session_state.output_dir)
        .joinpath("ash_aggregated_results.json")
        .as_posix()
    )

# Import the Bedrock helper from relative


class BedrockHelper:
    """Helper class for interacting with Amazon Bedrock"""

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None):
        """Initialize the Bedrock helper

        Args:
            region: AWS region where Bedrock is available
            profile: AWS profile name to use (optional)
        """
        self.region = region
        self.profile = profile
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.bedrock_runtime = self.session.client("bedrock-runtime")
        self.bedrock = self.session.client("bedrock")
        self.available_models = []

    def get_available_models(self) -> List[Dict[str, Any]]:
        """Get available foundation models in the current region

        Returns:
            List of available models with their details, including inference profile ARNs for models
            that only support inference profiles
        """
        try:
            final_model_list = []
            inference_profiles = self.bedrock.list_inference_profiles()
            model_profile_map = {}
            for profile in inference_profiles.get("inferenceProfileSummaries", []):
                for model in [
                    item
                    for item in profile.get("models", [])
                    if item.get("modelArn", None) is not None
                ]:
                    model_profile_map[model["modelArn"]] = profile
            print("Fetching available foundation models...")
            # Get foundation models
            response = self.bedrock.list_foundation_models()
            active_models = [
                item
                for item in response.get("modelSummaries", [])
                if item.get("modelLifecycle", {}).get("status", "NA") == "ACTIVE"
                and "TEXT" in item.get("inputModalities", [])
                and "TEXT" in item.get("outputModalities", [])
            ]
            print(f"Found {len(active_models)} active foundation models")
            for model in active_models:
                if "ON_DEMAND" in model.get("inferenceTypesSupported", []):
                    final_model_list.append(
                        {
                            "modelId": model.get("modelId", "unknown"),
                            "modelName": model.get("modelName", "unknown"),
                            "modelArn": model.get("modelArn", "unknown"),
                            "providerName": model.get("providerName", "unknown"),
                            "inferenceType": "ON_DEMAND",
                        }
                    )
                if "INFERENCE_PROFILE" in model.get("inferenceTypesSupported", []):
                    if model.get("modelArn", "unknown") not in model_profile_map:
                        # Unable to find the inference profile ID!
                        continue
                    final_model_list.append(
                        {
                            "modelId": model_profile_map[
                                model.get("modelArn", "unknown")
                            ]["inferenceProfileId"],
                            "modelName": model.get("modelName", "unknown"),
                            "modelArn": model.get("modelArn", "unknown"),
                            "providerName": model.get("providerName", "unknown"),
                            "inferenceType": "INFERENCE_PROFILE",
                        }
                    )

            self.available_models = final_model_list
            return self.available_models
        except Exception as e:
            print(f"Error getting available models: {str(e)}")
            return []
        except Exception as e:
            print(f"Error getting available models: {str(e)}")
            return []

    @staticmethod
    def get_available_profiles() -> List[str]:
        """Get available AWS profiles from credentials file

        Returns:
            List of profile names
        """
        profiles = ["default"]
        try:
            # Check for credentials file
            credentials_path = os.path.expanduser("~/.aws/credentials")
            if os.path.exists(credentials_path):
                config = configparser.ConfigParser()
                config.read(credentials_path)
                profiles = config.sections()
                if "default" not in profiles:
                    profiles.insert(0, "default")

            # Check for config file
            config_path = os.path.expanduser("~/.aws/config")
            if os.path.exists(config_path):
                config = configparser.ConfigParser()
                config.read(config_path)
                for section in config.sections():
                    if section.startswith("profile "):
                        profile_name = section[8:]  # Remove "profile " prefix
                        if profile_name not in profiles:
                            profiles.append(profile_name)
        except Exception as e:
            print(f"Error reading AWS profiles: {str(e)}")

        return profiles

    def analyze_finding(
        self,
        finding: Dict[str, Any],
        file_content: Optional[str] = None,
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
    ) -> Dict[str, str]:
        """Analyze a security finding and recommend fixes

        Args:
            finding: The finding data
            file_content: Optional content of the file with the finding
            model_id: The Bedrock model ID or inference profile ARN to use

        Returns:
            Dictionary with analysis and recommendation
        """
        # Build the user message content
        user_message_content = f"""I'm analyzing a security finding from the Automated Security Helper (ASH) tool.
Please provide a detailed analysis of this finding and recommend specific fixes.

FINDING DETAILS:
- Title: {finding.get("title", "Unknown")}
- Severity: {finding.get("severity", "Unknown")}
- Scanner: {finding.get("scanner", "Unknown")}
- File: {finding.get("file_path", "Unknown")}
- Line: {finding.get("line", "Unknown")}
- Description: {finding.get("description", "Unknown")}
- CWE: {finding.get("cwe", "Unknown")}
"""

        if file_content:
            user_message_content += f"""
FILE CONTENT:
```
{file_content}
```
"""

        user_message_content += """
Please provide:
1. A brief explanation of why this is a security concern
2. The potential impact if exploited
3. Specific code changes to fix the issue (with before/after examples)
4. Additional security best practices related to this finding

Format your response in markdown.
"""

        try:
            # Log the request
            print(f"Generating message with model {model_id}")
            print(f"Model ID type: {type(model_id)}")

            # Use the converse API for all text models (not just Claude)
            # The converse API is the recommended approach for all text generation models
            print(f"Using converse API for model: {model_id}")

            # Create messages array for the conversation - content must be a list of message parts
            messages = [{"role": "user", "content": [{"text": user_message_content}]}]

            # System prompt must also be a list of message parts
            system = [
                {
                    "text": "You are a security expert specializing in code security analysis. Your task is to analyze security findings from the Automated Security Helper (ASH) tool and provide detailed, actionable recommendations to fix the issues. Focus on practical solutions and best practices."
                }
            ]

            # Inference parameters
            temperature = 0.5

            # Base inference config
            inference_config = {"temperature": temperature}

            # Additional model fields - customize based on model type
            additional_model_fields = {}

            # Add model-specific parameters
            if "claude" in model_id.lower():
                # Claude models support top_k
                additional_model_fields["top_k"] = 200
            # Add other model-specific parameters as needed
            # elif "nova" in model_id.lower():
            #    additional_model_fields["specific_nova_param"] = value

            try:
                print(f"Sending converse request to model: {model_id}")

                # Prepare the converse API call
                converse_args = {
                    "modelId": model_id,
                    "messages": messages,
                    "system": system,
                    "inferenceConfig": inference_config,
                }

                # Only add additionalModelRequestFields if we have any
                if additional_model_fields:
                    converse_args["additionalModelRequestFields"] = (
                        additional_model_fields
                    )

                # Use the converse API
                response = self.bedrock_runtime.converse(**converse_args)
                print("Converse request successful")

                # Extract the response content
                if (
                    response
                    and "output" in response
                    and "message" in response["output"]
                ):
                    message = response["output"]["message"]
                    if "content" in message:
                        content_list = message["content"]
                        # Combine all text parts
                        full_text = ""
                        for content_item in content_list:
                            if "text" in content_item:
                                full_text += content_item["text"]
                        return {"analysis": full_text}

                print(f"Response structure: {response.keys() if response else 'None'}")
                return {
                    "analysis": "No content found in the response. Raw response: "
                    + str(response)
                }
            except Exception as e:
                print(f"Error in converse API: {str(e)}")
                return {"analysis": f"Error using converse API: {str(e)}"}

        except Exception as e:
            import traceback

            error_details = traceback.format_exc()
            return {
                "analysis": f"Error invoking Bedrock model: {str(e)}\n\nDetails: {error_details}"
            }

    def get_file_content(self, file_path: str, source_dir: str) -> Optional[str]:
        """Get the content of a file

        Args:
            file_path: Path to the file
            source_dir: Source directory

        Returns:
            File content or None if file not found
        """
        try:
            # Handle both absolute and relative paths
            if Path(file_path).is_absolute():
                full_path = Path(file_path)
            else:
                full_path = Path(source_dir) / file_path

            print(f"Attempting to read file: {full_path}")

            if full_path.exists():
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                    print(
                        f"Successfully read file: {full_path}, content length: {len(content)}"
                    )
                    return content
            else:
                print(f"File not found: {full_path}")

                # Try alternative paths if the direct path doesn't work
                alt_paths = [
                    Path(source_dir)
                    / Path(file_path).name,  # Just the filename in source dir
                    Path(file_path.lstrip("/")),  # Remove leading slash
                ]

                for alt_path in alt_paths:
                    print(f"Trying alternative path: {alt_path}")
                    if alt_path.exists():
                        with open(
                            alt_path, "r", encoding="utf-8", errors="replace"
                        ) as f:
                            content = f.read()
                            print(
                                f"Successfully read file from alternative path: {alt_path}"
                            )
                            return content

            return None
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            return None


# Set page configuration
st.set_page_config(
    page_title="Automated Security Helper",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# App title and description
st.title("Automated Security Helper - UI")

st.write(
    "This is a UI for the Automated Security Helper. This interface is designed to help with running security scans with ASH, "
    "exploring the results emitted by ASH, and remediating findings with help from Agentic helpers."
)

# Version information
st.sidebar.info(f"ASH Version: {get_ash_version()}")

# Global configuration in sidebar
st.sidebar.header("Global Configuration")
st.session_state.source_dir = st.sidebar.text_input(
    "Source Directory",
    value=st.session_state.source_dir,
    help="The source directory to scan",
)
st.session_state.output_dir = st.sidebar.text_input(
    "Output Directory",
    value=st.session_state.output_dir,
    help="The directory to output results to",
)
st.session_state.results_file = st.sidebar.text_input(
    "Results File",
    value=Path(st.session_state.output_dir)
    .joinpath("ash_aggregated_results.json")
    .as_posix(),
    help="Path to the ASH results file",
)

# Initialize Bedrock helper in session state if not already present
if "bedrock_helper" not in st.session_state:
    st.session_state.bedrock_helper = None

# Create tabs for different sections
tab1, tab2, tab3 = st.tabs(["Run Scan", "View Results", "AI Analysis"])

with tab1:
    # Main visible section - Source directory and Run button in the same row
    st.header("Run ASH Scan")

    # Create two columns - one for the source directory input and one for the run button
    col1, col2 = st.columns([1, 1])
    # Default values from session state
    source_dir = st.session_state.source_dir
    output_dir = st.session_state.output_dir

    with col1:
        # Use session state values as defaults
        source_dir = st.text_input(
            "Source Directory",
            value=st.session_state.source_dir,
            help="The source directory to scan",
            key="tab1_source_dir",
        )
        # Update session state when changed
        if source_dir != st.session_state.source_dir:
            st.session_state.source_dir = source_dir

    with col2:
        output_dir = st.text_input(
            "Output Directory",
            value=st.session_state.output_dir,
            help="The directory to output results to",
            key="tab1_output_dir",
        )
        # Update session state when changed
        if output_dir != st.session_state.output_dir:
            st.session_state.output_dir = output_dir
            st.session_state.results_file = (
                Path(output_dir).joinpath("ash_aggregated_results.json").as_posix()
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
        value=st.session_state.results_file,
        help="Path to the ASH results file",
        key="tab2_results_file",
    )

    # Update session state when changed
    if results_file != st.session_state.results_file:
        st.session_state.results_file = results_file

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

                            # Store the selected finding in session state for AI analysis
                            st.session_state.selected_finding = flat_vulns[
                                finding_index
                            ]
                            st.session_state.source_dir = (
                                results.metadata.source_dir
                                if hasattr(results.metadata, "source_dir")
                                else ""
                            )
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

# AI Analysis tab
with tab3:
    st.header("AI Analysis with Amazon Bedrock")

    # Initialize session state variables if they don't exist
    if "findings_loaded_in_ai_tab" not in st.session_state:
        st.session_state.findings_loaded_in_ai_tab = False
    if "ai_tab_findings" not in st.session_state:
        st.session_state.ai_tab_findings = []
    if "current_finding_index" not in st.session_state:
        st.session_state.current_finding_index = 0
    if "show_actionable_only" not in st.session_state:
        st.session_state.show_unsuppressed_only = True

    # Create two columns for AWS connection and findings loading
    col1, col2 = st.columns(2)

    with col1:
        # Get available AWS profiles
        available_profiles = BedrockHelper.get_available_profiles()

        # AWS Profile selection
        aws_profile = st.selectbox(
            "AWS Profile",
            options=available_profiles,
            index=0,
            help="Select the AWS profile to use for Bedrock access",
        )

        # AWS Region selection
        aws_region = st.selectbox(
            "AWS Region",
            options=[
                "us-east-1",
                "us-west-2",
                "eu-central-1",
                "ap-southeast-1",
                "ap-northeast-1",
                "eu-west-1",
            ],
            index=0,
            help="Select the AWS region where Amazon Bedrock is available",
        )

        # Initialize Bedrock connection
        if st.button("Connect to Bedrock"):
            try:
                # Create Bedrock helper with region and profile
                with st.spinner("Connecting to Amazon Bedrock..."):
                    st.session_state.bedrock_helper = BedrockHelper(
                        region=aws_region,
                        profile=aws_profile if aws_profile != "default" else None,
                    )

                    # Get available models
                    st.session_state.available_models = (
                        st.session_state.bedrock_helper.get_available_models()
                    )

                    if st.session_state.available_models:
                        profile_msg = (
                            f" using profile '{aws_profile}'"
                            if aws_profile != "default"
                            else ""
                        )
                        st.success(
                            f"Connected to Amazon Bedrock in {aws_region}{profile_msg}"
                        )
                        st.session_state.connected = True
                    else:
                        st.warning(
                            f"Connected to AWS, but no Bedrock models are available in {aws_region} or with your current permissions"
                        )
                        st.session_state.connected = False
            except Exception as e:
                st.error(f"Failed to connect to Amazon Bedrock: {str(e)}")
                st.error("Make sure you have valid AWS credentials configured")
                st.session_state.connected = False

    with col2:
        # Allow user to select results file
        results_file = st.text_input(
            "Results File Path",
            value=st.session_state.results_file,
            help="Path to the ASH results file",
            key="ai_tab_results_file",
        )

        # Update session state when changed
        if results_file != st.session_state.results_file:
            st.session_state.results_file = results_file

        # Load findings button
        if st.button("Load Findings"):
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

                    # Get flat vulnerabilities
                    flat_vulns = results.to_flat_vulnerabilities()

                    if flat_vulns:
                        st.session_state.ai_tab_findings = flat_vulns
                        st.session_state.findings_loaded_in_ai_tab = True
                        st.session_state.current_finding_index = 0
                        st.session_state.source_dir = (
                            results.metadata.source_dir
                            if hasattr(results.metadata, "source_dir")
                            else st.session_state.source_dir
                        )
                        st.success(f"Loaded {len(flat_vulns)} findings")
                    else:
                        st.warning("No findings found in the results file")
                        st.session_state.findings_loaded_in_ai_tab = False
                except Exception as e:
                    st.error(f"Error loading results: {str(e)}")
                    st.session_state.findings_loaded_in_ai_tab = False
            else:
                st.error("Results file does not exist or path is invalid")

    # Display findings selection and navigation if findings are loaded
    if st.session_state.findings_loaded_in_ai_tab and st.session_state.ai_tab_findings:
        st.subheader("Finding Selection")

        # Filter for actionable findings (HIGH, CRITICAL, MEDIUM severity)
        show_unsuppressed_only = st.checkbox(
            "Show unsuppressed findings only",
            value=st.session_state.show_unsuppressed_only,
        )
        st.session_state.show_unsuppressed_only = show_unsuppressed_only

        if show_unsuppressed_only:
            filtered_findings = [
                f for f in st.session_state.ai_tab_findings if not f.is_suppressed
            ]
            displayed_findings = filtered_findings
        else:
            displayed_findings = st.session_state.ai_tab_findings

        if not displayed_findings:
            st.warning("No findings match the current filter")
        else:
            # Create a list of finding titles with severity for the dropdown
            finding_options = [
                f"{i + 1}. [{f.severity}] {f.title} ({f.scanner})"
                for i, f in enumerate(displayed_findings)
            ]

            # Finding selection dropdown
            selected_finding_idx = st.selectbox(
                "Select Finding",
                options=range(len(finding_options)),
                format_func=lambda i: finding_options[i],
                index=min(
                    st.session_state.current_finding_index, len(displayed_findings) - 1
                ),
                help="Select a finding to analyze",
            )

            st.session_state.current_finding_index = selected_finding_idx

            # Navigation buttons
            col1, col2, col3 = st.columns([1, 2, 1])
            with col1:
                if st.button("Previous Finding", disabled=selected_finding_idx == 0):
                    st.session_state.current_finding_index = max(
                        0, selected_finding_idx - 1
                    )
                    st.rerun()

            with col3:
                if st.button(
                    "Next Finding",
                    disabled=selected_finding_idx == len(displayed_findings) - 1,
                ):
                    st.session_state.current_finding_index = min(
                        len(displayed_findings) - 1, selected_finding_idx + 1
                    )
                    st.rerun()

            # Get the selected finding
            finding = displayed_findings[selected_finding_idx]
            source_dir = st.session_state.source_dir

            # Display finding details
            st.subheader(f"Analysis for Finding: {finding.title}")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Severity:** {finding.severity}")
                st.markdown(f"**Scanner:** {finding.scanner}")
            with col2:
                st.markdown(f"**File:** {finding.file_path}")

                # Handle different line number attributes
                if hasattr(finding, "line_start") and hasattr(finding, "line_end"):
                    st.markdown(f"**Lines:** {finding.line_start}-{finding.line_end}")
                elif hasattr(finding, "line"):
                    st.markdown(f"**Line:** {finding.line}")
                else:
                    st.markdown("**Line:** N/A")

            st.markdown(f"**Description:** {finding.description}")

            # Get file content if available
            file_content = None
            if finding.file_path and st.session_state.source_dir:
                st.write(
                    f"Looking for file in source directory: {st.session_state.source_dir}"
                )
                file_content = (
                    st.session_state.bedrock_helper.get_file_content(
                        finding.file_path, st.session_state.source_dir
                    )
                    if st.session_state.bedrock_helper
                    else None
                )

                if file_content:
                    with st.expander("View File Content"):
                        st.code(file_content)
                else:
                    st.warning(f"Could not find file: {finding.file_path}")
                    # Add a manual file content input option
                    manual_file_content = st.text_area(
                        "Enter file content manually",
                        height=200,
                        help="If the file couldn't be found automatically, you can paste its content here",
                    )
                    if manual_file_content:
                        file_content = manual_file_content

        # Model selection (only show after successful connection)
        if (
            "connected" in st.session_state
            and st.session_state.connected
            and "available_models" in st.session_state
        ):
            # Create a list of model options with appropriate display names
            model_options = []
            model_ids = {}
            vendor_models = {}

            for model in st.session_state.available_models:
                model_id = model["modelId"]
                model_name = model["modelName"]
                model_provider = model["providerName"]
                inference_type = model["inferenceType"]
                display_name = f"{model_provider} {model_name} ({model_id})"
                model_ids[display_name] = model_id
                if model_provider not in vendor_models:
                    vendor_models[model_provider] = []
                vendor_models[model_provider].append(display_name)
                model_options.append(display_name)

            if model_options:
                # Default to Claude if available, otherwise use first model
                default_index = 0
                for i, model_name in enumerate(model_options):
                    if "nova-lite" in model_name.lower():
                        default_index = i
                        break
                    elif "claude-3-7-sonnet" in model_name.lower():
                        default_index = i
                        break

                form = st.form(key="model_selection_form", border=False)
                col1, col2 = form.columns([1, 2])
                with col1:
                    form.subheader("Bedrock Model Selection")
                    selected_vendor = form.selectbox(
                        "Vendor",
                        options=["*", *sorted(set(vendor_models.keys()))],
                        index=0,
                        help="Select the vendor of the model to use for analysis",
                    )
                with col2:
                    filtered_models = []
                    for vendor, model in vendor_models.items():
                        if vendor == selected_vendor or selected_vendor == "*":
                            filtered_models.extend(model)
                    selected_model_display = form.selectbox(
                        "Bedrock Model",
                        options=filtered_models,
                        index=(
                            min(default_index, len(filtered_models) - 1)
                            if filtered_models
                            else 0
                        ),
                        help="Select the Amazon Bedrock model to use for analysis",
                    )
                    # Get the actual model ID or inference profile ARN to use
                    if selected_model_display in sorted(set(model_ids)):
                        model_id = model_ids[selected_model_display]
                        st.session_state.selected_model = model_id

                        # Show info about inference profile if applicable
                        if "Inference Profile" in selected_model_display:
                            st.info(
                                f"Using inference profile for {selected_model_display.split(' (')[0]}"
                            )
                            st.write(f"Inference Profile ARN: {model_id}")
                            st.info(
                                f"Using inference profile for {selected_model_display.split(' (')[0]}"
                            )
                    else:
                        st.session_state.selected_model = selected_model_display

                form_submit_button = form.form_submit_button(
                    "Analyze with Bedrock", type="primary"
                )
                # Analyze with Bedrock
                if (
                    st.session_state.bedrock_helper
                    and "selected_model" in st.session_state
                    and st.session_state.selected_model
                ):
                    if form_submit_button:
                        with st.spinner("Analyzing finding with Amazon Bedrock..."):
                            try:
                                # Convert finding to dict for analysis
                                finding_dict = finding.model_dump(
                                    by_alias=True, exclude_unset=True, exclude_none=True
                                )

                                # Get analysis from Bedrock with progress indicator
                                with st.status(
                                    "Amazon Bedrock is analyzing your finding...",
                                    expanded=True,
                                ) as status:
                                    st.write(
                                        f"Sending request to Bedrock using {st.session_state.selected_model}..."
                                    )
                                    analysis = (
                                        st.session_state.bedrock_helper.analyze_finding(
                                            finding_dict,
                                            file_content,
                                            model_id=st.session_state.selected_model,
                                        )
                                    )
                                    status.update(
                                        label="Analysis complete!",
                                        state="complete",
                                        expanded=False,
                                    )

                                # Store analysis in session state
                                st.session_state.current_analysis = analysis

                                # Display analysis
                                st.markdown("## AI Analysis")
                                st.markdown(analysis["analysis"])

                            except Exception as e:
                                st.error(f"Error analyzing finding: {str(e)}")
                else:
                    st.info(
                        "Please connect to Amazon Bedrock and select a model to analyze findings"
                    )

            else:
                st.warning(
                    "No suitable text models available in this region with your current permissions"
                )
                st.session_state.selected_model = None

    else:
        if not st.session_state.findings_loaded_in_ai_tab:
            st.info("Please load findings from a results file")
        elif not st.session_state.ai_tab_findings:
            st.info(
                "No findings available. Please run a scan or select a different results file."
            )

# Add footer with links
st.markdown("---")
st.markdown(
    "For more information, please visit the [ASH GitHub Repository](https://github.com/awslabs/automated-security-helper)"
)
