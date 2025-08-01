# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Data models for scanner validation and state tracking."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, TYPE_CHECKING
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.core.enums import ScannerStatus

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerStatusInfo,
    )


@dataclass
class ScannerValidationState:
    """Tracks the complete lifecycle state of a scanner during validation.

    This dataclass maintains comprehensive information about a scanner's
    status throughout the scan process, from registration through result inclusion.
    """

    name: str
    """The name/identifier of the scanner"""

    plugin_class: Optional[type] = None
    """The scanner plugin class, if available"""

    registration_status: str = "unknown"
    """Status of scanner registration: 'registered', 'failed', 'missing'"""

    enablement_status: str = "unknown"
    """Status of scanner enablement: 'enabled', 'disabled', 'excluded', 'missing_deps'"""

    enablement_reason: str = ""
    """Detailed reason for the enablement status"""

    dependency_errors: List[str] = field(default_factory=list)
    """List of specific dependency validation errors"""

    queued_for_execution: bool = False
    """Whether the scanner has a task in the execution queue"""

    execution_completed: bool = False
    """Whether the scanner completed its execution"""

    included_in_results: bool = False
    """Whether the scanner is included in the final results"""

    failure_reason: Optional[str] = None
    """Specific reason for failure, if applicable"""

    metadata: Dict[str, Any] = field(default_factory=dict)
    """Additional metadata for extensibility"""


@dataclass
class ValidationCheckpoint:
    """Captures a validation snapshot at a specific point in the scan process.

    This dataclass represents a validation checkpoint that compares expected
    vs actual scanner states and captures any discrepancies or errors found.
    """

    checkpoint_name: str
    """Name/identifier of the validation checkpoint"""

    timestamp: datetime = field(default_factory=datetime.now)
    """When this checkpoint was created"""

    expected_scanners: List[str] = field(default_factory=list)
    """List of scanner names that were expected at this checkpoint"""

    actual_scanners: List[str] = field(default_factory=list)
    """List of scanner names that were actually found at this checkpoint"""

    discrepancies: List[str] = field(default_factory=list)
    """List of discrepancies found (missing or unexpected scanners)"""

    errors: List[str] = field(default_factory=list)
    """List of errors encountered during validation"""

    metadata: Dict[str, Any] = field(default_factory=dict)
    """Additional metadata for the checkpoint"""

    def add_discrepancy(self, discrepancy: str) -> None:
        """Add a discrepancy to the checkpoint.

        Args:
            discrepancy: Description of the discrepancy found
        """
        self.discrepancies.append(discrepancy)

    def add_error(self, error: str) -> None:
        """Add an error to the checkpoint.

        Args:
            error: Description of the error encountered
        """
        self.errors.append(error)

    def has_issues(self) -> bool:
        """Check if this checkpoint has any discrepancies or errors.

        Returns:
            True if there are discrepancies or errors, False otherwise
        """
        return len(self.discrepancies) > 0 or len(self.errors) > 0

    def get_missing_scanners(self) -> List[str]:
        """Get list of scanners that were expected but not found.

        Returns:
            List of scanner names that are missing
        """
        return [
            scanner
            for scanner in self.expected_scanners
            if scanner not in self.actual_scanners
        ]

    def get_unexpected_scanners(self) -> List[str]:
        """Get list of scanners that were found but not expected.

        Returns:
            List of scanner names that were unexpected
        """
        return [
            scanner
            for scanner in self.actual_scanners
            if scanner not in self.expected_scanners
        ]


class ScannerValidationManager:
    """Manages scanner validation throughout the scan lifecycle.

    This class coordinates all scanner validation activities and maintains
    state throughout the scan process, providing comprehensive visibility
    into scanner registration, enablement, execution, and result inclusion.
    """

    def __init__(self, plugin_context: "PluginContext"):
        """Initialize the scanner validation manager.

        Args:
            plugin_context: The plugin context containing configuration and paths
        """
        self.plugin_context = plugin_context
        self.scanner_states: Dict[str, ScannerValidationState] = {}
        self.checkpoints: List[ValidationCheckpoint] = []
        self.logger = ASH_LOGGER

    def get_scanner_state(self, scanner_name: str) -> Optional[ScannerValidationState]:
        """Get the validation state for a specific scanner.

        Args:
            scanner_name: Name of the scanner

        Returns:
            ScannerValidationState if found, None otherwise
        """
        return self.scanner_states.get(scanner_name)

    def update_scanner_state(
        self, scanner_name: str, **kwargs
    ) -> ScannerValidationState:
        """Update or create a scanner validation state.

        Args:
            scanner_name: Name of the scanner
            **kwargs: Fields to update in the scanner state

        Returns:
            Updated ScannerValidationState
        """
        is_new_scanner = scanner_name not in self.scanner_states

        if is_new_scanner:
            self.scanner_states[scanner_name] = ScannerValidationState(
                name=scanner_name
            )
            self.logger.debug(f"Created new scanner state for: {scanner_name}")

        state = self.scanner_states[scanner_name]

        # Log state transitions for debugging
        state_changes = []
        for key, value in kwargs.items():
            if hasattr(state, key):
                old_value = getattr(state, key)
                if old_value != value:
                    state_changes.append(f"{key}: {old_value} -> {value}")
                setattr(state, key, value)
            else:
                self.logger.warning(f"Unknown scanner state field: {key}")

        # Log state transitions at DEBUG level
        if state_changes:
            self.logger.debug(
                f"Scanner '{scanner_name}' state transitions: {', '.join(state_changes)}"
            )

        return state

    def create_checkpoint(self, checkpoint_name: str, **kwargs) -> ValidationCheckpoint:
        """Create a new validation checkpoint.

        Args:
            checkpoint_name: Name of the checkpoint
            **kwargs: Additional checkpoint fields

        Returns:
            Created ValidationCheckpoint
        """
        checkpoint = ValidationCheckpoint(checkpoint_name=checkpoint_name, **kwargs)
        self.checkpoints.append(checkpoint)

        # Enhanced logging for checkpoint creation with accurate scanner lists
        expected_count = len(checkpoint.expected_scanners)
        actual_count = len(checkpoint.actual_scanners)

        self.logger.debug(
            f"Created validation checkpoint '{checkpoint_name}' with {expected_count} expected and {actual_count} actual scanners"
        )

        # Log detailed scanner lists for better visibility
        if checkpoint.expected_scanners:
            self.logger.debug(
                f"  Expected scanners: {', '.join(sorted(checkpoint.expected_scanners))}"
            )
        if checkpoint.actual_scanners:
            self.logger.debug(
                f"  Actual scanners: {', '.join(sorted(checkpoint.actual_scanners))}"
            )

        # Enhanced issue reporting with specific details
        if checkpoint.has_issues():
            discrepancy_count = len(checkpoint.discrepancies)
            error_count = len(checkpoint.errors)
            self.logger.debug(
                f"Checkpoint '{checkpoint_name}' has {discrepancy_count} discrepancies and {error_count} errors"
            )

            # Log missing and unexpected scanners for clarity
            missing_scanners = checkpoint.get_missing_scanners()
            unexpected_scanners = checkpoint.get_unexpected_scanners()

            if missing_scanners:
                self.logger.debug(
                    f"  Missing scanners: {', '.join(sorted(missing_scanners))}"
                )
            if unexpected_scanners:
                self.logger.debug(
                    f"  Unexpected scanners: {', '.join(sorted(unexpected_scanners))}"
                )

        return checkpoint

    def get_scanners_by_status(self, status_field: str, status_value: str) -> List[str]:
        """Get scanner names filtered by a specific status.

        Args:
            status_field: The status field to filter by (e.g., 'registration_status')
            status_value: The status value to match (e.g., 'registered')

        Returns:
            List of scanner names matching the status
        """
        matching_scanners = []
        for name, state in self.scanner_states.items():
            if (
                hasattr(state, status_field)
                and getattr(state, status_field) == status_value
            ):
                matching_scanners.append(name)
        return sorted(matching_scanners)

    def validate_registered_scanners(
        self, scanner_instances: List[Any]
    ) -> ValidationCheckpoint:
        """Validate and log all registered scanner plugins.

        This method validates all registered scanner plugins, updates their states,
        and creates a validation checkpoint with the results.

        Args:
            scanner_instances: List of registered scanner plugin instances

        Returns:
            ValidationCheckpoint containing the validation results
        """
        self.logger.verbose("Starting validation of registered scanner plugins")

        # Extract scanner names and sort alphabetically
        scanner_names = []
        for scanner_instance in scanner_instances:
            # Get scanner name from scanner.config.name to avoid class name duplicates
            scanner_name = scanner_instance.config.name
            scanner_names.append(scanner_name)

            # Update scanner state with registration information
            self.update_scanner_state(
                scanner_name,
                plugin_class=scanner_instance.__class__,
                registration_status="registered",
            )

        # Sort scanner names alphabetically
        scanner_names.sort()

        # Log registration summary
        total_count = len(scanner_names)
        self.logger.verbose(f"Found {total_count} registered scanner plugins:")
        for scanner_name in scanner_names:
            self.logger.verbose(f"  - {scanner_name}")

        # Create validation checkpoint
        checkpoint = self.create_checkpoint(
            checkpoint_name="registered_scanners",
            expected_scanners=scanner_names,  # For this checkpoint, expected = actual
            actual_scanners=scanner_names,
            metadata={
                "total_registered": total_count,
                "scanner_classes": [
                    instance.__class__.__name__ for instance in scanner_instances
                ],
            },
        )

        self.logger.debug(
            f"Created registration validation checkpoint with {total_count} scanners"
        )
        return checkpoint

    def validate_scanner_enablement(
        self,
        enabled_scanners: List[str],
        excluded_scanners: List[str],
        dependency_errors: Dict[str, List[str]] | None = None,
    ) -> ValidationCheckpoint:
        """Validate which scanners are enabled and why others are not.

        Args:
            enabled_scanners: List of scanner names that are enabled
            excluded_scanners: List of scanner names that are excluded
            dependency_errors: Optional dict mapping scanner names to dependency error lists

        Returns:
            ValidationCheckpoint containing the enablement validation results
        """
        self.logger.verbose("Starting validation of scanner enablement status")

        if dependency_errors is None:
            dependency_errors = {}

        # Get all registered scanners
        all_registered = self.get_scanners_by_status(
            "registration_status", "registered"
        )

        # Sort lists for consistent output
        enabled_scanners = sorted(enabled_scanners)
        excluded_scanners = sorted(excluded_scanners)

        # Enhanced logging for scanner enablement validation
        self.logger.info("Scanner enablement validation summary:")
        self.logger.info(f"  Total registered scanners: {len(all_registered)}")
        self.logger.info(
            f"  Enabled scanners ({len(enabled_scanners)}): {', '.join(enabled_scanners) if enabled_scanners else 'None'}"
        )
        self.logger.info(
            f"  Excluded scanners ({len(excluded_scanners)}): {', '.join(excluded_scanners) if excluded_scanners else 'None'}"
        )

        if dependency_errors:
            dep_error_scanners = sorted(dependency_errors.keys())
            self.logger.verbose(
                f"  Scanners with dependency errors ({len(dep_error_scanners)}): {', '.join(dep_error_scanners)}"
            )
            for scanner_name, errors in dependency_errors.items():
                self.logger.debug(f"    {scanner_name}: {', '.join(errors)}")
        else:
            self.logger.verbose("  Scanners with dependency errors (0): None")

        # Update scanner states based on enablement status
        for scanner_name in all_registered:
            if scanner_name in enabled_scanners:
                self.update_scanner_state(
                    scanner_name,
                    enablement_status="enabled",
                    enablement_reason="Scanner is enabled and ready for execution",
                )
            elif scanner_name in excluded_scanners:
                self.update_scanner_state(
                    scanner_name,
                    enablement_status="excluded",
                    enablement_reason="Scanner is excluded by configuration",
                )
            elif scanner_name in dependency_errors:
                errors = dependency_errors[scanner_name]
                self.update_scanner_state(
                    scanner_name,
                    enablement_status="missing_deps",
                    enablement_reason=f"Missing dependencies: {', '.join(errors)}",
                    dependency_errors=errors,
                )
            else:
                # Scanner is registered but not enabled - determine why
                self.update_scanner_state(
                    scanner_name,
                    enablement_status="disabled",
                    enablement_reason="Scanner is disabled (reason unknown)",
                )

        # Create validation checkpoint
        checkpoint = self.create_checkpoint(
            checkpoint_name="scanner_enablement",
            expected_scanners=all_registered,
            actual_scanners=enabled_scanners,
            metadata={
                "enabled_count": len(enabled_scanners),
                "excluded_count": len(excluded_scanners),
                "dependency_error_count": len(dependency_errors),
                "enabled_scanners": enabled_scanners,
                "excluded_scanners": excluded_scanners,
                "dependency_errors": dependency_errors,
            },
        )

        return checkpoint

    def validate_execution_completion(
        self, completed_scanners: List[str]
    ) -> ValidationCheckpoint:
        """Validate that all expected scanners completed execution.

        Args:
            completed_scanners: List of scanner names that completed execution

        Returns:
            ValidationCheckpoint containing the execution completion validation results
        """
        self.logger.verbose("Starting validation of scanner execution completion")

        # Sort completed scanners for consistent output
        completed_scanners = sorted(completed_scanners)

        # Update scanner states for completed scanners
        for scanner_name in completed_scanners:
            self.update_scanner_state(scanner_name, execution_completed=True)

        # Get expected scanners (those that were queued for execution)
        expected_scanners = []
        for name, state in self.scanner_states.items():
            if state.queued_for_execution:
                expected_scanners.append(name)
        expected_scanners.sort()

        # Enhanced logging for execution completion validation
        completion_rate = (
            len(completed_scanners) / len(expected_scanners)
            if expected_scanners
            else 0.0
        )
        # Log any scanners that didn't complete and mark them as failed
        missing_completions = [
            s for s in expected_scanners if s not in completed_scanners
        ]
        self.logger.info("Scanner execution completion validation summary:")
        if missing_completions:
            self.logger.info(
                f"  Expected to complete ({len(expected_scanners)}): {', '.join(expected_scanners) if expected_scanners else 'None'}"
            )
            self.logger.info(
                f"  Actually completed ({len(completed_scanners)}): {', '.join(completed_scanners) if completed_scanners else 'None'}"
            )
            self.logger.info(
                f"  Completion rate: {completion_rate:.1%} ({len(completed_scanners)}/{len(expected_scanners)})"
            )
            self.logger.warning(
                f"  Scanners that didn't complete ({len(missing_completions)}): {', '.join(sorted(missing_completions))}"
            )

            # Mark missing scanners as failed with explicit failure reason
            for scanner_name in missing_completions:
                self.update_scanner_state(
                    scanner_name,
                    execution_completed=False,
                    failure_reason="Scanner was queued for execution but did not complete - execution failed",
                )
                self.logger.error(
                    f"  Scanner '{scanner_name}' failed to complete execution"
                )
        else:
            self.logger.verbose("  All expected scanners completed execution")

        # Create validation checkpoint
        checkpoint = self.create_checkpoint(
            checkpoint_name="execution_completion",
            expected_scanners=expected_scanners,
            actual_scanners=completed_scanners,
            metadata={
                "expected_count": len(expected_scanners),
                "completed_count": len(completed_scanners),
                "completion_rate": completion_rate,
            },
        )

        return checkpoint

    def ensure_complete_results(
        self, aggregated_results: "AshAggregatedResults"
    ) -> ValidationCheckpoint:
        """Ensure all originally registered scanners appear in results.

        This method validates that all originally registered scanners are included
        in the final aggregated results. For scanners that are missing, it adds
        them with appropriate status and 0 findings, including failure reasons.

        Uses scanner.config.name consistently to avoid duplicate entries from class names.

        Args:
            aggregated_results: The aggregated scan results to validate and potentially modify

        Returns:
            ValidationCheckpoint containing the result completeness validation results
        """
        self.logger.verbose("Starting validation of result completeness")

        # Import here to avoid circular imports

        # Get all originally registered scanners using proper scanner names (scanner.config.name)
        all_registered = self.get_scanners_by_status(
            "registration_status", "registered"
        )

        # Ensure we're working with proper scanner names only (no class names)
        all_registered = [
            name for name in all_registered if name and not name.endswith("Scanner")
        ]
        all_registered.sort()

        # Get scanners that actually executed successfully from validation manager state
        # This is the correct data source that's available at validation time
        executed_scanners = self._get_executed_scanners_from_validation_state(
            aggregated_results
        )

        # Enhanced result completeness validation summary with accurate scanner states
        self.logger.verbose("Result completeness validation summary:")
        self.logger.verbose(
            f"  Originally registered scanners ({len(all_registered)}): {', '.join(sorted(all_registered)) if all_registered else 'None'}"
        )
        self.logger.verbose(
            f"  Scanners that executed successfully ({len(executed_scanners)}): {', '.join(sorted(executed_scanners)) if executed_scanners else 'None'}"
        )

        # Provide detailed breakdown of scanner states for better visibility
        scanner_state_summary = self._get_scanner_state_summary()
        if scanner_state_summary:
            self.logger.verbose("  Scanner state breakdown:")
            for state, scanners in scanner_state_summary.items():
                if scanners:
                    self.logger.verbose(
                        f"    {state.title()} ({len(scanners)}): {', '.join(sorted(scanners))}"
                    )

        # Calculate and log completion rate
        completion_rate = (
            len(executed_scanners) / len(all_registered) if all_registered else 1.0
        )
        self.logger.verbose(
            f"  Completion rate: {completion_rate:.1%} ({len(executed_scanners)}/{len(all_registered)})"
        )

        # Create validation checkpoint
        checkpoint = self.create_checkpoint(
            checkpoint_name="result_completeness",
            expected_scanners=all_registered,
            actual_scanners=executed_scanners,
            metadata={
                "expected_count": len(all_registered),
                "executed_count": len(executed_scanners),
                "completeness_rate": completion_rate,
            },
        )

        # Find missing scanners and add them to results
        missing_scanners = checkpoint.get_missing_scanners()
        added_scanners = []

        if missing_scanners:
            self.logger.verbose(
                f"Found {len(missing_scanners)} scanners missing from results, adding them with appropriate status:"
            )

            for scanner_name in missing_scanners:
                # Ensure we're using proper scanner name (not class name)
                if not scanner_name or scanner_name.endswith("Scanner"):
                    self.logger.warning(
                        f"Skipping invalid scanner name: {scanner_name}"
                    )
                    continue

                # Double-check that this scanner isn't already in results
                if (
                    aggregated_results.scanner_results
                    and scanner_name in aggregated_results.scanner_results
                ):
                    self.logger.debug(
                        f"Scanner '{scanner_name}' already exists in results, skipping"
                    )
                    continue

                scanner_state = self.get_scanner_state(scanner_name)

                # CRITICAL: Check if scanner was properly excluded during filtering
                # If scanner was excluded but not tracked, don't add it as missing
                if scanner_state and scanner_state.enablement_status == "excluded":
                    self.logger.debug(
                        f"Scanner '{scanner_name}' was properly excluded, not adding to missing results"
                    )
                    continue

                # Get detailed status information for better logging
                status_info = self.determine_scanner_status_from_execution_data(
                    scanner_name
                )

                # Create appropriate scanner status info based on scanner state
                scanner_status_info = self._create_missing_scanner_result_entry(
                    scanner_name, scanner_state
                )

                # Add to aggregated results
                if aggregated_results.scanner_results is None:
                    aggregated_results.scanner_results = {}

                aggregated_results.scanner_results[scanner_name] = scanner_status_info
                added_scanners.append(scanner_name)

                # Update scanner state to reflect inclusion in results
                self.update_scanner_state(scanner_name, included_in_results=True)

                # Enhanced logging with detailed reason
                reason = status_info.get(
                    "failure_reason", "No specific reason provided"
                )

                # Use different log levels based on status
                if scanner_status_info.status == ScannerStatus.ERROR:
                    self.logger.error(
                        f"  + Added '{scanner_name}' with status {scanner_status_info.status.value} - EXECUTION FAILED (Reason: {reason})"
                    )
                elif scanner_status_info.status == ScannerStatus.MISSING:
                    self.logger.warning(
                        f"  + Added '{scanner_name}' with status {scanner_status_info.status.value} (Reason: {reason})"
                    )
                else:
                    self.logger.verbose(
                        f"  + Added '{scanner_name}' with status {scanner_status_info.status.value} (Reason: {reason})"
                    )
        else:
            self.logger.verbose(
                "All registered scanners are present in results - no missing scanners to add"
            )

        # Update all scanners that executed successfully to reflect inclusion in results
        for scanner_name in executed_scanners:
            if scanner_name and not scanner_name.endswith("Scanner"):
                # Check if this is an unexpected scanner (not in registered list)
                if scanner_name not in all_registered:
                    # Create state for unexpected scanner
                    self.update_scanner_state(
                        scanner_name,
                        registration_status="untracked",
                        included_in_results=True,
                    )
                else:
                    # Update existing registered scanner
                    self.update_scanner_state(scanner_name, included_in_results=True)

        # Add discrepancies to checkpoint
        if missing_scanners:
            for scanner_name in missing_scanners:
                if scanner_name and not scanner_name.endswith("Scanner"):
                    scanner_state = self.get_scanner_state(scanner_name)
                    reason = (
                        scanner_state.failure_reason
                        if scanner_state
                        else "Unknown reason"
                    )
                    checkpoint.add_discrepancy(
                        f"Scanner '{scanner_name}' was missing from results: {reason}"
                    )

        # Add discrepancies for unexpected scanners
        unexpected_scanners = checkpoint.get_unexpected_scanners()
        if unexpected_scanners:
            for scanner_name in unexpected_scanners:
                if scanner_name and not scanner_name.endswith("Scanner"):
                    checkpoint.add_discrepancy(
                        f"Scanner '{scanner_name}' was found in results but not registered"
                    )

        # Final validation summary with accurate counts
        final_scanner_count = (
            len(aggregated_results.scanner_results)
            if aggregated_results.scanner_results
            else 0
        )
        self.logger.verbose("Result completeness validation completed:")
        self.logger.verbose(f"  Final scanner count in results: {final_scanner_count}")
        self.logger.verbose(f"  Scanners added to results: {len(added_scanners)}")

        if added_scanners:
            self.logger.verbose(
                f"  Added scanners: {', '.join(sorted(added_scanners))}"
            )

        if unexpected_scanners:
            filtered_unexpected = [
                s for s in unexpected_scanners if s and not s.endswith("Scanner")
            ]
            if filtered_unexpected:
                self.logger.verbose(
                    f"  Unexpected scanners found: {', '.join(sorted(filtered_unexpected))}"
                )

        # Log validation checkpoint status
        if checkpoint.has_issues():
            self.logger.warning(
                f"Validation checkpoint has {len(checkpoint.discrepancies)} discrepancies and {len(checkpoint.errors)} errors"
            )
        else:
            self.logger.verbose("Result completeness validation passed without issues")

        return checkpoint

    def _get_scanner_state_summary(self) -> Dict[str, List[str]]:
        """Get a summary of scanner states for logging purposes.

        Returns:
            Dictionary mapping state names to lists of scanner names in that state
        """
        state_summary = {
            "completed": [],
            "excluded": [],
            "missing_deps": [],
            "failed": [],
            "missing": [],
        }

        for scanner_name, scanner_state in self.scanner_states.items():
            # Skip class name entries
            if scanner_name.endswith("Scanner"):
                continue

            # Use the status determination method to get accurate status
            status_info = self.determine_scanner_status_from_execution_data(
                scanner_name
            )
            status = status_info["status"]

            if status in state_summary:
                state_summary[status].append(scanner_name)
            else:
                # Default to missing for unknown states
                state_summary["missing"].append(scanner_name)

        return state_summary

    def determine_scanner_status_from_execution_data(
        self, scanner_name: str
    ) -> Dict[str, Any]:
        """Determine scanner status from execution data stored in validation manager state.

        This method analyzes the scanner's validation state to determine its actual execution
        status and maps it to the appropriate scanner status values. It handles different
        scanner states including completed, excluded, failed, and missing dependencies.

        Args:
            scanner_name: Name of the scanner to analyze

        Returns:
            Dictionary containing status information with keys:
            - status: The determined scanner status (completed, excluded, failed, missing_deps)
            - dependencies_satisfied: Whether dependencies are satisfied
            - excluded: Whether scanner was excluded by configuration
            - execution_completed: Whether execution completed successfully
            - failure_reason: Reason for failure if applicable
        """
        scanner_state = self.get_scanner_state(scanner_name)

        if not scanner_state:
            # No state information - scanner is missing/unknown
            return {
                "status": "missing",
                "dependencies_satisfied": True,
                "excluded": False,
                "execution_completed": False,
                "failure_reason": "Scanner state not found in validation manager",
            }

        # Determine status based on validation state data
        if scanner_state.enablement_status == "missing_deps":
            return {
                "status": "missing_deps",
                "dependencies_satisfied": False,
                "excluded": False,
                "execution_completed": False,
                "failure_reason": f"Missing dependencies: {', '.join(scanner_state.dependency_errors)}",
            }

        elif scanner_state.enablement_status == "excluded":
            return {
                "status": "excluded",
                "dependencies_satisfied": True,
                "excluded": True,
                "execution_completed": False,
                "failure_reason": scanner_state.enablement_reason,
            }

        elif scanner_state.enablement_status == "disabled":
            return {
                "status": "excluded",
                "dependencies_satisfied": True,
                "excluded": True,
                "execution_completed": False,
                "failure_reason": scanner_state.enablement_reason or "Scanner disabled",
            }

        elif scanner_state.execution_completed:
            return {
                "status": "completed",
                "dependencies_satisfied": True,
                "excluded": False,
                "execution_completed": True,
                "failure_reason": None,
            }

        elif (
            scanner_state.queued_for_execution and not scanner_state.execution_completed
        ):
            # Scanner was queued but didn't complete - likely failed
            failure_reason = (
                scanner_state.failure_reason
                or "Scanner was queued for execution but did not complete - execution failed"
            )
            return {
                "status": "failed",
                "dependencies_satisfied": scanner_state.enablement_status
                != "missing_deps",
                "excluded": False,
                "execution_completed": False,
                "failure_reason": failure_reason,
            }

        elif scanner_state.failure_reason:
            return {
                "status": "failed",
                "dependencies_satisfied": scanner_state.enablement_status
                != "missing_deps",
                "excluded": scanner_state.enablement_status == "excluded",
                "execution_completed": False,
                "failure_reason": scanner_state.failure_reason,
            }

        else:
            # Default case - scanner registered but status unclear
            return {
                "status": "missing",
                "dependencies_satisfied": scanner_state.enablement_status
                != "missing_deps",
                "excluded": scanner_state.enablement_status == "excluded",
                "execution_completed": False,
                "failure_reason": "Scanner registered but execution status unclear",
            }

    def _get_executed_scanners_from_validation_state(
        self, aggregated_results: "AshAggregatedResults"
    ) -> List[str]:
        """Get list of scanners that executed successfully from validation manager state.

        This method checks both the validation manager's scanner states and any existing
        scanner_results to determine which scanners actually completed execution or are
        already present in results.

        Args:
            aggregated_results: The aggregated scan results to check for existing scanners

        Returns:
            List of scanner names that completed execution successfully or are already present
        """
        executed_scanners = []

        # First, check scanners that are already in scanner_results (if any)
        if aggregated_results.scanner_results:
            existing_scanners = [
                name
                for name in aggregated_results.scanner_results.keys()
                if name and not name.endswith("Scanner")
            ]
            executed_scanners.extend(existing_scanners)
            self.logger.debug(
                f"Found {len(existing_scanners)} scanners already in results: {sorted(existing_scanners)}"
            )

        # Then, check validation manager state for scanners that executed
        for scanner_name, scanner_state in self.scanner_states.items():
            # Skip class name entries
            if scanner_name.endswith("Scanner"):
                continue

            # Skip if already found in scanner_results
            if scanner_name in executed_scanners:
                continue

            # Use the new status determination method to check if scanner completed
            status_info = self.determine_scanner_status_from_execution_data(
                scanner_name
            )
            if status_info["status"] == "completed":
                executed_scanners.append(scanner_name)
                self.logger.debug(
                    f"Scanner '{scanner_name}' marked as executed in validation state"
                )

        # Remove duplicates and sort
        executed_scanners = sorted(list(set(executed_scanners)))
        self.logger.debug(
            f"Found {len(executed_scanners)} total executed scanners: {executed_scanners}"
        )
        return executed_scanners

    def _create_missing_scanner_result_entry(
        self, scanner_name: str, scanner_state: Optional[ScannerValidationState]
    ) -> "ScannerStatusInfo":
        """Create a scanner result entry for a missing scanner with appropriate status.

        Args:
            scanner_name: Name of the scanner
            scanner_state: The scanner's validation state, if available

        Returns:
            ScannerStatusInfo with appropriate status for the missing scanner
        """
        # Import here to avoid circular imports
        from automated_security_helper.models.asharp_model import ScannerStatusInfo

        # Validate that we're working with a proper scanner name, not a class name
        if not scanner_name or scanner_name.endswith("Scanner"):
            self.logger.warning(f"Invalid scanner name provided: {scanner_name}")
            return ScannerStatusInfo(
                status=ScannerStatus.MISSING,
                dependencies_satisfied=False,
                excluded=False,
            )

        # Use the new status determination method to get accurate status
        status_info = self.determine_scanner_status_from_execution_data(scanner_name)

        # Map our internal status to ScannerStatus enum
        if status_info["status"] == "completed":
            status = ScannerStatus.PASSED
        elif status_info["status"] == "excluded":
            status = ScannerStatus.SKIPPED
        elif status_info["status"] == "missing_deps":
            status = ScannerStatus.MISSING  # Use MISSING for dependency issues
        elif status_info["status"] == "failed":
            status = ScannerStatus.ERROR  # Use ERROR for execution failures
        else:  # missing or unknown
            status = ScannerStatus.MISSING

        # Create the scanner status info using the determined status
        scanner_status_info = ScannerStatusInfo(
            status=status,
            dependencies_satisfied=status_info["dependencies_satisfied"],
            excluded=status_info["excluded"],
        )

        return scanner_status_info

    def validate_task_queue(self, queue_contents: List[tuple]) -> ValidationCheckpoint:
        """Validate that all expected scanners have tasks in the queue.

        Args:
            queue_contents: List of tuples from the task queue

        Returns:
            ValidationCheckpoint containing the queue validation results
        """
        self.logger.verbose("Starting validation of scanner task queue")

        # Extract scanner names from queue contents
        queued_scanner_names = []
        for queue_item in queue_contents:
            if len(queue_item) >= 1:
                scanner_name = queue_item[0]
                queued_scanner_names.append(scanner_name)

                # Update scanner state to indicate it's queued
                self.update_scanner_state(scanner_name, queued_for_execution=True)

        # Sort for consistent output
        queued_scanner_names.sort()

        # Get expected scanners (those that are enabled)
        expected_scanners = self.get_scanners_by_status("enablement_status", "enabled")

        # Enhanced logging for task queue validation
        self.logger.verbose("Task queue validation summary:")
        self.logger.verbose(
            f"  Expected scanners to be queued ({len(expected_scanners)}): {', '.join(expected_scanners) if expected_scanners else 'None'}"
        )
        self.logger.verbose(
            f"  Actually queued scanners ({len(queued_scanner_names)}): {', '.join(queued_scanner_names) if queued_scanner_names else 'None'}"
        )

        # Create validation checkpoint
        checkpoint = self.create_checkpoint(
            checkpoint_name="task_queue_validation",
            expected_scanners=expected_scanners,
            actual_scanners=queued_scanner_names,
            metadata={
                "expected_count": len(expected_scanners),
                "queued_count": len(queued_scanner_names),
                "queue_items": len(queue_contents),
            },
        )

        return checkpoint

    def report_result_completeness(
        self, completeness_checkpoint: ValidationCheckpoint
    ) -> Dict[str, Any]:
        """Generate detailed reporting of result completeness adjustments.

        Args:
            completeness_checkpoint: The checkpoint containing result completeness validation results

        Returns:
            Dict containing detailed completeness report information
        """
        return {
            "has_adjustments": completeness_checkpoint.has_issues(),
            "missing_scanners": completeness_checkpoint.get_missing_scanners(),
            "unexpected_scanners": completeness_checkpoint.get_unexpected_scanners(),
        }

    def get_all_scanner_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get status information for all scanners tracked by the validation manager.

        Returns:
            Dictionary mapping scanner names to their status information
        """
        all_statuses = {}

        for scanner_name in self.scanner_states.keys():
            # Skip class name entries
            if scanner_name.endswith("Scanner"):
                continue

            all_statuses[scanner_name] = (
                self.determine_scanner_status_from_execution_data(scanner_name)
            )

        return all_statuses

    def retry_scanner_registration(self, missing_scanners: List[str]) -> List[str]:
        """Attempt to retry registration for missing scanners.

        Args:
            missing_scanners: List of scanner names that are missing from the task queue

        Returns:
            List of scanner names that were successfully re-enabled
        """
        self.logger.verbose(
            f"Starting retry registration for {len(missing_scanners)} missing scanners"
        )

        # For now, this is a placeholder implementation
        # In a full implementation, this would attempt to re-register scanners
        # that might have failed initial registration

        successfully_registered = []
        for scanner_name in missing_scanners:
            # Update scanner state to indicate retry attempt
            self.update_scanner_state(
                scanner_name,
                failure_reason="Scanner was missing from task queue, retry attempted",
            )
            self.logger.debug(
                f"Attempted retry registration for scanner: {scanner_name}"
            )

        self.logger.verbose(
            f"Retry registration completed. Successfully registered: {len(successfully_registered)} scanners"
        )
        return successfully_registered

    def add_queue_validation_error(
        self, error_message: str, scanner_name: str | None = None
    ) -> None:
        """Add a queue validation error to the latest queue validation checkpoint.

        Args:
            error_message: Description of the error
            scanner_name: Optional scanner name associated with the error
        """
        self.logger.error(f"Queue validation error: {error_message}")

        # Find the latest queue validation checkpoint and add the error
        for checkpoint in reversed(self.checkpoints):
            if checkpoint.checkpoint_name == "task_queue_validation":
                checkpoint.add_error(error_message)
                break
        else:
            # If no queue validation checkpoint exists, create one
            self.logger.warning(
                "No queue validation checkpoint found, creating one for error tracking"
            )
            checkpoint = self.create_checkpoint(
                checkpoint_name="task_queue_validation_errors",
                expected_scanners=[],
                actual_scanners=[],
                errors=[error_message],
            )

    def handle_queue_validation_errors(
        self,
        validation_checkpoint: ValidationCheckpoint,
        scan_results: Optional[Any] = None,
    ) -> None:
        """Handle errors from queue validation and ensure scan continuity.

        Args:
            validation_checkpoint: The checkpoint containing validation results
            scan_results: Optional scan results object to add errors to
        """
        self.logger.verbose(
            "Processing queue validation errors and ensuring scan continuity"
        )

        if validation_checkpoint.has_issues():
            missing_scanners = validation_checkpoint.get_missing_scanners()

            if missing_scanners:
                self.logger.warning(
                    f"Found {len(missing_scanners)} scanners missing from queue"
                )

                # Update scanner states for missing scanners
                for scanner_name in missing_scanners:
                    self.update_scanner_state(
                        scanner_name,
                        failure_reason="Scanner was expected to be queued but was not found in task queue",
                    )
                    self.logger.debug(
                        f"Updated failure reason for missing scanner: {scanner_name}"
                    )

            # Log all errors from the checkpoint
            for error in validation_checkpoint.errors:
                self.logger.error(f"Queue validation error: {error}")

        self.logger.verbose("Queue validation error handling completed")

    def report_execution_discrepancies(
        self, execution_checkpoint: ValidationCheckpoint
    ) -> Dict[str, Any]:
        """Generate detailed reporting of execution discrepancies.

        Args:
            execution_checkpoint: The checkpoint containing execution validation results

        Returns:
            Dict containing detailed discrepancy report information
        """
        missing_scanners = execution_checkpoint.get_missing_scanners()
        unexpected_scanners = execution_checkpoint.get_unexpected_scanners()

        return {
            "has_discrepancies": execution_checkpoint.has_issues(),
            "missing_scanners": missing_scanners,
            "unexpected_scanners": unexpected_scanners,
            "missing_count": len(missing_scanners),
            "unexpected_count": len(unexpected_scanners),
            "total_discrepancies": len(missing_scanners) + len(unexpected_scanners),
        }
