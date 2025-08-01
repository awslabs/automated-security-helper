# Scanner Validation System

The Scanner Validation System provides comprehensive monitoring and validation throughout the ASH scan lifecycle to ensure all expected scanners are properly registered, enabled, queued, executed, and included in results. This system addresses intermittent issues where security scanners might be silently dropped during the scan process.

## Overview

The Scanner Validation System was introduced to address reliability issues where scanners (particularly Checkov and Detect-Secrets on Windows) were not being included in ASH scans without clear indication of why. The system implements validation checkpoints at key phases of the scan lifecycle to provide comprehensive visibility and ensure scan completeness.

## Architecture

The Scanner Validation System follows a checkpoint-based architecture that monitors scanner state throughout the scan process:

1. **Registration Validation**: Validates which scanner plugins are discovered and registered
2. **Enablement Validation**: Validates which scanners are enabled and captures reasons for disabled scanners
3. **Task Queue Validation**: Validates that all enabled scanners have tasks in the execution queue
4. **Execution Completion Validation**: Validates that all expected scanners completed execution
5. **Result Completeness Validation**: Ensures all originally registered scanners appear in final results

## Key Components

### ScannerValidationManager

The `ScannerValidationManager` class orchestrates all validation activities and maintains state throughout the scan process.

#### Core Responsibilities

- Track registered scanners and their states throughout the scan lifecycle
- Validate scanner enablement status and capture specific reasons for disabled scanners
- Monitor task queue population to ensure no scanners are silently dropped
- Verify scan execution completion for all expected scanners
- Ensure complete result inclusion with appropriate status for failed/missing scanners

#### Key Methods

##### `validate_registered_scanners(scanner_classes: List[type]) -> ValidationCheckpoint`

Validates and logs all registered scanner plugins at the beginning of the scan process.

- Extracts scanner names from plugin classes
- Updates scanner states with registration information
- Creates a validation checkpoint with registration results
- Logs summary of registered scanners in alphabetical order

##### `validate_scanner_enablement(enabled_scanners, excluded_scanners, dependency_errors) -> ValidationCheckpoint`

Validates which scanners are enabled and captures specific reasons for disabled scanners.

- Updates scanner states based on enablement status
- Captures specific reasons for disabled scanners (configuration, dependencies, exclusions)
- Creates validation checkpoint with enablement results
- Logs comprehensive enablement summary with reasons

##### `validate_task_queue(queue_contents: List[tuple]) -> ValidationCheckpoint`

Validates that all expected scanners have tasks in the execution queue.

- Extracts scanner names from queue contents
- Compares expected scanners (enabled) against actual queued scanners
- Updates scanner states to indicate queuing status
- Identifies missing scanners and unexpected scanners in the queue
- Creates validation checkpoint with queue validation results
- Logs detailed queue validation summary and any discrepancies

##### `retry_scanner_registration(missing_scanners: List[str]) -> List[str]`

Attempts to retry registration for scanners missing from the task queue.

- Re-validates scanner dependencies and configuration
- Attempts to re-enable scanners that can be recovered
- Updates scanner states with retry outcomes
- Returns list of successfully re-enabled scanners

##### `ensure_complete_results(aggregated_results: AshAggregatedResults) -> ValidationCheckpoint`

Ensures all originally registered scanners appear in the final aggregated results.

- Validates that all registered scanners are included in results
- Adds missing scanners with appropriate status (SKIPPED, FAILED, or MISSING)
- Includes specific failure reasons for missing scanners
- Handles scanners with missing dependencies, exclusions, or execution failures
- Updates scanner states to reflect inclusion in results
- Creates validation checkpoint with completeness validation results

##### `generate_validation_report() -> str`

Generates a comprehensive validation report with detailed information about all validation activities.

- Creates a detailed report of all validation checkpoints and scanner states
- Includes executive summary with key metrics and validation status
- Groups scanners by status (enabled, disabled, missing dependencies, etc.)
- Shows detailed checkpoint information with timestamps and discrepancies
- Provides scanner-specific information including failure reasons and metadata
- Includes dependency analysis with common missing dependencies
- Generates actionable recommendations based on validation findings
- Returns formatted string report suitable for logging or file output

### Data Models

#### ScannerValidationState

Tracks the complete lifecycle state of a scanner during validation:

```python
@dataclass
class ScannerValidationState:
    name: str
    plugin_class: Optional[type] = None
    registration_status: str = "unknown"  # "registered", "failed", "missing"
    enablement_status: str = "unknown"    # "enabled", "disabled", "excluded", "missing_deps"
    enablement_reason: str = ""
    dependency_errors: List[str] = field(default_factory=list)
    queued_for_execution: bool = False
    execution_completed: bool = False
    included_in_results: bool = False
    failure_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
```

#### ValidationCheckpoint

Captures a validation snapshot at a specific point in the scan process:

```python
@dataclass
class ValidationCheckpoint:
    checkpoint_name: str
    timestamp: datetime = field(default_factory=datetime.now)
    expected_scanners: List[str] = field(default_factory=list)
    actual_scanners: List[str] = field(default_factory=list)
    discrepancies: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
```

## Validation Checkpoints

### 1. Registration Validation

**When**: After plugin discovery, before scanner filtering
**Purpose**: Validate all scanner plugins are properly discovered and registered
**Validates**:
- Total count of registered scanners
- Scanner names and plugin classes
- Registration success/failure status

### 2. Enablement Validation

**When**: After scanner filtering, before task queue creation
**Purpose**: Validate which scanners are enabled and capture reasons for disabled scanners
**Validates**:
- Enabled vs disabled scanner counts
- Specific reasons for disabled scanners (config, dependencies, exclusions)
- Dependency validation results with detailed error information

### 3. Task Queue Validation

**When**: After task queue population, before scanner execution
**Purpose**: Validate that all enabled scanners have corresponding tasks in the queue
**Validates**:
- Expected scanners (enabled) vs actual scanners in queue
- Missing scanners that should be queued but aren't
- Unexpected scanners that are queued but not marked as enabled
- Queue item counts and structure

### 4. Execution Completion Validation

**When**: After scanner execution, before result aggregation
**Purpose**: Validate that all expected scanners completed execution
**Validates**:
- Expected scanners vs completed scanners
- Missing scanners that didn't complete execution
- Execution status and completion tracking

### 5. Result Completeness Validation

**When**: Before finalizing scan results
**Purpose**: Ensure all originally registered scanners appear in final results
**Validates**:
- All registered scanners have entries in final results
- Failed/missing scanners are included with appropriate status
- Failure reasons are captured and included
- Unexpected scanners in results are identified and tracked
- Final completeness rate is calculated and logged

## Error Handling and Recovery

### Registration Retry Logic

When scanners are missing from the task queue, the system attempts recovery:

1. **Dependency Re-validation**: Check if missing dependencies have been resolved
2. **Configuration Re-check**: Verify scanner configuration hasn't changed
3. **Re-enablement**: Attempt to re-enable scanners that can be recovered
4. **State Updates**: Update scanner states with retry outcomes
5. **Logging**: Log all retry attempts and results for debugging

### Graceful Degradation

When scanners fail or are missing:

1. **Result Inclusion**: Include scanner entry in results with appropriate status
2. **Status Assignment**: Assign appropriate status (SKIPPED for disabled/excluded, FAILED for execution failures, MISSING for unknown issues)
3. **Failure Reasons**: Include detailed failure reason in scanner entry
4. **Dependency Tracking**: Mark dependency satisfaction status for scanners with missing dependencies
5. **Exclusion Tracking**: Mark exclusion status for scanners excluded by configuration
6. **Scan Continuity**: Maintain scan process continuity despite individual scanner failures

## Logging and Debugging

The Scanner Validation System provides comprehensive logging at multiple levels:

- **DEBUG**: Detailed state transitions and checkpoint creation
- **INFO**: Validation summaries, scanner counts, and status information
- **WARNING**: Missing scanners, retry attempts, and validation discrepancies
- **ERROR**: Critical validation failures and unrecoverable errors

### Example Log Output

```
INFO: Starting validation of registered scanner plugins
INFO: Found 6 registered scanner plugins:
INFO:   - bandit
INFO:   - checkov
INFO:   - detect-secrets
INFO:   - grype
INFO:   - semgrep
INFO:   - syft
INFO: Starting validation of scanner enablement status
INFO: Scanner enablement summary:
INFO:   Enabled scanners (4): bandit, detect-secrets, grype, semgrep
INFO:   Excluded scanners (1): syft
INFO:   Scanners with dependency issues (1):
INFO:     - checkov: Missing required tool: terraform
INFO: Starting validation of scanner task queue
INFO: Task queue validation summary:
INFO:   Expected scanners in queue (4): bandit, detect-secrets, grype, semgrep
INFO:   Actual scanners in queue (3): bandit, detect-secrets, semgrep
WARNING: Scanner 'grype' is enabled but missing from task queue
INFO: ✅ Task queue validation passed - all expected scanners are queued
INFO: Starting validation of result completeness
INFO: Result completeness validation summary:
INFO:   Originally registered scanners (6): bandit, checkov, detect-secrets, grype, semgrep, syft
INFO:   Scanners in current results (4): bandit, detect-secrets, grype, semgrep
INFO: Found 2 scanners missing from results, adding them:
INFO:   + Added 'checkov' with status SKIPPED: Missing dependencies: Missing required tool: terraform
INFO:   + Added 'syft' with status SKIPPED: Scanner was excluded by configuration
INFO: 🔧 Result completeness validation completed with 2 adjustments
INFO:    Added missing scanners: checkov, syft
INFO: 📊 Final result completeness rate: 100.0% (6/6)
```

## Integration with ScanPhase

The Scanner Validation System integrates with the existing `ScanPhase` class at key checkpoints. The `ScannerValidationManager` is initialized during `ScanPhase` construction and used throughout the scan lifecycle:

### Initialization

```python
class ScanPhase(EnginePhase):
    def __init__(self, plugin_context, plugins=None, progress_display=None, asharp_model=None):
        """Initialize the ScanPhase with validation manager.

        Args:
            plugin_context: Plugin context with paths and configuration
            plugins: List of plugins to use
            progress_display: Progress display to use for reporting progress
            asharp_model: AshAggregatedResults to update with results
        """
        super().__init__(plugin_context, plugins or [], progress_display, asharp_model)
        self.validation_manager = ScannerValidationManager(plugin_context)
```

### Validation Integration Points

The validation manager is integrated at key points during scan execution:

```python
def _execute_phase(self, aggregated_results, **kwargs):
    # 1. Registration validation (planned)
    scanner_classes = self.plugins
    # self.validation_manager.validate_registered_scanners(scanner_classes)

    # 2. Enablement validation (planned)
    enabled, excluded, dep_errors = self._filter_scanners(scanner_classes)
    # self.validation_manager.validate_scanner_enablement(enabled, excluded, dep_errors)

    # 3. Task queue validation (planned)
    queue_contents = self._populate_task_queue(enabled)
    # checkpoint = self.validation_manager.validate_task_queue(queue_contents)

    # 4. Retry missing scanners if needed (planned)
    # if checkpoint.get_missing_scanners():
    #     self.validation_manager.retry_scanner_registration(checkpoint.get_missing_scanners())

    # 5. Execute scanners
    completed = self._execute_scanners(queue_contents)

    # 6. Execution completion validation (planned)
    # self.validation_manager.validate_execution_completion(completed)

    # 7. Result completeness validation (planned)
    # self.validation_manager.ensure_complete_results(aggregated_results)
```

### Current Implementation Status

As of the current implementation:

- ✅ **Infrastructure**: `ScannerValidationManager` is initialized and available in `ScanPhase`
- ✅ **Registration Validation**: Scanner registration validation is active after plugin discovery
- ✅ **Enablement Validation**: Scanner enablement validation is active during scanner filtering
- ✅ **Task Queue Validation**: Task queue validation is integrated and active after queue population
- ✅ **Execution Completion Validation**: Execution completion validation is integrated and active after scanner execution
- ✅ **Result Completeness Validation**: Result completeness validation is integrated and active before finalizing results
- ✅ **Core Validation Methods**: All validation methods are implemented and tested
- ✅ **Integration Tests**: Comprehensive integration tests validate all validation checkpoints
- ✅ **Error Handling**: Graceful error handling and recovery mechanisms are implemented

The validation manager is fully integrated and actively validates all aspects of the scanner lifecycle. All five validation checkpoints are operational and provide comprehensive visibility into scanner status throughout the scan process.

## Integration with ScanPhase

The Scanner Validation System is fully integrated with the existing `ScanPhase` class at all key checkpoints. The `ScannerValidationManager` is initialized during `ScanPhase` construction and used throughout the scan lifecycle.

### Initialization

```python
class ScanPhase(EnginePhase):
    def __init__(self, plugin_context, plugins=None, progress_display=None, asharp_model=None):
        """Initialize the ScanPhase with validation manager."""
        super().__init__(plugin_context, plugins or [], progress_display, asharp_model)
        self.validation_manager = ScannerValidationManager(plugin_context)
```

### Validation Integration Points

The validation manager is integrated at all key points during scan execution:

```python
def _execute_phase(self, aggregated_results, **kwargs):
    # 1. Registration validation - ACTIVE
    scanner_classes = self.plugins
    if scanner_classes:
        self.validation_manager.validate_registered_scanners(scanner_classes)

    # 2. Enablement validation - ACTIVE
    enabled, excluded, dep_errors = self._filter_scanners(scanner_classes)
    self.validation_manager.validate_scanner_enablement(enabled, excluded, dep_errors)

    # 3. Task queue validation - ACTIVE
    self._validate_task_queue(aggregated_results)

    # 4. Execute scanners
    results = self._execute_scanners()

    # 5. Execution completion validation - ACTIVE
    self._validate_execution_completion(aggregated_results)

    # 6. Result completeness validation - ACTIVE
    self._validate_result_completeness(aggregated_results)
```

### Validation Methods in ScanPhase

The `ScanPhase` class includes several validation methods that integrate with the validation manager:

#### `_validate_task_queue(aggregated_results)`
- Extracts queue contents and validates against expected scanners
- Handles retry logic for missing scanners
- Adds validation checkpoints to aggregated results
- Provides comprehensive error handling

#### `_validate_execution_completion(aggregated_results)`
- Validates that all expected scanners completed execution
- Identifies missing scanners and reports discrepancies
- Updates validation summary in metadata
- Handles graceful error recovery

#### `_validate_result_completeness(aggregated_results)`
- Ensures all registered scanners appear in final results
- Adds missing scanners with appropriate status
- Includes failure reasons for failed scanners
- Maintains complete scan coverage visibility

### Integration Verification

A verification script (`verify_integration.py`) is available to test the scanner validation integration:

```bash
# Run the integration verification test
python verify_integration.py
```

This script validates that:
- The `ScannerValidationManager` is properly initialized in `ScanPhase`
- Validation methods are available and callable
- The integration points are working correctly

## Validation Output and Reporting

### Validation Checkpoints in Results

All validation checkpoints are automatically added to the `AshAggregatedResults` object and included in the final scan output. Each checkpoint contains:

- **Checkpoint Name**: Identifies the validation phase (e.g., "registered_scanners", "task_queue_validation")
- **Timestamp**: When the validation occurred
- **Expected vs Actual Scanners**: Lists of scanners expected and actually found
- **Discrepancies**: Detailed list of any issues found
- **Metadata**: Additional context and statistics

### Comprehensive Validation Report

The Scanner Validation System can generate a comprehensive validation report using the `generate_validation_report()` method. This report provides:

#### Executive Summary
- Total scanners tracked, registered, enabled, completed, and included in results
- Total validation checkpoints and count of checkpoints with issues
- Overall validation status indicator (✅ or ⚠️)

#### Scanner States Summary
Scanners are grouped by status for easy analysis:
- **Registered & Enabled**: Scanners that are properly configured and ready
- **Registered & Disabled**: Scanners that are registered but disabled
- **Missing Dependencies**: Scanners that cannot run due to missing dependencies
- **Excluded**: Scanners that are excluded by configuration
- **Failed**: Scanners that encountered failures during execution
- **Unknown Status**: Scanners with unclear status

#### Validation Checkpoints Detail
For each validation checkpoint:
- Checkpoint name and timestamp
- Expected vs actual scanner counts
- Specific discrepancies and errors found
- Missing and unexpected scanners identified

#### Detailed Scanner Information
For each tracked scanner:
- Registration and enablement status
- Specific enablement reasons and dependency errors
- Execution and result inclusion status
- Failure reasons and metadata

#### Dependency Analysis
- Count of scanners with dependency issues
- Most common missing dependencies across scanners
- Scanner-specific dependency error details

#### Actionable Recommendations
Based on validation findings:
- Suggestions for resolving dependency issues
- Configuration review recommendations
- Investigation guidance for failed scanners

### Example Validation Report Output

```
================================================================================
SCANNER VALIDATION REPORT
================================================================================

EXECUTIVE SUMMARY
----------------------------------------
Total Scanners Tracked: 6
Registered Scanners: 6
Enabled Scanners: 4
Completed Scanners: 4
Included in Results: 6
Total Checkpoints: 5
Checkpoints with Issues: 2
⚠️  VALIDATION ISSUES DETECTED

SCANNER STATES SUMMARY
----------------------------------------
Registered & Enabled (4):
  • bandit [Queued, Completed, In Results]
  • detect-secrets [Queued, Completed, In Results]
  • grype [Queued, Completed, In Results]
  • semgrep [Queued, Completed, In Results]

Missing Dependencies (1):
  • checkov [In Results, Failed: Missing dependencies: Missing required tool: terraform]

Excluded (1):
  • syft [In Results]

VALIDATION CHECKPOINTS
----------------------------------------
1. REGISTERED_SCANNERS
   Timestamp: 2023-01-01 12:00:00
   Expected: 6 scanners
   Actual: 6 scanners
   ✅ No issues detected

2. SCANNER_ENABLEMENT
   Timestamp: 2023-01-01 12:00:01
   Expected: 6 scanners
   Actual: 4 scanners
   ⚠️  ISSUES DETECTED:
   Discrepancies:
     - Scanner 'checkov' not enabled: Missing dependencies: Missing required tool: terraform
     - Scanner 'syft' not enabled: Scanner is excluded by configuration
   Missing: checkov, syft

RECOMMENDATIONS
----------------------------------------
1. Install missing dependencies for 1 scanners
2. Review configuration for 1 excluded scanners
3. Investigate failure reasons for 1 scanners

================================================================================
Report generated at: 2023-01-01 12:00:32
================================================================================
```

### Validation Summary in Metadata

The validation system adds a comprehensive summary to the scan metadata:

```json
{
  "validation_summary": {
    "registration_validation": {
      "timestamp": "2023-01-01T12:00:00",
      "total_registered": 6,
      "has_issues": false
    },
    "enablement_validation": {
      "timestamp": "2023-01-01T12:00:01",
      "enabled_count": 4,
      "excluded_count": 1,
      "dependency_error_count": 1,
      "has_issues": true
    },
    "task_queue_validation": {
      "timestamp": "2023-01-01T12:00:02",
      "expected_count": 4,
      "actual_count": 3,
      "missing_count": 1,
      "successfully_retried": 0,
      "has_issues": true
    },
    "execution_completion_validation": {
      "timestamp": "2023-01-01T12:00:30",
      "expected_count": 4,
      "completed_count": 4,
      "missing_count": 0,
      "completion_rate": 1.0,
      "has_issues": false
    },
    "result_completeness_validation": {
      "timestamp": "2023-01-01T12:00:31",
      "originally_registered": 6,
      "in_results": 6,
      "added_missing": 2,
      "completeness_rate": 1.0,
      "has_issues": false
    }
  }
}
```

### Accessing Validation Information

Validation information can be accessed from the aggregated results:

```python
# Access validation checkpoints
for checkpoint in aggregated_results.validation_checkpoints:
    print(f"Checkpoint: {checkpoint['checkpoint_name']}")
    print(f"Issues: {len(checkpoint.get('discrepancies', []))}")

# Access validation summary
validation_summary = aggregated_results.metadata.validation_summary
if validation_summary:
    for phase, summary in validation_summary.items():
        print(f"{phase}: {'✅' if not summary.get('has_issues') else '⚠️'}")

# Generate comprehensive validation report
validation_manager = ScannerValidationManager(plugin_context)
# ... perform validation activities ...
validation_report = validation_manager.generate_validation_report()
print(validation_report)

# Save validation report to file
with open('.ash/ash_output/validation_report.txt', 'w') as f:
    f.write(validation_report)
```

## Benefits

The Scanner Validation System provides several key benefits:

1. **Reliability**: Ensures all expected scanners are included in scans
2. **Visibility**: Provides clear insight into scanner status throughout the scan process
3. **Debugging**: Comprehensive logging helps troubleshoot intermittent scanner issues
4. **Recovery**: Automatic retry logic can recover from transient failures
5. **Completeness**: Guarantees all registered scanners appear in final results
6. **Consistency**: Standardized validation approach across all scan phases

## Future Enhancements

Potential future enhancements to the Scanner Validation System:

1. **Metrics Collection**: Collect validation metrics for monitoring and alerting
2. **Configurable Retry Logic**: Allow configuration of retry attempts and strategies
3. **Validation Reporting**: Generate detailed validation reports for audit purposes
4. **Performance Monitoring**: Track validation overhead and optimize performance
5. **Custom Validation Rules**: Allow custom validation rules for specific environments