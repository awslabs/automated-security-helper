# Built-in Event Callbacks

ASH includes built-in event callbacks that respond to scan lifecycle events, providing enhanced logging, notifications, and workflow integration capabilities.

## Event Callback Overview

| Callback                                              | Purpose                        | Events        | Key Features               |
|-------------------------------------------------------|--------------------------------|---------------|----------------------------|
| **[Scan Completion Logger](#scan-completion-logger)** | Enhanced scan progress logging | SCAN_COMPLETE | Remaining scanner tracking |

## Event System

ASH's event system allows plugins to subscribe to lifecycle events:

- **SCAN_START**: Scan phase begins
- **SCAN_TARGET**: Scanner targets a specific file/directory
- **SCAN_PROGRESS**: Scanner reports progress
- **SCAN_COMPLETE**: Individual scanner completes
- **CONVERT_START**: Conversion phase begins
- **CONVERT_COMPLETE**: Conversion phase completes
- **REPORT_START**: Reporting phase begins
- **REPORT_COMPLETE**: Reporting phase completes

## Built-in Event Callbacks

### Scan Completion Logger

**Purpose**: Provides enhanced logging when scanners complete, showing remaining scanner information.

**Events**: `SCAN_COMPLETE`

**Configuration**:
```yaml
event_callbacks:
  scan_completion_logger:
    enabled: true
    options:
      log_level: "INFO"
      show_remaining_count: true
      show_remaining_scanners: true
```

**Key Features**:
- Logs remaining scanner count
- Lists remaining scanner names
- Provides completion progress feedback
- Integrates with ASH logging system

**Example Output**:
```
INFO: Remaining scanners (2): semgrep, checkov
INFO: Remaining scanners (1): checkov
INFO: All scanners completed!
```

**Use Cases**:
- Progress monitoring in CI/CD
- Debugging scanner execution order
- Performance analysis
- User feedback during long scans

## Custom Event Callbacks

You can create custom event callbacks by following the built-in patterns:

```python
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins import ash_plugin_manager

def my_custom_callback(**kwargs):
    """Custom event callback function."""
    scanner = kwargs.get('scanner', 'unknown')
    print(f"Scanner {scanner} completed!")
    return True

# Register the callback
ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, my_custom_callback)
```

## Event Data

Each event provides specific data relevant to the lifecycle stage:

### SCAN_COMPLETE Event Data

```python
{
    'scanner': 'bandit',              # Scanner name
    'completed_count': 3,             # Scanners completed so far
    'total_count': 5,                 # Total scanners to run
    'remaining_count': 2,             # Scanners still running
    'remaining_scanners': ['semgrep', 'checkov'],  # List of remaining scanners
    'message': 'Scanner bandit completed. 2 remaining: semgrep, checkov'
}
```

## Configuration

Event callbacks can be configured in your ASH configuration file:

```yaml
# Enable/disable built-in event callbacks
event_callbacks:
  scan_completion_logger:
    enabled: true
    options:
      log_level: "INFO"

# Or disable all event callbacks
event_callbacks:
  scan_completion_logger:
    enabled: false
```

## Integration Examples

### CI/CD Notifications

```python
def ci_notification_callback(**kwargs):
    """Send notifications to CI/CD system."""
    remaining = kwargs.get('remaining_count', 0)
    if remaining == 0:
        # All scanners complete - send success notification
        send_slack_message("✅ Security scan completed successfully!")
    return True

ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, ci_notification_callback)
```

### Progress Tracking

```python
def progress_tracker(**kwargs):
    """Track scan progress for dashboards."""
    completed = kwargs.get('completed_count', 0)
    total = kwargs.get('total_count', 1)
    progress = (completed / total) * 100

    update_dashboard_progress(progress)
    return True

ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, progress_tracker)
```

## Best Practices

### Event Callback Design

```python
def robust_callback(**kwargs):
    """Example of robust event callback design."""
    try:
        # Extract data with defaults
        scanner = kwargs.get('scanner', 'unknown')
        remaining = kwargs.get('remaining_count', 0)

        # Perform callback logic
        if remaining == 0:
            logger.info("All scanners completed!")
        else:
            logger.info(f"Scanner {scanner} completed, {remaining} remaining")

        # Always return True for successful handling
        return True

    except Exception as e:
        # Log errors but don't break the scan
        logger.error(f"Event callback error: {e}")
        return False
```

### Performance Considerations

```python
def efficient_callback(**kwargs):
    """Keep callbacks lightweight and fast."""
    # Avoid heavy processing in callbacks
    # Use async operations for external calls
    # Return quickly to avoid blocking scan progress

    scanner = kwargs.get('scanner')
    # Quick logging only
    logger.debug(f"Scanner {scanner} completed")
    return True
```

## Troubleshooting

### Callback Not Firing

Check if event callbacks are enabled:
```yaml
event_callbacks:
  scan_completion_logger:
    enabled: true  # Ensure this is true
```

### Performance Issues

```python
# Avoid blocking operations in callbacks
def bad_callback(**kwargs):
    time.sleep(10)  # DON'T DO THIS
    return True

def good_callback(**kwargs):
    # Use async or background processing
    threading.Thread(target=background_task, args=(kwargs,)).start()
    return True
```

### Error Handling

```python
def safe_callback(**kwargs):
    try:
        # Your callback logic here
        process_event(kwargs)
        return True
    except Exception as e:
        # Log but don't re-raise to avoid breaking scan
        logger.error(f"Callback error: {e}")
        return False
```

## Next Steps

- **[Plugin Development](../development-guide.md)**: Create custom event callbacks
- **[Scanner Integration](scanners.md)**: Understand scanner lifecycle
- **[Advanced Usage](../../advanced-usage.md)**: Complex workflow integration
