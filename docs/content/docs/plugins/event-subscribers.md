# Event Subscribers

ASH provides a comprehensive event system that allows plugins to react to various events during the scanning process. This enables you to create custom logging, notifications, integrations, and other reactive behaviors.

## Overview

The event system uses a discovery-based pattern similar to how ASH discovers scanners, converters, and reporters. Event subscribers are registered using the `ASH_EVENT_HANDLERS` dictionary in your plugin module.

## Basic Event Subscriber

Here's a simple example of creating an event subscriber:

```python
# my_ash_plugins/__init__.py
from automated_security_helper.plugins.events import AshEventType

def handle_scan_complete(**kwargs):
    """Handle scan complete event"""
    scanner = kwargs.get('scanner', 'Unknown')
    remaining_count = kwargs.get('remaining_count', 0)

    print(f"Scanner '{scanner}' completed!")
    if remaining_count > 0:
        print(f"{remaining_count} scanners still running")
    else:
        print("All scanners completed!")

    return True

# Event callback registry
ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [handle_scan_complete],
}
```

## Available Event Types

ASH provides the following event types:

### Phase Events
- `AshEventType.CONVERT_START`: Fired when the convert phase begins
- `AshEventType.CONVERT_COMPLETE`: Fired when the convert phase completes
- `AshEventType.SCAN_START`: Fired when the scan phase begins
- `AshEventType.SCAN_COMPLETE`: Fired when each individual scanner completes
- `AshEventType.REPORT_START`: Fired when the report phase begins
- `AshEventType.REPORT_COMPLETE`: Fired when the report phase completes

### General Events
- `AshEventType.ERROR`: Fired when errors occur
- `AshEventType.WARNING`: Fired for warning conditions
- `AshEventType.INFO`: Fired for informational events

## Event Data

Each event type provides specific data through keyword arguments:

### SCAN_COMPLETE Event Data

The `SCAN_COMPLETE` event is fired each time an individual scanner finishes and provides:

- `scanner`: Name of the completed scanner
- `completed_count`: Number of scanners completed so far
- `total_count`: Total number of scanners
- `remaining_count`: Number of scanners still running
- `remaining_scanners`: List of remaining scanner names
- `message`: Human-readable summary message
- `phase`: The phase name ("scan")
- `plugin_context`: The current plugin context

### Common Event Data

All events include:

- `phase`: The name of the current phase
- `plugin_context`: The current plugin context with source/output directories and configuration

## Multiple Event Subscribers

You can register multiple subscribers for the same event:

```python
def log_scan_completion(**kwargs):
    """Log scan completion to file"""
    scanner = kwargs.get('scanner')
    with open('/tmp/scan.log', 'a') as f:
        f.write(f"Scanner {scanner} completed at {datetime.now()}\n")
    return True

def notify_scan_completion(**kwargs):
    """Send notification about scan completion"""
    scanner = kwargs.get('scanner')
    remaining = kwargs.get('remaining_count', 0)
    # Send notification logic here
    return True

ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [
        log_scan_completion,
        notify_scan_completion,
    ],
}
```

## Multiple Event Types

You can subscribe to multiple event types:

```python
def handle_phase_start(**kwargs):
    """Handle any phase start"""
    phase = kwargs.get('phase', 'Unknown')
    print(f"Phase '{phase}' started")
    return True

def handle_phase_complete(**kwargs):
    """Handle any phase completion"""
    phase = kwargs.get('phase', 'Unknown')
    print(f"Phase '{phase}' completed")
    return True

ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_START: [handle_phase_start],
    AshEventType.SCAN_COMPLETE: [handle_scan_completion],
    AshEventType.CONVERT_START: [handle_phase_start],
    AshEventType.CONVERT_COMPLETE: [handle_phase_complete],
    AshEventType.REPORT_START: [handle_phase_start],
    AshEventType.REPORT_COMPLETE: [handle_phase_complete],
}
```

## Error Handling

Event subscribers should handle errors gracefully to avoid disrupting the scan process:

```python
def robust_event_handler(**kwargs):
    """Event handler with proper error handling"""
    try:
        scanner = kwargs.get('scanner', 'Unknown')
        # Your event handling logic here
        print(f"Processing completion of {scanner}")
        return True
    except Exception as e:
        # Log the error but don't re-raise to avoid disrupting the scan
        print(f"Error in event handler: {e}")
        return False
```

## Real-World Examples

### Slack Notifications

```python
import requests

def notify_slack_on_completion(**kwargs):
    """Send Slack notification when all scanners complete"""
    remaining_count = kwargs.get('remaining_count', 0)

    if remaining_count == 0:  # All scanners completed
        webhook_url = os.environ.get("SLACK_WEBHOOK", None)
        if webhook_url is None:
            ASH_LOGGER.error("SLACK_WEBHOOK variable is unset! Unable to send webhook.")
            return False
        message = {
            "text": "🎉 ASH security scan completed successfully!",
            "channel": "#security-alerts"
        }
        try:
            requests.post(webhook_url, json=message)
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")

    return True

ASH_EVENT_HANDLERS = {
    AshEventType.EXECUTION_COMPLETE: [notify_slack_on_completion],
}
```

### Custom Metrics Collection

```python
import time

# Global state for tracking metrics
scan_metrics = {}

def track_scan_metrics(**kwargs):
    """Track scan performance metrics"""
    scanner = kwargs.get('scanner')
    completed_count = kwargs.get('completed_count', 0)
    total_count = kwargs.get('total_count', 0)

    # Record completion time
    scan_metrics[scanner]['completed_at'] = time.time()

    # Calculate progress
    progress = (completed_count / total_count) * 100 if total_count > 0 else 0
    print(f"Scan progress: {progress:.1f}% ({completed_count}/{total_count})")

    return True

ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [track_scan_metrics],
}
```

### Integration with External Systems

```python
import json
import requests
from datetime import datetime, timezone

def send_to_monitoring_system(**kwargs):
    """Send scan completion data to external monitoring system"""
    try:
        scanner = kwargs.get('scanner')
        completed_count = kwargs.get('completed_count', 0)
        total_count = kwargs.get('total_count', 0)
        remaining_count = kwargs.get('remaining_count', 0)

        # Prepare monitoring data
        monitoring_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'scanner_completed',
            'scanner_name': scanner,
            'progress': {
                'completed': completed_count,
                'total': total_count,
                'remaining': remaining_count,
                'percentage': (completed_count / total_count * 100) if total_count > 0 else 0
            }
        }

        # Send to monitoring endpoint
        response = requests.post(
            'https://monitoring.example.com/api/events',
            json=monitoring_data,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )

        if response.status_code == 200:
            print(f"Successfully sent monitoring data for {scanner}")
        else:
            print(f"Failed to send monitoring data: {response.status_code}")

    except Exception as e:
        print(f"Error sending monitoring data: {e}")

    return True

ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [send_to_monitoring_system],
}
```

### Database Logging

```python
import sqlite3
from datetime import datetime

def log_to_database(**kwargs):
    """Log scan events to SQLite database"""
    try:
        scanner = kwargs.get('scanner')
        completed_count = kwargs.get('completed_count', 0)
        total_count = kwargs.get('total_count', 0)
        phase = kwargs.get('phase', 'unknown')

        # Connect to database
        conn = sqlite3.connect('/tmp/ash_scan_log.db')
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                phase TEXT,
                scanner TEXT,
                completed_count INTEGER,
                total_count INTEGER,
                progress_percentage REAL
            )
        ''')

        # Insert event data
        progress = (completed_count / total_count * 100) if total_count > 0 else 0
        cursor.execute('''
            INSERT INTO scan_events
            (timestamp, phase, scanner, completed_count, total_count, progress_percentage)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now(timezone.utc).isoformat(),
            phase,
            scanner,
            completed_count,
            total_count,
            progress
        ))

        conn.commit()
        conn.close()

        print(f"Logged scan event for {scanner} to database")

    except Exception as e:
        print(f"Error logging to database: {e}")

    return True

ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [log_to_database],
}
```

## Plugin Discovery

ASH automatically discovers event subscribers by:

1. Loading modules specified in the `internal_modules` list (for built-in plugins)
2. Loading additional modules specified in configuration via `ash_plugin_modules`
3. Scanning for `ASH_EVENT_HANDLERS` constants in loaded modules
4. Registering discovered event subscribers with the plugin manager

The event subscribers are called in the order they appear in the callback list for each event type.

## Best Practices

1. **Return Values**: Always return `True` for successful handling or `False` for errors
2. **Error Handling**: Use try-catch blocks to prevent event handler errors from disrupting scans
3. **Performance**: Keep event handlers lightweight to avoid slowing down the scan process
4. **Logging**: Use appropriate log levels and avoid excessive output
5. **State Management**: Be careful with global state in multi-threaded environments
6. **Resource Cleanup**: Clean up any resources (files, connections) in your event handlers
7. **Timeouts**: Use timeouts for external API calls to prevent hanging
8. **Graceful Degradation**: Design handlers to fail gracefully without affecting the main scan process

## Advanced Usage

### Conditional Event Handling

```python
def conditional_handler(**kwargs):
    """Only handle events under certain conditions"""
    scanner = kwargs.get('scanner')
    remaining_count = kwargs.get('remaining_count', 0)

    # Only notify for critical scanners or when all complete
    critical_scanners = ['bandit', 'semgrep', 'checkov']

    if scanner in critical_scanners or remaining_count == 0:
        print(f"Important: {scanner} completed!")
        # Send notification logic here

    return True
```

### Event Filtering

```python
def filtered_handler(**kwargs):
    """Filter events based on context"""
    plugin_context = kwargs.get('plugin_context')

    # Only handle events for certain source directories
    if plugin_context and 'production' in str(plugin_context.source_dir):
        scanner = kwargs.get('scanner')
        print(f"Production scan: {scanner} completed")
        # Handle production-specific logic

    return True
```

### Stateful Event Handling

```python
class ScanProgressTracker:
    def __init__(self):
        self.start_time = None
        self.completed_scanners = []

    def handle_scan_start(self, **kwargs):
        """Track scan start time"""
        self.start_time = time.time()
        self.completed_scanners = []
        print("Scan progress tracking started")
        return True

    def handle_scan_complete(self, **kwargs):
        """Track individual scanner completion"""
        scanner = kwargs.get('scanner')
        remaining_count = kwargs.get('remaining_count', 0)

        self.completed_scanners.append(scanner)

        if self.start_time:
            elapsed = time.time() - self.start_time
            print(f"Scanner {scanner} completed after {elapsed:.1f}s")

        if remaining_count == 0:
            total_time = time.time() - self.start_time if self.start_time else 0
            print(f"All scanners completed in {total_time:.1f}s")
            print(f"Completion order: {', '.join(self.completed_scanners)}")

        return True

# Create tracker instance
tracker = ScanProgressTracker()

ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_START: [tracker.handle_scan_start],
    AshEventType.SCAN_COMPLETE: [tracker.handle_scan_complete],
}
```

## Integration with Built-in Events

ASH includes built-in event subscribers for core functionality like scan completion logging. Your custom event subscribers will run alongside these built-in handlers, allowing you to extend ASH's behavior without replacing core functionality.

The built-in scan completion logger provides enhanced logging that shows remaining scanners:

```
INFO: Completed scanner: bandit
INFO: Remaining scanners (2): semgrep, checkov
```

Your custom event subscribers will receive the same event data and can provide additional functionality like notifications, metrics collection, or integration with external systems.
