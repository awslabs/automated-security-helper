# Built-in Event Handlers

ASH includes built-in event handlers that respond to scan lifecycle events.

> For detailed visual diagrams of the built-in event handler architecture and workflows, see [Built-in Event Handler Diagrams](event-handlers-diagrams.md).

## Event Handler Overview

| Handler | Purpose | Events | Key Features |
|---------|---------|--------|--------------|
| **Scan Completion Logger** | Enhanced scan progress logging | SCAN_COMPLETE | Remaining scanner tracking |
| **Suppression Expiration Checker** | Check for expiring suppressions | EXECUTION_START | Proactive expiration warnings |

## Built-in Event Handlers

### Scan Completion Logger

**Purpose**: Provides enhanced logging when scanners complete, showing remaining scanner information.

**Events**: `SCAN_COMPLETE`

**Module**: `automated_security_helper.plugin_modules.ash_builtin.event_handlers.scan_completion_logger`

**Example Output**:
```
INFO: Remaining scanners (2): semgrep, checkov
INFO: All scanners completed!
```

### Suppression Expiration Checker

**Purpose**: Checks for suppressions that are approaching their expiration date and warns users at the start of execution.

**Events**: `EXECUTION_START`

**Module**: `automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker`

**Key Features**:
- Warns about suppressions expiring within 30 days
- Provides helpful guidance on updating suppressions
- Respects the `--ignore-suppressions` flag
- Detailed logging with rule ID, file path, expiration date, and reason

**Example Output**:
```
The following suppressions will expire within 30 days:
  - Rule B101 for src/test.py expires on 2024-07-15. Reason: Test file with intentional assert
To update suppression expiration dates, modify your ASH configuration file
```

## Enhanced Offline Mode Logging

The offline mode validation system has been enhanced with emoji-prefixed logging:

- `Semgrep offline mode: Found 150 rule files in cache`
- `Semgrep offline mode: SEMGREP_RULES_CACHE_DIR not set, falling back to p/ci`
- `Grype offline mode: Cache directory validated with 5 files`
- `Grype offline mode: Database is 45 days old, consider updating`

## Custom Event Handlers

You can create custom event handlers:

```python
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins import ash_plugin_manager

def my_custom_callback(**kwargs):
    scanner = kwargs.get("scanner", "unknown")
    print(f"Scanner {scanner} completed!")
    return True

ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, my_custom_callback)
```

## Benefits

1. **Better Observability** - Comprehensive visibility into scan execution
2. **Integration Capabilities** - Easy integration with external systems
3. **Custom Automation** - Trigger custom actions based on scan events
4. **Improved Debugging** - Detailed event logging for troubleshooting
