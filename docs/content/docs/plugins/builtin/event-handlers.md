# Built-in Event Handlers

ASH includes built-in event handlers that respond to scan lifecycle events.

> For detailed visual diagrams of the built-in event handler architecture and workflows, see [Built-in Event Handler Diagrams](event-handlers-diagrams.md).

## Event Handler Overview

| Handler | Purpose | Events | Key Features |
|---------|---------|--------|--------------|
| **Scan Completion Logger** | Enhanced scan progress logging | SCAN_COMPLETE | Remaining scanner tracking |
| **Suppression Expiration Checker** | Check for expiring suppressions and ignore paths | EXECUTION_START | Proactive expiration warnings |

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

**Purpose**: Checks for suppressions and ignore paths that are approaching their expiration date and warns users at the start of execution.

**Events**: `EXECUTION_START`

**Module**: `automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker`

**Key Features**:
- Warns about suppressions and ignore paths expiring within the next 30 days,
  including the entries of bandit `excluded_paths`, checkov `skip_path` and syft
  `exclude`
- Lists, in one warning, the suppressions and ignore paths that have already expired
  (including any whose expiration date is today), since they no longer apply
- Provides helpful guidance on updating suppressions
- Skips the suppression check under `--ignore-suppressions`; ignore paths are still
  checked, because that flag turns off suppressions only and ignore paths still apply
- Detailed logging with rule ID, file path, expiration date, and reason

**Example Output**:
```
The following ignore paths and suppressions have expired and no longer apply:
  - Ignore path 'build/generated/**' expired on 2024-06-30. Reason: Generated until the build moves
Remove them, or move their expiration dates, in your ASH configuration file.
The following ignore paths will expire within 30 days:
  - Ignore path 'vendor/**' expires on 2024-07-20. Reason: Vendored until the upgrade
To update ignore path expiration dates, modify your ASH configuration file
The following suppressions will expire within 30 days:
  - Rule 'B101' for 'src/test.py' expires on 2024-07-15. Reason: Test file with intentional assert
To update suppression expiration dates, modify your ASH configuration file
```

## Enhanced Offline Mode Logging

The offline mode validation system has been enhanced with emoji-prefixed logging:

- `Semgrep offline mode: Found 150 rule files in cache`
- `Semgrep is running in offline mode but no rule cache was found. Set $SEMGREP_RULES_CACHE_DIR to a directory containing .yaml/.yml rule files.`
- `Grype offline mode: Cache directory validated with 5 files`
- `Grype offline mode: Database is 45 days old, past the 120h bound grype enforces online; consider updating`

There is no fallback to the online `p/ci` ruleset when the cache is missing. An
offline run that silently fetched the registry ruleset would be a different scan
than the one that was requested, reported as the one that was requested. The
scanner declines instead: it records the reason above, `ash` reports it as
`MISSING`, and the run fails the completeness gate when
`--fail-on-incomplete-scanners` is in effect.

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

Where the handler is defined decides which scans notify it. A handler defined in your
own program, outside ASH's plugin namespace, is notified in every scan that program
runs. A handler defined in a plugin package is notified only in scans whose
`ash_plugin_modules` name that package, and only when the package defines, imports or
lists it (see [Using Custom Plugin Packages](../development-guide.md#using-custom-plugin-packages)).

## Benefits

1. **Better Observability** - Comprehensive visibility into scan execution
2. **Integration Capabilities** - Easy integration with external systems
3. **Custom Automation** - Trigger custom actions based on scan events
4. **Improved Debugging** - Detailed event logging for troubleshooting
