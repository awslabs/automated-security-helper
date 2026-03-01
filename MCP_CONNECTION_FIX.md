# MCP Connection Management Fix

## Problem

The MCP server was closing connections when clients polled `get_scan_progress`, even though the ASH integration guide explicitly recommends polling every 5 seconds to keep the connection alive.

## Root Cause

The issue was in the background monitoring task (`_monitor_scan_progress`) that runs after `run_ash_scan` starts a scan:

1. **Orphaned Task Reference**: The background task was created with `asyncio.create_task()` but no reference was kept, making it susceptible to garbage collection
2. **Stale Context Usage**: The monitoring task continued trying to send progress updates through a context that may have been closed when the client disconnected
3. **Connection Interference**: When the monitoring task tried to send updates on a closed connection, it could interfere with new client connections attempting to poll progress

## Solution

### 1. Task Reference Management

Added proper task reference management to prevent garbage collection:

```python
# Store task reference to prevent it from being garbage collected
monitor_task = asyncio.create_task(_monitor_scan_progress(ctx, scan_id))
# Add task to a set to keep it alive (but don't await it)
if not hasattr(run_ash_scan, '_monitor_tasks'):
    run_ash_scan._monitor_tasks = set()
run_ash_scan._monitor_tasks.add(monitor_task)
# Remove task from set when it completes
monitor_task.add_done_callback(lambda t: run_ash_scan._monitor_tasks.discard(t))
```

### 2. Connection State Tracking

Added `connection_alive` flag to track whether the context is still usable:

```python
connection_alive = True  # Track if we can still send updates
```

### 3. Graceful Degradation

Modified all context operations to:
- Check `connection_alive` before attempting to send updates
- Catch exceptions and mark connection as dead instead of failing
- Continue monitoring silently even if connection is lost
- Use `logger.debug()` instead of `logger.warning()` for connection errors

```python
try:
    if connection_alive:
        await ctx.report_progress(...)
except Exception as e:
    logger.debug(f"Failed to send progress update: {str(e)}")
    connection_alive = False
```

## Benefits

1. **Resilient Monitoring**: Background task continues monitoring even if client disconnects
2. **No Connection Interference**: Failed context operations don't interfere with new client connections
3. **Clean Separation**: Background monitoring and client polling operate independently
4. **Reduced Noise**: Connection errors logged at debug level instead of warning level

## Testing Recommendations

Test the following scenarios:

1. **Normal Operation**: Client polls every 5 seconds until completion
2. **Client Disconnect**: Client disconnects mid-scan, then reconnects and polls
3. **Multiple Clients**: Multiple clients polling the same scan_id
4. **Long Scans**: Scans taking 2+ minutes with continuous polling

## Expected Behavior

- Background monitoring task sends updates when connection is alive
- When connection closes, task continues monitoring silently
- Client can poll `get_scan_progress` at any time without connection issues
- Scan completes successfully regardless of client connection state
