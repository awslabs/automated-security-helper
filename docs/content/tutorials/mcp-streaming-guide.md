# ASH MCP Streaming Results Guide

This guide explains how to use ASH's streaming functionality through the Model Context Protocol (MCP) server for real-time progress tracking during security scans.

## Overview

The streaming functionality provides real-time progress updates during ASH security scans. Instead of waiting for a complete scan to finish, you can now:

- Start scans in the background
- Monitor progress in real-time
- Get partial results as they become available
- Manage multiple concurrent scans
- Cancel running scans

This is especially useful for large codebases where scans can take several minutes to complete.

## How It Works

ASH's MCP server uses an event-driven system to track scan progress. When you start a scan with progress tracking, ASH:

1. Starts the scan in the background
2. Returns a unique scan ID immediately
3. Publishes progress events as the scan proceeds
4. Allows you to check progress and get partial results
5. Provides final results when the scan completes

## Available Commands

When using ASH through an MCP-compatible AI assistant, you can use these streaming capabilities:

### Starting a Streaming Scan

```
"Start a security scan with progress tracking on this directory"
"Begin a background security scan and show me updates as it runs"
```

This uses the `scan_directory_with_progress` tool, which returns immediately with a scan ID.

### Monitoring Progress

```
"Show me the progress of my security scan"
"What's the current status of scan [scan-id]?"
"How many security issues have been found so far?"
```

This uses the `get_scan_progress` tool to show:
- Overall progress percentage
- Current scanning phase
- Which scanner is currently running
- Number of findings discovered so far
- Estimated time remaining

### Managing Multiple Scans

```
"Show me all my active security scans"
"List the status of all running scans"
```

This uses the `list_active_scans` tool to display all concurrent scans and their status.

### Canceling Scans

```
"Cancel the security scan on the backend directory"
"Stop scan [scan-id]"
```

This uses the `cancel_scan` tool to stop a running scan and clean up resources.

### Getting Final Results

```
"Get the final results for my completed security scan"
"Show me the detailed findings from scan [scan-id]"
```

This uses the `get_scan_results` tool to retrieve comprehensive results once a scan completes.

## Progress Phases

Your security scan progresses through these phases:

1. **Initializing** (0%): Setting up the scan and validating parameters
2. **Running** (0-25%): Starting the scan execution
3. **Scanning** (25-85%): Individual security scanners are running
   - detect-secrets (finding hardcoded secrets)
   - bandit (Python security issues)
   - semgrep (code patterns and vulnerabilities)
   - checkov (infrastructure security)
   - And others based on your project type
4. **Generating Reports** (85-95%): Creating output files and summaries
5. **Finished** (100%): Scan completed successfully

## Real-Time Updates

During the scanning phase, you'll see updates like:

- "Running bandit scanner..." (Python security analysis)
- "Running semgrep scanner..." (Pattern-based vulnerability detection)
- "Running detect-secrets scanner..." (Credential scanning)
- "Found 3 new security issues in current file..."
- "Completed infrastructure security checks..."

## Example Workflow

Here's a typical workflow using streaming scans:

1. **Start the scan:**
   ```
   "Start a security scan with progress tracking on my project"
   ```
   Response: "Started security scan with ID abc-123. I'll monitor the progress for you."

2. **Monitor progress:**
   ```
   "How is my security scan progressing?"
   ```
   Response: "Your scan is 45% complete. Currently running semgrep scanner. Found 2 security issues so far."

3. **Check multiple scans:**
   ```
   "Show me all my active scans"
   ```
   Response: "You have 2 active scans: Project A (75% complete), Project B (30% complete)."

4. **Get final results:**
   ```
   "My scan finished - show me the results"
   ```
   Response: "Scan completed! Found 5 security issues: 2 high severity, 3 medium severity. Here are the details..."

## Benefits

### For Large Projects
- No need to wait for long scans to complete
- See progress and early findings immediately
- Can work on other tasks while scans run

### For Multiple Projects
- Run scans on different directories simultaneously
- Track progress across all your projects
- Prioritize which results to review first

### For Development Workflow
- Start scans when you begin code review
- Get immediate feedback on critical issues
- Cancel scans if you need to make changes

## Configuration

The streaming functionality works with all your existing ASH configurations:

- **Severity thresholds**: Set minimum severity levels
- **Custom scanners**: Enable/disable specific security tools
- **Ignore patterns**: Skip certain files or directories
- **Output formats**: Choose how results are presented

Example requests:
```
"Start a high-severity security scan with progress tracking"
"Scan this directory but ignore the test files, and show me progress"
"Run only the secrets scanner with streaming updates"
```

## Troubleshooting

### Scan Stuck or Taking Too Long
```
"Cancel my security scan and start a new one"
"Show me what scanner is currently running"
```

### Multiple Scans Consuming Resources
```
"List all my active scans"
"Cancel all running scans except the most recent one"
```

### Missing Progress Updates
```
"Check the status of scan [scan-id]"
"Is my security scan still running?"
```

## Best Practices

### 1. Use for Large Codebases
Streaming is most beneficial for projects with many files or complex security configurations.

### 2. Monitor Critical Scans
For production or release-critical code, monitor progress to catch high-severity issues early.

### 3. Manage Resources
Don't run too many concurrent scans - they can consume significant CPU and memory.

### 4. Set Appropriate Thresholds
Use higher severity thresholds (HIGH or CRITICAL) for faster scans when you only need the most important issues.

## Integration with Development Workflow

### Code Review Process
1. Start streaming scan when beginning code review
2. Monitor for critical issues while reviewing
3. Address high-priority security findings first

### CI/CD Integration
1. Start background scans early in the pipeline
2. Monitor progress and fail fast on critical issues
3. Generate detailed reports for successful builds

### Daily Development
1. Start scans on modified directories
2. Work on other tasks while scans run
3. Review findings when convenient

## Next Steps

- Learn more about [Using ASH with MCP](using-ash-with-mcp.md) for basic setup
- Explore [ASH Configuration](../docs/configuration-guide.md) for customizing scans
- Check out [Running ASH in CI](running-ash-in-ci.md) for automation workflows

The streaming functionality makes security scanning a more integrated part of your development workflow, providing immediate feedback without blocking your productivity.