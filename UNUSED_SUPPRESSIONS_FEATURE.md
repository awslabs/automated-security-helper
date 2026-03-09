# Unused Suppressions Detection Feature

## Overview

This feature adds the ability to identify suppressions that are configured but not actually being used to suppress any findings. This helps keep your ASH configuration clean and maintainable by identifying:

- Suppressions for files that no longer exist
- Suppressions for findings that have been fixed
- Suppressions that are no longer applicable

## Implementation

### 1. New Reporter Plugin

**File**: `automated_security_helper/plugin_modules/ash_builtin/reporters/unused_suppressions_reporter.py`

A new reporter plugin that generates both JSON and Markdown reports identifying unused suppressions.

**Configuration**:
- Name: `unused-suppressions`
- Extension: `unused-suppressions.json` (or `.md` for markdown)
- Enabled by default: `true`
- Output formats: JSON and Markdown

### 2. Suppression Tracking

**Modified Files**:
- `automated_security_helper/models/asharp_model.py` - Added `used_suppressions` field to track which suppressions were applied
- `automated_security_helper/utils/sarif_utils.py` - Modified `apply_suppressions_to_sarif()` to track used suppressions
- `automated_security_helper/core/phases/scan_phase.py` - Updated to pass the tracking set to suppression application

**How it works**:
1. During scan execution, when a suppression is applied to a finding, its unique ID is added to the `used_suppressions` set
2. The suppression ID format is: `path|rule_id|line_start|line_end` (with `*` for unspecified values)
3. After the scan completes, the reporter compares all configured suppressions against the used set

### 3. Report Formats

The reporter generates two types of reports:

#### JSON Report

Location: `.ash/ash_output/reports/ash.unused-suppressions.json`

```json
{
  "summary": {
    "total_suppressions": 10,
    "used_suppressions": 7,
    "unused_suppressions": 3
  },
  "unused_suppressions": [
    {
      "path": "src/old_file.py",
      "rule_id": "B201",
      "line_start": 42,
      "line_end": 42,
      "reason": "False positive - debug mode only in development",
      "expiration": "2026-12-31"
    }
  ]
}
```

#### Markdown Report

Location: `.ash/ash_output/reports/ash.unused-suppressions.md`

Human-readable format with:
- Summary statistics with visual indicators (✅ or ⚠️)
- Percentage of unused suppressions
- Detailed list of each unused suppression with all metadata
- Actionable recommendations for cleanup

Example output:

```markdown
# Unused Suppressions Report

## Summary

- **Total Suppressions**: 10
- **Used Suppressions**: 7
- **Unused Suppressions**: 3

⚠️  **30.0% of suppressions are unused**

## Unused Suppressions

The following suppressions are configured but not currently matching any findings:

### 1. src/old_file.py

- **Rule ID**: `B201`
- **Line**: 42
- **Reason**: False positive - debug mode only in development
- **Expiration**: 2026-12-31

## Recommendations

Review each unused suppression and consider:

1. **File no longer exists**: Remove the suppression from your configuration
2. **Finding was fixed**: Remove the suppression as it's no longer needed
3. **Path/rule/line mismatch**: Update the suppression to match the current code
4. **Still needed**: Verify the suppression is correctly configured
```

## Usage

### Automatic Generation

Both reports are automatically generated during every ASH scan when the reporter is enabled (default).

### Enabling/Disabling

To disable the reporter, add to your `.ash/.ash.yaml`:

```yaml
reporters:
  unused-suppressions:
    enabled: false
```

### Choosing Output Format

By default, both JSON and Markdown reports are generated. To specify a preference:

```yaml
reporters:
  unused-suppressions:
    enabled: true
    options:
      output_format: "markdown"  # "json" or "markdown"
```

### Reviewing Unused Suppressions

After a scan, check the reports:

```bash
# View markdown report (human-readable)
cat .ash/ash_output/reports/ash.unused-suppressions.md

# View JSON summary
jq '.summary' .ash/ash_output/reports/ash.unused-suppressions.json

# View detailed unused suppressions
jq '.unused_suppressions' .ash/ash_output/reports/ash.unused-suppressions.json
```

### Cleaning Up

Review each unused suppression and:

1. **If the file no longer exists**: Remove the suppression
2. **If the finding was fixed**: Remove the suppression
3. **If the suppression is still needed**: Verify the path/rule_id/line numbers are correct

## Example Workflow

1. Run ASH scan:
   ```bash
   ash --mode local
   ```

2. Check for unused suppressions:
   ```bash
   cat .ash/ash_output/reports/ash.unused-suppressions.md
   ```

3. Review details in JSON format:
   ```bash
   jq '.unused_suppressions[] | {path, rule_id, reason}' .ash/ash_output/reports/ash.unused-suppressions.json
   ```

4. Update your `.ash/.ash.yaml` to remove unused suppressions

5. Re-run scan to verify:
   ```bash
   ash --mode local
   ```

## Benefits

- **Cleaner Configuration**: Remove obsolete suppressions
- **Better Maintenance**: Identify suppressions that may need updating
- **Audit Trail**: Track which suppressions are actively being used
- **Compliance**: Ensure suppressions are still relevant and justified
- **Human-Readable**: Markdown format makes it easy to review and share with team

## Technical Details

### Suppression ID Generation

The unique ID for each suppression is generated using the format:
```
path|rule_id|line_start|line_end
```

Where:
- `path`: File path or glob pattern
- `rule_id`: Scanner rule identifier (or `*` if not specified)
- `line_start`: Starting line number (or `*` if not specified)
- `line_end`: Ending line number (defaults to `line_start` if not specified, or `*` if neither specified)

### Tracking Mechanism

1. `AshAggregatedResults.used_suppressions` - A set that accumulates suppression IDs during the scan
2. `apply_suppressions_to_sarif()` - When a suppression matches a finding, its ID is added to the set
3. `UnusedSuppressionsReporter` - Compares configured suppressions against the used set and generates reports

### Output Format Selection

The reporter supports two output formats:
- **JSON**: Machine-readable, suitable for automation and CI/CD integration
- **Markdown**: Human-readable, suitable for manual review and documentation

## Testing

Tests are included in `tests/unit/reporters/test_unused_suppressions_reporter.py` covering:
- All suppressions unused
- Some suppressions used
- All suppressions used
- No suppressions configured

Run tests with:
```bash
uv run pytest tests/unit/reporters/test_unused_suppressions_reporter.py
```

## CI/CD Integration

### Example: Fail Build on Unused Suppressions

```bash
#!/bin/bash
# Check for unused suppressions and fail if threshold exceeded

UNUSED_COUNT=$(jq '.summary.unused_suppressions' .ash/ash_output/reports/ash.unused-suppressions.json)
THRESHOLD=5

if [ "$UNUSED_COUNT" -gt "$THRESHOLD" ]; then
  echo "❌ Too many unused suppressions: $UNUSED_COUNT (threshold: $THRESHOLD)"
  echo "Review: .ash/ash_output/reports/ash.unused-suppressions.md"
  exit 1
else
  echo "✅ Unused suppressions within threshold: $UNUSED_COUNT"
fi
```

### Example: Generate Report Artifact

```yaml
# GitHub Actions example
- name: Run ASH Scan
  run: ash --mode local

- name: Upload Unused Suppressions Report
  uses: actions/upload-artifact@v3
  with:
    name: unused-suppressions-report
    path: .ash/ash_output/reports/ash.unused-suppressions.md
```

## Future Enhancements

Potential improvements:
- Add a CLI command to automatically remove unused suppressions
- Include usage statistics (how many times each suppression was applied)
- Add warnings for suppressions that haven't been used in X scans
- Integration with CI/CD to fail if unused suppressions exceed a threshold
- Historical tracking of suppression usage over time
