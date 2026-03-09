# Global Suppressions

ASH v3 supports global suppressions, allowing you to suppress specific security findings across your project. This feature helps reduce noise from known issues that have been reviewed and accepted, allowing teams to focus on new and relevant security findings.

## Understanding Suppressions vs. Ignore Paths

ASH provides two mechanisms for excluding findings:

1. **Ignore Paths**: Files matching these patterns are completely excluded from scanning and do not appear in final results. Use this when you want to completely skip scanning certain files or directories (like test data, third-party code, or generated files).
2. **Suppressions**: Findings matching these rules are still scanned but marked as suppressed in the final report, making them visible but not counted toward failure thresholds. Use this for specific known issues that have been reviewed and accepted.

Key differences:

| Feature     | Ignore Paths                 | Suppressions                                    |
|-------------|------------------------------|-------------------------------------------------|
| Scope       | Entire files/directories     | Specific findings                               |
| Visibility  | Files not scanned at all     | Findings still visible but marked as suppressed |
| Granularity | File-level only              | Rule ID, file path, and line number             |
| Tracking    | No tracking of ignored files | Suppressed findings are tracked and reported    |
| Expiration  | No expiration mechanism      | Can set expiration dates                        |

## Configuring Suppressions

Suppressions are defined in the `.ash.yaml` configuration file under the `global_settings` section:

```yaml
global_settings:
  suppressions:
    - rule_id: 'RULE-123'
      path: 'src/example.py'
      line_start: 10
      line_end: 15
      reason: 'False positive due to test mock'
      expiration: '2025-12-31'
    - rule_id: 'RULE-456'
      path: 'src/*.js'
      reason: 'Known issue, planned for fix in v2.0'
```

### Suppression Properties

Each suppression rule can include the following properties:

| Property     | Required | Description                                    |
|--------------|----------|------------------------------------------------|
| `path`       | Yes      | File path or glob pattern to match             |
| `reason`     | Yes      | Justification for the suppression              |
| `rule_id`    | Yes      | The scanner-specific rule ID to suppress       |
| `line_start` | No       | Starting line number for the suppression       |
| `line_end`   | No       | Ending line number for the suppression         |
| `expiration` | No       | Date when the suppression expires (YYYY-MM-DD) |

### Matching Rules

- **Rule ID**: Must match exactly the rule ID reported by the scanner
- **File Path**: Supports glob patterns (e.g., `src/*.js`, `**/*.py`)
- **Line Range**: If specified, only findings within this line range will be suppressed

## Examples

### Suppress a Specific Rule in a File

```yaml
suppressions:
  - rule_id: 'B605'  # Bandit rule for os.system
    path: 'src/utils.py'
    reason: 'Command is properly sanitized'
```

### Suppress a Rule in Multiple Files

```yaml
suppressions:
  - rule_id: 'CKV_AWS_123'
    path: 'terraform/*.tf'
    reason: 'Approved exception per security review'
```

### Suppress a Rule for Specific Lines

```yaml
suppressions:
  - rule_id: 'detect-secrets'
    path: 'config/settings.py'
    line_start: 45
    line_end: 47
    reason: 'Test credentials used in CI only'
```

### Suppress with Expiration Date

```yaml
suppressions:
  - rule_id: 'RULE-789'
    path: 'src/legacy.py'
    reason: 'Will be fixed in next sprint'
    expiration: '2025-06-30'
```

## Temporarily Disabling Suppressions

To temporarily ignore all suppressions and see all findings, use the `--ignore-suppressions` flag:

```bash
ash --ignore-suppressions
```

This is useful when you want to:

- Verify if previously suppressed issues have been fixed
- Get a complete view of all security findings in your codebase
- Perform a comprehensive security review

When this flag is used, ASH will process all findings as if no suppressions were defined, but will still respect the `ignore_paths` settings.

## Expiring Suppressions

When a suppression has an expiration date:

1. The suppression will only be applied until that date
2. When the date is reached, the suppression will no longer be applied
3. ASH will warn you when suppressions are about to expire within 30 days

This helps ensure that temporary exceptions don't become permanent security gaps.

## Best Practices

1. **Always provide a reason**: Document why the finding is being suppressed
2. **Use expiration dates**: Set an expiration date for temporary suppressions
3. **Be specific**: Use line numbers when possible to limit the scope of suppressions
4. **Regular review**: Periodically review suppressions to ensure they're still valid
5. **Document approvals**: Include reference to security review or approval in the reason

## Identifying Unused Suppressions

ASH automatically tracks which suppressions are actually being applied to findings and generates a report of unused suppressions. This helps you maintain a clean configuration by identifying:

- Suppressions for files that no longer exist
- Suppressions for findings that have been fixed
- Suppressions that are no longer applicable due to code changes

### Unused Suppressions Report

After each scan, ASH generates two reports for unused suppressions:

1. **JSON Report**: `.ash/ash_output/reports/ash.unused-suppressions.json`
2. **Markdown Report**: `.ash/ash_output/reports/ash.unused-suppressions.md` (human-readable)

#### JSON Report Format

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

#### Markdown Report Format

The markdown report provides a human-readable summary with:
- Overall statistics (total, used, unused counts)
- Percentage of unused suppressions
- Detailed list of each unused suppression
- Recommendations for cleanup

### Reviewing Unused Suppressions

Check the summary after a scan:

```bash
# View summary statistics
jq '.summary' .ash/ash_output/reports/ash.unused-suppressions.json

# View all unused suppressions
jq '.unused_suppressions' .ash/ash_output/reports/ash.unused-suppressions.json

# Or view the markdown report
cat .ash/ash_output/reports/ash.unused-suppressions.md
```

### Cleaning Up Unused Suppressions

For each unused suppression, determine the appropriate action:

1. **File no longer exists**: Remove the suppression from your configuration
2. **Finding was fixed**: Remove the suppression as it's no longer needed
3. **Path/rule/line mismatch**: Update the suppression to match the current code structure
4. **Still needed**: Verify the suppression is correctly configured (check path, rule_id, line numbers)

Example cleanup workflow:

```bash
# 1. Run scan
ash --mode local

# 2. Check for unused suppressions
cat .ash/ash_output/reports/ash.unused-suppressions.md

# 3. Edit configuration to remove unused suppressions
vim .ash/.ash.yaml

# 4. Re-run scan to verify
ash --mode local
```

### Configuration Options

The unused suppressions reporter is enabled by default. To customize its behavior, add to your `.ash/.ash.yaml`:

```yaml
reporters:
  unused-suppressions:
    enabled: true  # Set to false to disable
    options:
      output_format: "json"  # "json" or "markdown"
```

### Integration with CI/CD

You can use the unused suppressions report in your CI/CD pipeline:

```bash
# Check if there are unused suppressions
UNUSED_COUNT=$(jq '.summary.unused_suppressions' .ash/ash_output/reports/ash.unused-suppressions.json)

if [ "$UNUSED_COUNT" -gt 0 ]; then
  echo "Warning: $UNUSED_COUNT unused suppressions found"
  echo "Review: .ash/ash_output/reports/ash.unused-suppressions.md"
  # Optionally fail the build
  # exit 1
fi
```