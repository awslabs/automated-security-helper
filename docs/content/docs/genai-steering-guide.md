# ASH GenAI Integration Guide

## Overview

This document provides comprehensive guidance for GenAI tools (AI assistants, LLMs, code analysis tools) on how to properly interact with ASH (Automated Security Helper) scan results. Following these guidelines ensures efficient processing, accurate analysis, and proper handling of security findings.

## Quick Reference

- **Primary Results File**: `ash_aggregated_results.json` (machine-readable, source of truth)
- **Human Reports**: HTML, Markdown, Text (NOT for machine parsing)
- **Dependencies**: CycloneDX SBOM at `reports/ash.cdx.json`
- **Configuration**: `.ash/.ash.yaml` (YAML format with JSON schema)
- **Suppressions**: Defined in configuration file under `global_settings.suppressions`

## Critical Rules for GenAI Tools

### 1. Always Use JSON Formats for Machine Processing

**DO:**
- Read `ash_aggregated_results.json` for complete scan results
- Use `reports/ash.flat.json` for simplified finding structure
- Use `reports/ash.sarif` for SARIF-compliant tooling
- Use `reports/ash.cdx.json` for dependency analysis

**DO NOT:**
- Parse HTML reports (`reports/ash.html`) - designed for human viewing only
- Parse Markdown summaries (`reports/ash.summary.md`) - may have formatting inconsistencies
- Parse Text summaries (`reports/ash.summary.txt`) - lossy representation

### 2. Severity Discrepancies - Source of Truth

**IMPORTANT**: Severity levels may differ between report formats due to underlying scanner behavior.

**Source of Truth**: `ash_aggregated_results.json` contains the canonical severity levels.

**Why This Matters**:
- Some scanners report different severities in JSON vs text output
- Markdown/HTML summaries may show "CRITICAL" while JSON shows "HIGH"
- Always validate severity from `ash_aggregated_results.json` before taking action

**Example**:
```json
// ash_aggregated_results.json (SOURCE OF TRUTH)
{
  "scanner_results": {
    "bandit": {
      "findings": [
        {
          "severity": "HIGH",  // ← Use this value
          "rule_id": "B201"
        }
      ]
    }
  }
}
```

### 3. Understanding Suppressed vs Actionable Findings

**Key Concepts**:
- **Total Findings**: All findings detected by scanners
- **Suppressed Findings**: Findings marked as false positives or accepted risks
- **Actionable Findings**: Total - Suppressed = findings requiring attention

**Always Check**:
```json
{
  "metadata": {
    "summary_stats": {
      "total": 156,
      "actionable": 61,
      "suppressed": 95
    }
  }
}
```

## File Structure and Locations

### Output Directory Structure

```
.ash/ash_output/
├── ash_aggregated_results.json    # PRIMARY: Complete scan results
├── ash.log                         # Scan execution log
├── ash-scan-set-files-list.txt    # List of files scanned
├── reports/
│   ├── ash.sarif                  # SARIF format (industry standard)
│   ├── ash.flat.json              # Simplified JSON structure
│   ├── ash.cdx.json               # CycloneDX SBOM (dependencies)
│   ├── ash.csv                    # CSV format (spreadsheet-friendly)
│   ├── ash.html                   # HTML report (HUMAN ONLY)
│   ├── ash.summary.md             # Markdown summary (HUMAN ONLY)
│   ├── ash.summary.txt            # Text summary (HUMAN ONLY)
│   ├── ash.ocsf.json              # OCSF format
│   ├── ash.junit.xml              # JUnit XML (CI/CD)
│   └── ash.gl-sast-report.json    # GitLab SAST format
└── scanners/
    ├── bandit/
    │   └── source/
    │       └── ASH.ScanResults.json
    ├── semgrep/
    │   └── source/
    │       └── ASH.ScanResults.json
    └── [other scanners]/
```

## Working with ash_aggregated_results.json

### Schema Overview

```json
{
  "name": "ASH Scan 2026-02-28T10:10:46.211371",
  "description": "Aggregated security scan results",
  "metadata": {
    "report_id": "ASH-20261028",
    "generated_at": "2026-02-28T15:10:46+00:00",
    "project_name": "ASH",
    "tool_version": "3.2.2",
    "summary_stats": {
      "total": 156,
      "actionable": 61,
      "suppressed": 95,
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 61,
      "info": 0,
      "passed": 9,
      "failed": 0,
      "missing": 1,
      "skipped": 0,
      "duration": 80.615062
    }
  },
  "ash_config": { /* Configuration used for scan */ },
  "scanner_results": { /* Detailed findings by scanner */ },
  "converter_results": { /* File conversion results */ },
  "additional_reports": { /* External reports included */ },
  "validation_checkpoints": [ /* Scan validation data */ ]
}
```

### Key Fields

#### metadata.summary_stats
- `total`: Total findings detected
- `actionable`: Findings requiring attention (not suppressed)
- `suppressed`: Findings marked as false positives/accepted risks
- `critical`, `high`, `medium`, `low`, `info`: Counts by severity
- `passed`: Scanners that completed successfully
- `failed`: Scanners that encountered errors
- `duration`: Scan duration in seconds

#### scanner_results
Contains findings organized by scanner name:

```json
{
  "scanner_results": {
    "bandit": {
      "findings": [
        {
          "rule_id": "B201",
          "severity": "HIGH",
          "message": "Flask app appears to be run with debug=True",
          "file_path": "app.py",
          "line_start": 42,
          "line_end": 42,
          "suppressed": false,
          "suppression_reason": null
        }
      ]
    }
  }
}
```

### Efficient Querying with jq

**Get actionable findings count**:
```bash
jq '.metadata.summary_stats.actionable' ash_aggregated_results.json
```

**Get all critical/high findings**:
```bash
jq '.scanner_results | to_entries[] | .value.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")' ash_aggregated_results.json
```

**Get findings by scanner**:
```bash
jq '.scanner_results.bandit.findings' ash_aggregated_results.json
```

**Get non-suppressed findings**:
```bash
jq '.scanner_results | to_entries[] | .value.findings[] | select(.suppressed == false)' ash_aggregated_results.json
```

**Count findings by severity**:
```bash
jq '[.scanner_results | to_entries[] | .value.findings[] | .severity] | group_by(.) | map({severity: .[0], count: length})' ash_aggregated_results.json
```

## Working with CycloneDX SBOM

### Purpose
The CycloneDX SBOM (`reports/ash.cdx.json`) provides a complete Software Bill of Materials, including:
- Direct and transitive dependencies
- Component versions and licenses
- Known vulnerabilities (CVEs)
- Dependency relationships

### Schema Overview

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2026-02-28T15:12:09+00:00",
    "tools": [
      {
        "vendor": "AWS Labs",
        "name": "Automated Security Helper",
        "version": "3.2.2"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:pypi/requests@2.31.0",
      "dependsOn": [
        "pkg:pypi/urllib3@2.0.7",
        "pkg:pypi/certifi@2023.7.22"
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
      },
      "ratings": [
        {
          "severity": "high",
          "score": 7.5,
          "method": "CVSSv3"
        }
      ],
      "affects": [
        {
          "ref": "pkg:pypi/requests@2.31.0"
        }
      ]
    }
  ]
}
```

### Querying Dependencies with jq

**List all components**:
```bash
jq '.components[] | {name: .name, version: .version, type: .type}' ash.cdx.json
```

**Find components with vulnerabilities**:
```bash
jq '.vulnerabilities[] | .affects[].ref' ash.cdx.json | sort -u
```

**Get high/critical vulnerabilities**:
```bash
jq '.vulnerabilities[] | select(.ratings[].severity == "high" or .ratings[].severity == "critical")' ash.cdx.json
```

**List all licenses**:
```bash
jq '[.components[].licenses[]?.license.id] | unique' ash.cdx.json
```

**Find dependency tree for a component**:
```bash
jq --arg pkg "pkg:pypi/requests@2.31.0" '.dependencies[] | select(.ref == $pkg)' ash.cdx.json
```

## Configuration File Schema

### Location
- Default: `.ash/.ash.yaml` in the project root
- Custom: Specify with `--config` flag or `ASH_CONFIG` environment variable

### Schema Structure

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json

project_name: my-project

fail_on_findings: true  # Exit with code 2 if actionable findings exist

global_settings:
  severity_threshold: MEDIUM  # CRITICAL, HIGH, MEDIUM, LOW, INFO
  
  ignore_paths:
    - path: 'tests/test_data/**'
      reason: 'Test data only'
      expiration: null  # Optional: ISO date string
  
  suppressions:
    - path: 'src/app.py'
      rule_id: 'B201'
      line_start: 42
      line_end: 42
      reason: 'False positive - debug mode only in development'
      expiration: '2026-12-31'  # Optional: ISO date string

scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high  # all, high, medium, low
      ignore_nosec: false
      config_file: .ash/bandit.yaml
  
  semgrep:
    enabled: true
    options:
      config: auto  # or specific ruleset like 'p/security-audit'
  
  checkov:
    enabled: true
    options:
      frameworks:
        - all
      severity_threshold: LOW

reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true
      max_detailed_findings: 20
  
  html:
    enabled: true
  
  sarif:
    enabled: true
  
  cyclonedx:
    enabled: true
```

### Key Configuration Sections

#### global_settings.severity_threshold
Minimum severity level to report. Findings below this threshold are still detected but not counted as actionable.

#### global_settings.suppressions
Array of suppression rules to mark findings as false positives or accepted risks.

**Suppression Fields**:
- `path`: File path (supports glob patterns like `tests/**/*.py`)
- `rule_id`: Scanner-specific rule identifier (e.g., `B201`, `SECRET-SECRET-KEYWORD`)
- `line_start`: Optional - specific line number
- `line_end`: Optional - end line for multi-line suppressions
- `reason`: Required - explanation for suppression
- `expiration`: Optional - ISO date when suppression expires

#### scanners
Configuration for each scanner. Common options:
- `enabled`: Boolean to enable/disable scanner
- `options`: Scanner-specific configuration

## Creating Suppressions Properly

### When to Suppress
- False positives (scanner incorrectly flagged safe code)
- Accepted risks (security team approved the pattern)
- Test data (not production code)
- Third-party code (cannot be modified)

### Suppression Best Practices

**1. Always Provide a Reason**:
```yaml
suppressions:
  - path: 'src/utils.py'
    rule_id: 'B603'
    reason: 'subprocess.call uses list args (no shell=True), validated inputs only'
```

**2. Be Specific with Paths**:
```yaml
# Good - specific file
- path: 'src/auth/login.py'
  rule_id: 'B201'

# Good - specific directory
- path: 'tests/**/*.py'
  rule_id: 'B101'

# Avoid - too broad
- path: '**/*.py'
  rule_id: 'B201'
```

**3. Use Line Numbers for Precision**:
```yaml
suppressions:
  - path: 'src/app.py'
    rule_id: 'B201'
    line_start: 42
    line_end: 42
    reason: 'Debug mode only enabled in development environment'
```

**4. Set Expiration Dates for Temporary Suppressions**:
```yaml
suppressions:
  - path: 'src/legacy/old_api.py'
    rule_id: 'B501'
    reason: 'Legacy code - will be refactored in Q2 2026'
    expiration: '2026-06-30'
```

### Suppression Workflow

1. **Identify the Finding**:
   - Check `ash_aggregated_results.json` for exact details
   - Note: `rule_id`, `file_path`, `line_start`, `line_end`

2. **Verify It's a False Positive or Accepted Risk**:
   - Review the code context
   - Consult security team if needed
   - Document the decision

3. **Add Suppression to Configuration**:
   ```yaml
   global_settings:
     suppressions:
       - path: 'path/from/finding'
         rule_id: 'RULE_ID_FROM_FINDING'
         line_start: 42  # Optional but recommended
         reason: 'Clear explanation of why this is suppressed'
   ```

4. **Re-run Scan to Verify**:
   ```bash
   ash --mode local
   ```

5. **Confirm Suppression Applied**:
   ```bash
   jq '.metadata.summary_stats.suppressed' .ash/ash_output/ash_aggregated_results.json
   ```

## Common Pitfalls and Known Issues

### 1. Severity Inconsistencies
**Issue**: Markdown summary shows "CRITICAL" but JSON shows "HIGH"

**Solution**: Always use `ash_aggregated_results.json` as source of truth

**Example**:
```bash
# Wrong - parsing markdown
grep "CRITICAL" .ash/ash_output/reports/ash.summary.md

# Correct - querying JSON
jq '.scanner_results | to_entries[] | .value.findings[] | select(.severity == "CRITICAL")' .ash/ash_output/ash_aggregated_results.json
```

### 2. Suppression Not Applied
**Issue**: Suppression added but finding still shows as actionable

**Common Causes**:
- Path doesn't match exactly (check for leading `./` or trailing `/`)
- Rule ID typo or case mismatch
- Line numbers don't match (scanner may report different lines)

**Solution**:
```bash
# Check exact path and rule_id from results
jq '.scanner_results | to_entries[] | .value.findings[] | select(.suppressed == false) | {file_path, rule_id, line_start}' ash_aggregated_results.json

# Verify suppression in config matches exactly
```

### 3. HTML Report Parsing Failures
**Issue**: Attempting to parse HTML with regex or string matching

**Solution**: Never parse HTML reports. Use JSON formats:
- `ash_aggregated_results.json` - complete results
- `reports/ash.flat.json` - simplified structure
- `reports/ash.sarif` - SARIF format

### 4. Missing Scanner Results
**Issue**: Expected scanner results not in output

**Check**:
```bash
# Verify scanner was enabled and executed
jq '.metadata.validation_summary' ash_aggregated_results.json

# Check for scanner errors
jq '.scanner_results | to_entries[] | select(.value.status == "FAILED")' ash_aggregated_results.json
```

### 5. Dependency Analysis Confusion
**Issue**: Trying to extract dependencies from scan findings

**Solution**: Use CycloneDX SBOM:
```bash
# Get all dependencies
jq '.components[] | {name, version, type}' reports/ash.cdx.json

# Get vulnerable dependencies
jq '.vulnerabilities[] | .affects[].ref' reports/ash.cdx.json
```

## Integration Patterns

### Pattern 1: CI/CD Pipeline Gate

```python
import json
import sys

# Read results
with open('.ash/ash_output/ash_aggregated_results.json') as f:
    results = json.load(f)

stats = results['metadata']['summary_stats']

# Fail on critical/high findings
if stats['critical'] > 0:
    print(f"FAILED: {stats['critical']} critical findings")
    sys.exit(1)

if stats['high'] > 5:
    print(f"FAILED: {stats['high']} high findings (threshold: 5)")
    sys.exit(1)

print(f"PASSED: {stats['actionable']} actionable findings (within threshold)")
sys.exit(0)
```

### Pattern 2: Finding Analysis and Remediation

```python
import json

# Read results
with open('.ash/ash_output/ash_aggregated_results.json') as f:
    results = json.load(f)

# Get all actionable high/critical findings
actionable_findings = []
for scanner, data in results['scanner_results'].items():
    for finding in data.get('findings', []):
        if not finding['suppressed'] and finding['severity'] in ['HIGH', 'CRITICAL']:
            actionable_findings.append({
                'scanner': scanner,
                'rule_id': finding['rule_id'],
                'severity': finding['severity'],
                'file': finding['file_path'],
                'line': finding['line_start'],
                'message': finding['message']
            })

# Sort by severity
actionable_findings.sort(key=lambda x: 0 if x['severity'] == 'CRITICAL' else 1)

# Generate remediation plan
for finding in actionable_findings:
    print(f"\n[{finding['severity']}] {finding['file']}:{finding['line']}")
    print(f"  Rule: {finding['rule_id']} ({finding['scanner']})")
    print(f"  Issue: {finding['message']}")
    print(f"  Action: [Suggest remediation based on rule_id]")
```

### Pattern 3: Dependency Vulnerability Report

```python
import json

# Read CycloneDX SBOM
with open('.ash/ash_output/reports/ash.cdx.json') as f:
    sbom = json.load(f)

# Extract vulnerable components
vulnerable_components = {}
for vuln in sbom.get('vulnerabilities', []):
    for affect in vuln.get('affects', []):
        component_ref = affect['ref']
        if component_ref not in vulnerable_components:
            vulnerable_components[component_ref] = []
        vulnerable_components[component_ref].append({
            'cve': vuln['id'],
            'severity': vuln['ratings'][0]['severity'],
            'score': vuln['ratings'][0].get('score', 'N/A')
        })

# Generate report
print("Vulnerable Dependencies:")
for component, vulns in vulnerable_components.items():
    print(f"\n{component}")
    for vuln in vulns:
        print(f"  - {vuln['cve']} ({vuln['severity']}, CVSS: {vuln['score']})")
```

## MCP Server Integration

If using ASH via the Model Context Protocol (MCP) server, follow these guidelines:

### Available Tools
- `run_ash_scan` - Start a security scan
- `get_scan_results` - Get scan results with filtering
- `get_scan_summary` - Get lightweight summary
- `get_scan_result_paths` - Get file paths for all reports
- `list_active_scans` - List running scans
- `cancel_scan` - Cancel a running scan

### Filtering Results

Use `filter_level` parameter to control response size:

```python
# Minimal - fast status check (1-2KB)
status = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="minimal"
)

# Summary - dashboard data (5-15KB)
summary = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary"
)

# Full - complete results (50KB-2MB)
results = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="full"
)
```

### Content Filtering

Filter by scanner or severity:

```python
# Only critical findings
critical = await get_scan_results(
    output_dir=".ash/ash_output",
    severities="critical"
)

# Specific scanners
sast_results = await get_scan_results(
    output_dir=".ash/ash_output",
    scanners="bandit,semgrep"
)

# Combined filtering
high_priority_sast = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    scanners="bandit,semgrep",
    severities="critical,high"
)
```

## Scanner-Specific Notes

### Bandit (Python SAST)
- **Rule ID Format**: `B###` (e.g., `B201`, `B603`)
- **Confidence Levels**: HIGH, MEDIUM, LOW
- **Common False Positives**: `B101` (assert usage in tests), `B404`/`B603` (subprocess usage)

### Semgrep (Multi-language SAST)
- **Rule ID Format**: `category.subcategory.rule-name` (e.g., `python.lang.security.audit.dangerous-system-call`)
- **Rulesets**: `p/security-audit`, `p/ci`, `p/owasp-top-ten`
- **Custom Rules**: Can be added via configuration

### Checkov (IaC Scanner)
- **Rule ID Format**: `CKV_###` (e.g., `CKV_AWS_1`)
- **Frameworks**: Terraform, CloudFormation, Kubernetes, Dockerfile, etc.
- **Severity**: Determined by rule metadata

### detect-secrets (Secret Detection)
- **Rule ID Format**: `SECRET-TYPE-PATTERN` (e.g., `SECRET-SECRET-KEYWORD`, `SECRET-BASE64-HIGH-ENTROPY-STRING`)
- **Common False Positives**: Test data, documentation examples, variable names
- **Best Practice**: Always verify secrets before suppressing

### Grype (Vulnerability Scanner)
- **Rule ID Format**: CVE IDs (e.g., `CVE-2023-12345`)
- **Data Source**: Multiple vulnerability databases (NVD, GitHub, etc.)
- **SBOM Integration**: Results included in CycloneDX SBOM

## Performance Optimization

### For Large Codebases

1. **Use Specific Scanners**:
   ```bash
   ash --scanners bandit,semgrep --exclude-scanners grype,npm-audit
   ```

2. **Ignore Unnecessary Paths**:
   ```yaml
   global_settings:
     ignore_paths:
       - path: 'node_modules/**'
       - path: 'vendor/**'
       - path: '.venv/**'
   ```

3. **Use Parallel Strategy**:
   ```bash
   ash --strategy parallel
   ```

### For CI/CD Pipelines

1. **Use Precommit Mode**:
   ```bash
   ash --mode precommit
   ```

2. **Cache Dependencies**:
   - Cache `.ash/` directory between runs
   - Use `--offline` mode when possible

3. **Filter Results Early**:
   ```python
   # Use MCP filtering to reduce data transfer
   summary = await get_scan_results(
       output_dir=".ash/ash_output",
       filter_level="minimal",
       severities="critical,high"
   )
   ```

## Troubleshooting

### Scan Fails with Missing Scanner

**Check**:
```bash
ash dependencies check
```

**Solution**: Install missing dependencies or exclude scanner:
```bash
ash --exclude-scanners cfn-nag
```

### Results File Not Found

**Check**:
```bash
ls -la .ash/ash_output/ash_aggregated_results.json
```

**Solution**: Verify scan completed successfully:
```bash
ash --mode local --verbose
```

### Suppression Not Working

**Debug**:
```bash
# Check exact finding details
jq '.scanner_results | to_entries[] | .value.findings[] | select(.suppressed == false) | {file_path, rule_id, line_start, line_end}' .ash/ash_output/ash_aggregated_results.json

# Verify suppression syntax
yamllint .ash/.ash.yaml
```

## Additional Resources

- **ASH Documentation**: https://awslabs.github.io/automated-security-helper/
- **Configuration Schema**: https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
- **MCP Tools Reference**: See `docs/content/docs/MCP-TOOLS-REFERENCE.md`
- **MCP Filtering Guide**: See `docs/content/docs/MCP-FILTERING-GUIDE.md`
- **GitHub Repository**: https://github.com/awslabs/automated-security-helper

## Version Information

This guide is for ASH v3.2.2 and later. For earlier versions, some features may not be available.

---

**Last Updated**: 2026-02-28
**Document Version**: 1.0.0
