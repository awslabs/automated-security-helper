# ASH GenAI Integration Guide

## Overview

This document provides comprehensive guidance for GenAI tools (AI assistants, LLMs, code analysis tools) on how to properly interact with ASH (Automated Security Helper) scan results. Following these guidelines ensures efficient processing, accurate analysis, and proper handling of security findings.

## Installing This Guide

### Quick Install

```bash
# Download the guide
ash get-genai-guide -o ash-genai-guide.md
```

### Installation for AI Coding Tools

Choose the installation method based on your AI coding tool:

#### Kiro (Recommended: Global Installation)

**Global installation** (available in all Kiro workspaces):
```bash
# Create steering directory if it doesn't exist
mkdir -p ~/.kiro/steering

# Download the guide
ash get-genai-guide -o ~/.kiro/steering/ash-integration.md
```

Kiro will automatically load this as steering context for all workspaces. This is the recommended approach as it makes ASH guidance available everywhere.

**Project-specific installation** (only for current project):
```bash
# Create project steering directory
mkdir -p .kiro/steering

# Download the guide
ash get-genai-guide -o .kiro/steering/ash-integration.md
```

**Verification**:
After installation, you can verify Kiro sees the guide by checking the steering files list in Kiro's UI or by asking: "What steering files do you have loaded?"

**How Kiro Steering Works**:
- Files in `~/.kiro/steering/` are automatically loaded as context for all workspaces (global)
- Files in `.kiro/steering/` are loaded only for the current workspace (project-specific)
- Steering files are always included in Kiro's context, so you don't need to reference them in prompts
- Kiro will automatically follow the guidance when working with ASH results

#### Cline (VS Code Extension)

**Option 1: Project-specific** (recommended):
```bash
# Create Cline directory
mkdir -p .cline

# Download the guide
ash get-genai-guide -o .cline/ash-guide.md
```

**Option 2: VS Code workspace**:
```bash
# Add to VS Code settings
mkdir -p .vscode
ash get-genai-guide -o .vscode/ash-integration-guide.md
```

Then reference it in your Cline prompts: "Please read the ASH guide at .cline/ash-guide.md before analyzing scan results."

#### Claude Desktop / MCP Clients

**Dedicated documentation folder**:
```bash
# Create AI guides folder
mkdir -p ~/Documents/ai-guides

# Download the guide
ash get-genai-guide -o ~/Documents/ai-guides/ash-integration.md
```

**Usage**: In your prompts, reference the guide:
```
Please read the ASH integration guide at ~/Documents/ai-guides/ash-integration.md 
before processing these scan results.
```

#### Amazon Q CLI

**Project documentation**:
```bash
# Add to project docs
mkdir -p docs/ai-guides
ash get-genai-guide -o docs/ai-guides/ash-integration.md
```

**Usage**: Reference in your Q CLI prompts or add to project documentation index.

#### Cursor

**Option 1: Cursor rules directory**:
```bash
# Create Cursor directory
mkdir -p .cursor

# Download the guide
ash get-genai-guide -o .cursor/ash-guide.md
```

**Option 2: Project root** (for easy discovery):
```bash
# Download to project root with clear name
ash get-genai-guide -o ASH_INTEGRATION_GUIDE.md
```

**Usage**: Reference in `.cursorrules` or mention in prompts.

#### Generic / Other Tools

**Project root** (universal approach):
```bash
# Download with descriptive name
ash get-genai-guide -o ASH_GENAI_GUIDE.md
```

Then reference it in your AI tool's context or prompts.

### Updating the Guide

When ASH is updated, refresh the guide:
```bash
# Re-download to the same location (overwrites existing)
ash get-genai-guide -o ~/.kiro/steering/ash-integration.md
```

### Verification

After installation, verify the guide is accessible:
```bash
# Check file exists
ls -lh ~/.kiro/steering/ash-integration.md

# View first few lines
head -n 20 ~/.kiro/steering/ash-integration.md
```

## Quick Reference

**Before Analyzing Results - Check Tool Availability**:
```bash
# Verify jq is available (preferred method)
command -v jq && echo "✓ jq available (recommended)" || echo "✗ jq not found, will use Python fallback"
```

**Default Tool Priority**:
1. **jq** - Fastest and most efficient (ALWAYS TRY FIRST)
2. **Python** - Reliable fallback (if jq unavailable)
3. **grep/awk** - Last resort only (limited functionality)

**Recommended Approach for GenAI Tools**:
1. **For most use cases**: Use `reports/ash.flat.json` (simpler structure, smaller size)
2. **For complete data**: Use `ash_aggregated_results.json` (but parse efficiently - see warnings below)
3. **For dependencies**: Use `reports/ash.cdx.json` (CycloneDX SBOM)
4. **For CI/CD integration**: Use `reports/ash.junit.xml` or `reports/ash.csv`

**File Locations**:
- **Primary Results File**: `ash_aggregated_results.json` (complete but large - 1-10MB+)
- **Simplified Results**: `reports/ash.flat.json` (recommended for most use cases)
- **Human Reports**: HTML, Markdown, Text (NOT for machine parsing)
- **Dependencies**: `reports/ash.cdx.json` (CycloneDX SBOM)
- **Configuration**: `.ash/.ash.yaml` (YAML format with JSON schema)
- **Suppressions**: Defined in configuration file under `global_settings.suppressions`

**Tool Requirements**:
- **Preferred**: `jq` (fastest, most efficient for JSON queries - ALWAYS TRY FIRST)
- **Fallback**: Python 3.x (reliable, widely available)
- **Last Resort**: `grep`, `awk` (basic text processing, always available)

## Critical Rules for GenAI Tools

### 1. Always Use JSON Formats for Machine Processing

**DO:**
- Read `ash_aggregated_results.json` for complete scan results (but see file size warnings below)
- Use `reports/ash.flat.json` for simplified finding structure (recommended for most use cases)
- Use `reports/ash.sarif` for SARIF-compliant tooling
- Use `reports/ash.cdx.json` for dependency analysis

**DO NOT:**
- Parse HTML reports (`reports/ash.html`) - designed for human viewing only
- Parse Markdown summaries (`reports/ash.summary.md`) - may have formatting inconsistencies
- Parse Text summaries (`reports/ash.summary.txt`) - lossy representation

### 2. Handle Large Files Efficiently

**CRITICAL**: ASH result files can be very large (1-10MB+). Always:
- Check file size before loading into memory
- Use streaming parsers for files >5MB
- Extract only the data you need
- Consider using simpler formats (`ash.flat.json`, `ash.csv`)
- Provide progress indicators for large file operations

**Example - Check before loading**:
```python
import os
import json

results_file = 'ash_aggregated_results.json'
file_size_mb = os.path.getsize(results_file) / (1024 * 1024)

if file_size_mb > 5:
    print(f"Large file detected ({file_size_mb:.1f}MB). Using streaming parser...")
    # Use streaming approach
else:
    # Safe to load into memory
    with open(results_file) as f:
        data = json.load(f)
```

### 3. Check Tool Availability

**IMPORTANT**: Always attempt to use `jq` first for maximum efficiency, but never assume it's installed. Always:
- Check if tools are available before using them
- Try `jq` first (fastest and most efficient)
- Provide fallback methods (Python, grep, awk)
- Use the most reliable method available
- Document which tools are required vs optional

**Tool Availability Check**:
```python
import shutil

# Check for jq (PREFERRED)
has_jq = shutil.which('jq') is not None

# Check for Python (almost always available)
has_python = shutil.which('python3') is not None or shutil.which('python') is not None

# Use best available method (PREFER jq)
if has_jq:
    # Use jq (PREFERRED - fastest and most efficient)
    pass
elif has_python:
    # Fallback to Python
    pass
else:
    # Last resort: grep/awk
    pass
```

### 4. Severity Discrepancies - Source of Truth

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

### 5. Understanding Suppressed vs Actionable Findings

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

### Important: File Size Considerations

**WARNING**: The `ash_aggregated_results.json` file can be very large (often 1-10MB, sometimes larger for big codebases).

**Best Practices**:
1. **DO NOT load the entire file into memory** if you only need specific data
2. **Use streaming JSON parsers** when possible
3. **Extract only what you need** using command-line tools or streaming libraries
4. **Consider using alternative formats** for specific use cases:
   - `reports/ash.flat.json` - Simplified structure, smaller size
   - `reports/ash.csv` - Easy to filter and query
   - `reports/ash.sarif` - Industry standard, well-supported

### Parsing Strategies

**DEFAULT APPROACH**: Always attempt `jq` first for maximum efficiency. Only use Python or grep if `jq` is unavailable.

#### Strategy 1: Using jq (PREFERRED - Check Availability First)

**Recommended: Use jq for all queries** (most Linux/macOS systems have it installed):
```bash
# Extract just summary stats
jq '.metadata.summary_stats' ash_aggregated_results.json

# Get specific scanner results
jq '.scanner_results.bandit' ash_aggregated_results.json
```

#### Strategy 2: Using Python (FALLBACK - If jq is NOT available)
```bash
# Extract summary stats
python3 -c "import json; data=json.load(open('ash_aggregated_results.json')); print(json.dumps(data['metadata']['summary_stats'], indent=2))"

# Get actionable count
python3 -c "import json; print(json.load(open('ash_aggregated_results.json'))['metadata']['summary_stats']['actionable'])"
```

**Alternative: Use grep for simple extractions** (always available):
```bash
# Get actionable count (quick and dirty)
grep -o '"actionable": [0-9]*' ash_aggregated_results.json | grep -o '[0-9]*'

# Check for critical findings
grep -o '"critical": [0-9]*' ash_aggregated_results.json | head -1
```

#### Strategy 3: Streaming JSON Parsers (For Large Files)

**Python with ijson** (streaming parser):
```python
import ijson

# Stream parse - memory efficient
with open('ash_aggregated_results.json', 'rb') as f:
    # Extract just summary stats without loading entire file
    parser = ijson.items(f, 'metadata.summary_stats')
    summary_stats = next(parser)
    print(f"Actionable findings: {summary_stats['actionable']}")
```

**Python standard library** (load specific sections):
```python
import json

# Load and extract only what you need
with open('ash_aggregated_results.json') as f:
    data = json.load(f)
    
# Immediately extract and discard the rest
summary = data['metadata']['summary_stats']
del data  # Free memory

print(f"Actionable: {summary['actionable']}")
print(f"Critical: {summary['critical']}")
```

#### Strategy 4: Use Simpler Formats

**For most use cases, use the flat JSON format instead**:
```python
# reports/ash.flat.json is much smaller and easier to parse
import json

with open('reports/ash.flat.json') as f:
    findings = json.load(f)

# Simpler structure, direct access to findings
for finding in findings:
    if finding['severity'] in ['CRITICAL', 'HIGH']:
        print(f"{finding['file_path']}: {finding['message']}")
```

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

### Efficient Querying

**IMPORTANT**: Always attempt `jq` first for maximum efficiency. Check availability and provide fallbacks for compatibility.

#### Recommended: Using jq (Check Availability First)

**Get actionable findings count** (preferred method):
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

#### Fallback: Using Python (If jq is unavailable)

**Get actionable findings count**:
```bash
python3 -c "import json; print(json.load(open('ash_aggregated_results.json'))['metadata']['summary_stats']['actionable'])"
```

**Get all critical/high findings**:
```python
import json

with open('ash_aggregated_results.json') as f:
    data = json.load(f)

for scanner, results in data['scanner_results'].items():
    for finding in results.get('findings', []):
        if finding['severity'] in ['CRITICAL', 'HIGH']:
            print(f"{scanner}: {finding['file_path']}:{finding['line_start']} - {finding['message']}")
```

**Get findings by scanner**:
```python
import json

with open('ash_aggregated_results.json') as f:
    data = json.load(f)

bandit_findings = data['scanner_results']['bandit']['findings']
print(json.dumps(bandit_findings, indent=2))
```

**Count findings by severity**:
```python
import json
from collections import Counter

with open('ash_aggregated_results.json') as f:
    data = json.load(f)

severities = []
for scanner, results in data['scanner_results'].items():
    for finding in results.get('findings', []):
        severities.append(finding['severity'])

counts = Counter(severities)
for severity, count in counts.items():
    print(f"{severity}: {count}")
```

#### Last Resort: Using grep/awk (If neither jq nor Python available)

**Get actionable findings count** (basic but works):
```bash
grep -o '"actionable": [0-9]*' ash_aggregated_results.json | head -1 | grep -o '[0-9]*'
```

**Check for critical findings**:
```bash
grep -c '"severity": "CRITICAL"' ash_aggregated_results.json
```

**List all severity levels found**:
```bash
grep -o '"severity": "[A-Z]*"' ash_aggregated_results.json | sort -u
```

#### Recommended Approach for GenAI Tools

**1. Check tool availability first**:
```python
import subprocess
import shutil

def get_actionable_count(results_file):
    """Get actionable findings count using best available method."""
    
    # Method 1: Try jq (fastest - PREFERRED)
    if shutil.which('jq'):
        try:
            result = subprocess.run(
                ['jq', '.metadata.summary_stats.actionable', results_file],
                capture_output=True, text=True, check=True
            )
            return int(result.stdout.strip())
        except Exception:
            pass
    
    # Method 2: Use Python (most reliable fallback)
    try:
        import json
        with open(results_file) as f:
            data = json.load(f)
        return data['metadata']['summary_stats']['actionable']
    except Exception:
        pass
    
    # Method 3: Fallback to grep (always available)
    try:
        result = subprocess.run(
            ['grep', '-o', '"actionable": [0-9]*', results_file],
            capture_output=True, text=True, check=True
        )
        return int(result.stdout.strip().split(':')[1].strip())
    except Exception:
        return None
```

**2. Use the flat JSON format when possible**:
```python
# Simpler, smaller, easier to parse
with open('reports/ash.flat.json') as f:
    findings = json.load(f)

actionable = [f for f in findings if not f.get('suppressed', False)]
critical_high = [f for f in actionable if f['severity'] in ['CRITICAL', 'HIGH']]
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

### Querying Dependencies

**IMPORTANT**: CycloneDX files can also be large. Use efficient parsing methods. Always attempt `jq` first.

#### Recommended: Using jq (Check Availability First)

**List all components** (preferred method):
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

#### Fallback: Using Python (If jq is unavailable)

**List all components**:
```python
import json

with open('reports/ash.cdx.json') as f:
    sbom = json.load(f)

for component in sbom.get('components', []):
    print(f"{component['name']} {component['version']} ({component['type']})")
```

**Find components with vulnerabilities**:
```python
import json

with open('reports/ash.cdx.json') as f:
    sbom = json.load(f)

vulnerable_refs = set()
for vuln in sbom.get('vulnerabilities', []):
    for affect in vuln.get('affects', []):
        vulnerable_refs.add(affect['ref'])

for ref in sorted(vulnerable_refs):
    print(ref)
```

**Get high/critical vulnerabilities**:
```python
import json

with open('reports/ash.cdx.json') as f:
    sbom = json.load(f)

for vuln in sbom.get('vulnerabilities', []):
    for rating in vuln.get('ratings', []):
        if rating.get('severity') in ['high', 'critical']:
            print(f"{vuln['id']}: {rating['severity']} (score: {rating.get('score', 'N/A')})")
            for affect in vuln.get('affects', []):
                print(f"  Affects: {affect['ref']}")
            break
```

**List all licenses**:
```python
import json

with open('reports/ash.cdx.json') as f:
    sbom = json.load(f)

licenses = set()
for component in sbom.get('components', []):
    for license_info in component.get('licenses', []):
        if 'license' in license_info and 'id' in license_info['license']:
            licenses.add(license_info['license']['id'])

for license_id in sorted(licenses):
    print(license_id)
```

#### Last Resort: Using grep (If neither jq nor Python available)

**Count total components**:
```bash
grep -c '"type": "library"' reports/ash.cdx.json
```

**Find if specific package exists**:
```bash
grep -i "requests" reports/ash.cdx.json
```

**Count vulnerabilities**:
```bash
grep -c '"id": "CVE-' reports/ash.cdx.json
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

# Fail on actionable critical/high findings
# Note: Use actionable count to exclude suppressed findings (false positives)
if stats['critical'] > 0:
    print(f"FAILED: {stats['critical']} critical actionable findings")
    sys.exit(1)

if stats['high'] > 5:
    print(f"FAILED: {stats['high']} high actionable findings (threshold: 5)")
    sys.exit(1)

print(f"PASSED: {stats['actionable']} actionable findings (within threshold)")
sys.exit(0)
```

**Using MCP Server:**
```python
# Get only actionable findings for CI/CD gate
result = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical,high",
    filter_level="minimal"
)

if result["summary_stats"]["critical"] > 0:
    print("FAILED: Critical actionable findings detected")
    sys.exit(1)
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

**Using MCP Server:**
```python
# Get actionable high/critical findings with full details
results = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical,high",
    filter_level="full"
)

# Process findings from SARIF
for run in results["raw_results"]["sarif"]["runs"]:
    for result in run["results"]:
        # All results here are actionable (suppressed findings already filtered)
        print(f"[{result['level']}] {result['ruleId']}: {result['message']['text']}")
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
- `get_scan_progress` - Get current progress and partial results
- `get_scan_results` - Get scan results with filtering
- `get_scan_summary` - Get lightweight summary
- `get_scan_result_paths` - Get file paths for all reports
- `list_active_scans` - List running scans
- `cancel_scan` - Cancel a running scan

### Managing Long-Running Scans

**CRITICAL**: ASH scans can take 30-120+ seconds. MCP connections may timeout if you don't keep them alive.

#### ❌ WRONG: Sleep and Wait (Connection Timeout)

```python
# This will cause connection timeout!
result = run_ash_scan(source_dir="/path/to/project")
scan_id = result['scan_id']

# Sleeping for 60+ seconds causes MCP connection to close
time.sleep(60)

# This will fail - connection already timed out
summary = get_scan_summary()  # ERROR: Connection closed
```

#### ✅ CORRECT: Poll Progress (Keep Connection Alive)

```python
# 1. Start scan (returns immediately with scan_id)
result = run_ash_scan(source_dir="/path/to/project")
scan_id = result['scan_id']

# 2. Poll progress periodically to keep connection alive
while True:
    progress = get_scan_progress(scan_id=scan_id)
    
    # Check if scan is complete
    if progress.get('is_complete') or progress.get('status') in ['completed', 'failed', 'cancelled']:
        break
    
    # Wait 5 seconds before next check (keeps connection alive)
    time.sleep(5)

# 3. Get results after completion
if progress.get('status') == 'completed':
    # Use filtered queries to reduce data transfer
    results = get_scan_results(
        output_dir=progress['output_directory'],
        filter_level="summary",
        actionable_only=True,
        severities="critical,high"
    )
```

#### Best Practice: Progress Monitoring with Status Updates

```python
import time

def run_ash_scan_with_monitoring(source_dir: str) -> dict:
    """Run ASH scan with proper progress monitoring."""
    
    # Start scan
    result = run_ash_scan(source_dir=source_dir)
    if not result.get('success'):
        return {'error': result.get('error', 'Failed to start scan')}
    
    scan_id = result['scan_id']
    print(f"Scan started: {scan_id}")
    
    # Monitor progress
    last_status = None
    while True:
        progress = get_scan_progress(scan_id=scan_id)
        
        # Show status updates
        current_status = progress.get('message', 'Running...')
        if current_status != last_status:
            print(f"Status: {current_status}")
            last_status = current_status
        
        # Check completion
        if progress.get('is_complete'):
            break
        
        if progress.get('status') in ['failed', 'cancelled']:
            return {'error': f"Scan {progress['status']}: {progress.get('error', 'Unknown error')}"}
        
        # Wait before next poll (keeps connection alive)
        time.sleep(5)
    
    # Get filtered results
    output_dir = progress.get('output_directory', f"{source_dir}/.ash/ash_output")
    results = get_scan_results(
        output_dir=output_dir,
        filter_level="summary",
        actionable_only=True,
        severities="critical,high,medium"
    )
    
    return results
```

#### Why This Matters

1. **Connection Keepalive**: Polling `get_scan_progress()` every 5 seconds keeps the MCP connection active
2. **Status Updates**: You can show progress to users instead of appearing frozen
3. **Early Failure Detection**: Detect scan failures immediately instead of waiting for timeout
4. **Efficient Data Transfer**: Use filtered queries after completion to get only what you need

#### Recommended Polling Intervals

- **Development/Interactive**: 3-5 seconds (responsive feedback)
- **CI/CD/Automated**: 10-15 seconds (reduce overhead)
- **Never**: >30 seconds (risks connection timeout)

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

Filter by scanner, severity, or actionable status:

```python
# Only actionable findings (exclude suppressed)
actionable = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True
)

# Only critical findings
critical = await get_scan_results(
    output_dir=".ash/ash_output",
    severities="critical"
)

# Actionable critical findings only
actionable_critical = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical"
)

# Specific scanners
sast_results = await get_scan_results(
    output_dir=".ash/ash_output",
    scanners="bandit,semgrep"
)

# Combined filtering - actionable high-priority SAST findings
high_priority_sast = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    scanners="bandit,semgrep",
    severities="critical,high",
    actionable_only=True
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
   # Use MCP filtering to reduce data transfer and focus on actionable findings
   summary = await get_scan_results(
       output_dir=".ash/ash_output",
       filter_level="minimal",
       actionable_only=True,
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
