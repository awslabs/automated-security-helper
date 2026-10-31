# ASH GenAI integration guide

This file tells an AI agent how to run ASH (Automated Security Helper), read its results,
and propose suppressions without hiding real problems. Give it to your agent as context,
for example as a rules file or a steering file. To save a copy in the current directory:

```bash
ash get-genai-guide --output ash-genai-guide.md
```

The guide ships with every installation of ASH (a wheel or sdist, an install from a
git URL, a clone of the repository, and the container images ASH builds), so this
writes the copy for the installed version without network access. `--from-github`
downloads it from GitHub instead, from `main` or from the branch or release tag
`--branch` names.

### Installation for AI Coding Tools

The rest of this file is written for the agent.

## Rules

- Never report a project as clean unless every selected scanner ran and there are zero
  actionable findings. A scan that ended `incomplete`, or with exit code 1, did not run every
  scanner: name the scanners that did not run, and why.
- Fix before you suppress. Propose a suppression only for a false positive or a risk the user
  accepts, with a reason the user agrees with, and never to make a scan pass.
- Do not change what the scan checks to get a passing result: do not disable scanners, raise
  severity thresholds, set `fail_on_findings: false`, add broad `ignore_paths`, or pass
  `--ignore-suppressions`, `--no-fail-on-findings`, or `--no-fail-on-incomplete-scanners`,
  unless the user asks for that change.
- Do not set `client_supplied` in a config. ASH sets it.
- Do not add sandbox grants or plugin modules to the repository's config to make a scanner
  work. They are the operator's settings, and ASH ignores sandbox grants from a config inside
  the scanned repository.
- When a scanner is MISSING because its tool is installed only inside the project, install
  the tool outside the project. Do not pass `--allow-in-tree-tools` or set
  `ASH_ALLOW_IN_TREE_TOOLS` unless the user asks you to.
- Do not make `.ash`, `.ash/ash_output`, or any directory under it a symbolic link. ASH refuses
  to write through one.
- Do not repeat a detected secret's value in your answers. Refer to the file and line.
- If a tool, option, or field named here does not exist, the installed ASH is older than this
  guide. Tell the user, and use what the installed version reports (`ash --help`, the MCP
  server's tool list).

## Run a scan with the MCP tools

When the ASH MCP server is connected, a scan takes three steps:

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns
   at once with a `scan_id` and status `running`.
2. Call `get_scan_progress` with the `scan_id` about every 5 seconds until `is_complete` is
   true. It is true for every final status: `completed`, `incomplete`, `failed`, or
   `cancelled`.
3. When `results_available` is true, which it is for `completed` and `incomplete`, read the
   results from `output_directory`, an absolute path in the progress response.

| Final status | Meaning | What to do |
|--------------|---------|------------|
| `completed` | Every selected scanner ran. | Read the results. |
| `incomplete` | The scan finished and its results are readable, but a selected scanner did not run or did not finish, or a content database was too old. | Read the results, report `incomplete_scanners` and `stale_content_databases`, and say the coverage is partial. |
| `failed` | The scan crashed, left no readable results, or ran longer than the server allows. | Report `error_message`. |
| `cancelled` | The scan was canceled. | Say so. |

After `failed` or `cancelled`, `results_available` is false, so do not report results for that
scan. Once ASH has put the previous scan's results back in the output directory,
`output_holds_previous_results` is true, and the results tools refuse that directory with
`error_category` `scan_incomplete` until another scan finishes there.

The examples in this section call each tool as a function that takes the tool's arguments
and returns its response, a dictionary. A response with `success` false has an `error`
message instead of the keys below. Adapt the calls to your MCP client:

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
```text
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
ash get-genai-guide -o ash-integration-guide.md
```

**Usage**: Reference in `.cursorrules` or mention in prompts.

#### Generic / Other Tools

**Project root** (universal approach):
```bash
# Download with descriptive name
ash get-genai-guide -o ash-genai-guide.md
```

Then reference it in your AI tool's context or prompts.

### Updating the Guide

When ASH is updated, refresh the guide:
```bash
# Create the directory if this is the first download
mkdir -p ~/.kiro/steering

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
- **Configuration**: the ASH config file (`.ashrc.yaml` in a new project; a project's existing `.ash/.ash.yaml` is read first), YAML with a JSON schema
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
<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import time

# LOW is stricter than the default MEDIUM, so LOW findings count as actionable too.
# Leave severity_threshold out to use the config's threshold.
scan = run_ash_scan(source_dir="/path/to/project", severity_threshold="LOW")
if scan.get("success") is False:
    raise RuntimeError(scan["error"])

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
has_jq = shutil.which("jq") is not None

# Check for Python (almost always available)
has_python = shutil.which("python3") is not None or shutil.which("python") is not None

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

### 4. Understanding Suppressed vs Actionable Findings

**Key Concepts**:
- **Total Findings**: All findings detected by scanners
- **Suppressed Findings**: Findings marked as false positives or accepted risks
- **Actionable Findings**: Total - Suppressed = findings requiring attention

**Always Check**:
<!-- doctest: config kind=ash-output model=automated_security_helper.models.asharp_model.AshAggregatedResults -->
```json
{
  "metadata": {
    "summary_stats": {
      "total": 156,
      "actionable": 61,
      "severity_counts": {
        "suppressed": 95
      }
    }
  }
}
```

## File Structure and Locations

### Output Directory Structure

```text
.ash/ash_output/
├── ash_aggregated_results.json    # PRIMARY: Complete scan results
├── ash.log                         # Scan execution log
├── ash-scan-set-files-list.txt    # List of files scanned
├── ash-scan-set-run.json          # Which run wrote that list
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
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
# Extract just summary stats
jq '.metadata.summary_stats' ash_aggregated_results.json

# Get specific scanner results
jq '.scanner_results.bandit' ash_aggregated_results.json
```

#### Strategy 2: Using Python (FALLBACK - If jq is NOT available)
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
# Extract summary stats
python3 -c "import json; data=json.load(open('ash_aggregated_results.json')); print(json.dumps(data['metadata']['summary_stats'], indent=2))"

# Get actionable count
python3 -c "import json; print(json.load(open('ash_aggregated_results.json'))['metadata']['summary_stats']['actionable'])"
```

**Alternative: Use grep for simple extractions** (always available):
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
# Get actionable count (quick and dirty)
grep -o '"actionable": [0-9]*' ash_aggregated_results.json | grep -o '[0-9]*'

# Check for critical findings
grep -o '"critical": [0-9]*' ash_aggregated_results.json | head -1
```

#### Strategy 3: Streaming JSON Parsers (For Large Files)

**Python with ijson** (streaming parser, installed separately with `pip install ijson`):
<!-- doctest: illustrative reason="needs ijson, a third-party package that ASH does not install" -->
```python
import importlib

ijson = importlib.import_module("ijson")  # a third-party package, not part of ASH

# Stream parse - memory efficient
with open("ash_aggregated_results.json", "rb") as f:
    # Extract just summary stats without loading entire file
    parser = ijson.items(f, "metadata.summary_stats")
    summary_stats = next(parser)
    print(f"Actionable findings: {summary_stats['actionable']}")
```

**Python standard library** (load specific sections):
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```python
import json

# Load and extract only what you need
with open("ash_aggregated_results.json") as f:
    data = json.load(f)

# Immediately extract and discard the rest
summary = data["metadata"]["summary_stats"]
del data  # Free memory

print(f"Actionable: {summary['actionable']}")
# The per-severity counts are nested under severity_counts, not flat keys
print(f"Critical: {summary['severity_counts']['critical']}")
```

#### Strategy 4: Use Simpler Formats

**For most use cases, use the flat JSON format instead**:
<!-- doctest: illustrative reason="reads a report file that an earlier scan has to have written to the current directory" -->
```python
# reports/ash.flat.json is much smaller and easier to parse
import json

with open("reports/ash.flat.json") as f:
    findings = json.load(f)

# Simpler structure, direct access to findings
for finding in findings:
    if finding["severity"] in ["CRITICAL", "HIGH"]:
        print(f"{finding['file_path']}: {finding['message']}")
```

### Schema Overview

<!-- doctest: config kind=ash-output model=automated_security_helper.models.asharp_model.AshAggregatedResults -->
```jsonc
{
  "name": "ASH Scan 2026-02-28T10:10:46.211371",
  "description": "Aggregated security scan results",
  "metadata": {
    "report_id": "ASH-20260228151046-3f9c0e2b7d1a",
    "generated_at": "2026-02-28T15:10:46+00:00",
    "project_name": "my-service",
    "tool_version": "3.2.2",
    "summary_stats": {
      "severity_counts": {
        "suppressed": 95,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 61,
        "info": 0
      },
      "start": "2026-02-28T15:09:25+00:00",
      "end": "2026-02-28T15:10:46+00:00",
      "duration": 80.615062,
      "total": 156,
      "actionable": 61,
      "passed": 9,
      "failed": 0,
      "missing": 1,
      "skipped": 0,
      "error": 0
    }
  },
  "ash_config": { /* Configuration used for scan */ },
  "scanner_results": { /* One status record per scanner; the findings are in sarif */ },
  "converter_results": { /* File conversion results */ },
  "additional_reports": { /* External reports included */ },
  "validation_checkpoints": [ /* Scan validation data */ ]
}
```

### Key Fields

#### metadata.summary_stats
- `total`: Total findings detected
- `actionable`: Findings that fail the scan: not suppressed, and at or above the severity threshold
- `severity_counts.suppressed`: Findings marked as false positives/accepted risks
- `severity_counts.critical`, `.high`, `.medium`, `.low`, `.info`: Counts by severity. The file has no flat `critical` or `suppressed` key at the `summary_stats` level; read them under `severity_counts`
- `passed`: Scanners that completed successfully
- `failed`: Scanners that found something at or above their threshold
- `missing`, `skipped`, `error`: Scanners that did not run, were skipped, or started and failed
- `duration`: Scan duration in seconds

#### scanner_results
Contains one status record per scanner, keyed by scanner name. A record says how the scanner ended and how many findings it produced. It does not hold the findings themselves; those are in `sarif`, below.

<!-- doctest: config kind=other reason="a trimmed sketch of one scanner's status record, not the whole file" -->
```json
{
  "scanner_results": {
    "bandit": {
      "status": "FAILED",
      "dependencies_satisfied": true,
      "excluded": false,
      "severity_counts": {
        "suppressed": 0,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0
      },
      "finding_count": 2,
      "actionable_finding_count": 1,
      "suppressed_finding_count": 0,
      "exit_code": 0,
      "duration": 1.25,
      "missing_reason": null,
      "skipped_reason": null
    }
  }
}
```

- `status`: `PASSED`, `FAILED` (at least one actionable finding), `ERROR`, `MISSING` (the tool was not found) or `SKIPPED`
- `severity_counts`, `finding_count`, `actionable_finding_count`, `suppressed_finding_count`: the scanner's findings by severity, in total, actionable, and suppressed
- `duration`: seconds the scanner ran
- `exit_code`: the scanner tool's exit code, or `null` when no tool ran
- `missing_reason`, `skipped_reason`: why the scanner did not run, set on a `MISSING` and a `SKIPPED` record respectively and `null` otherwise

#### sarif
The findings are in `sarif`, a SARIF 2.1.0 report. Each finding is one entry of `sarif.runs[].results[]`. A file ASH writes has one run that holds every scanner's findings, so loop over all `runs` rather than reading only the first, and use `properties.scanner_name` to tell the scanners apart. The fields to read:

- `ruleId`: the scanner's rule identifier
- `message.text`: what the scanner found
- `locations[0].physicalLocation.artifactLocation.uri`: the file path
- `locations[0].physicalLocation.region.startLine`: the first line (`endLine` is the last)
- `level`: the SARIF level, `error`, `warning`, `note` or `none`
- `properties.scanner_name`: the scanner that reported the finding, the same name as the key in `scanner_results`
- `properties.issue_severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO`; when a result has none, ASH grades it from its rule's score or its `level`
- `suppressions`: `null` or empty for an active finding, and one or more entries for a suppressed one

For one record per finding with flat field names, read `reports/ash.flat.json` instead.

### Efficient Querying

**IMPORTANT**: Always attempt `jq` first for maximum efficiency. Check availability and provide fallbacks for compatibility.

#### Recommended: Using jq (Check Availability First)

**Get actionable findings count** (preferred method):
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
jq '.metadata.summary_stats.actionable' ash_aggregated_results.json
```

**Get all critical/high findings** (suppressed ones included; the findings are in `sarif`):
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
jq '.sarif.runs[].results[] | select(.properties.issue_severity == "CRITICAL" or .properties.issue_severity == "HIGH") | {scanner: .properties.scanner_name, rule: .ruleId, severity: .properties.issue_severity, file: .locations[0].physicalLocation.artifactLocation.uri, line: .locations[0].physicalLocation.region.startLine, message: .message.text}' ash_aggregated_results.json
```

**Get findings by scanner**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
jq '[.sarif.runs[].results[] | select(.properties.scanner_name == "bandit")]' ash_aggregated_results.json
```

**Get a scanner's status and finding counts**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
jq '.scanner_results.bandit' ash_aggregated_results.json
```

**Get non-suppressed findings**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
jq '.sarif.runs[].results[] | select((.suppressions // []) | length == 0)' ash_aggregated_results.json
```

**Count findings by severity**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
jq '[.sarif.runs[].results[] | .properties.issue_severity] | group_by(.) | map({severity: .[0], count: length})' ash_aggregated_results.json
```

#### Fallback: Using Python (If jq is unavailable)

**Get actionable findings count**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
python3 -c "import json; print(json.load(open('ash_aggregated_results.json'))['metadata']['summary_stats']['actionable'])"
```

**Get all critical/high findings**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```python
import json

with open("ash_aggregated_results.json") as f:
    data = json.load(f)

for run in data["sarif"]["runs"]:
    for result in run["results"]:
        properties = result.get("properties") or {}
        if properties.get("issue_severity") in ["CRITICAL", "HIGH"]:
            locations = result.get("locations") or [{}]
            location = locations[0].get("physicalLocation", {})
            uri = location.get("artifactLocation", {}).get("uri")
            line = location.get("region", {}).get("startLine")
            message = result.get("message", {}).get("text")
            print(f"{properties.get('scanner_name')}: {uri}:{line} - {message}")
```

**Get findings by scanner**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```python
import json

with open("ash_aggregated_results.json") as f:
    data = json.load(f)

bandit_findings = [
    result
    for run in data["sarif"]["runs"]
    for result in run["results"]
    if (result.get("properties") or {}).get("scanner_name") == "bandit"
]
print(json.dumps(bandit_findings, indent=2))
```

**Count findings by severity**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```python
import json
from collections import Counter

with open("ash_aggregated_results.json") as f:
    data = json.load(f)

severities = []
for run in data["sarif"]["runs"]:
    for result in run["results"]:
        severities.append((result.get("properties") or {}).get("issue_severity"))

counts = Counter(severities)
for severity, count in counts.items():
    print(f"{severity}: {count}")
```

#### Last Resort: Using grep/awk (If neither jq nor Python available)

**Get actionable findings count** (basic but works):
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
grep -o '"actionable": [0-9]*' ash_aggregated_results.json | head -1 | grep -o '[0-9]*'
```

**Check for critical findings**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
grep -c '"issue_severity": "CRITICAL"' ash_aggregated_results.json
```

**List all severity levels found**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
grep -o '"issue_severity": "[A-Z]*"' ash_aggregated_results.json | sort -u
```

#### Recommended Approach for GenAI Tools

**1. Check tool availability first**:
```python
import subprocess
import shutil


def get_actionable_count(results_file):
    """Get actionable findings count using best available method."""

    # Method 1: Try jq (fastest - PREFERRED)
    if shutil.which("jq"):
        try:
            result = subprocess.run(
                ["jq", ".metadata.summary_stats.actionable", results_file],
                capture_output=True,
                text=True,
                check=True,
            )
            return int(result.stdout.strip())
        except Exception:
            pass

    # Method 2: Use Python (most reliable fallback)
    try:
        import json

        with open(results_file) as f:
            data = json.load(f)
        return data["metadata"]["summary_stats"]["actionable"]
    except Exception:
        pass

    # Method 3: Fallback to grep (always available)
    try:
        result = subprocess.run(
            ["grep", "-o", '"actionable": [0-9]*', results_file],
            capture_output=True,
            text=True,
            check=True,
        )
        return int(result.stdout.strip().split(":")[1].strip())
    except Exception:
        return None
```

**2. Use the flat JSON format when possible**:
<!-- doctest: illustrative reason="reads a report file that an earlier scan has to have written to the current directory" -->
```python
import json

# Simpler, smaller, easier to parse
with open("reports/ash.flat.json") as f:
    findings = json.load(f)

actionable = [f for f in findings if not f.get("suppressed", False)]
critical_high = [f for f in actionable if f["severity"] in ["CRITICAL", "HIGH"]]
```

## Working with CycloneDX SBOM

### Purpose
The CycloneDX SBOM (`reports/ash.cdx.json`) provides a complete Software Bill of Materials, including:
- Direct and transitive dependencies
- Component versions and licenses
- Known vulnerabilities (CVEs)
- Dependency relationships

### Schema Overview

<!-- doctest: config kind=other reason="a CycloneDX software bill of materials, a standard format that the Syft scanner writes" -->
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
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
jq '.components[] | {name: .name, version: .version, type: .type}' ash.cdx.json
```

**Find components with vulnerabilities**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
jq '.vulnerabilities[] | .affects[].ref' ash.cdx.json | sort -u
```

**Get high/critical vulnerabilities**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
jq '.vulnerabilities[] | select(.ratings[].severity == "high" or .ratings[].severity == "critical")' ash.cdx.json
```

**List all licenses**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
jq '[.components[].licenses[]?.license.id] | unique' ash.cdx.json
```

**Find dependency tree for a component**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
jq --arg pkg "pkg:pypi/requests@2.31.0" '.dependencies[] | select(.ref == $pkg)' ash.cdx.json
```

#### Fallback: Using Python (If jq is unavailable)

**List all components**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```python
import json

with open("reports/ash.cdx.json") as f:
    sbom = json.load(f)

for component in sbom.get("components", []):
    print(f"{component['name']} {component['version']} ({component['type']})")
```

**Find components with vulnerabilities**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```python
import json

with open("reports/ash.cdx.json") as f:
    sbom = json.load(f)

vulnerable_refs = set()
for vuln in sbom.get("vulnerabilities", []):
    for affect in vuln.get("affects", []):
        vulnerable_refs.add(affect["ref"])

for ref in sorted(vulnerable_refs):
    print(ref)
```

**Get high/critical vulnerabilities**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```python
import json

with open("reports/ash.cdx.json") as f:
    sbom = json.load(f)

for vuln in sbom.get("vulnerabilities", []):
    for rating in vuln.get("ratings", []):
        if rating.get("severity") in ["high", "critical"]:
            print(
                f"{vuln['id']}: {rating['severity']} (score: {rating.get('score', 'N/A')})"
            )
            for affect in vuln.get("affects", []):
                print(f"  Affects: {affect['ref']}")
            break
```

**List all licenses**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```python
import json

with open("reports/ash.cdx.json") as f:
    sbom = json.load(f)

licenses = set()
for component in sbom.get("components", []):
    for license_info in component.get("licenses", []):
        if "license" in license_info and "id" in license_info["license"]:
            licenses.add(license_info["license"]["id"])

for license_id in sorted(licenses):
    print(license_id)
```

#### Last Resort: Using grep (If neither jq nor Python available)

**Count total components**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
grep -c '"type": "library"' reports/ash.cdx.json
```

**Find if specific package exists**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
grep -i "requests" reports/ash.cdx.json
```

**Count vulnerabilities**:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
grep -c '"id": "CVE-' reports/ash.cdx.json
```

## Configuration File Schema

### Location
- Default: the first config file discovery finds; `ash config init` creates `.ashrc.yaml` in the project root
- Custom: Specify with `--config` flag or `ASH_CONFIG` environment variable

### Schema Structure

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json

project_name: my-project

fail_on_findings: true  # Exit with code 2 if actionable findings exist

global_settings:
  severity_threshold: MEDIUM  # ALL, LOW, MEDIUM, HIGH, CRITICAL
  
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
The least severe finding that counts as actionable. Findings below it are still detected and reported, but not counted as actionable: they do not fail the scan, and `get_scan_results(actionable_only=True)` leaves them out.

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
<!-- doctest: config kind=ash-fragment at=global_settings -->
```yaml
suppressions:
  - path: 'src/utils.py'
    rule_id: 'B603'
    reason: 'subprocess.call uses list args (no shell=True), validated inputs only'
```

**2. Be Specific with Paths**:
<!-- doctest: config kind=ash-fragment at=global_settings.suppressions -->
```yaml
# Good - specific file
- path: 'src/auth/login.py'
  rule_id: 'B201'
  reason: 'Debug mode is only enabled in the local development server'

# Good - specific directory
- path: 'tests/**/*.py'
  rule_id: 'B101'
  reason: 'assert is how the tests check results'

# Avoid - too broad
- path: '**/*.py'
  rule_id: 'B201'
  reason: 'Too broad: this hides B201 in every Python file'
```

**3. Use Line Numbers for Precision**:
<!-- doctest: config kind=ash-fragment at=global_settings -->
```yaml
suppressions:
  - path: 'src/app.py'
    rule_id: 'B201'
    line_start: 42
    line_end: 42
    reason: 'Debug mode only enabled in development environment'
```

**4. Set Expiration Dates for Temporary Suppressions**:
<!-- doctest: config kind=ash-fragment at=global_settings -->
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
   <!-- doctest: illustrative reason="runs every enabled scanner, which needs each scanner's tool" -->
   ```bash
   ash --mode local
   ```

5. **Confirm Suppression Applied**:
   <!-- doctest: illustrative reason="reads the results of the full scan above" -->
   ```bash
   jq '.metadata.summary_stats.severity_counts.suppressed' .ash/ash_output/ash_aggregated_results.json
   ```

## Common Pitfalls and Known Issues

### 1. Suppression Not Applied
**Issue**: Suppression added but finding still shows as actionable

**Common Causes**:
- Path doesn't match exactly (check for leading `./` or trailing `/`)
- Rule ID typo or case mismatch
- Line numbers don't match (scanner may report different lines)

**Solution**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
# Check exact path and rule_id from results
jq '.sarif.runs[].results[] | select((.suppressions // []) | length == 0) | {file: .locations[0].physicalLocation.artifactLocation.uri, rule: .ruleId, line: .locations[0].physicalLocation.region.startLine}' ash_aggregated_results.json

# Verify suppression in config matches exactly
```

### 2. HTML Report Parsing Failures
**Issue**: Attempting to parse HTML with regex or string matching

**Solution**: Never parse HTML reports. Use JSON formats:
- `ash_aggregated_results.json` - complete results
- `reports/ash.flat.json` - simplified structure
- `reports/ash.sarif` - SARIF format

### 3. Missing Scanner Results
**Issue**: Expected scanner results not in output

**Check**:
<!-- doctest: illustrative reason="reads a results file that an earlier scan has to have written to the current directory" -->
```bash
# Verify scanner was enabled and executed
jq '.metadata.validation_summary' ash_aggregated_results.json

# Check for scanner errors
jq '.scanner_results | to_entries[] | select(.value.status == "FAILED")' ash_aggregated_results.json
```

### 4. Dependency Analysis Confusion
**Issue**: Trying to extract dependencies from scan findings

**Solution**: Use CycloneDX SBOM:
<!-- doctest: illustrative reason="reads a software bill of materials that an earlier scan has to have written to the current directory" -->
```bash
# Get all dependencies
jq '.components[] | {name, version, type}' reports/ash.cdx.json

# Get vulnerable dependencies
jq '.vulnerabilities[] | .affects[].ref' reports/ash.cdx.json
```

## Integration Patterns

### Pattern 1: CI/CD Pipeline Gate

<!-- doctest: illustrative reason="reads .ash/ash_output, which a scan has to have written first" -->
```python
import json
import sys

# Read results
with open(".ash/ash_output/ash_aggregated_results.json") as f:
    results = json.load(f)

stats = results["metadata"]["summary_stats"]
# The per-severity counts are nested under severity_counts, not flat keys
counts = stats["severity_counts"]

# Fail on actionable critical/high findings
# Note: Use actionable count to exclude suppressed findings (false positives)
if counts["critical"] > 0:
    print(f"FAILED: {counts['critical']} critical actionable findings")
    sys.exit(1)

if counts["high"] > 5:
    print(f"FAILED: {counts['high']} high actionable findings (threshold: 5)")
    sys.exit(1)

print(f"PASSED: {stats['actionable']} actionable findings (within threshold)")
sys.exit(0)
```

**Using MCP Server:**
<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import sys

# Get only actionable critical/high findings for a CI/CD gate. actionable_only
# adds `findings`, the findings that fail the scan (unsuppressed, at or above its
# severity threshold) and match the filters; the list is in a filter_level="full"
# response only.
result = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical,high",
    filter_level="full",
)

if result["findings_count"] > 0:
    print(f"FAILED: {result['findings_count']} actionable critical/high findings")
    sys.exit(1)
```

### Pattern 2: Finding Analysis and Remediation

<!-- doctest: illustrative reason="reads .ash/ash_output, which a scan has to have written first" -->
```python
import json

# Read results
with open(".ash/ash_output/ash_aggregated_results.json") as f:
    results = json.load(f)

# Get all actionable high/critical findings
actionable_findings = []
for run in results["sarif"]["runs"]:
    for finding in run["results"]:
        properties = finding.get("properties") or {}
        if finding.get("suppressions"):
            continue
        if properties.get("issue_severity") in ["HIGH", "CRITICAL"]:
            locations = finding.get("locations") or [{}]
            location = locations[0].get("physicalLocation", {})
            actionable_findings.append(
                {
                    "scanner": properties.get("scanner_name"),
                    "rule_id": finding.get("ruleId"),
                    "severity": properties["issue_severity"],
                    "file": location.get("artifactLocation", {}).get("uri"),
                    "line": location.get("region", {}).get("startLine"),
                    "message": finding.get("message", {}).get("text"),
                }
            )

# Sort by severity
actionable_findings.sort(key=lambda x: 0 if x["severity"] == "CRITICAL" else 1)

# Generate remediation plan
for finding in actionable_findings:
    print(f"\n[{finding['severity']}] {finding['file']}:{finding['line']}")
    print(f"  Rule: {finding['rule_id']} ({finding['scanner']})")
    print(f"  Issue: {finding['message']}")
    print(f"  Action: [Suggest remediation based on rule_id]")
```

**Using MCP Server:**
<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
# Get actionable high/critical findings, one entry per finding
results = await get_scan_results(
    output_dir=".ash/ash_output",
    actionable_only=True,
    severities="critical,high",
    filter_level="full",
)

# `findings` holds the findings that fail the scan (unsuppressed, at or above its
# severity threshold) and match the filters. The SARIF they come from is not part
# of the response; read it from the file get_scan_result_paths names if you need
# it, or the findings below the threshold.
for finding in results["findings"]:
    print(
        f"[{finding['severity']}] {finding.get('file_path')}:{finding.get('line_start')} "
        f"{finding['rule_id']} ({finding.get('scanner')}): {finding.get('message')}"
    )
```

### Pattern 3: Dependency Vulnerability Report

<!-- doctest: illustrative reason="reads .ash/ash_output, which a scan has to have written first" -->
```python
import json

# Read CycloneDX SBOM
with open(".ash/ash_output/reports/ash.cdx.json") as f:
    sbom = json.load(f)

# Extract vulnerable components
vulnerable_components = {}
for vuln in sbom.get("vulnerabilities", []):
    for affect in vuln.get("affects", []):
        component_ref = affect["ref"]
        if component_ref not in vulnerable_components:
            vulnerable_components[component_ref] = []
        vulnerable_components[component_ref].append(
            {
                "cve": vuln["id"],
                "severity": vuln["ratings"][0]["severity"],
                "score": vuln["ratings"][0].get("score", "N/A"),
            }
        )

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
- `cancel_scan` - Cancel a running scan and stop it: its running scanner is stopped and no reports are written after the cancel

### Managing Long-Running Scans

**CRITICAL**: ASH scans can take 30-120+ seconds. MCP connections may timeout if you don't keep them alive.

#### ❌ WRONG: Sleep and Wait (Connection Timeout)

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
# This will cause connection timeout!
result = run_ash_scan(source_dir="/path/to/project")
scan_id = result["scan_id"]

# Sleeping for 60+ seconds causes MCP connection to close
time.sleep(60)

# This will fail - connection already timed out
summary = get_scan_summary()  # ERROR: Connection closed
```

#### ✅ CORRECT: Poll Progress (Keep Connection Alive)

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import time

# 1. Start scan (returns immediately with scan_id). severity_threshold can make
#    the config's global_settings.severity_threshold stricter for this scan,
#    never looser; omit it to use the config's. LOW also counts LOW findings
#    against the default MEDIUM; a looser value such as HIGH is ignored.
result = run_ash_scan(source_dir="/path/to/project", severity_threshold="LOW")
scan_id = result["scan_id"]

# 2. Poll progress periodically to keep connection alive
while True:
    progress = get_scan_progress(scan_id=scan_id)

    # is_complete is true for every ending: completed, incomplete, failed and
    # cancelled
    if progress.get("is_complete"):
        break
    time.sleep(5)

# 3. Get results if this scan has its own. A completed or incomplete scan does
#    (an incomplete one's findings are real but partial). A failed or cancelled
#    one does not: its output directory holds the previous scan's results.
if progress.get("results_available"):
    # Use filtered queries to reduce data transfer
    results = get_scan_results(
        output_dir=progress["output_directory"], actionable_only=True
    )
else:
    print(f"Scan {progress['status']}: {progress.get('error_message')}")
```

What to know about the tools:

- `run_ash_scan` takes no scanner list. The project's ASH config chooses the scanners and
  the severity thresholds.
- Its `severity_threshold` argument can make the config's `global_settings.severity_threshold`
  stricter for that scan, never looser: `LOW` over a configured `MEDIUM` makes LOW findings
  actionable, and `CRITICAL` over `MEDIUM` changes nothing. It tightens a scanner's own
  `severity_threshold` option the same way, and a scanner without one follows the tightened
  global threshold. The threshold decides which findings are actionable and whether a
  scanner reports FAILED, not which findings are reported. `get_scan_progress` returns the
  argument as `requested_severity_threshold` and, once the scan has results, the threshold
  it was judged by as `severity_threshold`.
- Each scan writes `.ash/ash_output` inside `source_dir`. Once its options and config are
  accepted, it sets the previous scan's results there aside, and it deletes them once it has
  results of its own; a scan that fails or is canceled puts them back, and a scan refused
  for its scanner selection or its config leaves them as they were. Copy `ash_aggregated_results.json` before the next scan
  if you need it for a comparison.
- `cancel_scan` stops a running scan: the scanner tool running at the time is stopped, and no
  further scanner, phase, or reporter starts, so a scan canceled before its report phase
  writes no reports. A scanner that is already reading its tool's output can still write its
  own files, but `ash_aggregated_results.json` is not written after the cancel. Previous
  results that the output directory held are put back in place of the results the scan
  wrote; the scan's log, `ash.log`, stays, and an `ash.log.jsonl` already there is left as it
  was. With none to put back, what the scan wrote before it stopped stays, though a cancel
  during the report phase removes that phase's reports, all but
  `reports/ash.unused-suppressions.md`. Its status is `cancelled` at once. Until the scan has stopped, `run_ash_scan`
  refuses another scan of that directory.
- `get_scan_results` returns counts and per-scanner summaries. With `actionable_only` set, a
  response at the default `filter_level`, `full`, also has a `findings` list of the
  actionable findings, without their IDs, and its `findings_count`. Those are the findings
  that are not suppressed and are at or above the threshold their scanner was judged by, the
  ones that fail the scan. Findings below it are left out. A `summary` or `minimal` response
  has no list. Read the IDs, and the suppressed findings, from `reports/ash.flat.json` in the
  output directory.
  `get_scan_result_paths` returns the absolute paths of the main reports and of
  `ash_aggregated_results.json`.
- The server's operator limits how many scans it holds at once, running or waiting
  (`max_concurrent_scans`), and how long one may run (`scan_timeout_seconds`). A scan over
  the first limit is refused with an `error` that names it; start it again when another scan
  has finished. A scan over the second is stopped and ends `failed`.
- The server keeps its list of scans in memory. After it restarts, `get_scan_progress`
  fails with `error_category` `scan_not_found` for older scan IDs; read their results from the
  output directory.

After a scan, `get_scan_progress` reports `scanner_statuses` for every scanner ASH considered
and `skipped_scanners` for the ones that did not run. Use them to tell "ran and found nothing"
from "never ran". `check_installation` reports whether each built-in scanner's tool is
installed: `ready` is false when a scanner that ASH enables by default cannot run and no scan
will install its tool, and `missing_dependencies` names those scanners. It does not read the
project's config, and it installs and downloads nothing. When the tool of a scanner that ASH
installs with uv is missing, the first scan installs it if the server is online and has uv;
such a scanner is listed in `installs_on_first_scan` and counts toward `ready`, and otherwise
it is in `missing_dependencies`. Offline, semgrep is also missing when it has no rules cache.

The [MCP tools reference](https://github.com/awslabs/automated-security-helper/blob/main/docs/content/reference/mcp-tools.md)
lists every tool and its parameters.

### Stop a scan that runs too long

A canceled scan's status is `cancelled` at once, so the next poll ends the loop, and
`results_available` is false:

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import time


def scan_or_cancel(source_dir):
    scan = run_ash_scan(source_dir=source_dir)
    if scan.get("success") is False:
        return {"error": scan["error"]}
    deadline = time.monotonic() + 20 * 60
    canceled = False
    while True:
        progress = get_scan_progress(scan_id=scan_id)

        # Show status updates
        current_status = progress.get("message", "Running...")
        if current_status != last_status:
            print(f"Status: {current_status}")
            last_status = current_status

        # Check completion: is_complete is true for every ending
        if progress.get("is_complete"):
            break

        # Wait before next poll (keeps connection alive)
        time.sleep(5)

    # A failed or cancelled scan has no results of its own; the files in its
    # output directory are the previous scan's.
    if not progress.get("results_available"):
        reason = progress.get("error_message") or "no results"
        return {"error": f"Scan {progress['status']}: {reason}"}

    # Get filtered results
    output_dir = progress.get("output_directory", f"{source_dir}/.ash/ash_output")
    results = get_scan_results(
        output_dir=output_dir,
        filter_level="summary",
        actionable_only=True,
        severities="critical,high,medium",
    )
```

### Pattern 1: fail a build on critical or high findings

Run from the scanned directory after the scan has ended with results:

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import sys
from pathlib import Path

# Summary - dashboard data (5-15KB)
summary = await get_scan_results(output_dir=".ash/ash_output", filter_level="summary")

# Full - complete results (50KB-2MB)
results = await get_scan_results(output_dir=".ash/ash_output", filter_level="full")
```

### Content Filtering

Filter by scanner, severity, or actionable status:

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
# Only actionable findings: unsuppressed, at or above the severity threshold
actionable = await get_scan_results(output_dir=".ash/ash_output", actionable_only=True)

# Only critical findings
critical = await get_scan_results(output_dir=".ash/ash_output", severities="critical")

# Actionable critical findings only
actionable_critical = await get_scan_results(
    output_dir=".ash/ash_output", actionable_only=True, severities="critical"
)

# Specific scanners
sast_results = await get_scan_results(
    output_dir=".ash/ash_output", scanners="bandit,semgrep"
)

# Combined filtering - actionable high-priority SAST findings
high_priority_sast = await get_scan_results(
    output_dir=".ash/ash_output",
    filter_level="summary",
    scanners="bandit,semgrep",
    severities="critical,high",
    actionable_only=True,
)
if results.get("success") is False:
    print(results["error"])
    sys.exit(1)
if results["findings_count"] > 0:
    print(f"{results['findings_count']} actionable critical or high findings")
    sys.exit(1)
```

The list holds the findings that the scan's own exit code and `summary_stats.actionable`
count, those at or above each scanner's severity threshold, narrowed here to critical and
high.

### Pattern 2: list the findings to fix

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
from pathlib import Path

results = get_scan_results(
    output_dir=str(Path(".ash/ash_output").resolve()),
    actionable_only=True,
    severities="critical,high",
)
for finding in results["findings"]:
    print(
        finding["severity"],
        finding.get("scanner"),
        finding.get("rule_id"),
        f"{finding.get('file_path')}:{finding.get('line_start')}",
        finding.get("message"),
    )
```

The list leaves out suppressed findings. `reports/ash.flat.json` in the output directory has
every finding, with `is_suppressed`.

### When the server is remote

A server on another host cannot read the user's files. Deliver the source first with
`set_source_git` or `set_source_zip_chunk` and `set_source_zip_finalize`, then call
`run_ash_scan` without `source_dir`. A config file inside delivered source is checked against
the server's policy: if it sets a field the server does not let clients set, such as
`fail_on_findings`, the scan is refused with `error_type` `config_field_denied` and a message
naming the field. Remove the field and deliver again. Suppressions and ignore paths in
delivered source are applied and marked as client-supplied in the results.

## Run a scan with the command line

From the project's root directory:

<!-- doctest: illustrative reason="runs every scanner, which needs the scanner tools and network access" -->
```bash
ash --source-dir . --no-progress
```

`ash` and `ash scan` are the same command. The scan runs on this machine and writes its
output to `.ash/ash_output` under the scanned directory unless you pass `--output-dir`.
`--scanners` runs only the named scanners and `--exclude-scanners` skips them; use them only
when the user asks for a narrower scan. This scan runs detect-secrets alone, without network
access:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

| Exit code | Meaning |
|-----------|---------|
| 0 | No actionable findings, or the config does not fail on findings. |
| 1 | The scan is incomplete: a scanner was MISSING or ended in ERROR, a converter failed, a rule could not be evaluated, a content database was too old, or ASH itself failed. |
| 2 | Actionable findings. |
| 3 | The config is invalid. |
| 4 | A workspace definition or workspace policy is invalid. |
| 5 | The command line is wrong: an unknown option or argument, a value ASH does not accept, such as a mistyped scanner name, or options that cannot be combined. No scanner ran. |

A value ASH does not accept is a usage error, and no scanner runs:

<!-- doctest: run expect-exit=5 -->
```bash
ash --source-dir . --scanners detect-secrets --min-severity urgent --offline --no-progress
```

To print a summary of the last scan:

```bash
ash report --output-dir .ash/ash_output
```

## Read the results

The output directory, `.ash/ash_output` by default, contains:

| Path | Use it for |
|------|------------|
| `reports/ash.flat.json` | Findings, one record each. Start here. |
| `ash_aggregated_results.json` | Each scanner's status and the scan's totals. |
| `reports/ash.summary.md` | A readable summary to show the user. |
| `reports/ash.sarif` | SARIF, for tools that read it. |
| `reports/ash.unused-suppressions.json` | Suppressions that matched no finding, including expired ones. |
| `ash.log` | The scan's log, for errors. |

`reports/ash.flat.json` is an object. Its `findings` list holds one record per finding with
these fields: `id`, `title`, `description`, `severity`, `scanner`, `rule_id`, `file_path`,
`line_start`, `line_end`, `is_suppressed`, `code_snippet`, and, for suppressed findings,
`suppression_kind` and `suppression_justification`. Fields with no value are left out, so
read them with a default. `tags`, `properties`, and `raw_data` hold JSON encoded as strings.

```python
import json
from pathlib import Path

report = json.loads(Path(".ash/ash_output/reports/ash.flat.json").read_text())
for finding in report["findings"]:
    if finding.get("is_suppressed"):
        continue
    print(
        finding["severity"],
        finding["scanner"],
        finding["rule_id"],
        f"{finding.get('file_path')}:{finding.get('line_start')}",
        finding["id"],
    )
```

In `ash_aggregated_results.json`, `metadata.summary_stats` holds the totals:

- `severity_counts` counts findings by severity (`critical`, `high`, `medium`, `low`,
  `info`) and counts suppressed findings separately in `suppressed`.
- `total` is the number of findings that are not suppressed.
- `actionable` is the number of findings that are not suppressed and are at or above the
  severity threshold. The threshold comes from `global_settings.severity_threshold` in the
  config, MEDIUM by default, or from a scanner's own `severity_threshold` option, which
  replaces it for that scanner.
- `passed`, `failed`, `missing`, `skipped`, and `error` count scanners by status.

The config sets both:

<!-- doctest: config kind=ash -->
```yaml
global_settings:
  severity_threshold: MEDIUM  # ALL, LOW, MEDIUM, HIGH, CRITICAL
scanners:
  bandit:
    options:
      severity_threshold: HIGH
```

```python
import json
from pathlib import Path

results = json.loads(Path(".ash/ash_output/ash_aggregated_results.json").read_text())
stats = results["metadata"]["summary_stats"]
print("actionable:", stats["actionable"], stats["severity_counts"])
for name, scanner in results["scanner_results"].items():
    if scanner["status"] in ("MISSING", "ERROR"):
        print(name, scanner["status"], scanner.get("missing_reason"))
```

`scanner_results` has one entry per scanner, with its `status`, `finding_count`,
`actionable_finding_count`, `suppressed_finding_count`, and `severity_counts`. A MISSING
scanner also has a `missing_reason`. The statuses are:

| Status | Meaning |
|--------|---------|
| PASSED | It ran and found nothing at or above its threshold. |
| FAILED | It ran and found something at or above its threshold. This is a result, not an error. |
| MISSING | It had files to scan, but its tool is not installed, or was found only inside the scanned tree. It did not run. |
| ERROR | It started and failed. |
| SKIPPED | It did not run: it is disabled or excluded, or there was nothing for it to scan. |

A finding that a scanner reports with no severity of its own, only the SARIF level `error`, as
detect-secrets does, is CRITICAL in `ash.flat.json`, `ash.summary.md`, `summary_stats`, the
MCP counts, and the threshold check alike.

## Explain a finding

Take the finding's `id` from `ash.flat.json` and call `explain_finding` with it and
`results_path` set to the output directory. The answer has the scanner's description, the
severity and why it is or is not actionable, CWE and CVE identifiers when the scanner gives
them, and the matched code. Without MCP, use the record in `ash.flat.json` and read the code
at `file_path` and `line_start`.

An `id` is the scanner, the rule, and 12 hexadecimal digits of a hash of where the finding is:
its file and lines, or the fingerprints its scanner reports. For example,
`bandit-B602-e1cb79ce5694`. Findings at different places have different `id`s.

## Suggest a suppression

Call `suggest_suppression` with the finding's `id`, `results_path` set to the
`ash_aggregated_results.json` file (not the directory), and the user's reason as
`justification`. It writes nothing and returns one entry as `yaml` and `json`. Its
`expiration` defaults to 90 days from today. Leave out the `client_supplied` key it includes,
and put the entry under `global_settings.suppressions` in the project's config:

<!-- doctest: save-as=.ashrc.yaml -->
```yaml
global_settings:
  suppressions:
    - rule_id: "SECRET-SECRET-KEYWORD"
      path: "app.py"
      line_start: 3
      line_end: 3
      reason: "Test fixture value, not a real credential"
      expiration: "2027-06-30"
```

- `path` and `reason` are required. `path` is relative to the scanned directory and may use
  glob patterns such as `tests/**`. Do not start it with `./`, which matches nothing.
- `rule_id` matches without regard to case and may use glob patterns.
- `line_start` and `line_end` tie the suppression to those lines. Leave them out to match the
  rule anywhere in the path.
- Write `expiration` as a quoted `YYYY-MM-DD` date. From that date on, the suppression no
  longer applies and the finding counts again. An expired suppression is listed in
  `reports/ash.unused-suppressions.json`, with the ones that matched nothing.
- `ignore_paths` entries also need `path` and `reason`, and drop every finding in the matching
  files. Prefer a suppression for one rule.

Edit the config file the scan used, or create `.ashrc.yaml` in the scanned directory if it
has none. ASH uses the first of these it finds in the scanned
directory: `.ash.yml`, `.ash.yaml`, `.ash.json`, `ash.yml`, `ash.yaml`, `ash.json` (each in the
directory, then in `.ash/`), then `.ashrc.toml`, `.ashrc.yaml`, `.ashrc.yml`, `.ashrc.json`,
`ashrc.toml`, `ashrc.yaml`, `ashrc.yml`, and `ashrc.json` in the directory, then the
`[tool.ash]` table of `pyproject.toml`. If the config has an `extends` key, its own
`suppressions` list replaces the base config's list instead of adding to it; keep the base's
entries by adding yours with a `patch` operation `add` at `/global_settings/suppressions/-`.

Check the edited config before you scan. `ash config validate`, run in the scanned directory,
checks the config a scan there would use the way the scan loads it: it names each field the
scan would refuse, such as a suppression without a `reason` or with a misspelled key, and
exits with code 3 when there is one. `--config` names another file. Over MCP,
`validate_config` with `config_path` gives the same verdict: `errors` lists what the scan
would refuse, `warnings` what it accepts but is probably a mistake, and `valid` is true when
there are no errors.

```bash
# Check exact finding details
jq '.sarif.runs[].results[] | select((.suppressions // []) | length == 0) | {file: .locations[0].physicalLocation.artifactLocation.uri, rule: .ruleId, line: .locations[0].physicalLocation.region.startLine, end_line: .locations[0].physicalLocation.region.endLine}' .ash/ash_output/ash_aggregated_results.json

# Verify suppression syntax
ash config validate
```

After the next scan, the finding has `is_suppressed` true and the scan's suppressed count
includes it. Tell the user which suppressions you added and why, so they can review them.

## Compare two scans

Copy `ash_aggregated_results.json` before the next scan replaces it. Then call
`diff_scan_results` with `before_path` and `after_path` set to the two files. It returns
`new`, `resolved`, and `severity_changed`, each a list of finding records shaped like those in
`ash.flat.json`. It matches findings by `id`:

- A finding that was only suppressed between the two scans appears in none of the lists.
  Compare `is_suppressed` in the two `ash.flat.json` files to see it.
- An `id` comes from where the finding is. When a finding's lines move, because code above it
  was added or removed, it gets a new `id` and appears once in `resolved` and once in `new`,
  unless its scanner reports fingerprints. When two findings share a place, their column and
  message tell them apart, so a changed message can change those `id`s too. Compare
  `rule_id`, `file_path`, and the code before you report a finding as new or fixed.

## Errors

A failed MCP call returns `success` false, an `error` message, and an `error_type`; some also
return an `error_category`. The names below appear in one of those two fields.

| You see | Do this |
|---------|---------|
| Exit code 1, or status `incomplete`, with MISSING scanners | Tell the user. `ash dependencies install` installs the scanner tools for the user that runs ASH. A tool installed only inside the project does not count. |
| Exit code 3 | Run `ash config validate` in the scanned directory to see each invalid field, and fix it. |
| Exit code 5 | The command line is wrong. Check the option names and values with `ash --help`. |
| `scan_target_not_permitted`, or `invalid_path` from a results tool | The MCP server does not allow that directory. Ask the user to add it to the server's `ASH_MCP_ALLOWED_ROOTS`, or deliver the source. |
| `config_input_not_permitted` | The server does not allow reading that config file. Use the project's own config, or ask the user. |
| `config_field_denied` | A delivered config sets a field the server does not let clients set. Remove the field it names. |
| `output_dir_not_permitted` | `.ash` or `.ash/ash_output` in the project is a symbolic link. Ask the user to replace it with a directory. |
| `no_source_delivered` | Pass `source_dir`, or deliver the source first. |
| `source_delivery_busy` | A scan of this session is running, or its source is being replaced. Call the tool again once the scan has finished. |
| `session_workspace_busy` | The server is removing this session's workspace, which nobody used for longer than its time to live. Call `select_profile` again if the session had a profile, and send an upload again from chunk 0. |
| `clone_host_not_permitted` | The server does not clone from that host. Deliver the source as a zip, or ask the user to add the host to the server's `ASH_MCP_GIT_ALLOWED_HOSTS`. |
| `clone_url_not_permitted` or `clone_ref_not_permitted` | `set_source_git` takes only an `https` or `ssh` URL, and no URL or ref that begins with `-` or uses the `ext::` transport. Fix the URL or ref. |
| `local_clone_source_refused` | `set_source_git` never clones a local path or `file://` URL. Pass the directory as `run_ash_scan`'s `source_dir`. |
| `ssh_key_not_registered` | Call `set_source_git` without `ssh_key_id`; the server registers no SSH keys. |
| `invalid_clone_depth` | Pass a `depth` of 1 or more, or leave it out for the latest commit. |
| `git_clone_failed` or `git_checkout_failed` | git ran and failed, and `error` has its message. Check the URL and ref, or deliver the source as a zip. |
| `clone_timed_out` | A git command ran past 10 minutes and was stopped. Deliver the source as a zip. |
| `invalid_session_id` | The server refused the session ID the call carries. Tell the user. |
| `session_identity_required` | The server is stateless and cannot tell which session the call belongs to. Tell the user; the server needs a session to scan, deliver source, or track scans. |
| `scan_start_failure` | `run_ash_scan` did not start a scan, and `error` says why. If it names `max_concurrent_scans`, start the scan again when another scan has finished. If it says a scan of the directory is still stopping, try again in a few seconds. |
| `scan_incomplete` with `output_holds_previous_results` true | The last scan of that directory failed or was canceled, and its output directory holds the scan before it. Run the scan again. |
| `scan_not_found` | The server restarted or the ID is wrong. Read the results from the output directory. |

More detail for people is in the
[ASH documentation](https://github.com/awslabs/automated-security-helper/blob/main/docs/content/index.md).
