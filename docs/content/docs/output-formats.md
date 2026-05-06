# Output formats

ASH produces scan results in multiple formats. Every scan writes an internal aggregated-results JSON file (`ash_aggregated_results.json`), and reporters transform that data into the formats listed below. You can enable any combination of reporters in your configuration or on the command line.

## Quick reference

| Format | File extension | Primary use case | Standard |
|--------|---------------|-----------------|----------|
| [Flat JSON](#flat-json) | `.flat.json` | Programmatic consumption, dashboards | ASH-native |
| [SARIF](#sarif) | `.sarif` | IDE integration, GitHub/GitLab code scanning | [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) |
| [CycloneDX](#cyclonedx) | `.cdx.json` | Software bill of materials (SBOM) | [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) |
| [SPDX](#spdx) | `.spdx.json` | License compliance, SBOM | [SPDX 2.3](https://spdx.dev/specifications/) |
| [OCSF](#ocsf) | `.ocsf.json` | Security data lakes, SIEM ingestion | [OCSF 1.0](https://schema.ocsf.io/) |
| [GitLab SAST](#gitlab-sast) | `.gl-sast-report.json` | GitLab Security Dashboard | [GitLab SAST report](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportssast) |
| [JUnit XML](#junit-xml) | `.junit.xml` | CI/CD test result reporting | [JUnit XML](https://llg.cubic.org/docs/junit/) |
| [CSV](#csv) | `.csv` | Spreadsheet analysis, filtering | RFC 4180 |
| [HTML](#html) | `.html` | Interactive browser-based reports | -- |
| [Markdown](#markdown) | `.summary.md` | Pull request comments, documentation | CommonMark |
| [YAML](#yaml) | `.yaml` | Human-readable structured data | -- |
| [Text](#text) | `.summary.txt` | Console output, logs | -- |

## Generating reports

By default, ASH generates flat-json, SARIF, CycloneDX, OCSF, GitLab SAST, JUnit XML, CSV, HTML, Markdown, and Text reports. SPDX and YAML are available but disabled by default. To request a specific set of formats, use the `reporters` section in your configuration file:

```yaml
# .ash/ash.yaml
reporters:
  flat-json:
    enabled: true
  sarif:
    enabled: true
  html:
    enabled: false
```

Reports are written to `.ash/ash_output/reports/` by default.

---

## Flat JSON

The flat-json format is ASH's native machine-readable output. It flattens the internal SARIF-based data model into a simple array of finding objects, making it straightforward to consume from scripts, dashboards, and downstream tooling.

### Schema overview

The top-level structure contains four sections:

```json
{
  "metadata": { ... },
  "scanner_metrics": { ... },
  "top_hotspots": [ ... ],
  "findings": [ ... ]
}
```

**`metadata`** -- report-level information (project name, scan time, report time, tool version, time delta).

**`scanner_metrics`** -- a list of per-scanner objects with finding counts by severity and pass/fail status.

**`top_hotspots`** -- the files with the most findings, ranked by count.

**`findings`** -- an array of `FlatVulnerability` objects (described below).

### Finding fields

Each object in the `findings` array has these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the finding (e.g., `bandit-B105-4821`) |
| `title` | string | Rule ID or short name of the finding |
| `description` | string | Human-readable explanation of the issue |
| `severity` | string | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `scanner` | string | Name of the scanner that produced the finding (e.g., `bandit`, `checkov`) |
| `scanner_type` | string | Category of scanner: `SAST`, `SCA`, `IAC`, `SECRETS`, `SBOM`, or `UNKNOWN` |
| `rule_id` | string or null | The scanner-specific rule identifier |
| `file_path` | string or null | Path to the affected file, relative to the scan root |
| `line_start` | integer or null | Starting line number |
| `line_end` | integer or null | Ending line number |
| `cve_id` | string or null | CVE identifier, if applicable |
| `cwe_id` | string or null | CWE identifier, if applicable |
| `fix_available` | boolean or null | Whether a known fix exists |
| `is_suppressed` | boolean | `true` if the finding was suppressed via configuration or inline annotation |
| `suppression_kind` | string or null | `"inSource"` or `"external"`, depending on how it was suppressed |
| `suppression_justification` | string or null | Reason text provided with the suppression |
| `detected_at` | string or null | ISO 8601 timestamp of detection |
| `code_snippet` | string or null | Relevant source code fragment |
| `tags` | string or null | JSON-encoded array of tags |
| `properties` | string or null | JSON-encoded map of additional scanner-specific properties |
| `references` | string or null | JSON-encoded array of reference URIs |
| `raw_data` | string or null | Full SARIF result object as a JSON string, for lossless access |

### Example output

```json
{
  "metadata": {
    "project": "my-service",
    "scan_time": "2025-05-01 - 12:00 (UTC)",
    "report_time": "2025-05-01T12:00:05+00:00",
    "tool_version": "3.4.0",
    "time_delta": "0:00:05"
  },
  "scanner_metrics": [
    {
      "scanner_name": "bandit",
      "suppressed": 2,
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 17,
      "info": 0,
      "total": 18,
      "actionable": 3,
      "status": "FAILED"
    }
  ],
  "top_hotspots": [
    { "location": "src/auth/handler.py", "count": 7 }
  ],
  "findings": [
    {
      "id": "bandit-B105-4821",
      "title": "B105",
      "description": "Possible hardcoded password: 'secret_key'",
      "severity": "HIGH",
      "scanner": "bandit",
      "scanner_type": "SAST",
      "rule_id": "B105",
      "file_path": "src/auth/handler.py",
      "line_start": 42,
      "line_end": 42,
      "is_suppressed": false,
      "detected_at": "2025-05-01T12:00:01+00:00"
    }
  ]
}
```

### Consuming flat-json with jq

```bash
# Count findings by severity
jq '[.findings[] | .severity] | group_by(.) | map({(.[0]): length}) | add' ash.flat.json

# List all HIGH and CRITICAL findings with file paths
jq '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL") | {title, file_path, line_start}' ash.flat.json

# Show only unsuppressed findings
jq '[.findings[] | select(.is_suppressed == false)]' ash.flat.json

# Get the top 5 files by finding count
jq '[.findings[] | .file_path] | group_by(.) | map({file: .[0], count: length}) | sort_by(-.count) | .[0:5]' ash.flat.json
```

### Consuming flat-json with Python

```python
import json
from pathlib import Path

report = json.loads(Path(".ash/ash_output/reports/ash.flat.json").read_text())

# Metadata
metadata = report["metadata"]
print(f"Project: {metadata['project']}, Tool: {metadata['tool_version']}")

# Scanner results
for scanner in report["scanner_metrics"]:
    print(f"{scanner['scanner_name']}: {scanner['status']} ({scanner['actionable']} actionable)")

# Filter to actionable HIGH findings
high_findings = [
    f for f in report["findings"]
    if f["severity"] == "HIGH" and not f.get("is_suppressed", False)
]

for finding in high_findings:
    print(f"  {finding['file_path']}:{finding.get('line_start', '?')} - {finding['description']}")
```

---

## SARIF

[SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) is an OASIS standard for static analysis output. ASH produces SARIF 2.1.0 reports that work with GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer, and other tools in the SARIF ecosystem.

The SARIF report is ASH's internal canonical representation -- all other formats are derived from it.

**Configuration:**
```yaml
reporters:
  sarif:
    enabled: true
```

**Output file:** `reports/ash.sarif`

---

## CycloneDX

[CycloneDX](https://cyclonedx.org/) is an OWASP standard for Software Bill of Materials. ASH produces CycloneDX 1.6 JSON documents that inventory dependencies and their known vulnerabilities. Use this format for SBOM compliance workflows and supply-chain security tools.

**Configuration:**
```yaml
reporters:
  cyclonedx:
    enabled: true
```

**Output file:** `reports/ash.cdx.json`

---

## SPDX

[SPDX](https://spdx.dev/) (Software Package Data Exchange) is a Linux Foundation standard focused on license compliance and software composition.

> **Note:** The SPDX reporter is currently a stub and is disabled by default. It does not yet produce valid SPDX 2.3 JSON -- the output is a raw YAML model dump. A proper SPDX document generator is planned for a future release.

**Configuration:**
```yaml
reporters:
  spdx:
    enabled: true  # disabled by default
```

**Output file:** `reports/ash.spdx.json`

---

## OCSF

[OCSF](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework) is a vendor-agnostic schema for security telemetry. The OCSF reporter transforms ASH findings into OCSF Vulnerability Finding events, suitable for ingestion into security data lakes and SIEM platforms like Amazon Security Lake.

**Configuration:**
```yaml
reporters:
  ocsf:
    enabled: true
```

**Output file:** `reports/ash.ocsf.json`

---

## GitLab SAST

The GitLab SAST reporter produces output compatible with GitLab's [SAST report artifact](https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportssast), allowing findings to appear in the GitLab Security Dashboard and merge request widgets.

**Configuration:**
```yaml
reporters:
  gitlab-sast:
    enabled: true
```

**Output file:** `reports/ash.gl-sast-report.json`

**GitLab CI example:**

```yaml
ash-scan:
  stage: test
  script:
    - ash scan --source-dir . --output-dir ash_output
  artifacts:
    reports:
      sast: ash_output/reports/ash.gl-sast-report.json
```

---

## JUnit XML

The JUnit XML reporter maps each scanner to a test suite and each finding to a test case failure. CI/CD systems (Jenkins, GitHub Actions, GitLab CI, Azure DevOps) can parse this format natively to display scan results alongside unit test results.

**Configuration:**
```yaml
reporters:
  junitxml:
    enabled: true
```

**Output file:** `reports/ash.junit.xml`

---

## CSV

Comma-separated values output for importing findings into spreadsheets or data pipelines. Each row represents one finding with columns for scanner, file path, line number, severity, rule ID, description, and suppression status.

**Configuration:**
```yaml
reporters:
  csv:
    enabled: true
```

**Output file:** `reports/ash.csv`

---

## HTML

An interactive single-file HTML report that can be opened in any browser. Includes sortable tables, severity filters, and per-scanner breakdowns.

**Configuration:**
```yaml
reporters:
  html:
    enabled: true
```

**Output file:** `reports/ash.html`

---

## Markdown

A Markdown summary suitable for embedding in pull request descriptions, README files, or documentation sites.

**Configuration:**
```yaml
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true
```

**Output file:** `reports/ash.summary.md`

---

## YAML

Structured findings in YAML format for human review or consumption by tools that prefer YAML over JSON.

**Configuration:**
```yaml
reporters:
  yaml:
    enabled: true
```

**Output file:** `reports/ash.yaml`

---

## Text

A plain-text summary written to the console and to a file. This is the format you see printed at the end of every scan.

**Configuration:**
```yaml
reporters:
  text:
    enabled: true
```

**Output file:** `reports/ash.summary.txt`

---

## Relationship between formats

```
                    ┌─────────────────────┐
                    │  Scanner outputs     │
                    │  (bandit, checkov,   │
                    │   semgrep, ...)      │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  SARIF (canonical)   │
                    │  ash.sarif           │
                    └─────────┬───────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
        ┌───────────┐  ┌───────────┐  ┌───────────┐
        │ Flat JSON  │  │ CycloneDX │  │ HTML/MD/  │
        │ OCSF      │  │ SPDX      │  │ CSV/Text  │
        │ GitLab    │  │           │  │ YAML      │
        │ JUnit XML │  │           │  │           │
        └───────────┘  └───────────┘  └───────────┘
```

All reporters read from the same internal `AshAggregatedResults` model. SARIF is the primary interchange format; the flat-json reporter flattens the SARIF data into a simpler structure, while CycloneDX and SPDX focus on the software-composition subset. The human-readable formats (HTML, Markdown, Text) and tabular formats (CSV, JUnit XML) present the same underlying data in different layouts.
