# Built-in Reporters

ASH includes 13 built-in reporters that generate scan results in various formats to support different use cases, from human-readable reports to machine-processable data formats for CI/CD integration.

## Reporter Overview

| Reporter                                          | Format     | Use Case                    | Key Features                               |
|---------------------------------------------------|------------|-----------------------------|--------------------------------------------|
| **[CSV Reporter](#csv-reporter)**                 | CSV        | Data analysis, spreadsheets | Tabular data, easy filtering               |
| **[CycloneDX Reporter](#cyclonedx-reporter)**     | JSON/XML   | SBOM compliance             | Software Bill of Materials                 |
| **[Flat JSON Reporter](#flat-json-reporter)**     | JSON       | Simple data processing      | Flattened structure                        |
| **[GitLab SAST Reporter](#gitlab-sast-reporter)** | JSON       | GitLab Security Dashboard   | GitLab CI/CD integration                   |
| **[HTML Reporter](#html-reporter)**               | HTML       | Interactive reports         | Web-based, searchable                      |
| **[JUnit XML Reporter](#junit-xml-reporter)**     | XML        | CI/CD test results          | Test framework integration                 |
| **[Markdown Reporter](#markdown-reporter)**       | Markdown   | Documentation, README       | Human-readable, version control friendly   |
| **[OCSF Reporter](#ocsf-reporter)**               | JSON       | Security data lakes         | Open Cybersecurity Schema Framework        |
| **[SARIF Reporter](#sarif-reporter)**             | JSON       | IDE integration, CI/CD      | Static Analysis Results Interchange Format |
| **[SPDX Reporter](#spdx-reporter)**               | JSON       | License compliance          | Software Package Data Exchange             |
| **[Text Reporter](#text-reporter)**               | Plain text | Console output, logs        | Simple, lightweight                        |
| **[YAML Reporter](#yaml-reporter)**               | YAML       | Configuration-style output  | Human-readable structured data             |

## Reporter Details

### CSV Reporter

**Purpose**: Exports findings in comma-separated values format for spreadsheet analysis.

**Configuration**:
```yaml
reporters:
  csv:
    enabled: true
    options:
      include_suppressed: false
      delimiter: ","
      quote_char: "\""
```

**Output Structure**:
- Scanner name
- File path
- Line number
- Severity level
- Rule ID
- Description
- Suppression status

**Use Cases**:
- Data analysis in Excel/Google Sheets
- Custom reporting dashboards
- Bulk finding management

---

### CycloneDX Reporter

**Purpose**: Generates Software Bill of Materials (SBOM) in CycloneDX format.

**Configuration**:
```yaml
reporters:
  cyclonedx:
    enabled: true
    options:
      format: "json"  # json, xml
      include_licenses: true
      include_vulnerabilities: true
```

**Key Features**:
- Component inventory
- Dependency relationships
- Vulnerability mappings
- License information
- Supply chain transparency

**Use Cases**:
- Software supply chain security
- Compliance reporting
- Vulnerability management
- License tracking

---

### Flat JSON Reporter

**Purpose**: Simplified JSON format with flattened structure for easy processing.

**Configuration**:
```yaml
reporters:
  flatjson:
    enabled: true
    options:
      pretty_print: true
      include_metadata: true
```

**Output Structure**:
```json
{
  "findings": [
    {
      "scanner": "bandit",
      "file": "src/app.py",
      "line": 42,
      "severity": "HIGH",
      "rule_id": "B602",
      "message": "subprocess call with shell=True",
      "suppressed": false
    }
  ]
}
```

**Use Cases**:
- Simple data processing scripts
- Custom integrations
- Lightweight parsing

---

### GitLab SAST Reporter

**Purpose**: Generates reports compatible with GitLab Security Dashboard.

**Configuration**:
```yaml
reporters:
  gitlab_sast:
    enabled: true
    options:
      version: "15.0.4"
      include_dismissed: false
```

**Key Features**:
- GitLab Security Dashboard integration
- Vulnerability tracking
- Merge request security widgets
- Pipeline security reports

**Use Cases**:
- GitLab CI/CD pipelines
- Security dashboard visualization
- Merge request security gates

---

### GitLab SAST Reporter

**Purpose**: Generates reports in GitLab Security Dashboard format for seamless CI/CD integration.

**Configuration**:
```yaml
reporters:
  gitlab-sast:
    enabled: true
    options:
      include_suppressed: false
```

**Output Structure**:
- GitLab SAST report format
- Vulnerability details with locations
- Severity mapping to GitLab standards
- Scanner metadata and timestamps

**Use Cases**:
- GitLab CI/CD pipeline integration
- GitLab Security Dashboard visualization
- Compliance with GitLab security workflows

**Integration Example**:
```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - ash scan . --reporters gitlab-sast
  artifacts:
    reports:
      sast: output/gl-sast-report.json
```

---

### HTML Reporter

**Purpose**: Interactive web-based report with search and filtering capabilities.

**Configuration**:
```yaml
reporters:
  html:
    enabled: true
    options:
      include_suppressed: false
      theme: "light"  # light, dark
      show_metrics: true
      embed_assets: true
```

**Key Features**:
- Interactive filtering and search
- Severity-based color coding
- Expandable finding details
- Summary statistics
- Responsive design

**Use Cases**:
- Security team reviews
- Executive reporting
- Developer feedback
- Audit documentation

---

### JUnit XML Reporter

**Purpose**: Formats results as JUnit XML for CI/CD test result integration.

**Configuration**:
```yaml
reporters:
  junitxml:
    enabled: true
    options:
      suite_name: "ASH Security Scan"
      failure_on_finding: true
```

**Key Features**:
- Test framework compatibility
- CI/CD integration
- Pass/fail status per scanner
- Detailed failure messages

**Use Cases**:
- Jenkins test results
- GitLab CI test reporting
- GitHub Actions test summaries
- Build pipeline gates

---

### Markdown Reporter

**Purpose**: Human-readable report in Markdown format for documentation.

**Configuration**:
```yaml
reporters:
  markdown:
    enabled: true
    options:
      include_toc: true
      include_suppressed: false
      max_findings_per_scanner: 50
```

**Key Features**:
- GitHub/GitLab compatible
- Table of contents
- Code syntax highlighting
- Collapsible sections

**Use Cases**:
- README security sections
- Pull request comments
- Documentation sites
- Security runbooks

---

### OCSF Reporter

**Purpose**: Outputs findings in Open Cybersecurity Schema Framework format.

**Configuration**:
```yaml
reporters:
  ocsf:
    enabled: true
    options:
      version: "1.0.0"
      include_raw_data: false
```

**Key Features**:
- Standardized security data format
- Cloud-native security tools integration
- Rich metadata support
- Event correlation capabilities

**Use Cases**:
- Security data lakes
- SIEM integration
- Security analytics platforms
- Compliance reporting

---

### SARIF Reporter

**Purpose**: Static Analysis Results Interchange Format for tool interoperability.

**Configuration**:
```yaml
reporters:
  sarif:
    enabled: true
    options:
      include_rule_metadata: true
      schema_version: "2.1.0"
      pretty_print: false
```

**Key Features**:
- IDE integration (VS Code, IntelliJ)
- GitHub Security tab integration
- Rich metadata and locations
- Tool interoperability

**Use Cases**:
- IDE security annotations
- GitHub Advanced Security
- Security tool chains
- Compliance reporting

---

### SPDX Reporter

**Purpose**: Software Package Data Exchange format for license compliance.

**Configuration**:
```yaml
reporters:
  spdx:
    enabled: true
    options:
      format: "json"  # json, yaml, tag-value
      include_files: true
      document_name: "ASH-SPDX-Report"
```

**Key Features**:
- License identification
- Copyright information
- Package relationships
- File-level details

**Use Cases**:
- License compliance
- Open source governance
- Legal review processes
- Supply chain transparency

---

### Text Reporter

**Purpose**: Simple plain text output for console display and logging.

**Configuration**:
```yaml
reporters:
  text:
    enabled: true
    options:
      show_summary: true
      show_suppressed: false
      max_line_length: 120
      color_output: true
```

**Key Features**:
- Console-friendly output
- Color-coded severity levels
- Compact summary format
- Configurable verbosity

**Use Cases**:
- Command-line usage
- Log file output
- Simple CI/CD notifications
- Quick security overviews

---

### YAML Reporter

**Purpose**: Structured YAML output for configuration-style data representation.

**Configuration**:
```yaml
reporters:
  yaml:
    enabled: true
    options:
      pretty_print: true
      include_metadata: true
      flow_style: false
```

**Key Features**:
- Human-readable structure
- Configuration file compatibility
- Hierarchical data organization
- Comment support

**Use Cases**:
- Configuration-based workflows
- Infrastructure as Code integration
- Human-readable data exchange
- Custom processing pipelines

## Multi-Reporter Usage

### Common Combinations

```bash
# Development workflow
ash scan --reporters text,html,sarif

# CI/CD pipeline
ash scan --reporters sarif,junitxml,gitlab-sast

# Compliance reporting
ash scan --reporters spdx,cyclonedx,ocsf

# Executive reporting
ash scan --reporters html,markdown,csv
```

### Configuration Example

```yaml
reporters:
  # Quick feedback
  text:
    enabled: true
    options:
      show_summary: true
      color_output: true

  # Detailed analysis
  html:
    enabled: true
    options:
      theme: "light"
      include_suppressed: false

  # CI/CD integration
  sarif:
    enabled: true
    options:
      include_rule_metadata: true

  # Data processing
  csv:
    enabled: true
    options:
      include_suppressed: true
```

## Best Practices

### Reporter Selection

Choose reporters based on your audience and use case:

```yaml
# For developers
reporters: [text, sarif, html]

# For security teams
reporters: [html, csv, ocsf]

# For compliance
reporters: [spdx, cyclonedx, markdown]

# For CI/CD
reporters: [sarif, junitxml, gitlab-sast]
```

### Performance Considerations

```yaml
# Optimize for speed
reporters:
  html:
    options:
      embed_assets: false  # Faster generation

  csv:
    options:
      include_suppressed: false  # Smaller files
```

### Output Organization

```bash
# Organize outputs by type
ash scan --output-dir results/ \
  --reporters sarif,html,csv \
  --output-format "{reporter}/{timestamp}"
```

## Integration Examples

### GitHub Actions

```yaml
- name: Security Scan
  run: ash scan --reporters sarif,text

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results/sarif/results.sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - ash scan --reporters gitlab-sast,text
  artifacts:
    reports:
      sast: results/gitlab-sast/results.json
```

### Jenkins

```yaml
pipeline {
  stages {
    stage('Security Scan') {
      steps {
        sh 'ash scan --reporters junitxml,html'
        publishTestResults testResultsPattern: 'results/junitxml/*.xml'
        publishHTML([
          allowMissing: false,
          alwaysLinkToLastBuild: true,
          keepAll: true,
          reportDir: 'results/html',
          reportFiles: 'index.html',
          reportName: 'Security Report'
        ])
      }
    }
  }
}
```

## Troubleshooting

### Common Issues

**Large report files**:
```yaml
reporters:
  html:
    options:
      max_findings_per_scanner: 100
      include_suppressed: false
```

**Encoding issues**:
```yaml
reporters:
  csv:
    options:
      encoding: "utf-8"
```

**CI/CD integration failures**:
```bash
# Validate output format
ash scan --reporters sarif --validate-output
```

## Next Steps

- **[Scanner Configuration](scanners.md)**: Configure security scanners
- **[Suppressions](../../suppressions.md)**: Manage false positives
- **[CI/CD Integration](../../advanced-usage.md)**: Automate security scanning
