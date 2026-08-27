# Built-in Security Scanners

ASH includes 10 built-in security scanners that analyze different aspects of your code and infrastructure. Each scanner specializes in specific security domains and file types.

> For detailed visual diagrams of the built-in scanner architecture and workflows, see [Built-in Scanner Diagrams](scanners-diagrams.md).

## Scanner Overview

| Scanner                               | Purpose                         | Languages/Formats               | Key Features                               |
|---------------------------------------|---------------------------------|---------------------------------|--------------------------------------------|
| **[Bandit](#bandit)**                 | Python security linter          | Python                          | AST-based analysis, security-focused rules |
| **[CDK-Nag](#cdk-nag)**               | AWS CDK security checker        | TypeScript, Python, Java        | CDK-specific security rules                |
| **[CFN-Nag](#cfn-nag)**               | CloudFormation security         | YAML, JSON                      | AWS resource security validation           |
| **[Checkov](#checkov)**               | Infrastructure-as-Code scanner  | Terraform, CF, K8s, Docker      | Policy-as-code framework                   |
| **[Detect-Secrets](#detect-secrets)** | Secret detection                | All text files                  | Entropy-based secret detection             |
| **[Grype](#grype)**                   | Container vulnerability scanner | Container images, SBOMs         | CVE database matching                      |
| **[NPM Audit](#npm-audit)**           | Node.js dependency scanner      | package.json, package-lock.json | NPM vulnerability database                 |
| **[Opengrep](#opengrep)**             | Code pattern matching           | Multiple languages              | Custom rule engine                         |
| **[Semgrep](#semgrep)**               | Static analysis scanner         | 30+ languages                   | Community and custom rules                 |
| **[Syft](#syft)**                     | SBOM generator                  | Container images, filesystems   | Software inventory generation              |

## Scanner Details

### Bandit

**Purpose**: Identifies common security issues in Python code through AST analysis.

**Configuration**:
```yaml
scanners:
  bandit:
    enabled: true
    options:
      severity_threshold: "MEDIUM"   # ALL, LOW, MEDIUM, HIGH, CRITICAL -- uppercase
      confidence_level: "high"       # all, low, medium, high -- lowercase
      ignore_nosec: false
      config_file: ".bandit"         # Selects individual tests; see below
```

Individual bandit test IDs are selected in a bandit configuration file, not through
ASH options. `severity_threshold` belongs under `options`, alongside the rest.

**Key Checks**:
- SQL injection vulnerabilities
- Hardcoded passwords and secrets
- Use of insecure functions
- Shell injection risks
- Cryptographic weaknesses

**Dependencies**: `bandit` Python package

---

### CDK-Nag

**Purpose**: Validates AWS CDK constructs against security best practices.

**Configuration**:
```yaml
scanners:
  cdk_nag:
    enabled: true
    options:
      rules_to_suppress: ["AwsSolutions-S1", "AwsSolutions-S2"]
      verbose: true
```

**Key Checks**:
- S3 bucket security configurations
- IAM policy validation
- VPC and networking security
- Encryption requirements
- Logging and monitoring setup

**Dependencies**: AWS CDK CLI, Node.js

---

### CFN-Nag

**Purpose**: Scans CloudFormation templates for security anti-patterns.

**Configuration**:
```yaml
scanners:
  cfn_nag:
    enabled: true
    options:
      rules_to_suppress: ["W1", "W2"]
      fail_on_warnings: false
```

**Key Checks**:
- IAM policies with excessive permissions
- Security groups with open access
- Unencrypted resources
- Missing logging configurations
- Insecure resource configurations

**Dependencies**: `cfn-nag` Ruby gem

---

### Checkov

**Purpose**: Comprehensive infrastructure-as-code security scanner with policy-as-code framework.

**Configuration**:
```yaml
scanners:
  checkov:
    enabled: true
    options:
      frameworks: ["terraform", "cloudformation", "kubernetes"]
      skip_frameworks: ["secrets"]
      skip_path:                         # Regular expressions, each with a reason
        - path: "tests/fixtures/.*"
          reason: "Vulnerable-by-design fixtures"
      config_file: ".checkov.yaml"       # Selects individual checks; see below
      additional_formats: ["cyclonedx_json"]
```

Individual check IDs and custom check directories are configured in a checkov
configuration file, which `config_file` points at.

**Key Checks**:
- Cloud resource misconfigurations
- Kubernetes security policies
- Docker security best practices
- Terraform module validation
- Custom policy enforcement

**Dependencies**: Managed via `uv tool run` (automatically downloaded when needed)

---

### Detect-Secrets

**Purpose**: Prevents secrets from being committed to version control through entropy-based detection.

**Configuration**:
```yaml
scanners:
  detect_secrets:
    enabled: true
    options:
      plugins: ["ArtifactoryDetector", "AWSKeyDetector", "Base64HighEntropyString"]
      exclude_files: ".*\\.lock$"
      exclude_lines: "password.*=.*\\{\\{.*\\}\\}"
```

**Key Checks**:
- High entropy strings (potential secrets)
- AWS access keys and secret keys
- Private keys and certificates
- Database connection strings
- API keys and tokens

**Dependencies**: `detect-secrets` Python package

---

### Grype

**Purpose**: Vulnerability scanner for container images and filesystems using CVE databases.

**Configuration**:
```yaml
scanners:
  grype:
    enabled: true
    options:
      severity_threshold: "MEDIUM"   # ALL, LOW, MEDIUM, HIGH, CRITICAL
      offline: false                 # Skip database updates
      config_file: null              # Explicit grype config, relative to the source directory
```

**Key Checks**:
- Known CVEs in installed packages
- Operating system vulnerabilities
- Language-specific package vulnerabilities
- Container base image issues

**Dependencies**: `grype` binary

---

### NPM Audit

**Purpose**: Identifies known vulnerabilities in Node.js dependencies.

**Configuration**:
```yaml
scanners:
  npm_audit:
    enabled: true
    options:
      audit_level: "moderate"  # info, low, moderate, high, critical
      production_only: false
```

**Key Checks**:
- Known vulnerabilities in npm packages
- Dependency tree analysis
- Severity-based filtering
- Fix recommendations

**Dependencies**: Node.js, npm

---

### Opengrep

**Purpose**: Open source fork of Semgrep. Static analysis with extensive rule library covering security, correctness, and performance.

**Configuration**:
```yaml
scanners:
  opengrep:
    enabled: true
    options:
      config: "p/ci"        # Ruleset, directory of YAML rules, or URL
      exclude_rule: []      # Rule IDs to skip
      severity: []          # Report only rules of these severities
      scan_timeout: 1800    # Seconds before the invocation is killed
      version: "v1.15.1"    # OpenGrep version to use
```

**Key Checks**:
- Custom security patterns
- Code quality issues
- Best practice violations
- Language-specific anti-patterns

**Dependencies**: `opengrep` binary

---

### Semgrep

**Purpose**: Static analysis with extensive rule library covering security, correctness, and performance.

**Configuration**:
```yaml
scanners:
  semgrep:
    enabled: true
    options:
      config: "p/ci"        # p/ci, p/security, p/owasp-top-10, a directory, or a URL
      scan_timeout: 1800    # Seconds before the invocation is killed
      exclude: ["test/", "*.min.js"]
      exclude_rule: []      # Rule IDs to skip
```

**Key Checks**:
- OWASP Top 10 vulnerabilities
- Language-specific security issues
- Code quality and maintainability
- Custom organizational rules

**Dependencies**: Managed via `uv tool run` (automatically downloaded when needed)

---

### Syft

**Purpose**: Generates Software Bill of Materials (SBOM) for dependency tracking and compliance.

**Configuration**:
```yaml
scanners:
  syft:
    enabled: true
    options:
      additional_outputs: ["syft-table"]   # Extra output formats beyond CycloneDX
      exclude: []                          # Paths to skip, matched as regular expressions
      offline: false                       # Skip update checks
```

**Key Features**:
- Package discovery across multiple ecosystems
- SBOM generation in standard formats
- Container and filesystem analysis
- License identification

**Dependencies**: `syft` binary

## Best Practices

### Scanner Selection

Choose scanners based on your technology stack:

```bash
# Python projects
ash --scanners bandit,detect-secrets,semgrep

# Infrastructure projects
ash --scanners checkov,cfn-nag,cdk-nag

# Container projects
ash --scanners grype,syft,checkov

# Node.js projects
ash --scanners npm-audit,detect-secrets,semgrep
```

### Performance Optimization

```yaml
# Optimize for speed
scanners:
  semgrep:
    options:
      scan_timeout: 60      # Give up quickly rather than waiting the 1800s default
      config: "p/ci"        # A narrower ruleset than a full audit pack

  grype:
    options:
      offline: true         # Skip the database update round trip
```

### CI/CD Integration

```yaml
# Different thresholds for different environments
scanners:
  bandit:
    severity_threshold: "LOW"    # Strict for production

  checkov:
    severity_threshold: "MEDIUM" # Balanced for staging
```

## Troubleshooting

### Common Issues

**Scanner not found**:
```bash
# Check dependencies
ash dependencies --check --scanner bandit

# Install missing tools
pip install bandit semgrep detect-secrets
```

**Performance issues**:
```bash
# Run with fewer concurrent scanners
ash --max-workers 2

# Exclude resource-intensive scanners
ash --exclude-scanners grype,syft
```

**False positives**:
```yaml
# Suppress specific findings
global_settings:
  suppressions:
    - rule_id: "B101"
      path: "tests/**"
      reason: "assert_used is expected in tests"
```

ASH suppresses findings through `global_settings.suppressions`, which applies to every
scanner uniformly. Skipping a bandit test ID instead requires a bandit configuration
file referenced by `options.config_file`; there is no `skips` option.

## Next Steps

- **[Reporter Configuration](reporters.md)**: Configure output formats
- **[Suppressions Guide](../../suppressions.md)**: Manage false positives
- **[Custom Rules](../development-guide.md)**: Create organization-specific rules
