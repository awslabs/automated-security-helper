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
    severity_threshold: "MEDIUM"
    options:
      confidence_level: "HIGH"  # LOW, MEDIUM, HIGH
      skips: ["B101", "B601"]   # Skip specific test IDs
      tests: ["B201", "B301"]   # Run only specific tests
```

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
      framework: ["terraform", "cloudformation", "kubernetes"]
      check: ["CKV_AWS_*", "CKV_K8S_*"]
      skip_check: ["CKV_AWS_123"]
      external_checks_dir: "/path/to/custom/checks"
      compact: true
```

**Key Checks**:
- Cloud resource misconfigurations
- Kubernetes security policies
- Docker security best practices
- Terraform module validation
- Custom policy enforcement

**Dependencies**: `checkov` Python package

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
      scope: "all-layers"  # all-layers, squashed
      fail_on: "medium"    # negligible, low, medium, high, critical
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
      rules: "auto"  # auto, or path to rules
      timeout: 300
      max_memory: 5000
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
      rules: "auto"  # auto, p/security, p/owasp-top-10, or custom
      timeout: 300
      max_memory: 5000
      exclude: ["test/", "*.min.js"]
```

**Key Checks**:
- OWASP Top 10 vulnerabilities
- Language-specific security issues
- Code quality and maintainability
- Custom organizational rules

**Dependencies**: `semgrep` Python package

---

### Syft

**Purpose**: Generates Software Bill of Materials (SBOM) for dependency tracking and compliance.

**Configuration**:
```yaml
scanners:
  syft:
    enabled: true
    options:
      scope: "all-layers"  # all-layers, squashed
      format: "spdx-json"  # spdx-json, cyclonedx-json, syft-json
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
      timeout: 60
      max_memory: 2000

  grype:
    options:
      scope: "squashed"  # Faster than all-layers
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
scanners:
  bandit:
    options:
      skips: ["B101"]  # Skip assert_used test
```

## Next Steps

- **[Reporter Configuration](reporters.md)**: Configure output formats
- **[Suppressions Guide](../../suppressions.md)**: Manage false positives
- **[Custom Rules](../development-guide.md)**: Create organization-specific rules
