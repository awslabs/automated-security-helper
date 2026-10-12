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

**Template copy**: cfn-nag is given a copy of each template, staged in its results
directory as `template.json`, `template.yaml` or `template.yml` by the template's
extension, and as `template.yaml` for any other extension. The `cfn_nag_scan` command
line is therefore the same whatever the template is called, including on Windows,
where `cfn_nag_scan` is a batch file. Findings name the original template.

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

**Baseline**: ASH reads a detect-secrets baseline for the plugins, filters and accepted
findings to use. It takes `baseline_file` when set, else `.ash/.secrets.baseline`, else
`.secrets.baseline`, each relative to the source directory, so the same tree gives the
same result whichever directory ASH runs from. See
[Detect-Secrets](../../configuration-guide.md#detect-secrets) in the configuration guide.

**Secret verification**: detect-secrets can send a candidate secret to the service that
issued it. ASH does that only when the operator's own configuration turns it on, never
from a baseline or config file the scanned repository holds, and never offline. See
[Secret verification](../../configuration-guide.md#secret-verification).

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
      config_file: null              # Explicit grype config, relative to the config file that sets it
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

In offline mode npm-audit runs no audit, since npm, pnpm and yarn audit only against
the registry's advisory service. Each lockfile is listed as not scanned in the results
and the summaries, and with a lockfile to audit npm-audit is MISSING, so the scan fails
under the default completeness gate. `--exclude-scanners npm-audit` leaves it out of an
offline scan. See
[What offline mode turns off](../../advanced-usage.md#what-offline-mode-turns-off).

npm-audit runs npm, pnpm and yarn without the scanned repository's settings files:
its `.npmrc`, the settings in `pnpm-workspace.yaml`, `.yarnrc` and `.yarnrc.yml`,
including a `yarn-path` or `yarnPath`, which would run a file from the repository.
Your own settings still apply: `~/.npmrc`, the global npmrc, `~/.yarnrc` and
`~/.yarnrc.yml`, so a private registry and its credentials work as before. npm and
pnpm run from a private copy of each package's `package.json` and lockfile; yarn
runs from a copy, outside the scanned tree, of its lockfile and every
`package.json` below it, with `YARN_IGNORE_PATH=1`. Under `--sandbox` the tool's home
is private, so only environment variables reach it, and yarn runs in the package
directory reading no settings file (`--no-default-rc`, or `YARN_RC_FILENAME` for
yarn 2 and later).

A `pnpm.auditConfig` in the repository's `package.json` (`ignoreCves`,
`ignoreGhsas`) hides those advisories, as a suppression in the repository's ASH
configuration would; `--ignore-suppressions` removes it from the copy pnpm audits.

npm, pnpm and yarn follow links. So every file npm-audit hands one of them (the
package's `package.json`, the lockfiles it reads, `npm-shrinkwrap.json` included,
and for yarn every workspace `package.json` below the package) has to resolve inside
the scanned tree and be a regular file. A package with a file that is a link out of
the tree, or that sits in a linked directory pointing out of it, is not audited: the
file is listed as not scanned, with the reason "link leaves the scanned tree", and
the scan fails, as for any lockfile left unaudited. A link to a file elsewhere in the
scanned tree (another project of the workspace, in workspace mode) is followed.

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
      version: "v1.30.2"    # OpenGrep version to use
      sha256: {}            # Required for any other version: digest per platform
```

ASH pins OpenGrep v1.30.2 and verifies its SHA256 before installing it. To use
another version, supply the release asset's digest for each platform you install
on, for example `sha256: {"linux/amd64": "<64 hex characters>"}`. GitHub lists a
digest for every release asset, or run `sha256sum` on the downloaded asset. A
platform with no digest is refused rather than installed unverified.

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
      exclude: []                          # Paths to skip, as globs starting ./, */ or **/
      offline: false                       # Skip update checks
```

syft runs from outside the scanned tree and is not given a `.syft.yaml` or
`config_file` from it, online or offline, because such a file can turn on remote
license and package lookups. A `config_file` outside the tree is still used.

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
