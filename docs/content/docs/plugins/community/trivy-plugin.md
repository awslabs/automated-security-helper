# Trivy Plugin

> ASH also has a builtin trivy scanner, `trivy`, which runs `trivy fs` with only the
> `vuln` scanner by default and is on in every scan. See
> [Trivy filesystem scanner](../builtin/trivy.md). Listing this module for `trivy-repo`
> therefore runs trivy twice, and each finding is reported once per scanner; set
> `scanners.trivy.enabled: false` to keep only `trivy-repo`.

**Description**: The Trivy plugin integrates Aquasec's Trivy CLI tool to provide comprehensive repository scanning for vulnerabilities, misconfigurations, secrets, and license issues. This plugin extends ASH's security scanning capabilities with Trivy's advanced detection algorithms and extensive vulnerability database.

**Repository**: Ships with ASH; loaded only when listed in `ash_plugin_modules`

**Author**: ASH Development Team

**License**: Apache 2.0

## Overview

Trivy is a comprehensive security scanner that can detect:
- **Vulnerabilities** in OS packages and language-specific packages
- **Misconfigurations** in Infrastructure as Code (IaC) files
- **Secrets** and sensitive information in code
- **License** compliance issues

The ASH Trivy plugin provides seamless integration with Trivy's repository scanning capabilities, allowing you to incorporate Trivy scans into your ASH security workflows with unified reporting and configuration management.

## Prerequisites

### Trivy CLI Installation

`ash dependencies install` installs the pinned trivy release (v0.75.0, checked against the SHA256 in `automated_security_helper/utils/tool_downloads.py`) that both `trivy` and `trivy-repo` run, and the ASH container image ships it. A trivy you install yourself, as below, is used when it is on `PATH`; ASH is tested against the pinned version.

trivy-repo runs the first `trivy` it finds: on `PATH`, then in ASH's bin directory (`~/.ash/bin`, or the directory `ASH_BIN_PATH` names), then in `/usr/local/bin`, except on Windows. Only an executable file counts ([Where ASH looks for a tool](../../advanced-usage.md#where-ash-looks-for-a-tool)).

#### Installation Options

**Using Homebrew (macOS/Linux):**
<!-- doctest: illustrative reason="installs a tool over the network" -->
```bash
brew install trivy
```

**Using Package Managers:**
<!-- doctest: illustrative reason="installs a tool over the network" -->
```bash
# Ubuntu/Debian
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# RHEL/CentOS
sudo vim /etc/yum.repos.d/trivy.repo
# Add repository configuration
sudo yum -y update
sudo yum -y install trivy
```

**Using Binary Releases:**

*Linux/macOS:*
<!-- doctest: illustrative reason="installs a tool over the network" -->
```bash
# Download and install from GitHub releases
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

*Windows:*
<!-- doctest: illustrative reason="installs a tool over the network" -->
```bash
# Download and install using the official endpoint
curl -sfL -o trivy.zip "https://get.trivy.dev/trivy?type=zip&os=windows&arch=amd64"
unzip trivy.zip
# Move trivy.exe to a directory in your PATH
```

### Verification

Verify Trivy installation:
<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
trivy version
```

## Configuration

### Basic Configuration

Add the Trivy plugin to your ASH config file (`.ashrc.yaml` in a new project):

```text
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_trivy_plugins
```

Configure the scanner based on your requirements:

```yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "misconfig", "secret", "license"]
      severity_threshold: "MEDIUM"
      ignore_unfixed: false
      license_full: false
      disable_telemetry: true
```

### Configuration Options

<!-- doctest: options of=scanners.trivy-repo -->
| Option               | Type      | Default                                      | Description                                                             |
| -------------------- | --------- | -------------------------------------------- | ----------------------------------------------------------------------- |
| `scanners`           | List[str] | `["vuln", "secret", "misconfig", "license"]` | Types of scans to perform                                               |
| `severity_threshold` | str       | `null`                                       | Minimum severity that fails the scan (`ALL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`); `null` uses the global threshold. Findings below it are still reported; ASH does not pass it as `trivy --severity` |
| `ignore_unfixed`     | bool      | `true`                                       | Ignore vulnerabilities without available fixes                          |
| `license_full`       | bool      | `true`                                       | Enable full license scanning (more comprehensive but slower)            |
| `disable_telemetry`  | bool      | `true`                                       | Disable Trivy telemetry data collection. Only `--config-overrides` or a config file outside every git checkout and the scanned directory can set it to `false`; any config can set it to `true` |
| `config_file`        | str       | `null`                                       | A trivy config file, passed as `trivy --config`; see below              |
| `module_dir`         | str       | `null`                                       | A directory of trivy modules, passed as `trivy --module-dir`; see below |
| `ignore_file`        | str       | `null`                                       | A trivy ignore file, passed as `trivy --ignorefile`; see below          |
| `secret_config_file` | str       | `null`                                       | A trivy secret-scanning config, passed as `trivy --secret-config`; see below |
| `offline`            | bool      | `false`                                      | Run offline even when ASH does not; ASH's offline mode applies regardless |
| `scan_timeout`       | int       | `1800`                                       | Seconds ASH lets trivy run; ASH does not pass `trivy --timeout`, so trivy's own 5-minute default still applies |

trivy-repo always passes `trivy --config` and `trivy --module-dir`, so trivy does not load a `trivy.yaml` from the directory it runs in. `config_file` and `module_dir` are honored only when set through `--config-overrides` or a config file outside every git checkout and the scanned directory (one that is not [repository-written](../../../concepts/trust-model.md#how-the-tier-is-decided)), and only for paths outside the scanned tree, which a path written inside the tree and led out of it by a symbolic link there is not; otherwise they are ignored with a warning. A relative path is taken from the directory of the ASH config file that sets it, or from the working directory for `--config-overrides`, not from the source directory (see [Relative paths in the operator's settings](../../../how-to/configure.md#relative-paths)). A configured path that does not exist fails the scan. Unset or ignored, `--config` names `TRIVY_CONFIG` when that is a file outside the scanned tree (a relative path in it is taken from the working directory ASH runs in), and otherwise an empty config ASH ships; `trivy --module-dir` names an empty directory ASH creates outside the scanned tree for each scanner run and removes when the run ends.

`ignore_file` and `secret_config_file` follow the same rule, a relative path included. Unset or refused, trivy-repo uses `TRIVY_IGNOREFILE` or `TRIVY_SECRET_CONFIG` from the environment for a file outside the scanned tree (a relative path in either is taken from the working directory ASH runs in), and otherwise an empty file ASH writes outside the scanned tree, so a `.trivyignore` or `trivy-secret.yaml` in the scanned repository does not remove findings or disable secret rules.

### Scanner Types

The `scanners` option accepts the following values:

- **`vuln`**: Vulnerability scanning for OS and language packages
- **`misconfig`**: Infrastructure as Code misconfiguration detection
- **`secret`**: Secret and sensitive information detection
- **`license`**: License compliance scanning

### Severity Levels

Trivy supports the following severity levels (from lowest to highest):
- `UNKNOWN`: Unknown severity
- `LOW`: Low severity issues
- `MEDIUM`: Medium severity issues  
- `HIGH`: High severity issues
- `CRITICAL`: Critical severity issues

## Usage Examples

### Basic Repository Scan

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# Scan current directory with default Trivy settings
ash --scanners trivy-repo

# Scan specific directory
ash --source-dir /path/to/project --scanners trivy-repo
```

### Vulnerability-Only Scan

```yaml
# ASH config file (.ashrc.yaml in a new project)
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln"]
      severity_threshold: "HIGH"
      ignore_unfixed: true
```

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
ash --scanners trivy-repo
```

### Comprehensive Security Scan

```yaml
# ASH config file (.ashrc.yaml in a new project)
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "misconfig", "secret", "license"]
      severity_threshold: "LOW"
      license_full: true
```

### Integration with Other Scanners

```yaml
# ASH config file (.ashrc.yaml in a new project)
scanners:
  # Combine Trivy with other ASH scanners
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "misconfig"]
      severity_threshold: "MEDIUM"
  
  bandit:
    enabled: true
    options:
      severity_threshold: "MEDIUM"
  
  semgrep:
    enabled: true
    options:
      severity_threshold: "MEDIUM"
```

## Output and Reporting

The Trivy plugin integrates with ASH's unified reporting system, producing results in SARIF format that can be converted to various output formats.

trivy-repo accepts only exit code 0 as a completed run. trivy exits 0 whether or not
it found anything and 1 on an error, so a run that exits 1 is recorded `ERROR` and its
results file is not graded. ASH passes `trivy --exit-code=0`, which outranks an `exit-code`
setting in your trivy config or in `TRIVY_EXIT_CODE`, so a run with findings still
exits 0 and is reported; a `trivy.yaml` in the scanned directory is not read at all.
ASH decides the scan's exit code from the findings. See
[A scanner is ERROR with an exit code it does not accept](../../../how-to/troubleshoot.md#a-scanner-is-error-with-an-exit-code-it-does-not-accept).

### Available Output Formats

- **SARIF**: Machine-readable results for CI/CD integration
- **HTML**: Human-readable reports with detailed findings
- **Markdown**: Documentation-friendly format
- **CSV**: Spreadsheet-compatible format
- **JSON**: Structured data for custom processing

### Example Output Configuration

```yaml
# ASH config file (.ashrc.yaml in a new project)
reporters:
  sarif:
    enabled: true
    # Reporters write to the scan's output directory under a fixed name; there
    # is no per-reporter output_file option.

  html:
    enabled: true

  markdown:
    enabled: true
```

## Performance Considerations

### Resource Requirements

#### Memory Usage

| Repository Size    | Scan Types | Expected Memory | Peak Memory |
| ------------------ | ---------- | --------------- | ----------- |
| Small (<100MB)     | All        | 150-300MB       | 500MB       |
| Medium (100MB-1GB) | All        | 300-800MB       | 1.2GB       |
| Large (1-5GB)      | All        | 800MB-2GB       | 3GB         |
| Very Large (>5GB)  | Selective  | 1-3GB           | 5GB+        |

#### Disk Space Requirements

- **Vulnerability Database**: ~200MB (updated automatically)
- **Cache Directory**: 50-500MB depending on scan history
- **Temporary Files**: 10-100MB during scan execution
- **Results Storage**: 1-50MB per scan depending on findings

#### Network Requirements

- **Initial Setup**: 200MB download for vulnerability database
- **Regular Updates**: 10-50MB daily for database updates
- **Bandwidth**: Minimal during scanning (only for updates)
- **Offline Support**: Full offline scanning supported after initial setup

#### CPU Performance

| Repository Type               | Scan Duration | CPU Usage |
| ----------------------------- | ------------- | --------- |
| Python project (1000 files)   | 30-60 seconds | 1-2 cores |
| Node.js project (5000 files)  | 1-3 minutes   | 2-4 cores |
| Multi-language (10000+ files) | 3-10 minutes  | 4+ cores  |
| Monorepo (50000+ files)       | 10-30 minutes | 8+ cores  |

### Performance Optimization Strategies

#### 1. Scan Type Optimization

```yaml
# Fast vulnerability-only scan
scanners:
  trivy-repo:
    options:
      scanners: ["vuln"]
      severity_threshold: "HIGH"
      ignore_unfixed: true

# Comprehensive but slower scan
scanners:
  trivy-repo:
    options:
      scanners: ["vuln", "misconfig", "secret", "license"]
      severity_threshold: "LOW"
      license_full: true
```

#### 2. Directory-Based Optimization

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# Scan critical paths first
ash --source-dir src/ --scanners trivy-repo  # Core application code
ash --source-dir config/ --scanners trivy-repo  # Configuration files

# Skip non-critical directories
```

```yaml
global_settings:
  ignore_paths:
    - path: "node_modules/**"
      reason: "Package manager cache"
    - path: "vendor/**"
      reason: "Third-party dependencies"
    - path: "**/*.min.*"
      reason: "Minified assets"
    - path: "build/**"
      reason: "Build artifacts"
    - path: "dist/**"
      reason: "Distribution files"
```

#### 3. Caching Optimization

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Optimize cache location for performance
export TRIVY_CACHE_DIR=/fast-ssd/trivy-cache

# Pre-warm cache for CI/CD
trivy image --download-db-only --cache-dir /shared/trivy-cache

# Use shared cache in team environments
export TRIVY_CACHE_DIR=/shared/trivy-cache
chmod -R 755 /shared/trivy-cache
```

#### 4. Parallel Processing

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# parallel-scan.sh

# Define scan targets
TARGETS=("src/" "lib/" "config/" "scripts/")

# Run parallel scans
for target in "${TARGETS[@]}"; do
  ash --source-dir "$target" --scanners trivy-repo --config ".ash/${target%/}.yaml" &
done

# Wait for all scans to complete
wait

# Merge results
python scripts/merge_scan_results.py
```

#### 5. Incremental Scanning

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# incremental-scan.sh

# Only scan changed files since last scan
if [ -f .last_trivy_scan ]; then
  CHANGED_FILES=$(find . -newer .last_trivy_scan -name "*.py" -o -name "*.js" -o -name "*.yaml")
  
  if [ -n "$CHANGED_FILES" ]; then
    echo "Scanning changed files: $CHANGED_FILES"
    echo "$CHANGED_FILES" | xargs -I {} dirname {} | sort -u | while read dir; do
      ash --source-dir "$dir" --scanners trivy-repo
    done
  else
    echo "No changes detected, skipping scan"
  fi
else
  echo "First scan, scanning entire repository"
  ash --scanners trivy-repo
fi

touch .last_trivy_scan
```

### Benchmarking and Monitoring

#### Performance Measurement

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# benchmark-trivy.sh

echo "Starting Trivy performance benchmark..."

# Measure scan time
start_time=$(date +%s)
ash --scanners trivy-repo --formats flat-json
end_time=$(date +%s)

scan_duration=$((end_time - start_time))
echo "Scan completed in ${scan_duration} seconds"

# Measure resource usage
echo "Memory usage during scan:"
ps aux | grep trivy | awk '{print $6}' | sort -n | tail -1

# Measure result size
result_size=$(du -h .ash/ash_output/reports/ash_aggregated_results.json | cut -f1)
echo "Results file size: $result_size"

# Count findings
finding_count=$(jq '[.runs[].results[]] | length' .ash/ash_output/reports/ash_aggregated_results.json)
echo "Total findings: $finding_count"
```

#### Continuous Performance Monitoring

<!-- doctest: illustrative reason="a fragment of plugin code that names objects defined elsewhere" -->
```python
# performance_monitor.py
# Needs psutil, which is not part of ASH: pip install psutil
import importlib
import json
import time
import subprocess
from datetime import datetime
from pathlib import Path

psutil = importlib.import_module("psutil")


class TrivyPerformanceMonitor:
    def __init__(self):
        self.metrics = []

    def run_monitored_scan(self):
        start_time = time.time()
        start_memory = psutil.virtual_memory().used

        # Run ASH with Trivy
        process = subprocess.Popen(
            ["ash", "--scanners", "trivy-repo", "--formats", "flat-json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Monitor resource usage
        max_memory = start_memory
        while process.poll() is None:
            current_memory = psutil.virtual_memory().used
            max_memory = max(max_memory, current_memory)
            time.sleep(1)

        end_time = time.time()

        # Collect metrics
        duration = end_time - start_time
        memory_used = max_memory - start_memory

        # Count results
        results_file = Path(".ash/ash_output/reports/ash_aggregated_results.json")
        finding_count = 0
        if results_file.exists():
            with open(results_file) as f:
                data = json.load(f)
                finding_count = sum(
                    len(run.get("results", [])) for run in data.get("runs", [])
                )

        # Store metrics
        metric = {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "memory_mb": memory_used / (1024 * 1024),
            "finding_count": finding_count,
            "exit_code": process.returncode,
        }

        self.metrics.append(metric)
        return metric

    def save_metrics(self, filename="trivy_performance.json"):
        with open(filename, "w") as f:
            json.dump(self.metrics, f, indent=2)


if __name__ == "__main__":
    monitor = TrivyPerformanceMonitor()
    metric = monitor.run_monitored_scan()
    monitor.save_metrics()

    print(f"Scan completed in {metric['duration_seconds']:.1f}s")
    print(f"Memory used: {metric['memory_mb']:.1f}MB")
    print(f"Findings: {metric['finding_count']}")
```

### Scaling Strategies

#### Horizontal Scaling

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# distributed-scan.sh

# Split repository by language/framework
find . -name "*.py" | head -1000 | xargs dirname | sort -u > python_dirs.txt
find . -name "*.js" | head -1000 | xargs dirname | sort -u > javascript_dirs.txt
find . -name "*.yaml" -o -name "*.yml" | head -1000 | xargs dirname | sort -u > yaml_dirs.txt

# Distribute across multiple workers
cat python_dirs.txt | xargs -P 4 -I {} ash --source-dir {} --scanners trivy-repo &
cat javascript_dirs.txt | xargs -P 4 -I {} ash --source-dir {} --scanners trivy-repo &
cat yaml_dirs.txt | xargs -P 4 -I {} ash --source-dir {} --scanners trivy-repo &

wait
```

#### Container-Based Scaling

<!-- doctest: config kind=docker-compose -->
```yaml
# docker-compose.yml for distributed scanning
version: '3.8'
services:
  trivy-scanner-1:
    image: ash:latest
    volumes:
      - ./src:/workspace/src
      - ./trivy-cache:/root/.cache/trivy
    command: ash --source-dir /workspace/src --scanners trivy-repo
  
  trivy-scanner-2:
    image: ash:latest
    volumes:
      - ./lib:/workspace/lib
      - ./trivy-cache:/root/.cache/trivy
    command: ash --source-dir /workspace/lib --scanners trivy-repo
  
  trivy-scanner-3:
    image: ash:latest
    volumes:
      - ./config:/workspace/config
      - ./trivy-cache:/root/.cache/trivy
    command: ash --source-dir /workspace/config --scanners trivy-repo
```

### Resource Limits and Constraints

#### Memory Limits

<!-- doctest: illustrative reason="needs a container runtime" -->
```bash
# Set memory limits for container mode
docker run --memory=2g ash --scanners trivy-repo

# Monitor memory usage
ulimit -v 2097152  # 2GB virtual memory limit
ash --scanners trivy-repo
```

#### Time Limits

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# Set timeout for scans
timeout 600 ash --scanners trivy-repo  # 10-minute timeout

# Use with retry logic
for i in {1..3}; do
  if timeout 600 ash --scanners trivy-repo; then
    break
  else
    echo "Scan attempt $i failed, retrying..."
    sleep 30
  fi
done
```

#### Disk Space Management

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Clean up old results
find .ash/ash_output -name "*.sarif" -mtime +7 -delete

# Rotate Trivy cache
if [ $(du -s ~/.cache/trivy | cut -f1) -gt 1048576 ]; then  # 1GB
  rm -rf ~/.cache/trivy/db
  trivy image --download-db-only
fi

# Compress old results
find .ash/ash_output -name "*.json" -mtime +1 -exec gzip {} \;
```

## Scanning Scenarios and Use Cases

### 1. Development Workflow Integration

#### Pre-commit Scanning
<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# .git/hooks/pre-commit

# Quick scan of staged files only
STAGED_FILES=$(git diff --cached --name-only)

if [ -n "$STAGED_FILES" ]; then
  echo "Running security scan on staged files..."
  
  # Create temporary directory with staged files
  TEMP_DIR=$(mktemp -d)
  echo "$STAGED_FILES" | while read file; do
    if [ -f "$file" ]; then
      mkdir -p "$TEMP_DIR/$(dirname "$file")"
      cp "$file" "$TEMP_DIR/$file"
    fi
  done
  
  # Scan staged files
  ash --source-dir "$TEMP_DIR" --scanners trivy-repo --config .ash/precommit.yaml
  SCAN_RESULT=$?
  
  # Cleanup
  rm -rf "$TEMP_DIR"
  
  if [ $SCAN_RESULT -ne 0 ]; then
    echo "Security scan failed. Commit aborted."
    exit 1
  fi
fi
```

#### Pull Request Scanning
<!-- doctest: config kind=github-actions runner=none reason="a workflow for the reader's own repository, which installs ASH from GitHub" -->
```yaml
# .github/workflows/pr-security-scan.yml
name: PR Security Scan
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Get changed files
        id: changed-files
        run: |
          git diff --name-only origin/${{ github.base_ref }}..HEAD > changed_files.txt
          echo "files=$(cat changed_files.txt | tr '\n' ' ')" >> $GITHUB_OUTPUT
      
      - name: Scan changed files
        run: |
          # Create directory structure for changed files
          mkdir -p scan_target
          while read file; do
            if [ -f "$file" ]; then
              mkdir -p "scan_target/$(dirname "$file")"
              cp "$file" "scan_target/$file"
            fi
          done < changed_files.txt
          
          # Run security scan
          ash --source-dir scan_target --scanners trivy-repo --formats sarif,markdown
      
      - name: Comment PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            if (fs.existsSync('.ash/ash_output/reports/security-report.md')) {
              const report = fs.readFileSync('.ash/ash_output/reports/security-report.md', 'utf8');
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: '## Security Scan Results\n\n' + report
              });
            }
```

### 2. Multi-Language Project Scanning

#### Monorepo Configuration
```yaml
# .ash/monorepo.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "secret", "misconfig"]
      severity_threshold: "MEDIUM"

global_settings:
  ignore_paths:
    # Language-specific ignores
    - path: "**/node_modules/**"
      reason: "Node.js dependencies"
    - path: "**/vendor/**"
      reason: "PHP/Go dependencies"
    - path: "**/__pycache__/**"
      reason: "Python cache"
    - path: "**/target/**"
      reason: "Rust/Java build output"
    - path: "**/build/**"
      reason: "Build artifacts"
```

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# scan-monorepo.sh

# Define language-specific directories
PYTHON_DIRS=$(find . -name "*.py" -not -path "*/.*" | head -100 | xargs dirname | sort -u)
NODE_DIRS=$(find . -name "package.json" -not -path "*/node_modules/*" | xargs dirname)
GO_DIRS=$(find . -name "go.mod" | xargs dirname)
RUST_DIRS=$(find . -name "Cargo.toml" | xargs dirname)

# Scan each language ecosystem
echo "Scanning Python projects..."
echo "$PYTHON_DIRS" | while read dir; do
  [ -n "$dir" ] && ash --source-dir "$dir" --scanners trivy-repo --config .ash/python.yaml
done

echo "Scanning Node.js projects..."
echo "$NODE_DIRS" | while read dir; do
  [ -n "$dir" ] && ash --source-dir "$dir" --scanners trivy-repo --config .ash/nodejs.yaml
done

echo "Scanning Go projects..."
echo "$GO_DIRS" | while read dir; do
  [ -n "$dir" ] && ash --source-dir "$dir" --scanners trivy-repo --config .ash/golang.yaml
done

echo "Scanning Rust projects..."
echo "$RUST_DIRS" | while read dir; do
  [ -n "$dir" ] && ash --source-dir "$dir" --scanners trivy-repo --config .ash/rust.yaml
done
```

### 3. Infrastructure as Code Scanning

#### Terraform Projects
```yaml
# .ash/terraform.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["misconfig", "secret"]
      severity_threshold: "HIGH"

global_settings:
  ignore_paths:
    - path: "**/.terraform/**"
      reason: "Terraform cache"
    - path: "**/*.tfstate*"
      reason: "Terraform state files"
```

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Scan Terraform modules
find . -name "*.tf" | xargs dirname | sort -u | while read tf_dir; do
  echo "Scanning Terraform directory: $tf_dir"
  ash --source-dir "$tf_dir" --scanners trivy-repo --config .ash/terraform.yaml
done
```

#### Kubernetes Manifests
```yaml
# .ash/kubernetes.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["misconfig", "secret"]
      severity_threshold: "MEDIUM"
```

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Scan Kubernetes manifests
find . -name "*.yaml" -o -name "*.yml" | grep -E "(k8s|kubernetes|manifests)" | xargs dirname | sort -u | while read k8s_dir; do
  echo "Scanning Kubernetes directory: $k8s_dir"
  ash --source-dir "$k8s_dir" --scanners trivy-repo --config .ash/kubernetes.yaml
done
```

### 4. Container and Docker Scanning

#### Dockerfile Analysis
<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# scan-dockerfiles.sh

# Find all Dockerfiles
find . -name "Dockerfile*" -o -name "*.dockerfile" | while read dockerfile; do
  dir=$(dirname "$dockerfile")
  echo "Scanning Docker context: $dir"
  
  # Scan the directory containing Dockerfile
  ash --source-dir "$dir" --scanners trivy-repo --config .ash/docker.yaml
  
  # Also scan the built image if available
  image_name=$(grep -E "^FROM" "$dockerfile" | tail -1 | awk '{print $2}')
  if [ -n "$image_name" ] && [ "$image_name" != "scratch" ]; then
    echo "Scanning base image: $image_name"
    trivy image --format sarif --output "${dir}/base-image.sarif" "$image_name" || true
  fi
done
```

#### Docker Compose Projects
<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# scan-compose-projects.sh

find . -name "docker-compose*.yml" -o -name "docker-compose*.yaml" | while read compose_file; do
  dir=$(dirname "$compose_file")
  echo "Scanning Docker Compose project: $dir"
  
  # Scan the compose directory
  ash --source-dir "$dir" --scanners trivy-repo --config .ash/docker-compose.yaml
  
  # Extract and scan referenced images
  grep -E "^\s*image:" "$compose_file" | awk '{print $2}' | tr -d '"' | while read image; do
    if [ "$image" != "scratch" ] && [[ "$image" != *"${"* ]]; then
      echo "Scanning compose image: $image"
      trivy image --format sarif --output "${dir}/compose-${image//\//_}.sarif" "$image" || true
    fi
  done
done
```

### 5. License Compliance Scanning

#### Open Source License Audit
```yaml
# .ash/license-audit.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["license"]
      license_full: true
      severity_threshold: "LOW"

reporters:
  csv:
    enabled: true
    # Reporters write to the scan's output directory under a fixed name; there
    # is no per-reporter output_file option.
  html:
    enabled: true
```

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# license-compliance-check.sh

echo "Running comprehensive license scan..."
ash --scanners trivy-repo --config .ash/license-audit.yaml

# Process license results
python3 << 'EOF'
import json
import csv
from collections import defaultdict

# Load scan results
with open('.ash/ash_output/reports/ash_aggregated_results.json') as f:
    data = json.load(f)

# Extract license information
licenses = defaultdict(list)
for run in data.get('runs', []):
    for result in run.get('results', []):
        if 'license' in result.get('ruleId', '').lower():
            license_name = result.get('message', {}).get('text', 'Unknown')
            file_path = result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'Unknown')
            licenses[license_name].append(file_path)

# Generate license summary
print("License Summary:")
print("================")
for license_name, files in licenses.items():
    print(f"{license_name}: {len(files)} files")
    for file_path in files[:5]:  # Show first 5 files
        print(f"  - {file_path}")
    if len(files) > 5:
        print(f"  ... and {len(files) - 5} more files")
    print()

# Check for problematic licenses
problematic_licenses = ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0']
issues = []
for license_name in licenses:
    if any(prob in license_name for prob in problematic_licenses):
        issues.append(license_name)

if issues:
    print("⚠️  Potentially problematic licenses found:")
    for issue in issues:
        print(f"  - {issue}")
else:
    print("✅ No known problematic licenses detected")
EOF
```

### 6. Security Baseline and Regression Testing

#### Establish Security Baseline
<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# establish-security-baseline.sh

echo "Establishing security baseline..."

# Run comprehensive scan
ash --scanners trivy-repo --formats flat-json --config .ash/baseline.yaml

# Store baseline
mkdir -p .security-baseline
cp .ash/ash_output/reports/ash_aggregated_results.json .security-baseline/baseline-$(date +%Y%m%d).json

# Generate baseline suppressions
python3 << 'EOF'
import json
from datetime import datetime, timedelta

with open('.ash/ash_output/reports/ash_aggregated_results.json') as f:
    data = json.load(f)

suppressions = []
expiration = (datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d')

for run in data.get('runs', []):
    for result in run.get('results', []):
        rule_id = result.get('ruleId')
        file_path = result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
        
        if rule_id and file_path:
            suppression = {
                'rule_id': rule_id,
                'path': file_path,
                'reason': 'Baseline finding - review and update',
                'expiration': expiration
            }
            suppressions.append(suppression)

# Write suppressions to YAML
import yaml
with open('.security-baseline/baseline-suppressions.yaml', 'w') as f:
    yaml.dump({'global_settings': {'suppressions': suppressions}}, f, default_flow_style=False)

print(f"Generated {len(suppressions)} baseline suppressions")
print("Review .security-baseline/baseline-suppressions.yaml and merge approved suppressions into your ASH config file (.ashrc.yaml in a new project)")
EOF
```

#### Regression Detection
<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# detect-security-regressions.sh

echo "Checking for security regressions..."

# Run current scan
ash --scanners trivy-repo --formats flat-json

# Compare with baseline
python3 << 'EOF'
import json
from pathlib import Path

# Load current results
with open('.ash/ash_output/reports/ash_aggregated_results.json') as f:
    current_data = json.load(f)

# Load baseline (most recent)
baseline_files = sorted(Path('.security-baseline').glob('baseline-*.json'))
if not baseline_files:
    print("No baseline found. Run establish-security-baseline.sh first.")
    exit(1)

with open(baseline_files[-1]) as f:
    baseline_data = json.load(f)

# Extract findings
def extract_findings(data):
    findings = set()
    for run in data.get('runs', []):
        for result in run.get('results', []):
            rule_id = result.get('ruleId')
            file_path = result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
            if rule_id and file_path:
                findings.add(f"{rule_id}:{file_path}")
    return findings

current_findings = extract_findings(current_data)
baseline_findings = extract_findings(baseline_data)

# Detect regressions (new findings)
regressions = current_findings - baseline_findings
improvements = baseline_findings - current_findings

print(f"Security Status:")
print(f"  Current findings: {len(current_findings)}")
print(f"  Baseline findings: {len(baseline_findings)}")
print(f"  New issues (regressions): {len(regressions)}")
print(f"  Fixed issues: {len(improvements)}")

if regressions:
    print("\n🚨 Security Regressions Detected:")
    for regression in sorted(regressions):
        rule_id, file_path = regression.split(':', 1)
        print(f"  - {rule_id} in {file_path}")
    exit(1)
else:
    print("\n✅ No security regressions detected")

if improvements:
    print("\n🎉 Security Improvements:")
    for improvement in sorted(improvements):
        rule_id, file_path = improvement.split(':', 1)
        print(f"  - Fixed {rule_id} in {file_path}")
EOF
```

## Troubleshooting

### Common Issues

#### Trivy CLI Not Found

**Error**: `Trivy CLI not found in PATH`

**Symptoms**:
- ASH reports "Dependencies not satisfied" for trivy-repo scanner
- Scanner is skipped during execution
- No Trivy results in output

**Solutions**:
1. **Verify Installation**: Check if Trivy is installed
   <!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
   ```bash
   trivy version
   which trivy
   ```

2. **PATH Configuration**: Ensure Trivy is in your PATH
   <!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
   ```bash
   echo $PATH
   export PATH=$PATH:/path/to/trivy/bin
   ```

3. **Reinstall Trivy**: Use your preferred installation method
   <!-- doctest: illustrative reason="installs a tool over the network" -->
   ```bash
   # Homebrew
   brew install trivy
   
   # Direct download
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   ```

4. **Container Mode Alternative**: Use ASH container mode
   <!-- doctest: illustrative reason="needs a container runtime" -->
   ```bash
   ash --mode container --scanners trivy-repo
   ```

#### Database Update Failures

**Error**: `Failed to update vulnerability database`

**Symptoms**:
- Trivy hangs during database download
- Network timeout errors
- Outdated vulnerability data

**Solutions**:
1. **Check Connectivity**: Verify internet access
   <!-- doctest: illustrative reason="needs the network" -->
   ```bash
   curl -I https://github.com/aquasecurity/trivy-db/releases
   ```

2. **Clear Cache**: Remove corrupted database cache
   <!-- doctest: illustrative reason="needs the network" -->
   ```bash
   rm -rf ~/.cache/trivy/
   trivy image --download-db-only
   ```

3. **Proxy Configuration**: Configure proxy settings
   <!-- doctest: illustrative reason="needs the network" -->
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=http://proxy.company.com:8080
   trivy image --download-db-only
   ```

4. **Offline Mode**: Use pre-downloaded database
   <!-- doctest: illustrative reason="needs the network" -->
   ```bash
   # Download database separately
   trivy image --download-db-only --cache-dir /shared/trivy-cache
   
   # Use cached database, with ASH offline: online, ASH updates the database
   # before the scan and fails without network
   export TRIVY_CACHE_DIR=/shared/trivy-cache
   export ASH_OFFLINE=YES
   ash --scanners trivy-repo
   ```

#### Permission Issues

**Error**: `Permission denied accessing scan target`

**Symptoms**:
- Scanner fails to read files
- Empty scan results
- Access denied errors in logs

**Solutions**:
1. **Check Permissions**: Verify directory access
   <!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
   ```bash
   ls -la /path/to/target
   find /path/to/target -type f ! -readable
   ```

2. **Fix Ownership**: Correct file ownership
   <!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
   ```bash
   sudo chown -R $USER:$USER /path/to/target
   chmod -R u+r /path/to/target
   ```

3. **Run with Sudo**: Use elevated permissions (not recommended)
   <!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
   ```bash
   sudo ash --scanners trivy-repo --source-dir /path/to/target
   ```

4. **Container Mode**: Use container with proper volume mounts
   <!-- doctest: illustrative reason="needs a container runtime" -->
   ```bash
   ash --mode container --source-dir /path/to/target --scanners trivy-repo
   ```

#### Large Repository Performance

**Issue**: Slow scanning on large repositories (>1GB or >10k files)

**Symptoms**:
- Scan takes >10 minutes
- High memory usage
- Timeout errors

**Performance Solutions**:

1. **Selective Scanning**: Target specific scan types
   ```yaml
   scanners:
     trivy-repo:
       options:
         scanners: ["vuln"]  # Only vulnerabilities
         severity_threshold: "HIGH"  # Reduce noise
   ```

2. **Directory Filtering**: Scan specific subdirectories
   <!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
   ```bash
   # Scan only source code directories
   ash --source-dir src/ --scanners trivy-repo
   ash --source-dir lib/ --scanners trivy-repo
   ```

3. **Ignore Patterns**: Use ASH ignore patterns
   ```yaml
   global_settings:
     ignore_paths:
       - path: "node_modules/**"
         reason: "Third-party dependencies"
       - path: "vendor/**"
         reason: "Vendor libraries"
       - path: "**/*.min.js"
         reason: "Minified files"
   ```

4. **Parallel Processing**: Split large repositories
   <!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
   ```bash
   # Process in parallel
   ash --source-dir frontend/ --scanners trivy-repo &
   ash --source-dir backend/ --scanners trivy-repo &
   wait
   ```

#### Memory Issues

**Error**: `Out of memory` or system becomes unresponsive

**Solutions**:
1. **Increase Memory Limits**: For container mode
   <!-- doctest: illustrative reason="needs a container runtime" -->
   ```bash
   docker run --memory=2g --scanners trivy-repo
   ```

2. **Process Smaller Chunks**: Break down large scans
   <!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
   ```bash
   find . -maxdepth 1 -type d | xargs -I {} ash --source-dir {} --scanners trivy-repo
   ```

3. **Optimize Configuration**: Reduce memory usage
   ```yaml
   scanners:
     trivy-repo:
       options:
         ignore_unfixed: true  # Reduce result set
         severity_threshold: "MEDIUM"  # Filter low-priority issues
   ```

#### Network and Firewall Issues

**Error**: `Connection timeout` or `SSL certificate verification failed`

**Solutions**:
1. **Corporate Firewall**: Configure proxy and certificates
   <!-- doctest: illustrative reason="needs the network" -->
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=http://proxy.company.com:8080
   export SSL_CERT_FILE=/path/to/corporate-ca.crt
   ```

2. **Disable SSL Verification** (not recommended for production):
   <!-- doctest: illustrative reason="needs the network" -->
   ```bash
   export TRIVY_INSECURE=true
   ```

3. **Use Internal Mirror**: Configure custom database repository
   <!-- doctest: illustrative reason="needs the network" -->
   ```bash
   export TRIVY_DB_REPOSITORY=internal-mirror.company.com/trivy-db
   ```

#### False Positives and Noise

**Issue**: Too many irrelevant findings

**Solutions**:
1. **Severity Filtering**: Adjust threshold
   ```yaml
   scanners:
     trivy-repo:
       options:
         severity_threshold: "HIGH"
         ignore_unfixed: true
   ```

2. **Targeted Suppressions**: Use ASH suppression system
   ```yaml
   global_settings:
     suppressions:
       - rule_id: "CVE-2023-12345"
         path: "**/*"
         reason: "Not applicable to our use case"
       - path: "test/**"
         reason: "Test files only"
       - rule_id: "GHSA-*"
         path: "vendor/**"
         reason: "Third-party code"
   ```

3. **Custom Ignore Files**: A `.trivyignore` in the scanned repository is not read.
   Use ASH suppressions, or an operator ignore file outside the scanned tree:
   <!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
   ```bash
   echo "CVE-2023-12345" > /etc/ash/trivyignore
   ash --scanners trivy-repo \
     --config-overrides 'scanners.trivy-repo.options.ignore_file=/etc/ash/trivyignore'
   ```

### Debug Mode and Logging

#### Enable Detailed Logging

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# ASH debug mode
ash --scanners trivy-repo --log-level DEBUG

# Trivy debug mode
export TRIVY_DEBUG=true
ash --scanners trivy-repo

# Combined debugging
TRIVY_DEBUG=true ash --scanners trivy-repo --log-level DEBUG
```

#### Log Analysis

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Check ASH logs
tail -f .ash/ash_output/scanners/trivy-repo/*/ash.log

# Check Trivy-specific logs
grep -i trivy .ash/ash_output/scanners/trivy-repo/*/ash.log

# Check for errors
grep -i error .ash/ash_output/scanners/trivy-repo/*/ash.log
```

### Container Mode Troubleshooting

#### Volume Mount Issues

**Error**: `No such file or directory` in container mode

**Solution**:
<!-- doctest: illustrative reason="needs a container runtime" -->
```bash
# Ensure proper volume mounting
ash --mode container --source-dir $(pwd) --scanners trivy-repo

# Check container logs
docker logs $(docker ps -q --filter ancestor=ash)
```

#### Container Network Issues

**Error**: Database download fails in container

**Solution**:
<!-- doctest: illustrative reason="needs a container runtime" -->
```bash
# Use the host network
ash build-image --container-network host

# Pre-download database
trivy image --download-db-only
ash --mode container --scanners trivy-repo
```

### Environment-Specific Issues

#### CI/CD Pipeline Issues

**Common Problems**:
- Network restrictions
- Limited disk space
- Time constraints

**Solutions**:
<!-- doctest: config kind=github-actions runner=none reason="steps for a job in the reader's own workflow, shown without the workflow around them" -->
```yaml
# GitHub Actions example
- name: Setup Trivy Cache
  uses: actions/cache@v3
  with:
    path: ~/.cache/trivy
    key: trivy-db-${{ github.run_id }}
    restore-keys: trivy-db-

- name: Pre-download Trivy DB
  run: trivy image --download-db-only

- name: Run ASH with Trivy
  run: ash --scanners trivy-repo --formats sarif
  timeout-minutes: 10
```

#### Windows-Specific Issues

**Path Separator Issues**:
<!-- doctest: illustrative reason="runs only on Windows" -->
```powershell
# Use forward slashes or escape backslashes
ash --source-dir "C:/projects/myapp" --scanners trivy-repo

# Or use PowerShell-style paths
ash --source-dir $PWD --scanners trivy-repo
```

### Getting Additional Help

#### Diagnostic Information Collection

When reporting issues, include:

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# System information
uv --version
python --version
trivy version
ash --version

# Configuration
cat .ashrc.yaml  # your ASH config file; `ash config validate` prints which one a scan uses

# Recent logs
tail -50 .ash/ash_output/scanners/trivy-repo/*/ash.log

# Environment variables
env | grep -i trivy
env | grep -i ash
```

#### Support Channels

1. **ASH Issues**: [GitHub Issues](https://github.com/aws-samples/automated-security-helper/issues)
2. **Trivy Issues**: [Trivy GitHub](https://github.com/aquasecurity/trivy/issues)
3. **Community Discussions**: [ASH Discussions](https://github.com/aws-samples/automated-security-helper/discussions)

## Integration Examples

### CI/CD Pipeline Integration

#### GitHub Actions

<!-- doctest: config kind=github-actions runner=none reason="a workflow for the reader's own repository, which installs ASH from GitHub" -->
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.1
      
      - name: Run Trivy Security Scan
        run: |
          ash --scanners trivy-repo --formats sarif,html
      
      - name: Upload Results
        # Also when ASH exits non-zero on findings: without a status function
        # GitHub skips this step after any failed step.
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          # Not the whole output directory: scanners/ and converted/ hold each
          # tool's raw output, which is not masked.
          path: |
            .ash/ash_output/reports
            .ash/ash_output/ash_aggregated_results.json
```

#### GitLab CI

<!-- doctest: config kind=gitlab-ci runner=none reason="a pipeline for the reader's own project, which installs ASH from GitHub" -->
```yaml
security-scan:
  stage: test
  image: python:3.10
  script:
    - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.1
    - ash --scanners trivy-repo --formats sarif,markdown
  artifacts:
    reports:
      sast: .ash/ash_output/reports/ash_aggregated_results.sarif
    paths:
      - .ash/ash_output/reports
      - .ash/ash_output/ash_aggregated_results.json
```

### Pre-commit Hook

<!-- doctest: config kind=pre-commit -->
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ash-trivy-scan
        name: ASH Trivy Security Scan
        entry: ash --mode precommit --scanners trivy-repo
        language: system
        pass_filenames: false
```

## Advanced Configuration

### Environment Variables

Trivy supports extensive configuration through environment variables:

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Database and caching
export TRIVY_CACHE_DIR=/custom/cache/path
export TRIVY_DB_REPOSITORY=custom-db-repo
export TRIVY_TIMEOUT=10m
# Offline scans: set ASH_OFFLINE=YES (or options.offline: true). TRIVY_OFFLINE_SCAN
# alone does not stop the database update ASH runs before an online scan.
export ASH_OFFLINE=YES

# Network and proxy
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export TRIVY_INSECURE=false

# Output and formatting
export TRIVY_DEBUG=true
export TRIVY_QUIET=false

# Run ASH with custom Trivy settings
ash --scanners trivy-repo
```

### Custom Database Configuration

#### Using Private Vulnerability Database

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Set custom database repository
export TRIVY_DB_REPOSITORY=registry.company.com/security/trivy-db

# Use custom OCI registry
export TRIVY_USERNAME=myuser
export TRIVY_PASSWORD=mypass
export TRIVY_DB_REPOSITORY=myregistry.azurecr.io/trivy-db

ash --scanners trivy-repo
```

#### Offline Scanning Setup

<!-- doctest: illustrative reason="needs the network" -->
```bash
# 1. Download database on internet-connected machine
trivy image --download-db-only --cache-dir /shared/trivy-cache

# 2. Copy cache to air-gapped environment
rsync -av /shared/trivy-cache/ airgapped-server:/opt/trivy-cache/

# 3. Configure offline scanning
export TRIVY_CACHE_DIR=/opt/trivy-cache
export ASH_OFFLINE=YES
ash --scanners trivy-repo
```

In offline mode (`--offline`, `ASH_OFFLINE`, or `options.offline: true`) ASH passes
`trivy --skip-db-update`, `trivy --skip-java-db-update`, `trivy --offline-scan` and `trivy --skip-check-update`,
and sets `TRIVY_SKIP_VERSION_CHECK=true` and `TRIVY_DISABLE_TELEMETRY=true`: trivy's
version check and telemetry contact check.trivy.dev, and `trivy --skip-check-update` covers
only the checks bundle. Variables rather than flags, because a trivy too old to know
the flags refuses the command, while it ignores the variables.

Online and offline, ASH passes `--config`: the operator's `config_file`, else
`TRIVY_CONFIG` when that names a file outside the scanned tree, otherwise an empty
config ASH ships, so a `trivy.yaml` in the scanned repository is never read. Its
settings can reach the network (a VEX repository, client/server mode) or change
what is reported. A relative path in `TRIVY_CONFIG` is taken from the working
directory ASH runs in, as one in `TRIVY_IGNOREFILE` or `TRIVY_SECRET_CONFIG` is,
not from the source directory.

Offline, trivy's Terraform checks do not run. trivy downloads the source of every
`module` block it evaluates (a registry module from registry.terraform.io, a `git::`
source with the host's `git`, an `https://` archive), whatever offline flags it is
given, so ASH passes `trivy --misconfig-scanners` with the installed trivy's default list
minus `terraform`, read from `trivy repository --help`. When that list cannot be read,
the `misconfig` scanner is left out of the offline scan, with a warning. checkov
still checks Terraform offline.

The copied database has to be current. After the scan ASH reads its `UpdatedAt`
(from `trivy version --format json`) and exits 1 once it is more than 24 hours old,
which is trivy's own rule: the published database sets `NextUpdate` 24 hours after
`UpdatedAt`, and trivy online replaces it after that. Offline, `trivy --skip-db-update`
bypasses that rule, so ASH applies it instead. Repeat steps 1 and 2 to refresh the
database, or pass `--allow-stale-content-db` (config: `content_db_staleness: warn`)
to scan with an older one and have the reports say so.

### Advanced Suppression Strategies

#### Rule-Based Suppressions

```yaml
# ASH config file (.ashrc.yaml in a new project)
global_settings:
  suppressions:
    # Suppress specific CVEs
    - rule_id: "CVE-2023-12345"
      path: "**/*"
      reason: "Patched in our custom build"
      expiration: "2024-12-31"
    
    # Suppress by severity and path
    - rule_id: "GHSA-*"
      path: "vendor/**"
      reason: "Third-party dependencies managed separately"
    
    # Suppress license issues in test files
    - rule_id: "LICENSE-*"
      path: "test/**"
      reason: "Test files don't affect production licensing"
    
    # Suppress secrets in documentation
    - rule_id: "SECRET-*"
      path: "docs/**"
      reason: "Documentation examples only"
```

#### Dynamic Suppressions

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# Scan, then turn each finding not already suppressed into a suppression entry
ash scan --scanners trivy-repo --output-formats sarif
jq '[.runs[].results[]
     | select((.suppressions // []) | length == 0)
     | {rule_id: .ruleId,
        path: .locations[0].physicalLocation.artifactLocation.uri,
        reason: "Baseline finding: review it before the suppression expires",
        expiration: (now + 90 * 86400 | strftime("%Y-%m-%d"))}]
    | unique' .ash/ash_output/reports/ash.sarif > suppressions.json

# Review suppressions.json, then append the entries to global_settings.suppressions
# in your ASH config file, 200 at a time: on Linux one command-line argument holds
# at most 128 KiB, and a single --set with a few hundred entries is refused with
# "Argument list too long".
jq -c '. as $all | range(0; length; 200) | $all[.:. + 200]' suppressions.json |
  while read -r part; do
    ash config update --set "global_settings.suppressions+=$part"
  done
```

Appending YAML to the config file (`cat suppressions.yaml >> .ashrc.yaml`) does
not work: it adds a second top-level `global_settings`, YAML keeps only the last
one, and every other global setting in the file is dropped. `ash config update`
keeps them, and writes each entry with only the fields it sets. It rewrites the
whole file, without its comments, and refuses a file that reads environment
variables (`!ENV` or `${VAR:default}`); add the entries to such a file by hand.

### Multi-Environment Configuration

#### Environment-Specific Configurations

```yaml
# .ash/production.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "secret"]
      severity_threshold: "MEDIUM"
      ignore_unfixed: false
      disable_telemetry: true

# .ash/development.yaml  
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "misconfig", "secret", "license"]
      severity_threshold: "HIGH"
      ignore_unfixed: true
      license_full: false
```

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# Use environment-specific configs
ash --config .ash/production.yaml --scanners trivy-repo
ash --config .ash/development.yaml --scanners trivy-repo
```

#### Multi-Target Scanning Strategies

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# Parallel scanning of different components
ash --source-dir frontend/ --scanners trivy-repo --config .ash/frontend.yaml &
ash --source-dir backend/ --scanners trivy-repo --config .ash/backend.yaml &
ash --source-dir infrastructure/ --scanners trivy-repo --config .ash/infra.yaml &
wait

# Sequential scanning with different thresholds
for dir in src/ lib/ config/; do
  ash --source-dir "$dir" --scanners trivy-repo --config ".ash/${dir%/}.yaml"
done
```

### Performance Optimization

#### Caching Strategies

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Shared cache for team environments
export TRIVY_CACHE_DIR=/shared/trivy-cache
mkdir -p /shared/trivy-cache
chmod 755 /shared/trivy-cache

# Pre-warm cache for CI/CD
trivy image --download-db-only --cache-dir /shared/trivy-cache

# Use cached database
ash --scanners trivy-repo
```

#### Incremental Scanning

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
# Scan only changed files (requires Git)
git diff --name-only HEAD~1 | while read file; do
  if [[ -f "$file" ]]; then
    ash --source-dir "$(dirname "$file")" --scanners trivy-repo
  fi
done

# Scan based on file types
find . -name "*.py" -newer .last_scan | xargs -I {} dirname {} | sort -u | while read dir; do
  ash --source-dir "$dir" --scanners trivy-repo
done
touch .last_scan
```

#### Resource Management

```yaml
# ASH config file (.ashrc.yaml in a new project) - Optimized for large repositories
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln"]  # Most critical findings only
      severity_threshold: "HIGH"  # Reduce noise
      ignore_unfixed: true  # Skip unfixable issues
      disable_telemetry: true  # Reduce network calls

global_settings:
  ignore_paths:
    - path: "node_modules/**"
      reason: "Package manager dependencies"
    - path: "vendor/**"
      reason: "Third-party code"
    - path: "**/*.min.*"
      reason: "Minified files"
    - path: "**/test_data/**"
      reason: "Test fixtures"
```

### Integration Patterns

#### Custom Reporting Pipeline

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# custom-trivy-scan.sh

# Run Trivy scan with custom processing
ash --scanners trivy-repo --formats sarif,flat-json

# Process results
python scripts/process_trivy_results.py .ash/ash_output/reports/

# Generate custom reports
python scripts/generate_security_dashboard.py

# Send notifications
python scripts/notify_security_team.py
```

#### Webhook Integration

<!-- doctest: illustrative reason="a fragment of plugin code that names objects defined elsewhere" -->
```python
# webhook_handler.py
import json
import requests
from pathlib import Path


def send_trivy_results():
    results_file = Path(".ash/ash_output/reports/ash_aggregated_results.json")

    if results_file.exists():
        with open(results_file) as f:
            results = json.load(f)

        # Filter Trivy results
        trivy_results = [
            r
            for r in results.get("runs", [])
            if r.get("tool", {}).get("driver", {}).get("name") == "trivy-repo"
        ]

        # Send to webhook
        webhook_url = "https://security-dashboard.company.com/webhook"
        requests.post(webhook_url, json={"trivy_results": trivy_results})


if __name__ == "__main__":
    send_trivy_results()
```

#### Database Integration

<!-- doctest: illustrative reason="a fragment of plugin code that names objects defined elsewhere" -->
```python
# store_results.py
import json
import sqlite3
from datetime import datetime
from pathlib import Path


def store_trivy_results():
    conn = sqlite3.connect("security_results.db")

    # Create table if not exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trivy_findings (
            id INTEGER PRIMARY KEY,
            scan_date TEXT,
            rule_id TEXT,
            severity TEXT,
            file_path TEXT,
            message TEXT,
            fixed_version TEXT
        )
    """)

    # Load and store results
    results_file = Path(".ash/ash_output/reports/ash_aggregated_results.json")
    if results_file.exists():
        with open(results_file) as f:
            data = json.load(f)

        scan_date = datetime.now().isoformat()

        for run in data.get("runs", []):
            if run.get("tool", {}).get("driver", {}).get("name") == "trivy-repo":
                for result in run.get("results", []):
                    conn.execute(
                        """
                        INSERT INTO trivy_findings 
                        (scan_date, rule_id, severity, file_path, message, fixed_version)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """,
                        (
                            scan_date,
                            result.get("ruleId"),
                            result.get("level"),
                            result.get("locations", [{}])[0]
                            .get("physicalLocation", {})
                            .get("artifactLocation", {})
                            .get("uri"),
                            result.get("message", {}).get("text"),
                            result.get("fixes", [{}])[0]
                            .get("description", {})
                            .get("text"),
                        ),
                    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    store_trivy_results()
```

### Specialized Use Cases

#### Container Image Scanning Integration

```yaml
# .ash/container-scan.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "secret"]
      severity_threshold: "HIGH"
      ignore_unfixed: false

# Custom script for container + repo scanning
```

<!-- doctest: illustrative reason="needs a container runtime" -->
```bash
#!/bin/bash
# container-and-repo-scan.sh

# Scan repository
ash --config .ash/container-scan.yaml --scanners trivy-repo

# Scan container images referenced in repo
find . -name "Dockerfile*" -o -name "docker-compose*.yml" | while read file; do
  echo "Found container definition: $file"
  # Extract image names and scan them with Trivy directly
  grep -E "FROM|image:" "$file" | while read line; do
    image=$(echo "$line" | awk '{print $NF}' | tr -d '"')
    if [[ "$image" != "scratch" && "$image" != *"$"* ]]; then
      echo "Scanning image: $image"
      trivy image --format sarif --output "trivy-image-${image//\//_}.sarif" "$image"
    fi
  done
done
```

#### License Compliance Workflow

```yaml
# .ash/license-compliance.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["license"]
      license_full: true
      severity_threshold: "LOW"

reporters:
  csv:
    enabled: true
    # Reporters write to the scan's output directory under a fixed name; there
    # is no per-reporter output_file option.
```

<!-- doctest: illustrative reason="runs a scan that needs trivy installed on the host" -->
```bash
# Generate license compliance report
ash --config .ash/license-compliance.yaml --scanners trivy-repo

# Process license data
python scripts/license_compliance_check.py license-report.csv
```

#### Security Baseline Establishment

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# establish-baseline.sh

# Initial comprehensive scan
ash --scanners trivy-repo --formats flat-json --config .ash/baseline.yaml

# Store baseline
cp .ash/ash_output/reports/ash_aggregated_results.json security-baseline.json

# Generate initial suppressions for existing issues
python scripts/generate_baseline_suppressions.py security-baseline.json > .ash/baseline-suppressions.yaml

echo "Security baseline established. Review and approve suppressions in .ash/baseline-suppressions.yaml"
```

### Monitoring and Alerting

#### Trend Analysis

<!-- doctest: illustrative reason="a fragment of plugin code that names objects defined elsewhere" -->
```python
# trend_analysis.py
# Needs matplotlib, which is not part of ASH: pip install matplotlib
import importlib
import json
from datetime import datetime, timedelta
from pathlib import Path

plt = importlib.import_module("matplotlib.pyplot")


def analyze_security_trends():
    # Load historical data
    history_dir = Path("security-history")

    dates = []
    vuln_counts = []

    for result_file in sorted(history_dir.glob("*.json")):
        with open(result_file) as f:
            data = json.load(f)

        date = datetime.fromisoformat(result_file.stem)
        dates.append(date)

        # Count vulnerabilities by severity
        vuln_count = sum(
            1
            for run in data.get("runs", [])
            for result in run.get("results", [])
            if result.get("level") in ["error", "warning"]
        )
        vuln_counts.append(vuln_count)

    # Generate trend chart
    plt.figure(figsize=(12, 6))
    plt.plot(dates, vuln_counts, marker="o")
    plt.title("Security Findings Trend")
    plt.xlabel("Date")
    plt.ylabel("Number of Findings")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("security-trend.png")

    return dates, vuln_counts


if __name__ == "__main__":
    analyze_security_trends()
```

#### Automated Alerting

<!-- doctest: illustrative reason="a shell outline that needs trivy and a checkout of a project to scan" -->
```bash
#!/bin/bash
# security-alert.sh

# Run scan
ash --scanners trivy-repo --formats flat-json

# Check for critical issues
CRITICAL_COUNT=$(jq '[.runs[].results[] | select(.level == "error")] | length' .ash/ash_output/reports/ash_aggregated_results.json)

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "ALERT: $CRITICAL_COUNT critical security issues found!"
  
  # Send Slack notification
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"🚨 Security Alert: $CRITICAL_COUNT critical issues found in $(pwd)\"}" \
    "$SLACK_WEBHOOK_URL"
  
  # Send email
  echo "Critical security issues detected. See attached report." | \
    mail -s "Security Alert: $(basename $(pwd))" -a .ash/ash_output/reports/security-report.html security-team@company.com
fi
```

## Comparison with Other Scanners

| Feature                 | Trivy            | Bandit        | Semgrep          | Checkov          |
| ----------------------- | ---------------- | ------------- | ---------------- | ---------------- |
| Vulnerability Detection | ✅ Excellent      | ❌ No          | ❌ No             | ❌ No             |
| IaC Misconfiguration    | ✅ Good           | ❌ No          | ✅ Limited        | ✅ Excellent      |
| Secret Detection        | ✅ Good           | ❌ No          | ✅ Good           | ✅ Limited        |
| License Scanning        | ✅ Excellent      | ❌ No          | ❌ No             | ❌ No             |
| Language Support        | ✅ Multi-language | 🟡 Python only | ✅ Multi-language | ✅ Multi-language |
| Performance             | 🟡 Moderate       | ✅ Fast        | 🟡 Moderate       | 🟡 Moderate       |
| Database Updates        | ✅ Automatic      | N/A           | ✅ Automatic      | ✅ Automatic      |

## Best Practices

### 1. Layered Security Approach

Combine Trivy with other ASH scanners for comprehensive coverage:

```yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln", "misconfig"]
  
  bandit:
    enabled: true  # Python-specific SAST
  
  semgrep:
    enabled: true  # General SAST rules
  
  checkov:
    enabled: true  # IaC best practices
```

### 2. Severity-based Workflows

Configure different severity thresholds for different environments:

```yaml
# Production pipeline - strict
scanners:
  trivy-repo:
    options:
      severity_threshold: "MEDIUM"
      ignore_unfixed: false

# Development pipeline - permissive  
scanners:
  trivy-repo:
    options:
      severity_threshold: "HIGH"
      ignore_unfixed: true
```

### 3. Targeted Scanning

Use specific scanner types based on your needs:

```yaml
# For container-focused projects
scanners:
  trivy-repo:
    options:
      scanners: ["vuln", "secret"]

# For infrastructure projects
scanners:
  trivy-repo:
    options:
      scanners: ["misconfig", "secret"]
```

### 4. Regular Database Updates

Ensure Trivy's vulnerability database stays current:

<!-- doctest: illustrative reason="needs the network" -->
```bash
# Manual database update
trivy image --download-db-only

# Automated in CI/CD
- name: Update Trivy DB
  run: trivy image --download-db-only
```

## Support and Resources

### Documentation
- [Trivy Official Documentation](https://aquasecurity.github.io/trivy/)
- [Write a scanner plugin](../../../plugins/write-a-scanner.md)
- [Configure ASH](../../../how-to/configure.md)

### Community
- [ASH GitHub Issues](https://github.com/aws-samples/automated-security-helper/issues)
- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
- [ASH Discussions](https://github.com/aws-samples/automated-security-helper/discussions)

### Getting Help

If you encounter issues with the Trivy plugin:

1. Check the [troubleshooting section](#troubleshooting) above
2. Review Trivy's official documentation
3. Search existing GitHub issues
4. Open a new issue with detailed information:
   - ASH version
   - Trivy version
   - Configuration used
   - Error messages
   - Steps to reproduce
