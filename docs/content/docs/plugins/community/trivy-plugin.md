# Trivy Plugin

**Description**: The Trivy plugin integrates Aquasec's Trivy CLI tool to provide comprehensive repository scanning for vulnerabilities, misconfigurations, secrets, and license issues. This plugin extends ASH's security scanning capabilities with Trivy's advanced detection algorithms and extensive vulnerability database.

**Repository**: Built-in ASH plugin (part of core distribution)

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

The Trivy plugin requires the Trivy CLI to be installed and available in your system PATH.

#### Installation Options

**Using Homebrew (macOS/Linux):**
```bash
brew install trivy
```

**Using Package Managers:**
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
```bash
# Download and install from GitHub releases
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

*Windows:*
```bash
# Download and install using the official endpoint
curl -sfL -o trivy.zip "https://get.trivy.dev/trivy?type=zip&os=windows&arch=amd64"
unzip trivy.zip
# Move trivy.exe to a directory in your PATH
```

### Verification

Verify Trivy installation:
```bash
trivy version
```

## Configuration

### Basic Configuration

Add the Trivy plugin to your `.ash/.ash.yaml` configuration:

```
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

| Option               | Type      | Default                                      | Description                                                             |
| -------------------- | --------- | -------------------------------------------- | ----------------------------------------------------------------------- |
| `scanners`           | List[str] | `["vuln", "misconfig", "secret", "license"]` | Types of scans to perform                                               |
| `severity_threshold` | str       | `"MEDIUM"`                                   | Minimum severity level to report (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL) |
| `ignore_unfixed`     | bool      | `false`                                      | Ignore vulnerabilities without available fixes                          |
| `license_full`       | bool      | `false`                                      | Enable full license scanning (more comprehensive but slower)            |
| `disable_telemetry`  | bool      | `true`                                       | Disable Trivy telemetry data collection                                 |

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

```bash
# Scan current directory with default Trivy settings
ash --scanners trivy-repo

# Scan specific directory
ash --target /path/to/project --scanners trivy-repo
```

### Vulnerability-Only Scan

```yaml
# .ash/.ash.yaml
scanners:
  trivy-repo:
    enabled: true
    options:
      scanners: ["vuln"]
      severity_threshold: "HIGH"
      ignore_unfixed: true
```

```bash
ash --scanners trivy-repo
```

### Comprehensive Security Scan

```yaml
# .ash/.ash.yaml
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
# .ash/.ash.yaml
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

### Available Output Formats

- **SARIF**: Machine-readable results for CI/CD integration
- **HTML**: Human-readable reports with detailed findings
- **Markdown**: Documentation-friendly format
- **CSV**: Spreadsheet-compatible format
- **JSON**: Structured data for custom processing

### Example Output Configuration

```yaml
# .ash/.ash.yaml
reporters:
  sarif:
    enabled: true
    options:
      output_file: "trivy-results.sarif"
  
  html:
    enabled: true
    options:
      output_file: "security-report.html"
  
  markdown:
    enabled: true
    options:
      output_file: "SECURITY.md"
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

```bash
# Scan critical paths first
ash --target src/ --scanners trivy-repo  # Core application code
ash --target config/ --scanners trivy-repo  # Configuration files

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

```bash
#!/bin/bash
# parallel-scan.sh

# Define scan targets
TARGETS=("src/" "lib/" "config/" "scripts/")

# Run parallel scans
for target in "${TARGETS[@]}"; do
  ash --target "$target" --scanners trivy-repo --config-file ".ash/${target%/}.yaml" &
done

# Wait for all scans to complete
wait

# Merge results
python scripts/merge_scan_results.py
```

#### 5. Incremental Scanning

```bash
#!/bin/bash
# incremental-scan.sh

# Only scan changed files since last scan
if [ -f .last_trivy_scan ]; then
  CHANGED_FILES=$(find . -newer .last_trivy_scan -name "*.py" -o -name "*.js" -o -name "*.yaml")
  
  if [ -n "$CHANGED_FILES" ]; then
    echo "Scanning changed files: $CHANGED_FILES"
    echo "$CHANGED_FILES" | xargs -I {} dirname {} | sort -u | while read dir; do
      ash --target "$dir" --scanners trivy-repo
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

```bash
#!/bin/bash
# benchmark-trivy.sh

echo "Starting Trivy performance benchmark..."

# Measure scan time
start_time=$(date +%s)
ash --scanners trivy-repo --reporters json
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

```python
# performance_monitor.py
import json
import time
import psutil
import subprocess
from datetime import datetime
from pathlib import Path

class TrivyPerformanceMonitor:
    def __init__(self):
        self.metrics = []
    
    def run_monitored_scan(self):
        start_time = time.time()
        start_memory = psutil.virtual_memory().used
        
        # Run ASH with Trivy
        process = subprocess.Popen(
            ["ash", "--scanners", "trivy-repo", "--reporters", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
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
                    len(run.get("results", []))
                    for run in data.get("runs", [])
                )
        
        # Store metrics
        metric = {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "memory_mb": memory_used / (1024 * 1024),
            "finding_count": finding_count,
            "exit_code": process.returncode
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

```bash
#!/bin/bash
# distributed-scan.sh

# Split repository by language/framework
find . -name "*.py" | head -1000 | xargs dirname | sort -u > python_dirs.txt
find . -name "*.js" | head -1000 | xargs dirname | sort -u > javascript_dirs.txt
find . -name "*.yaml" -o -name "*.yml" | head -1000 | xargs dirname | sort -u > yaml_dirs.txt

# Distribute across multiple workers
cat python_dirs.txt | xargs -P 4 -I {} ash --target {} --scanners trivy-repo &
cat javascript_dirs.txt | xargs -P 4 -I {} ash --target {} --scanners trivy-repo &
cat yaml_dirs.txt | xargs -P 4 -I {} ash --target {} --scanners trivy-repo &

wait
```

#### Container-Based Scaling

```yaml
# docker-compose.yml for distributed scanning
version: '3.8'
services:
  trivy-scanner-1:
    image: ash:latest
    volumes:
      - ./src:/workspace/src
      - ./trivy-cache:/root/.cache/trivy
    command: ash --target /workspace/src --scanners trivy-repo
  
  trivy-scanner-2:
    image: ash:latest
    volumes:
      - ./lib:/workspace/lib
      - ./trivy-cache:/root/.cache/trivy
    command: ash --target /workspace/lib --scanners trivy-repo
  
  trivy-scanner-3:
    image: ash:latest
    volumes:
      - ./config:/workspace/config
      - ./trivy-cache:/root/.cache/trivy
    command: ash --target /workspace/config --scanners trivy-repo
```

### Resource Limits and Constraints

#### Memory Limits

```bash
# Set memory limits for container mode
ash --mode container --memory 2g --scanners trivy-repo

# Monitor memory usage
ulimit -v 2097152  # 2GB virtual memory limit
ash --scanners trivy-repo
```

#### Time Limits

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
  ash --target "$TEMP_DIR" --scanners trivy-repo --config-file .ash/precommit.yaml
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
          ash --target scan_target --scanners trivy-repo --reporters sarif,markdown
      
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
  [ -n "$dir" ] && ash --target "$dir" --scanners trivy-repo --config-file .ash/python.yaml
done

echo "Scanning Node.js projects..."
echo "$NODE_DIRS" | while read dir; do
  [ -n "$dir" ] && ash --target "$dir" --scanners trivy-repo --config-file .ash/nodejs.yaml
done

echo "Scanning Go projects..."
echo "$GO_DIRS" | while read dir; do
  [ -n "$dir" ] && ash --target "$dir" --scanners trivy-repo --config-file .ash/golang.yaml
done

echo "Scanning Rust projects..."
echo "$RUST_DIRS" | while read dir; do
  [ -n "$dir" ] && ash --target "$dir" --scanners trivy-repo --config-file .ash/rust.yaml
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

```bash
# Scan Terraform modules
find . -name "*.tf" | xargs dirname | sort -u | while read tf_dir; do
  echo "Scanning Terraform directory: $tf_dir"
  ash --target "$tf_dir" --scanners trivy-repo --config-file .ash/terraform.yaml
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

```bash
# Scan Kubernetes manifests
find . -name "*.yaml" -o -name "*.yml" | grep -E "(k8s|kubernetes|manifests)" | xargs dirname | sort -u | while read k8s_dir; do
  echo "Scanning Kubernetes directory: $k8s_dir"
  ash --target "$k8s_dir" --scanners trivy-repo --config-file .ash/kubernetes.yaml
done
```

### 4. Container and Docker Scanning

#### Dockerfile Analysis
```bash
#!/bin/bash
# scan-dockerfiles.sh

# Find all Dockerfiles
find . -name "Dockerfile*" -o -name "*.dockerfile" | while read dockerfile; do
  dir=$(dirname "$dockerfile")
  echo "Scanning Docker context: $dir"
  
  # Scan the directory containing Dockerfile
  ash --target "$dir" --scanners trivy-repo --config-file .ash/docker.yaml
  
  # Also scan the built image if available
  image_name=$(grep -E "^FROM" "$dockerfile" | tail -1 | awk '{print $2}')
  if [ -n "$image_name" ] && [ "$image_name" != "scratch" ]; then
    echo "Scanning base image: $image_name"
    trivy image --format sarif --output "${dir}/base-image.sarif" "$image_name" || true
  fi
done
```

#### Docker Compose Projects
```bash
#!/bin/bash
# scan-compose-projects.sh

find . -name "docker-compose*.yml" -o -name "docker-compose*.yaml" | while read compose_file; do
  dir=$(dirname "$compose_file")
  echo "Scanning Docker Compose project: $dir"
  
  # Scan the compose directory
  ash --target "$dir" --scanners trivy-repo --config-file .ash/docker-compose.yaml
  
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
    options:
      output_file: "license-report.csv"
  html:
    enabled: true
    options:
      output_file: "license-report.html"
```

```bash
#!/bin/bash
# license-compliance-check.sh

echo "Running comprehensive license scan..."
ash --scanners trivy-repo --config-file .ash/license-audit.yaml

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
```bash
#!/bin/bash
# establish-security-baseline.sh

echo "Establishing security baseline..."

# Run comprehensive scan
ash --scanners trivy-repo --reporters json --config-file .ash/baseline.yaml

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
print("Review .security-baseline/baseline-suppressions.yaml and merge approved suppressions into .ash/.ash.yaml")
EOF
```

#### Regression Detection
```bash
#!/bin/bash
# detect-security-regressions.sh

echo "Checking for security regressions..."

# Run current scan
ash --scanners trivy-repo --reporters json

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
   ```bash
   trivy version
   which trivy
   ```

2. **PATH Configuration**: Ensure Trivy is in your PATH
   ```bash
   echo $PATH
   export PATH=$PATH:/path/to/trivy/bin
   ```

3. **Reinstall Trivy**: Use your preferred installation method
   ```bash
   # Homebrew
   brew install trivy
   
   # Direct download
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   ```

4. **Container Mode Alternative**: Use ASH container mode
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
   ```bash
   curl -I https://github.com/aquasecurity/trivy-db/releases
   ```

2. **Clear Cache**: Remove corrupted database cache
   ```bash
   rm -rf ~/.cache/trivy/
   trivy image --download-db-only
   ```

3. **Proxy Configuration**: Configure proxy settings
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=http://proxy.company.com:8080
   trivy image --download-db-only
   ```

4. **Offline Mode**: Use pre-downloaded database
   ```bash
   # Download database separately
   trivy image --download-db-only --cache-dir /shared/trivy-cache
   
   # Use cached database
   export TRIVY_CACHE_DIR=/shared/trivy-cache
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
   ```bash
   ls -la /path/to/target
   find /path/to/target -type f ! -readable
   ```

2. **Fix Ownership**: Correct file ownership
   ```bash
   sudo chown -R $USER:$USER /path/to/target
   chmod -R u+r /path/to/target
   ```

3. **Run with Sudo**: Use elevated permissions (not recommended)
   ```bash
   sudo ash --scanners trivy-repo --target /path/to/target
   ```

4. **Container Mode**: Use container with proper volume mounts
   ```bash
   ash --mode container --target /path/to/target --scanners trivy-repo
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
   ```bash
   # Scan only source code directories
   ash --target src/ --scanners trivy-repo
   ash --target lib/ --scanners trivy-repo
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
   ```bash
   # Process in parallel
   ash --target frontend/ --scanners trivy-repo &
   ash --target backend/ --scanners trivy-repo &
   wait
   ```

#### Memory Issues

**Error**: `Out of memory` or system becomes unresponsive

**Solutions**:
1. **Increase Memory Limits**: For container mode
   ```bash
   docker run --memory=2g --scanners trivy-repo
   ```

2. **Process Smaller Chunks**: Break down large scans
   ```bash
   find . -maxdepth 1 -type d | xargs -I {} ash --target {} --scanners trivy-repo
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
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=http://proxy.company.com:8080
   export SSL_CERT_FILE=/path/to/corporate-ca.crt
   ```

2. **Disable SSL Verification** (not recommended for production):
   ```bash
   export TRIVY_INSECURE=true
   ```

3. **Use Internal Mirror**: Configure custom database repository
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
         reason: "Not applicable to our use case"
       - path: "test/**"
         reason: "Test files only"
       - rule_id: "GHSA-*"
         path: "vendor/**"
         reason: "Third-party code"
   ```

3. **Custom Ignore Files**: Use Trivy's ignore functionality
   ```bash
   # Create .trivyignore file
   echo "CVE-2023-12345" > .trivyignore
   echo "GHSA-abcd-1234" >> .trivyignore
   ```

### Debug Mode and Logging

#### Enable Detailed Logging

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
```bash
# Ensure proper volume mounting
ash --mode container --target $(pwd) --scanners trivy-repo

# Check container logs
docker logs $(docker ps -q --filter ancestor=ash)
```

#### Container Network Issues

**Error**: Database download fails in container

**Solution**:
```bash
# Use host network
ash --mode container --network host --scanners trivy-repo

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
  run: ash --scanners trivy-repo --reporters sarif
  timeout-minutes: 10
```

#### Windows-Specific Issues

**Path Separator Issues**:
```powershell
# Use forward slashes or escape backslashes
ash --target "C:/projects/myapp" --scanners trivy-repo

# Or use PowerShell-style paths
ash --target $PWD --scanners trivy-repo
```

### Getting Additional Help

#### Diagnostic Information Collection

When reporting issues, include:

```bash
# System information
uv --version
python --version
trivy version
ash --version

# Configuration
cat .ash/.ash.yaml

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

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install ASH
        run: pip install automated-security-helper
      
      - name: Run Trivy Security Scan
        run: |
          ash --scanners trivy-repo --reporters sarif,html
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: .ash/ash_output/
```

#### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.10
  script:
    - pip install automated-security-helper
    - ash --scanners trivy-repo --reporters sarif,markdown
  artifacts:
    reports:
      sast: .ash/ash_output/reports/ash_aggregated_results.sarif
    paths:
      - .ash/ash_output/
```

### Pre-commit Hook

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

```bash
# Database and caching
export TRIVY_CACHE_DIR=/custom/cache/path
export TRIVY_DB_REPOSITORY=custom-db-repo
export TRIVY_TIMEOUT=10m
export TRIVY_OFFLINE_SCAN=true

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

```bash
# 1. Download database on internet-connected machine
trivy image --download-db-only --cache-dir /shared/trivy-cache

# 2. Copy cache to air-gapped environment
rsync -av /shared/trivy-cache/ airgapped-server:/opt/trivy-cache/

# 3. Configure offline scanning
export TRIVY_CACHE_DIR=/opt/trivy-cache
export TRIVY_OFFLINE_SCAN=true
ash --scanners trivy-repo
```

### Advanced Suppression Strategies

#### Rule-Based Suppressions

```yaml
# .ash/.ash.yaml
global_settings:
  suppressions:
    # Suppress specific CVEs
    - rule_id: "CVE-2023-12345"
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

```bash
# Generate suppressions from previous scan
ash --scanners trivy-repo --reporters json > results.json
python scripts/generate_suppressions.py results.json > suppressions.yaml

# Apply generated suppressions
cat suppressions.yaml >> .ash/.ash.yaml
```

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

```bash
# Use environment-specific configs
ash --config-file .ash/production.yaml --scanners trivy-repo
ash --config-file .ash/development.yaml --scanners trivy-repo
```

#### Multi-Target Scanning Strategies

```bash
# Parallel scanning of different components
ash --target frontend/ --scanners trivy-repo --config-file .ash/frontend.yaml &
ash --target backend/ --scanners trivy-repo --config-file .ash/backend.yaml &
ash --target infrastructure/ --scanners trivy-repo --config-file .ash/infra.yaml &
wait

# Sequential scanning with different thresholds
for dir in src/ lib/ config/; do
  ash --target "$dir" --scanners trivy-repo --config-file ".ash/${dir%/}.yaml"
done
```

### Performance Optimization

#### Caching Strategies

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

```bash
# Scan only changed files (requires Git)
git diff --name-only HEAD~1 | while read file; do
  if [[ -f "$file" ]]; then
    ash --target "$(dirname "$file")" --scanners trivy-repo
  fi
done

# Scan based on file types
find . -name "*.py" -newer .last_scan | xargs -I {} dirname {} | sort -u | while read dir; do
  ash --target "$dir" --scanners trivy-repo
done
touch .last_scan
```

#### Resource Management

```yaml
# .ash/.ash.yaml - Optimized for large repositories
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

```bash
#!/bin/bash
# custom-trivy-scan.sh

# Run Trivy scan with custom processing
ash --scanners trivy-repo --reporters sarif,json

# Process results
python scripts/process_trivy_results.py .ash/ash_output/reports/

# Generate custom reports
python scripts/generate_security_dashboard.py

# Send notifications
python scripts/notify_security_team.py
```

#### Webhook Integration

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
            r for r in results.get("runs", [])
            if r.get("tool", {}).get("driver", {}).get("name") == "trivy-repo"
        ]
        
        # Send to webhook
        webhook_url = "https://security-dashboard.company.com/webhook"
        requests.post(webhook_url, json={"trivy_results": trivy_results})

if __name__ == "__main__":
    send_trivy_results()
```

#### Database Integration

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
                    conn.execute("""
                        INSERT INTO trivy_findings 
                        (scan_date, rule_id, severity, file_path, message, fixed_version)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        scan_date,
                        result.get("ruleId"),
                        result.get("level"),
                        result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri"),
                        result.get("message", {}).get("text"),
                        result.get("fixes", [{}])[0].get("description", {}).get("text")
                    ))
    
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

```bash
#!/bin/bash
# container-and-repo-scan.sh

# Scan repository
ash --config-file .ash/container-scan.yaml --scanners trivy-repo

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
    options:
      output_file: "license-report.csv"
```

```bash
# Generate license compliance report
ash --config-file .ash/license-compliance.yaml --scanners trivy-repo

# Process license data
python scripts/license_compliance_check.py license-report.csv
```

#### Security Baseline Establishment

```bash
#!/bin/bash
# establish-baseline.sh

# Initial comprehensive scan
ash --scanners trivy-repo --reporters json --config-file .ash/baseline.yaml

# Store baseline
cp .ash/ash_output/reports/ash_aggregated_results.json security-baseline.json

# Generate initial suppressions for existing issues
python scripts/generate_baseline_suppressions.py security-baseline.json > .ash/baseline-suppressions.yaml

echo "Security baseline established. Review and approve suppressions in .ash/baseline-suppressions.yaml"
```

### Monitoring and Alerting

#### Trend Analysis

```python
# trend_analysis.py
import json
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from pathlib import Path

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
            1 for run in data.get("runs", [])
            for result in run.get("results", [])
            if result.get("level") in ["error", "warning"]
        )
        vuln_counts.append(vuln_count)
    
    # Generate trend chart
    plt.figure(figsize=(12, 6))
    plt.plot(dates, vuln_counts, marker='o')
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

```bash
#!/bin/bash
# security-alert.sh

# Run scan
ash --scanners trivy-repo --reporters json

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
- [ASH Plugin Development Guide](../../plugins/development-guide.md)
- [ASH Configuration Reference](../../configuration/reference.md)

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
