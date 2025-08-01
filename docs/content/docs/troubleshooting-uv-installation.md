# Troubleshooting UV Tool Installation

This guide helps resolve common issues with UV tool installation in ASH (Automated Security Helper).

## Quick Diagnosis

### Check Installation Status

```bash
# Check if UV is available
uv --version

# List installed UV tools
uv tool list

# Check specific tool installation
uv tool run bandit --version
uv tool run checkov --version
uv tool run semgrep --version
```

### Enable Debug Logging

```bash
export ASH_LOG_LEVEL=DEBUG
ash --mode local
```

Look for log messages with these tags:
- `[INSTALLATION_START]` - Installation beginning
- `[INSTALLATION_PROGRESS]` - Installation progress
- `[INSTALLATION_SUCCESS]` - Successful installation
- `[INSTALLATION_FAILED]` - Installation failure
- `[INSTALLATION_ERROR]` - Installation error
- `[INSTALLATION_SKIP]` - Installation skipped

## Common Issues and Solutions

### 1. UV Not Available

#### Symptoms
```
UV tool validation failed - UV is not available but required
```

#### Diagnosis
```bash
which uv
uv --version
```

#### Solutions

**Option A: Install UV via pip**
```bash
pip install uv
```

**Option B: Install UV via official installer**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc  # or restart terminal
```

**Option C: Install UV via package manager**
```bash
# macOS with Homebrew
brew install uv

# Ubuntu/Debian
sudo apt update && sudo apt install uv

# Arch Linux
pacman -S uv
```

**Option D: Use pre-installed tools**
```bash
# Install tools system-wide as fallback
pip install bandit checkov semgrep
```

### 2. Installation Timeout

#### Symptoms
```
Tool installation timed out after 300 seconds for bandit
```

#### Diagnosis
- Check network connectivity
- Check if PyPI is accessible
- Monitor installation progress

#### Solutions

**Option A: Increase timeout**
```yaml
# .ash/ash.yaml
scanners:
  bandit:
    options:
      install_timeout: 600  # 10 minutes
```

**Option B: Check network connectivity**
```bash
# Test PyPI connectivity
curl -I https://pypi.org/

# Test specific package availability
curl -I https://pypi.org/project/bandit/
```

**Option C: Use offline mode**
```bash
export ASH_OFFLINE=true
ash --mode local
```

**Option D: Pre-install tools**
```bash
# Pre-install before running ASH
uv tool install bandit
uv tool install checkov
uv tool install semgrep
```

### 3. Version Constraint Issues

#### Symptoms
```
Tool installation failed for bandit with exit code 1
No matching distribution found for bandit>=2.0.0
```

#### Diagnosis
```bash
# Check available versions
pip index versions bandit

# Test version constraint manually
uv tool install "bandit>=1.7.0,<2.0.0"
```

#### Solutions

**Option A: Fix version constraint syntax**
```yaml
# Correct syntax
tool_version: ">=1.7.0,<2.0.0"

# Common mistakes to avoid
tool_version: ">= 1.7.0, < 2.0.0"  # Extra spaces
tool_version: ">=1.7.0 <2.0.0"     # Missing comma
```

**Option B: Use broader version ranges**
```yaml
# Instead of exact version
tool_version: "==1.7.5"

# Use minimum version
tool_version: ">=1.7.0"
```

**Option C: Check version availability**
```bash
# List available versions
pip index versions bandit
pip index versions checkov
pip index versions semgrep
```

### 4. Offline Mode Issues

#### Symptoms
```
Offline mode is enabled (ASH_OFFLINE=true) but tool 'bandit' is not available
```

#### Diagnosis
```bash
# Check if tools are pre-installed
which bandit
which checkov
which semgrep

# Check UV tool installation
uv tool list
```

#### Solutions

**Option A: Pre-install tools with UV**
```bash
# Install tools before enabling offline mode
uv tool install bandit
uv tool install checkov
uv tool install semgrep

# Then enable offline mode
export ASH_OFFLINE=true
```

**Option B: Install tools system-wide**
```bash
pip install bandit checkov semgrep
```

**Option C: Use UV cache in offline mode**
```bash
# Set UV offline mode
export UV_OFFLINE=1
export ASH_OFFLINE=true
```

**Option D: Disable offline mode temporarily**
```bash
unset ASH_OFFLINE
ash --mode local
```

### 5. Permission Issues

#### Symptoms
```
Permission denied: '/usr/local/bin/uv'
[Errno 13] Permission denied: '/home/user/.local/share/uv'
```

#### Diagnosis
```bash
# Check UV installation location
which uv
ls -la $(which uv)

# Check UV cache directory permissions
uv cache dir
ls -la $(uv cache dir)
```

#### Solutions

**Option A: Fix UV permissions**
```bash
# If UV is installed system-wide
sudo chown $(whoami) $(which uv)

# If cache directory has permission issues
sudo chown -R $(whoami) $(uv cache dir)
```

**Option B: Install UV in user directory**
```bash
# Reinstall UV for current user
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Option C: Use virtual environment**
```bash
python -m venv venv
source venv/bin/activate
pip install uv
```

### 6. Network and Proxy Issues

#### Symptoms
```
Failed to download package: Connection timeout
SSL certificate verification failed
```

#### Diagnosis
```bash
# Test direct connectivity
curl -I https://pypi.org/

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY
```

#### Solutions

**Option A: Configure proxy for UV**
```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1
```

**Option B: Use trusted hosts**
```bash
# For pip fallback
pip install --trusted-host pypi.org --trusted-host pypi.python.org bandit
```

**Option C: Use offline mode with pre-downloaded packages**
```bash
# Download packages on a machine with internet
uv tool install bandit
uv tool install checkov
uv tool install semgrep

# Copy UV cache to offline machine
tar -czf uv-cache.tar.gz $(uv cache dir)
# Transfer and extract on offline machine
```

### 7. Disk Space Issues

#### Symptoms
```
No space left on device
OSError: [Errno 28] No space left on device
```

#### Diagnosis
```bash
# Check disk space
df -h

# Check UV cache size
du -sh $(uv cache dir)

# Check specific tool sizes
uv tool list
```

#### Solutions

**Option A: Clean UV cache**
```bash
uv cache clean
```

**Option B: Move UV cache to larger disk**
```bash
# Set custom cache directory
export UV_CACHE_DIR=/path/to/larger/disk/uv-cache
```

**Option C: Free up disk space**
```bash
# Remove unused packages
pip uninstall <unused-packages>

# Clean system package cache
sudo apt clean  # Ubuntu/Debian
brew cleanup    # macOS
```

### 8. Concurrent Installation Issues

#### Symptoms
```
Another uv process is already running
Lock file conflict during installation
```

#### Diagnosis
```bash
# Check for running UV processes
ps aux | grep uv

# Check for lock files
find /tmp -name "*uv*lock*" 2>/dev/null
```

#### Solutions

**Option A: Wait for other processes**
```bash
# Wait for other UV processes to complete
wait
```

**Option B: Kill stuck processes**
```bash
# Find and kill stuck UV processes
pkill -f "uv tool"
```

**Option C: Remove lock files**
```bash
# Remove stale lock files (use with caution)
rm -f /tmp/*uv*lock*
```

### 9. Tool-Specific Issues

#### Bandit Issues

**Symptoms:**
```
ModuleNotFoundError: No module named 'bandit.formatters.sarif'
```

**Solution:**
```yaml
# Ensure SARIF extra is installed
scanners:
  bandit:
    options:
      tool_version: ">=1.7.0"  # SARIF support requires 1.7.0+
```

#### Checkov Issues

**Symptoms:**
```
checkov: command not found after installation
```

**Solution:**
```bash
# Verify installation
uv tool run checkov --version

# Check PATH
echo $PATH | grep -o '[^:]*uv[^:]*'
```

#### Semgrep Issues

**Symptoms:**
```
Semgrep rules download failed in offline mode
```

**Solution:**
```bash
# Pre-download rules for offline use
export SEMGREP_RULES_CACHE_DIR=/path/to/rules/cache
semgrep --config=auto --download-rules
```

## Advanced Troubleshooting

### Debug Installation Process

```bash
# Enable maximum verbosity
export ASH_LOG_LEVEL=TRACE
export UV_VERBOSE=1

# Run with debug output
ash --mode local 2>&1 | tee ash-debug.log
```

### Manual Installation Testing

```bash
# Test manual UV tool installation
uv tool install --verbose bandit

# Test tool execution
uv tool run bandit --help

# Test with specific version
uv tool install "bandit>=1.7.0,<2.0.0"
```

### Environment Validation

```bash
# Check Python environment
python --version
which python

# Check UV environment
uv --version
uv tool dir
uv cache dir

# Check system resources
df -h
free -h
ulimit -a
```

### Configuration Validation

```bash
# Validate ASH configuration
ash --validate-config

# Check scanner configuration
ash --list-scanners

# Test specific scanner
ash --scanner bandit --dry-run
```

## Prevention Strategies

### 1. Pre-Installation in CI/CD

```yaml
# GitHub Actions example
- name: Setup UV and Tools
  run: |
    curl -LsSf https://astral.sh/uv/install.sh | sh
    uv tool install bandit
    uv tool install checkov
    uv tool install semgrep
```

### 2. Health Checks

```bash
#!/bin/bash
# health-check.sh

echo "Checking UV installation..."
uv --version || exit 1

echo "Checking tool installations..."
uv tool run bandit --version || exit 1
uv tool run checkov --version || exit 1
uv tool run semgrep --version || exit 1

echo "All tools are ready!"
```

### 3. Monitoring and Alerting

```bash
# Monitor installation success rates
grep "INSTALLATION_SUCCESS\|INSTALLATION_FAILED" ash.log | \
  awk '{print $1}' | sort | uniq -c
```

### 4. Backup Strategies

```bash
# Backup UV cache for offline use
tar -czf uv-cache-backup.tar.gz $(uv cache dir)

# Backup tool installations
uv tool list > installed-tools.txt
```

## Getting Help

If you continue to experience issues:

1. **Check ASH Documentation**: Review the main documentation for configuration examples
2. **Enable Debug Logging**: Use `ASH_LOG_LEVEL=DEBUG` for detailed error information
3. **Check UV Documentation**: Visit [UV documentation](https://docs.astral.sh/uv/) for UV-specific issues
4. **Report Issues**: Create an issue with:
   - ASH version
   - UV version
   - Operating system
   - Complete error logs
   - Configuration files (sanitized)

### Useful Commands for Issue Reports

```bash
# System information
uname -a
python --version
uv --version

# ASH information
ash --version
ash --list-scanners

# Configuration
cat .ash/ash.yaml

# Recent logs (sanitize sensitive information)
tail -100 ash.log
```