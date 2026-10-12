# Advanced Usage

This guide covers advanced features and usage patterns for ASH v3.

## Execution Modes

ASH v3 supports three execution modes:

### Local Mode

```bash
ash --mode local
```

- Runs entirely in the local Python process
- Only uses Python-based scanners by default
- Fastest execution but limited scanner coverage
- Ideal for quick checks during development

### Tools inside the scanned directory

ASH does not start a scanner or any other tool that it finds inside the directory it
is scanning. `uv run ash scan .` puts the repository's `.venv/bin` first on `PATH`,
and `npm run` does the same with `node_modules/.bin`, so under either a scanner
installed in the project, such as a `bandit` or `semgrep` dependency, is part of the
repository being scanned. ASH skips it and uses the next copy on `PATH`, or the one
`uv tool` installs. If there is none, the scanner is reported as MISSING, with the
in-tree path in its `missing_reason`, in the log, and in the message the incomplete
scan exits with.

ASH also never finds a tool through the working directory: not through an empty, `.`
or relative `PATH` entry, and on Windows not through the working directory that
`CreateProcess` and `shutil.which` search first. Tools on ordinary absolute `PATH`
entries are found, including Homebrew, nix profiles, uv and pipx shims,
asdf and mise shims, conda, Program Files, scoop and Chocolatey. Programs ASH and its
scanners start are given a `PATH` without the scanned directory's entries, unless you
allow in-tree tools.

To run tools from inside the scanned directory, pass `--allow-in-tree-tools` (or set
`"allow_in_tree_tools": true` in a `--cli-json-input` document), or set
`ASH_ALLOW_IN_TREE_TOOLS` to `1`, `true`, `yes` or `on`. ASH then uses them and logs a
warning naming each one.
This also covers the scanner sandbox's own programs (`bwrap`, `firejail`, `readlink`
and `true`). A
repository's configuration file cannot turn this on, and `ash mcp` ignores both: an
MCP client's scans never run a tool from inside a scanned or delivered directory, so
for MCP use, install scanners outside the repository. See
[Troubleshooting](troubleshooting.md#a-scanner-is-missing-because-it-was-found-only-inside-the-scanned-tree)
for the message and the fixes.

### Container Mode

```bash
ash --mode container
```

- Runs non-Python scanners in a container
- Provides full scanner coverage
- Requires a container runtime (Docker, Podman, etc.)
- Ideal for comprehensive scans

### Precommit Mode

```bash
ash --mode precommit
```

- Runs a subset of fast scanners
- Optimized for pre-commit hooks
- Includes only Python-based scanners + npm audit
- Ideal for git hooks and quick CI checks

## Custom Plugins

ASH v3 supports custom plugins for extending functionality:

### Creating Custom Plugins

1. Create a Python module with your plugins:

```python
# my_ash_plugins/scanners.py
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from pydantic import Field
from pathlib import Path
from typing import List, Literal


class MyCustomScannerConfig(ScannerPluginConfigBase):
    """Configuration for MyCustomScanner"""

    class Options:
        custom_option: str = Field(default="default", description="Custom option")


@ash_scanner_plugin
class MyCustomScanner(ScannerPluginBase):
    """Custom scanner implementation"""

    name = "my-custom-scanner"
    description = "My custom security scanner"
    version = "1.0.0"

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List = [],
        config=None,
    ):
        # Implement your scanning logic here
        results = self._run_subprocess(["my-scanner", "--target", str(target)])
        return results
```

2. Add your module to ASH configuration:

```yaml
ash_plugin_modules:
  - my_ash_plugins
```

3. Use your custom scanner:

```bash
ash --ash-plugin-modules my_ash_plugins
```

## Offline Mode

For air-gapped environments:

```bash
# Build an offline image
ash build-image --offline --offline-semgrep-rulesets p/ci

# Run in offline mode
ash --mode container --offline
```

An offline image's databases are frozen at build time, and ASH fails a scan whose
database is past its bound: grype's 5 days (120h) after it was built, the offline
semgrep and opengrep rulesets 30 days after they were downloaded. Rebuild the image
(`ash build-image --offline`) at least that often. To scan with an older image
anyway, pass `--allow-stale-content-db` or set `content_db_staleness: warn`; the scan
then passes and every report names the stale database. See
[Failing on a stale content database](configuration-guide.md#failing-on-a-stale-content-database).

### Which scanners run offline

Offline mode is decided when each scanner runs, from these sources in order:

1. ASH's offline mode: `--offline` on `ash scan`, `ASH_OFFLINE=true` in the
   environment, or an image built with `ash build-image --offline`. It applies to
   every scanner, and no scanner option turns it off.
2. A scanner's own `options.offline: true` (checkov, grype, npm-audit, opengrep,
   semgrep, syft, trivy, trivy-repo). It runs that one scanner offline while the rest of the
   scan stays online.

`options.offline: false` is the default and means "follow ASH's offline mode". It does
not put a scanner back online during an `--offline` scan; `ash config init` writes
`offline: false` for every scanner that has the option, so a generated config would
otherwise undo the flag.

#### What offline mode turns off

Online and offline, trivy, trivy-repo and syft read no config file from the scanned
tree, because a `trivy.yaml` there can turn on a VEX repository download or
client/server mode and a `.syft.yaml` remote license and package lookups. trivy always
gets `--config`, naming the operator's `config_file`, else `TRIVY_CONFIG` when that is
a file outside the scanned tree, and an empty config ASH ships otherwise; syft runs from outside the tree and is given only a
`config_file` outside it.

Besides the database and rule downloads, offline mode turns off what the scanners do
over the network on their own:

- Every scanner tool process ASH starts, the version probes of its dependency check
  included, gets environment variables that turn off each tool's update, version and
  telemetry checks: semgrep's version check and metrics
  (`SEMGREP_ENABLE_VERSION_CHECK=0`, `SEMGREP_SEND_METRICS=off`), checkov's PyPI update
  check (`CKV_SKIP_PACKAGE_UPDATE_CHECK=true`), npm's update notifier
  (`npm_config_update_notifier=false`), trivy's version check and telemetry
  (`TRIVY_SKIP_VERSION_CHECK`, `TRIVY_DISABLE_TELEMETRY`), and the update checks of
  syft and grype. They also turn off the lookups a tool's own config file can enable:
  syft's remote license searches, maven lookups and vcpkg git clones, and grype's
  external sources. On a Go module syft does not run the Go toolchain
  (`SYFT_GOLANG_USE_PACKAGES_LIB=false`), and the toolchain grype runs gets
  `GOPROXY=off` and `GOTOOLCHAIN=local`, so it downloads no module and no toolchain.
  The full list is in `automated_security_helper/utils/offline_tool_env.py`. A scanner
  set offline by its own `options.offline: true` while ASH runs online gets them too,
  on its scan and on the version probes of its dependency check.
- trivy's version check and telemetry are off whatever `disable_telemetry` says, through
  `TRIVY_SKIP_VERSION_CHECK` and `TRIVY_DISABLE_TELEMETRY` rather than flags, which a
  trivy too old to know them would refuse.
- trivy-repo, and trivy when `misconfig` is in its `scanners`, do not run trivy's
  Terraform checks offline. trivy downloads the source of every `module` block a
  `.tf` file names (from the Terraform registry, with the host's `git`, or over
  HTTPS), and has no setting that stops it, so ASH passes `--misconfig-scanners` with
  trivy's own default list minus `terraform`. If that list cannot be read from
  `trivy repository --help` (`trivy fs --help` for trivy), trivy's misconfiguration
  checks are skipped offline. checkov still checks Terraform. Any `git` a tool runs offline gets
  `GIT_ALLOW_PROTOCOL=file`, so it reaches no remote.
- npm-audit runs no audit, because npm, pnpm and yarn audit only against the package
  registry's advisory service: offline `npm audit --offline` reported no advisories for
  a lockfile with known ones, `pnpm audit --offline` sent the dependency list to the
  registry anyway, and `yarn npm audit` has no offline mode. Every lockfile it would
  have audited is listed as not scanned, with the reason, in
  `ash_aggregated_results.json` (the scanner's `inputs_not_scanned`), the console
  summary, and the "Inputs not scanned" section of `ash.summary.md` and
  `ash.summary.txt`. A workspace scan lists every project's, with workspace-relative
  paths, in each project's `inputs_not_scanned` entry in the workspace results, the
  merged summaries and the workspace console summary. When there is a lockfile, npm-audit is MISSING, as snyk-code is,
  so the scan fails under the default completeness gate (exit code 1). To scan a
  Node.js project offline without it, pass `--exclude-scanners npm-audit`. A project
  with no lockfile has nothing to audit, and npm-audit is SKIPPED.
- detect-secrets does not verify candidate secrets with their issuers, whatever the
  scanned repository's `.secrets.baseline` or any config says. See
  [Secret verification](configuration-guide.md#secret-verification).

#### Seeding the semgrep and opengrep rule cache

Offline, semgrep and opengrep read their rules only from a local cache: the directory
named by `SEMGREP_RULES_CACHE_DIR` or `OPENGREP_RULES_CACHE_DIR`, which must contain
at least one `.yaml` or `.yml` rule file. If the variable is unset or the directory
has no rule files, that scanner is reported MISSING and the scan exits 1. ASH does not
fall back to downloading the rules.

For the container, build the image with `--offline`. The build downloads each ruleset
in `--offline-semgrep-rulesets` (space-separated, default `p/ci`) into
`/deps/.semgrep` and `/deps/.opengrep` and sets both variables:

```bash
ash build-image --offline --offline-semgrep-rulesets "p/ci p/python"
```

For a local scan, download the rulesets yourself while online, using the same URL the
image build uses, and record the download time in `.ash-rules-fetched-at` next to
them. ASH reads that file to hold the rules to their 30-day bound; without it, it
falls back to the oldest rule file's modification time, which a copy resets.

```bash
export SEMGREP_RULES_CACHE_DIR="$HOME/.cache/ash/semgrep"
export OPENGREP_RULES_CACHE_DIR="$HOME/.cache/ash/opengrep"
mkdir -p "$SEMGREP_RULES_CACHE_DIR" "$OPENGREP_RULES_CACHE_DIR"
for ruleset in p/ci; do
  curl -sSf "https://semgrep.dev/c/${ruleset}" -o "$SEMGREP_RULES_CACHE_DIR/$(basename "$ruleset").yml"
done
cp "$SEMGREP_RULES_CACHE_DIR"/*.yml "$OPENGREP_RULES_CACHE_DIR/"
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$SEMGREP_RULES_CACHE_DIR/.ash-rules-fetched-at" \
  > "$OPENGREP_RULES_CACHE_DIR/.ash-rules-fetched-at"

ash --mode local --offline
```

Copy the cache directories to the air-gapped host and export the same two variables
there. Repeat the download at least every 30 days, or the scan fails as stale.

Under `--sandbox`, the sandbox mounts the directory each variable names read-only for
its scanner, wherever it is, including under `$HOME`, which the sandbox otherwise
hides. Only the variable in ASH's own environment grants it: a rules path in a
scanner's options, which the scanned repository can set, is not mounted, and an
empty or relative value grants nothing. A variable naming a file, `/`, `$HOME` or a
directory that holds `$HOME` is not mounted either, with a warning; point it at the
rules directory itself. If semgrep or opengrep still cannot read its rules, it exits 7 and is recorded
`ERROR`, and the scan exits 1.

## Customizing Scan Phases

ASH v3 executes scans in phases:

```bash
# Run only specific phases
ash --phases convert,scan

# Skip report generation
ash --phases convert,scan

# Include inspection phase
ash --phases convert,scan,report,inspect
```

## Using Existing Results

You can generate reports from existing scan results:

```bash
# Use existing results file
ash --use-existing --output-dir /path/to/results

# Generate a specific report format
ash report --format html --output-dir /path/to/results
```

## Interactive Findings Explorer

ASH v3 includes an interactive TUI for exploring findings:

```bash
# Launch the findings explorer
ash inspect findings --output-dir /path/to/results
```

## Container Customization

### Using Alternative Container Runtimes

```bash
# Use Podman instead of Docker
ash --mode container --oci-runner podman

# Use Finch
ash --mode container --oci-runner finch
```

### Custom Container Images

ASH does not publish a container image to a public registry. Building it yourself and
hosting it in your own registry is the recommended posture, so that the provenance and
patching cadence of the image that reads your source code belong to you. See
[Building your own container image](building-your-own-image.md) for the reasoning, the
rebuild cadence it commits you to, and offline builds.

```bash
# Specify a custom container image
export ASH_IMAGE_NAME="my-registry/ash:custom"
ash --mode container
```

### Building Custom Images

```bash
# Build a custom image
ash build-image --build-target ci --custom-containerfile ./my-dockerfile
```

## Advanced Configuration Overrides

```bash
# Complex configuration overrides
ash --config-overrides 'scanners.semgrep.options.rules=["p/ci", "p/owasp-top-ten"]'
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

## Working with Suppressions

### Adding Suppressions via Config Overrides

```bash
# Add a suppression rule
ash --config-overrides 'global_settings.suppressions+=[{"rule_id": "RULE-123", "path": "src/example.py", "reason": "False positive"}]'

# Add a suppression with line range and expiration
ash --config-overrides 'global_settings.suppressions+=[{"rule_id": "RULE-456", "path": "src/*.js", "line_start": 10, "line_end": 15, "reason": "Known issue", "expiration": "2025-12-31"}]'
```

### Inline code suppressions

You can suppress individual findings directly in your source code using
special comments. This is useful when a suppression only applies to a
single line and you want the context to live next to the code.

Two directives are supported:

| Directive | Effect |
|-----------|--------|
| `# ash-ignore: <rule-id> [reason]` | Suppresses the finding on the **same line** as the comment. |
| `# ash-ignore-next-line: <rule-id> [reason]` | Suppresses the finding on the **next line**. |

The directives are case-insensitive. The reason text is optional but
recommended.

```python
# Suppress a specific rule on the same line:
password = os.environ[
    "DB_PASS"
]  # ash-ignore: CKV-SEC-001 loaded from env, not hardcoded

# Suppress a specific rule on the next line:
# ash-ignore-next-line: BANDIT-B105 password variable is a placeholder
password = "changeme"
```

```javascript
// Languages that use // comments (JS, TS, Java, C#, Go):
const key = process.env.KEY; // ash-ignore: SEC-KEY env var is safe

// Or suppress the next line:
// ash-ignore-next-line: SEC-KEY env var is safe
const key = process.env.KEY;
```

Both inline and config-file suppressions use `Kind1.inSource` in the SARIF
output. They are distinguishable by their justification prefix: config
suppressions start with `"(ASH)"` while inline suppressions start with
`"(ASH inline)"`.

### Temporarily Ignoring Suppressions

```bash
# Run a scan ignoring all suppression rules, ignore_paths included
ash --ignore-suppressions

# Useful for verifying if suppressed issues have been fixed
ash --ignore-suppressions --output-dir ./verification-scan
```

## Programmatic Usage

ASH v3 can be used programmatically in Python:

```python
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.core.enums import RunMode, Strategy

# Run a scan
results = run_ash_scan(
    source_dir="/path/to/code",
    output_dir="/path/to/output",
    mode=RunMode.local,
    strategy=Strategy.parallel,
    scanners=["bandit", "semgrep"],
    config_overrides=["scanners.bandit.enabled=true"],
)

# Access scan results
print(f"Found {results.summary_stats.total_findings} findings")
```

## CI/CD Integration

> **Tip**: The examples below use pinned versions (`@v3.7.0`) for reproducibility. You can also use the `v3` floating tag (`@v3`) to always get the latest stable v3.x release, though pinned versions are recommended for CI/CD.

### GitHub Actions

```yaml
name: ASH Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - name: Run ASH scan
        run: ash --mode local
      - name: Upload scan results
        # Also when ASH exits non-zero on findings: without a status function
        # GitHub skips this step after any failed step.
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@v3
        with:
          name: ash-results
          path: |
            .ash/ash_output/reports
            .ash/ash_output/ash_aggregated_results.json
```

### GitLab CI

```yaml
ash-scan:
  image: python:3.10
  script:
    - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
    - ash --mode local
  artifacts:
    paths:
      - .ash/ash_output/reports
      - .ash/ash_output/ash_aggregated_results.json
```

Both examples keep `scanners/` and `converted/` out of the artifact: those hold each tool's raw output, which is not masked.

## Performance Optimization

```bash
# Run scanners in parallel (default)
ash --strategy parallel

# Run scanners sequentially
ash --strategy sequential

# Clean up temporary files after scan
ash --cleanup
```

## Debugging

```bash
# Enable debug logging
ash --debug

# Enable verbose logging
ash --verbose

# Disable progress display
ash --progress false
```

### Scanner Validation

ASH v3 includes comprehensive scanner validation that monitors scanner registration, enablement, and execution throughout the scan process. When debugging scanner issues:

- Check logs for validation warnings about missing or disabled scanners
- Use `--debug` to see detailed validation checkpoint information
- Look for specific reasons why scanners might be disabled (dependencies, configuration, etc.)
- Run the integration verification test: `python verify_integration.py` (if available in your installation)

The validation system includes result completeness validation that ensures all originally registered scanners appear in the final scan results, even if they failed or were disabled. This provides complete visibility into scan coverage and helps identify any scanners that may have been silently dropped during the scan process.

For detailed information about the scanner validation system, see the [Scanner Validation System](../developer-guide/scanner-validation-system.md) developer guide.