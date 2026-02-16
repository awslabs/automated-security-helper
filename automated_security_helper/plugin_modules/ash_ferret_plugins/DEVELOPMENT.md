# Ferret-Scan Plugin Development Guide

This document is for maintainers and developers working on the ASH Ferret-Scan plugin integration. It covers the architecture, integration points, constraints, and maintenance tasks.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [File Structure](#file-structure)
- [Integration Features](#integration-features)
- [ASH Conventions](#ash-conventions)
- [Version Compatibility](#version-compatibility)
- [Unsupported Options](#unsupported-options)
- [Testing](#testing)
- [Documentation](#documentation)
- [Common Maintenance Tasks](#common-maintenance-tasks)
- [Gotchas and Caveats](#gotchas-and-caveats)
- [False Positive Suppression and CI](#false-positive-suppression-and-ci)
- [Bundled Config File Safety](#bundled-config-file-ferret-configyaml-safety)
- [Scanner Return Contract](#scanner-return-contract)
- [ASH Integration Registration](#ash-integration-registration)

## Architecture Overview

The ferret-scan plugin follows ASH's scanner plugin architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                         ASH Orchestrator                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ScannerPluginBase (base class)                │
│  - Provides: _pre_scan, _post_scan, _run_subprocess, etc.       │
│  - Handles: results directory, logging, error handling          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FerretScanScanner (this plugin)               │
│  - Implements: scan(), validate_plugin_dependencies()           │
│  - Handles: config processing, version checking, SARIF output   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ferret-scan CLI (external tool)               │
│  - Invoked via subprocess                                        │
│  - Output: SARIF format to file                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

The primary trust boundary is between the ASH plugin (which validates config and
constructs arguments) and the ferret-scan binary (which is an external subprocess).
The plugin trusts ferret-scan's SARIF output and validates it through Pydantic.

```
┌─────────────────────────────────────────────────────┐
│  ASH Process (trusted)                              │
│  ┌───────────────────────────────────────────────┐  │
│  │  Ferret Plugin (trusted)                      │  │
│  │  - Config validation (Pydantic)               │  │
│  │  - Unsupported options guard                  │  │
│  │  - Argument construction (list, no shell)     │  │
│  │  - SARIF parsing + validation                 │  │
│  └──────────────┬────────────────────────────────┘  │
│                 │ subprocess (list args, no shell)   │
│  ┌──────────────▼────────────────────────────────┐  │
│  │  ferret-scan binary (semi-trusted)            │  │
│  │  - External tool, version-checked             │  │
│  │  - Reads config YAML (user-supplied)          │  │
│  │  - Reads target files (user-supplied)         │  │
│  │  - Writes SARIF output to file                │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

Key security properties:
- No `shell=True` anywhere in the execution path
- Unsupported options blocked before reaching subprocess
- Config file paths validated for existence before passing to ferret-scan
- `--no-color` always appended to prevent ANSI escape injection in reports
- `show_match=true` triggers a runtime WARNING about sensitive data exposure

## File Structure

```
automated_security_helper/
└── plugin_modules/
    └── ash_ferret_plugins/
        ├── __init__.py              # Plugin registration (ASH_SCANNERS list)
        ├── ferret_scanner.py        # Main scanner implementation
        ├── ferret-config.yaml       # Default bundled configuration
        ├── README.md                # User documentation
        └── DEVELOPMENT.md           # This file (maintainer docs)

tests/
└── unit/
    └── plugin_modules/
        └── ash_ferret_plugins/
            ├── __init__.py          # Test package marker
            ├── conftest.py          # Shared test fixtures
            └── test_ferret_scanner.py  # Unit tests (66 tests)

docs/
└── content/
    └── docs/
        └── plugins/
            └── community/
                ├── index.md         # Community plugins index (update when adding)
                └── ferret-scan-plugin.md  # Full user documentation
```

## Integration Features

### 1. SARIF Output (Required by ASH)

The plugin always outputs SARIF format, which is required by ASH for result aggregation:

```python
self.args = ToolArgs(
    format_arg="--format",
    format_arg_value="sarif",  # Always SARIF - required by ASH
    ...
)
```

**Why**: ASH aggregates results from multiple scanners into a unified report. SARIF is the standard format that enables this aggregation.

### 2. Debug/Verbose Handling

Bare `debug` and `verbose` options are blocked to avoid confusion with ASH's own
`--debug`/`--verbose` flags. Instead, use `ferret_debug` and `ferret_verbose` to
control ferret-scan's own log output independently of ASH logging.

- `ferret_debug: true` → passes `--debug` to ferret-scan (shows preprocessing and validation flow)
- `ferret_verbose: true` → passes `--verbose` to ferret-scan (shows detailed finding info)

**Why the prefix**: ASH's logger level is always TRACE (5). Actual filtering happens at the
RichHandler (console) level, so ASH's `--debug`/`--verbose` flags don't propagate to plugins.
The `ferret_` prefix makes it explicit that these control the ferret-scan binary, not ASH.

### 3. Version Compatibility Checking

The plugin validates ferret-scan version compatibility during dependency validation:

```python
# Version constants (update when ferret-scan releases breaking changes)
MIN_SUPPORTED_VERSION = "0.1.0"
MAX_SUPPORTED_VERSION = "2.0.0"
DEFAULT_VERSION_CONSTRAINT = ">=0.1.0,<2.0.0"
RECOMMENDED_VERSION = "1.0.0"
```

**Behavior**:
- Version check runs during `validate_plugin_dependencies()`
- Incompatible versions log a warning but don't block execution
- Users can bypass with `skip_version_check: true` in config

### 4. Config File Discovery

The plugin searches for ferret-scan config files in this order:

1. Explicitly specified via `config_file` option
2. Auto-discovery in source directory:
   - `ferret.yaml`, `ferret.yml`
   - `.ferret.yaml`, `.ferret.yml`
   - `.ash/ferret.yaml`, `.ash/ferret-scan.yaml`
3. Default config bundled with plugin (`ferret-config.yaml`)

### 5. Unsupported Options Validation

A Pydantic model validator prevents use of incompatible options:

```python
UNSUPPORTED_FERRET_OPTIONS = {
    "format": "ASH requires SARIF format...",
    "debug": "Use 'ferret_debug: true' instead...",
    "verbose": "Use 'ferret_verbose: true' instead...",
    # ... more options
}

@model_validator(mode="before")
@classmethod
def validate_no_unsupported_options(cls, data: Any) -> Any:
    """Validate that no unsupported options are being used."""
    if isinstance(data, dict):
        for key in data.keys():
            normalized_key = key.lower().replace("-", "_")
            if normalized_key in UNSUPPORTED_FERRET_OPTIONS:
                raise ValueError(f"Unsupported option '{key}'...")
    return data
```

## ASH Conventions

### Hardcoded by Plugin (Do NOT configure at plugin level)

| Feature | Plugin Behavior |
|---------|-----------------|
| Output format | Always SARIF (hardcoded via `--format sarif`) |
| Color output | Always `--no-color` (ASH handles formatting) |

### Managed by ASH Framework (not plugin-controlled)

| Feature | ASH Flag | Notes |
|---------|----------|-------|
| Suppressions | `.ash/suppressions.yaml` | ASH manages centrally |
| Output directory | `--output-dir` | Uses `.ash/ash_output/scanners/ferret-scan/` |
| Offline mode | `ASH_OFFLINE=true` | Respects environment variable |

### Plugin-Specific Options (CAN be configured)

| Option | Description | Default |
|--------|-------------|---------|
| `confidence_levels` | Filter by confidence: high, medium, low | `"all"` |
| `checks` | Specific checks to run | `"all"` |
| `recursive` | Scan directories recursively | `true` |
| `config_file` | Path to ferret config file | Auto-discovered |
| `profile` | Profile name from config file | None |
| `exclude_patterns` | Patterns to exclude from scanning | `[]` |
| `show_match` | Display matched text in findings | `false` |
| `enable_preprocessors` | Extract text from documents | `true` |
| `ferret_debug` | Enable ferret-scan's own debug logging (preprocessing/validation flow) | `false` |
| `ferret_verbose` | Enable ferret-scan's own verbose output (detailed finding info) | `false` |
| `tool_version` | Version constraint for installation | `">=0.1.0,<2.0.0"` |
| `skip_version_check` | Bypass version validation | `false` |

Note: Bare `debug` and `verbose` are blocked to avoid confusion with ASH's `--debug`/`--verbose` flags. Use the `ferret_` prefixed versions instead.

## Version Compatibility

### Updating Version Constants

When ferret-scan releases a new version:

1. **Test the new version** with the plugin
2. **Update constants** in `ferret_scanner.py`:

```python
# If new version is compatible:
MAX_SUPPORTED_VERSION = "3.0.0"  # Bump to next major
DEFAULT_VERSION_CONSTRAINT = ">=0.1.0,<3.0.0"

# If new version has breaking changes:
# Add version-specific handling in the code
```

3. **Update tests** in `test_ferret_scanner.py` if needed
4. **Update documentation** in README.md and ferret-scan-plugin.md

### Version Helper Functions

```python
parse_version("1.2.3")  # Returns (1, 2, 3)
compare_versions("1.0.0", "2.0.0")  # Returns -1 (v1 < v2)
is_version_compatible("1.5.0", "1.0.0", "2.0.0")  # Returns True
```

## Unsupported Options

### Adding New Unsupported Options

If ferret-scan adds a new option that conflicts with ASH:

1. **Add to `UNSUPPORTED_FERRET_OPTIONS`** dictionary:

```python
UNSUPPORTED_FERRET_OPTIONS = {
    # ... existing options ...
    "new_option": "Explanation of why this option is not supported in ASH.",
}
```

2. **Add a test** in `TestFerretScanScannerUnsupportedOptions`:

```python
def test_unsupported_option_new_option_raises_error(self):
    """Test that using 'new_option' raises an error."""
    with pytest.raises(ValueError) as exc_info:
        FerretScannerConfigOptions(new_option=True)
    
    assert "Unsupported option 'new_option'" in str(exc_info.value)
```

3. **Update documentation** in README.md

### Categories of Unsupported Options

| Category | Options | Reason |
|----------|---------|--------|
| Output format | `format`, `output_format` | ASH requires SARIF |
| Web server | `web`, `port` | Not applicable for batch scanning |
| Redaction | `enable_redaction`, `redaction_*`, `memory_scrub` | Post-processing, not scanning |
| Suppressions | `generate_suppressions`, `show_suppressed`, `suppressions_file` | ASH manages centrally |
| Utility modes | `extract_text` | Not a scanning mode |
| Logging | `debug`, `verbose` | Use `ferret_debug`/`ferret_verbose` instead (avoids confusion with ASH flags) |

## Testing

### Running Tests

```bash
# Run all ferret plugin tests
uv run pytest tests/unit/plugin_modules/ash_ferret_plugins/ -v --no-cov -n 0

# Run specific test class
uv run pytest tests/unit/plugin_modules/ash_ferret_plugins/test_ferret_scanner.py::TestFerretScannerConfig -v

# Run with coverage
uv run pytest tests/unit/plugin_modules/ash_ferret_plugins/ -v --cov=automated_security_helper.plugin_modules.ash_ferret_plugins
```

### Test Structure

The tests are organized into classes by functionality:

| Test Class | Purpose |
|------------|---------|
| `TestFerretScannerConfig` | Configuration initialization |
| `TestFerretScanScannerUnsupportedOptions` | Unsupported option validation |
| `TestFerretScannerConfigProcessing` | Config to CLI argument translation |
| `TestFerretScanScannerASHConventions` | ASH convention compliance |
| `TestFerretScannerConfigFileDiscovery` | Config file auto-discovery |
| `TestFerretScanScannerDependencies` | Dependency validation |
| `TestFerretScanScannerArgumentResolution` | CLI argument building |
| `TestFerretScanScannerScanning` | Scan workflow |
| `TestFerretScanScannerTargetValidation` | Target directory validation |
| `TestFerretScanScannerErrorHandling` | Error handling |
| `TestFerretScanScannerVersionSupport` | Version compatibility |

### Key Test Fixtures (in `conftest.py`)

```python
@pytest.fixture
def mock_plugin_context(tmp_path):
    """Creates a mock PluginContext with temp directories."""

@pytest.fixture
def default_ferret_config():
    """Returns default FerretScannerConfig."""

@pytest.fixture
def custom_ferret_config():
    """Returns FerretScannerConfig with custom options."""

@pytest.fixture
def mock_sarif_response():
    """Returns a valid SARIF response dict."""

@pytest.fixture
def mock_ferret_config_file(mock_plugin_context):
    """Creates a ferret.yaml file in the source directory."""
```

## Documentation

### Files to Update

When making changes to the plugin:

| Change Type | Files to Update |
|-------------|-----------------|
| New option | `ferret_scanner.py`, `README.md`, `ferret-scan-plugin.md`, `test_ferret_scanner.py` |
| New unsupported option | `ferret_scanner.py`, `README.md`, `test_ferret_scanner.py` |
| Version update | `ferret_scanner.py`, `README.md`, `ferret-scan-plugin.md` |
| Bug fix | `ferret_scanner.py`, `test_ferret_scanner.py` |
| Architecture change | All files including `DEVELOPMENT.md` |

### Documentation Locations

- **User docs**: `automated_security_helper/plugin_modules/ash_ferret_plugins/README.md`
- **Full docs**: `docs/content/docs/plugins/community/ferret-scan-plugin.md`
- **Community index**: `docs/content/docs/plugins/community/index.md`
- **Developer docs**: `automated_security_helper/plugin_modules/ash_ferret_plugins/DEVELOPMENT.md` (this file)

## Common Maintenance Tasks

### Task 1: Update for New ferret-scan Version

1. Install the new version: `pip install ferret-scan==X.Y.Z`
2. Run the test suite: `uv run pytest tests/unit/plugin_modules/ash_ferret_plugins/ -v`
3. If tests pass, update version constants if needed
4. If tests fail, add version-specific handling or update tests

### Task 2: Add a New Supported Option

1. Add field to `FerretScannerConfigOptions` class:
   ```python
   new_option: Annotated[
       bool,
       Field(description="Description of the option"),
   ] = False
   ```

2. Add processing in `_process_config_options()`:
   ```python
   if options.new_option:
       self.args.extra_args.append(
           ToolExtraArg(key="--new-option", value=None)
       )
   ```

3. Add tests in `test_ferret_scanner.py`
4. Update documentation

### Task 3: Handle Breaking Change in ferret-scan

1. Identify the breaking change
2. Add version-specific handling:
   ```python
   if compare_versions(self.tool_version, "2.0.0") >= 0:
       # New behavior for v2.0.0+
   else:
       # Old behavior
   ```
3. Update version constants
4. Update tests and documentation

## Gotchas and Caveats

### 1. Subprocess Mocking in Tests

When testing the scan workflow, you must mock multiple methods:

```python
with patch.object(scanner, '_pre_scan', return_value=True), \
     patch.object(scanner, '_post_scan'), \
     patch.object(scanner, '_run_subprocess') as mock_subprocess, \
     patch.object(scanner, '_plugin_log'), \
     patch("builtins.open", mock_open(read_data=json.dumps(mock_sarif_response))), \
     patch("pathlib.Path.exists", return_value=True):
```

**Why**: The scanner uses subprocess to run ferret-scan, and we don't want to actually execute it in unit tests.

### 2. Version Check During Dependency Validation

The version check runs during `validate_plugin_dependencies()`, not during scanning. This means:

- Version warnings appear early in the scan process
- Incompatible versions don't block execution (just warn)
- The `skip_version_check` option must be set before validation

### 3. Config File Discovery Order

The config file discovery has a specific priority order. If a user specifies `config_file` but it doesn't exist, the plugin will NOT fall back to auto-discovery - it will return `None` and log a warning.

### 4. Debug/Verbose: ferret_ Prefix Required

Bare `debug` and `verbose` are blocked to avoid confusion with ASH's `--debug`/`--verbose`.
Use `ferret_debug: true` and `ferret_verbose: true` to control ferret-scan's own output.

ASH's logger level is always TRACE (5) — actual filtering happens at the RichHandler level,
so ASH's flags don't propagate to plugins. The `ferret_` prefix makes the intent explicit.
See `docs/_investigation/log-level-file-handler-disclosure.md` for full details.

### 5. SARIF Output File Location

The SARIF output file is written to:
```
{results_dir}/{target_type}/ferret-scan.sarif
```

For example: `.ash/ash_output/scanners/ferret-scan/source/ferret-scan.sarif`

### 6. Edge Case: Empty and Missing Target Directories

**Empty directory**: The plugin invokes ferret-scan, which produces a SARIF file with `results: null`. ASH completes with 0 actionable findings. No crash, no error — graceful skip.

**Missing directory**: ASH itself throws `FileNotFoundError` before any plugin is invoked (the framework calls `os.chdir(source_dir)` in `run_ash_scan.py`). This is an ASH-level issue, not a plugin concern. The plugin's own `scan()` method also guards against this by returning `True` (skip) for non-existent paths, but that code path is never reached when running through `ash scan`.

### 7. Pydantic Model Validator Timing

The `validate_no_unsupported_options` validator runs in `mode="before"`, meaning it validates the raw input dict before Pydantic processes it. This catches unsupported options even if they're not defined as fields.

### 8. Extra Args Accumulation

The `_process_config_options()` method appends to `self.args.extra_args`. To prevent accumulation when called multiple times, the method clears `self.args.extra_args = []` at the start of each invocation. This was added to handle the case where `_resolve_arguments` calls `_process_config_options`, and the base class `model_post_init` also calls it.

### 9. Exclude Patterns: Simple Names, Not Globs

Ferret-scan's `--exclude` flag uses simple directory/file name matching, not glob
patterns. Use `.venv` instead of `.venv/**`. The plugin joins all exclude patterns
into a single comma-separated `--exclude` value (e.g., `--exclude .venv,.git,*.pyc`).

### 10. Bundled Config File Overrides CLI `--exclude`

When the bundled `ferret-config.yaml` is loaded via `--config`, ferret-scan's config
file settings can override CLI arguments including `--exclude`. This means exclude
patterns set via ASH plugin options may be silently ignored if `use_default_config`
is `true` (the default). Set `use_default_config: false` in the ASH config to ensure
CLI arguments take full effect.

### 11. `SECRET-SECRET-KEYWORD` Triggers on Variable Names, Not Values

The `SECRET-SECRET-KEYWORD` detection rule matches on variable/key **names** like
`API_KEY`, `SECRET`, `PASSWORD`, `TOKEN`, `PRIVATE_KEY`, etc. — regardless of the
assigned value. Even `API_KEY` `= "placeholder"` or `API_KEY` `= "test"` will be flagged.
The detector matches the keyword name next to an assignment operator.

This applies to Python source, YAML config, markdown documentation, and any other
scanned file type. The fix is to rename the variable to something neutral (e.g.,
`SETTING`, `CONFIG_VALUE`, `TEST_PARAM`) in test fixtures and documentation examples.
If renaming isn't practical (e.g., documentation explaining the problem), add a
suppression with line number to `.ash/.ash_community_plugins.yaml`.

## False Positive Suppression and CI

### Suppression Strategy

ASH supports suppressions in the config file under `global_settings.suppressions`.
For the ferret-scan community plugin, suppressions go in
`.ash/.ash_community_plugins.yaml` (not `.ash/.ash.yaml`).

Suppressions with `line_start`/`line_end` fields are the preferred approach for
documentation examples that intentionally contain triggering patterns. For test
fixtures and source code, eliminating the trigger from source is preferred when
practical.

### Two-Pronged Approach

| Situation | Approach |
|-----------|----------|
| Test fixtures with secret-like variable names | Rename to neutral names (`SETTING`, `CONFIG_VALUE`, `TEST_PARAM`) |
| Documentation explaining the detection pattern | Add a suppression with `line_start`/`line_end` to `.ash/.ash_community_plugins.yaml` |
| Hardcoded PII in test data generators | Use generator functions with `random.seed()` for reproducibility |
| Hex-like strings that trigger entropy detectors | Generate values at runtime, not as string literals in source |

### Adding a Suppression

Add entries under `global_settings.suppressions` in `.ash/.ash_community_plugins.yaml`:

```yaml
global_settings:
  suppressions:
    - path: automated_security_helper/plugin_modules/ash_ferret_plugins/DEVELOPMENT.md
      rule_id: SECRET-SECRET-KEYWORD
      line_start: 501
      line_end: 501
      reason: Documentation example showing the SECRET-SECRET-KEYWORD detection pattern.
```

Fields:
- `path`: Relative path to the file (supports fnmatch patterns)
- `rule_id`: The rule ID to suppress (e.g., `SECRET-SECRET-KEYWORD`)
- `line_start` / `line_end`: Line range for precision (strongly recommended)
- `reason`: Why this suppression exists
- `expiration`: Optional expiry date (e.g., `"2026-06-01"`)

When you add or move a suppression, update the `line_start`/`line_end` values if
the target content shifts. The validation script (check #10) verifies that all
SECRET-SECRET-KEYWORD hits in ferret plugin files have matching suppressions.

### Test Data Generator (`scripts/generate_test_docx.py`)

The synthetic test data docx is generated by `scripts/generate_test_docx.py`. All
PII-like data (credit cards, SSNs, passports, phone numbers, names) is produced by
generator functions seeded with `random.seed(42)` for reproducibility. No hardcoded
sensitive-looking strings appear in the Python source.

To regenerate the test data:
```bash
uv run python scripts/generate_test_docx.py
```

The generated file (`tests/test_data/scanners/ferret-scan/synthetic-pii-test.docx`)
is in `tests/test_data/`, which is excluded from scanning via ASH's `ignore_paths`
and the ferret-scan `exclude_patterns` config.

### Keeping Suppressions in Sync

When editing files that have line-specific suppressions, verify the line numbers
are still correct. The validation script's check #10 (`SUPPRESSION-COVERAGE`) will
catch suppressions that have drifted out of alignment.

### Pre-Push Validation Script (`scripts/validate_ferret_plugin.py`)

Run this before pushing to catch known CI failure patterns locally:

```bash
uv run python scripts/validate_ferret_plugin.py
```

The script checks for:

| Check | What it catches |
|-------|-----------------|
| `SECRET-SECRET-KEYWORD` | Variable names like `API_KEY`, `PASSWORD`, `TOKEN` that trigger secret detection regardless of value |
| `HARDCODED-PII` | Credit card numbers or SSNs as string literals in source |
| `HEX-HIGH-ENTROPY-STRING` | Long hex strings (32+ chars) that trigger entropy detectors |
| `EXCLUDE-GLOB-SYNTAX` | Exclude patterns using `**/` glob syntax instead of simple names (ferret-scan doesn't support globs) |
| `TEST-COUNT` | Ensures the unit test count hasn't regressed below 67 |
| `WINDOWS-PATH` | `str(Path)` instead of `Path.as_posix()` in CLI argument building — backslashes break ferret-scan on Windows |
| `EXCLUDE-MULTIPLE-ARGS` | Looping over exclude patterns to append individual `--exclude` args instead of joining into one comma-separated value |
| `FERRET-IN-ASH-YAML` | ferret-scan registered in `.ash.yaml` instead of `.ash_community_plugins.yaml` (it's a community plugin) |
| `CONFIG-OVERRIDE-EXCLUDES` | `exclude_patterns` set but `use_default_config` not `false` — the bundled config will silently override CLI excludes |
| `SUPPRESSION-COVERAGE` | SECRET-SECRET-KEYWORD hits in ferret plugin files must have matching suppressions with `line_start`/`line_end` in `.ash_community_plugins.yaml` |

These checks mirror what CI's `--ignore-suppressions` scan will flag. Passing this
script locally means no surprises on the PR.

The script also runs automatically as a unit test (`TestFerretPluginValidation::test_validate_ferret_plugin_passes`),
so any regression will fail the test suite in CI.

#### Adding a New Check

When you discover a new CI failure pattern, add a check to the script:

1. Add a new numbered section in `scripts/validate_ferret_plugin.py` following the existing pattern
2. Define a regex or file-scanning function
3. Decorate it with `@check("CHECK-NAME: description")`
4. Use `fail(check_name, filepath, line_num, message)` to report issues
5. Update `EXPECTED_MIN_TESTS` if you added new unit tests
6. Update this table in DEVELOPMENT.md

Example skeleton:

```python
# ----------------------------------------------------------------------------
# 10. Your new check description
# ----------------------------------------------------------------------------

@check("NEW-CHECK: brief description of what it catches")
def check_new_thing():
    for filepath in ALL_FILES:
        if filepath.suffix not in (".py", ".md", ".yaml", ".yml"):
            continue
        lines = filepath.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines, 1):
            if some_bad_pattern.search(line):
                fail(
                    "NEW-CHECK",
                    filepath.relative_to(PROJECT_ROOT),
                    i,
                    f"Description of what's wrong: {line.strip()[:80]}",
                )
```

Run `uv run python scripts/validate_ferret_plugin.py` to verify your new check works,
then run `uv run pytest tests/unit/plugin_modules/ash_ferret_plugins/ -v --no-cov -n 0`
to confirm the test suite still passes.

## Bundled Config File (`ferret-config.yaml`) Safety

The plugin ships a `ferret-config.yaml` that is passed to the ferret-scan binary
via `--config`. This file is consumed by ferret-scan itself — it is **not** parsed
by the ASH Pydantic model. The two config layers are completely independent:

| Layer | File / Source | Validated by | Contains |
|-------|--------------|-------------|----------|
| ASH plugin options | `.ash/.ash.yaml` → `scanners.ferret-scan.options` | `FerretScannerConfigOptions` (Pydantic) | Plugin behaviour: confidence, checks, recursive, profile, etc. |
| ferret-scan tool config | `ferret-config.yaml` (passed via `--config`) | ferret-scan binary | Tool behaviour: validators, patterns, profiles, defaults, redaction, suppressions |

### Why "unsupported" options in the config file are safe

The config file contains options that are listed as unsupported in the ASH plugin
(`format`, `debug`, `verbose`, `show_suppressed`, `generate_suppressions`, etc.).
These are safe because:

1. **CLI flags override config file values.** The plugin always passes `--format sarif`
   and `--no-color` on the command line. ferret-scan's CLI flags take precedence over
   config file defaults and profile values.

2. **The Pydantic validator only fires on ASH plugin options.** The
   `validate_no_unsupported_options` model validator runs on the dict passed to
   `FerretScannerConfigOptions` (i.e., what's under `scanners.ferret-scan.options`
   in `.ash.yaml`). It never sees the contents of `ferret-config.yaml`.

3. **Verified across all profiles.** Every profile in the bundled config (including
   those with `format: text`, `format: yaml`, `format: junit`, `debug: true`,
   `show_suppressed: true`) produces valid SARIF output when the plugin's
   `--format sarif` CLI flag is applied.

### Updating the bundled config from upstream

It is safe to copy the default config directly from the
[ferret-scan public repo](https://github.com/awslabs/ferret-scan/blob/main/examples/ferret.yaml),
provided that:

1. **New ferret-scan CLI options** that conflict with ASH conventions are added to
   `UNSUPPORTED_FERRET_OPTIONS` in `ferret_scanner.py` (so users can't set them
   via ASH plugin config).

2. **New config-file-only options** (validators, patterns, preprocessors, etc.)
   require no plugin changes — ferret-scan handles them transparently.

3. **Active `internal_urls` patterns** are reviewed for appropriateness. The upstream
   example may include cloud-provider-specific patterns (AWS S3, corporate network,
   etc.) that should be commented out or customized for the target audience. The
   bundled config keeps AWS S3 and generic corporate patterns active; all others
   are commented out with instructions.

4. **Profiles with `format:` values** other than `sarif` are fine — the CLI
   `--format sarif` always wins. No need to strip them.

## Manual Testing Guide

Before releasing changes to the ferret-scan plugin, perform these manual tests to verify end-to-end functionality.

### Test Data Location

The project includes comprehensive test data for ferret-scan at:
```
tests/test_data/scanners/ferret-scan/
├── sample.txt                # Text file with various sensitive data patterns
└── synthetic-pii-test.docx   # Synthetic document for preprocessor testing (generated, Apache-2.0)
```

The `sample.txt` file contains examples across confidence levels:
- **High confidence**: Valid credit cards (Visa, MasterCard, AMEX, Discover, JCB), valid passports (US, UK, Canadian, EU, MRZ)
- **Medium confidence**: Test cards, suspicious passport patterns
- **Low confidence**: Invalid checksums, repeated digits, wrong lengths
- **False positives**: SKUs, serial numbers, phone numbers, dates, code snippets
- **Edge cases**: Mathematical constants, formatting variations, mixed contexts
- **International examples**: European, Asian, North American formats

### Prerequisites

```bash
# Ensure ferret-scan is installed
pip install ferret-scan
ferret-scan --version
```

Ensure the plugin is enabled in `.ash/.ash.yaml`:
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins
```

### Test Scenarios

#### 1. Basic Plugin Discovery

```bash
# Verify plugin is discovered by ASH
uv run ash plugin list | grep -i ferret
# Expected: ferret-scan should appear in the list
```

#### 2. Basic Scan with Test Data

```bash
# Run a basic scan using the project's test data
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan

# Check output
ls -la .ash/ash_output/scanners/ferret-scan/source/
# Expected: ferret-scan.sarif file should exist with findings
```

#### 3. SARIF Output Verification

```bash
# Verify SARIF format
cat .ash/ash_output/scanners/ferret-scan/source/ferret-scan.sarif | jq '.version'
# Expected: "2.1.0"

# Check for findings (should find credit cards, passports, SSNs, etc.)
cat .ash/ash_output/scanners/ferret-scan/source/ferret-scan.sarif | jq '.runs[0].results | length'
# Expected: > 0 (should find many sensitive data patterns)

# View finding types
cat .ash/ash_output/scanners/ferret-scan/source/ferret-scan.sarif | jq '[.runs[0].results[].ruleId] | unique'
# Expected: Various rule IDs for credit cards, passports, etc.
```

#### 4. Ferret-Scan Debug Mode (ferret_debug)

```bash
# Enable ferret-scan's own debug output (independent of ASH logging)
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan \
    --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins \
    -o ferret_debug=true 2>&1
# Expected: ferret-scan debug output showing preprocessing and validation flow
```

#### 5. Ferret-Scan Verbose Mode (ferret_verbose)

```bash
# Enable ferret-scan's own verbose output (independent of ASH logging)
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan \
    --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins \
    -o ferret_verbose=true 2>&1
# Expected: ferret-scan verbose output with detailed finding info
```

#### 6. Custom Configuration Options

```bash
# Test with high confidence only
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan \
    --config-overrides "scanners.ferret-scan.options.confidence_levels=high"
# Expected: Should only show high-confidence findings (fewer results)

# Test with specific checks
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan \
    --config-overrides "scanners.ferret-scan.options.checks=CREDIT_CARD"
# Expected: Should only show credit card findings
```

#### 7. Version Compatibility Warning

```bash
# If you have an incompatible version installed, verify warning is shown
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan 2>&1 | grep -i "version"
```

#### 8. Unsupported Option Error

```bash
# Test that bare 'debug' is blocked (must use ferret_debug)
cat > /tmp/test-ash-config.yaml << 'EOF'
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_ferret_plugins
scanners:
  ferret-scan:
    enabled: true
    options:
      debug: true  # This should fail — use ferret_debug instead
EOF

uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --config /tmp/test-ash-config.yaml 2>&1
# Expected: Error message about unsupported 'debug' option, suggesting ferret_debug
rm /tmp/test-ash-config.yaml
```

#### 9. Empty Directory Handling

```bash
mkdir -p /tmp/empty-test-dir
uv run ash scan --source-dir /tmp/empty-test-dir --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins --no-aggregated-results 2>&1
# Expected: ferret-scan completes with 0 findings, SARIF has results: null, no crash
rmdir /tmp/empty-test-dir
```

#### 9a. Missing Directory Handling

```bash
uv run ash scan --source-dir /tmp/this-does-not-exist --ash-plugin-modules automated_security_helper.plugin_modules.ash_ferret_plugins --no-aggregated-results 2>&1
# Expected: ASH framework throws FileNotFoundError (os.chdir fails before plugin runs)
# This is an ASH-level issue, not a plugin concern
```

#### 10. Missing Binary Handling

```bash
# Temporarily rename ferret-scan binary
FERRET_PATH=$(which ferret-scan)
# Rename it, then run:
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan 2>&1
# Expected: Clear error about missing ferret-scan binary
# Remember to restore the binary!
```

#### 11. Profile Usage

```bash
# Test using a profile from the default config
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan \
    --config-overrides "scanners.ferret-scan.options.profile=quick"
# Expected: Should use the 'quick' profile settings (high confidence only)
```

#### 12. ASH Report Integration

```bash
# Verify ferret-scan results are included in aggregated ASH report
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan
cat .ash/ash_output/reports/ash.sarif | jq '.runs[] | select(.tool.driver.name == "ferret-scan")'
# Expected: ferret-scan run should be present in aggregated report
```

#### 13. Combined with Other Scanners

```bash
# Run ferret-scan alongside other scanners
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan,bandit
# Expected: Both scanners should run and results should be aggregated
```

#### 14. Document Preprocessing (DOCX)

```bash
# Test text extraction from Office documents
uv run ash scan --source-dir tests/test_data/scanners/ferret-scan --scanners ferret-scan \
    --config-overrides "scanners.ferret-scan.options.enable_preprocessors=true"
# Expected: Should scan both sample.txt and extract text from synthetic-pii-test.docx
```

### Quick Smoke Test Script

```bash
#!/bin/bash
# Save as test-ferret-plugin.sh
# Assumes plugin is enabled in .ash/.ash.yaml

set -e

echo "=== Ferret Plugin Smoke Test ==="

# Use project test data
TEST_DIR="tests/test_data/scanners/ferret-scan"
OUTPUT_DIR=".ash/ash_output"

echo "Test data directory: $TEST_DIR"

# Clean previous output
rm -rf "$OUTPUT_DIR"

# Run scan
echo "Running ASH scan..."
uv run ash scan --source-dir "$TEST_DIR" --scanners ferret-scan

# Verify output
if [ -f "$OUTPUT_DIR/scanners/ferret-scan/source/ferret-scan.sarif" ]; then
    echo "✓ SARIF output file created"
    
    FINDINGS=$(cat "$OUTPUT_DIR/scanners/ferret-scan/source/ferret-scan.sarif" | jq '.runs[0].results | length')
    echo "✓ Found $FINDINGS findings"
    
    if [ "$FINDINGS" -gt 0 ]; then
        echo "✓ Smoke test PASSED"
        
        # Show summary of finding types
        echo ""
        echo "Finding types detected:"
        cat "$OUTPUT_DIR/scanners/ferret-scan/source/ferret-scan.sarif" | jq -r '[.runs[0].results[].ruleId] | group_by(.) | map({rule: .[0], count: length}) | .[] | "  \(.rule): \(.count)"'
    else
        echo "✗ No findings detected (expected many)"
        exit 1
    fi
else
    echo "✗ SARIF output file not found"
    exit 1
fi

echo ""
echo "=== Test Complete ==="
```

### Cleanup

```bash
# Remove ASH output (test data is part of the project, don't delete it)
rm -rf .ash/ash_output
```

## Scanner Return Contract

The `scan()` return type convention is not formally documented in ASH but is
consistent across all built-in and community scanners (surveyed: bandit, cdk-nag,
cfn-nag, checkov, detect-secrets, grype, npm-audit, opengrep, semgrep, syft,
snyk-code, trivy-repo). This plugin follows the same contract.

| Return Value | Meaning | `scan_phase.py` Handling |
|---|---|---|
| `SarifReport` | Happy path — validated SARIF results | Full processing: path sanitization, suppressions, metrics extraction |
| `True` | Nothing to scan (empty dir, no scannable files) | Falls through all `isinstance` checks; container keeps defaults (no error, no findings) |
| `False` | `_pre_scan()` failed or dependencies not satisfied | Falsy → logs "plugin is missing dependencies", sets `ScannerStatus.MISSING` |
| `None` | Results file missing or unparseable output | Sets `status = "failed"` with error "Scanner returned None" |
| raw `dict` | JSON parsed but SARIF validation failed — fallback | Checks for `"status": "failed"`, then tries `severity_counts` or `findings` extraction |
| `raise ScannerError` | Fatal/unrecoverable failure | Caught by exception handler → structured error dict with stack trace |

### Standard flow

```
1. Empty/missing target?     → return True
2. _pre_scan() failed?       → return False
3. Dependencies not met?     → return False
4. Run subprocess
5. _post_scan()
6. Results file missing?     → return None (bare return)
7. json.load() + SarifReport.model_validate()
   ├─ Success               → return SarifReport
   ├─ JSONDecodeError       → return None (bare return)
   └─ Other Exception       → return raw dict from json.load()
8. Outer exception           → raise ScannerError
```

### Key distinctions

- **`None` vs `False`**: `False` → `ScannerStatus.MISSING` (scanner couldn't run).
  `None` → `status = "failed"` (scanner ran but produced no usable output).
  These are different statuses in the framework.

- **`True` is a silent no-op**: `True` is not `None`, not falsy, not a `SarifReport`,
  and not a `dict`. It falls through every `isinstance` check and the container keeps
  its default state. Every scanner uses this for "nothing to scan" and the framework
  tolerates it.

- **Raw dict fallback is intentional**: When `json.load()` succeeds but
  `SarifReport.model_validate()` fails, returning the raw dict preserves data for
  downstream processing. `scan_phase.py` will attempt to extract `severity_counts`
  or iterate `findings` from it.

### What NOT to return

Ad-hoc dicts like `{"findings": [], "errors": [...]}` without `"status": "failed"`
will be treated as a successful scan with zero findings by `scan_phase.py`. Use
`return` (None) instead — the framework correctly marks the container as failed.

## ASH Integration Registration

When adding this plugin to an ASH installation (or contributing it upstream), three
files outside the plugin directory must be updated. Both the Snyk and Trivy community
plugins follow this same pattern.

### 1. Register in `.ash/.ash_community_plugins.yaml`

Add the plugin module to `ash_plugin_modules`:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_snyk_plugins
  - automated_security_helper.plugin_modules.ash_trivy_plugins
  - automated_security_helper.plugin_modules.ash_ferret_plugins   # <-- add
```

Add a scanner config block under `scanners:`:

```yaml
scanners:
  ferret-scan:
    enabled: true
    options:
      confidence_levels: "high"
      checks: "CREDIT_CARD,SECRETS,SSN,PASSPORT"
      recursive: true
      use_default_config: false
      exclude_patterns:
        - ".venv"
        - "tests/test_data"
        - ".ash/ash_output"
        - ".git"
        - "__pycache__"
        - "*.pyc"
```

> **Why `use_default_config: false`**: The bundled `ferret-config.yaml` is a
> comprehensive reference config. When loaded via `--config`, ferret-scan's config
> file settings can override CLI arguments like `--exclude`. Disabling it gives
> full control to the ASH plugin options above.

> **Why simple directory names in `exclude_patterns`**: Ferret-scan's `--exclude`
> flag uses simple name matching, not glob patterns. Use `.venv` instead of
> `.venv/**`. Patterns are joined into a single comma-separated `--exclude` value.

### 2. Update CI workflow (`.github/workflows/ash-repo-scan-validation.yml`)

Add a `pip install ferret-scan` step in the "Install Community Plugin Tools" block,
alongside the Snyk and Trivy installs:

```yaml
# Install ferret-scan (cross-platform via pip)
echo "Installing ferret-scan..."
pip install ferret-scan

# Verify ferret-scan installation
ferret-scan --version
echo "ferret-scan installation completed!"
```

### 3. Update community plugin index (`docs/content/docs/plugins/community/index.md`)

Add ferret-scan to the "Available Community Plugins" list:

```markdown
- **[Ferret Scan Plugin](ferret-scan-plugin.md)** - Integrates Ferret Scan for
  comprehensive sensitive data detection (credit cards, passports, SSNs, API keys,
  secrets, and more)
```

## Related Resources

- [ferret-scan GitHub Repository](https://github.com/awslabs/ferret-scan)
- [ASH Plugin Development Guide](../../../docs/content/docs/plugins/development-guide.md)
- [ASH Scanner Plugin Architecture](../../../docs/content/docs/plugins/scanner-plugins.md)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
