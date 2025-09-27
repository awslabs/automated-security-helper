# Version Management System

This document describes the new automated version management system for the Automated Security Helper project. The system ensures that version information is centralized in `pyproject.toml` and automatically propagated to all documentation and code references.

## Overview

The version management system solves the problem of having to manually update version numbers in multiple files when releasing new versions. Now, you only need to update the version in one place - `pyproject.toml` - and all other references are automatically updated.

## Architecture

### Core Components

1. **Version Management Utility** (`automated_security_helper/utils/version_management.py`)
   - Centralized version detection from `pyproject.toml`
   - Fallback to installed package metadata
   - Version updating functionality

2. **Template System** (`scripts/version_template_manager.py`)
   - Converts documentation files to templates with version placeholders
   - Generates final documentation from templates
   - Manages `{{VERSION}}` placeholders

3. **Version Bump Script** (`scripts/version_bump.py`)
   - Semantic version bumping (major, minor, patch)
   - Automatic template regeneration
   - Version validation

4. **Build Integration** (`scripts/build_integration.py`)
   - Pre-build checks and template generation
   - Build environment validation
   - Version info file creation

## Usage

### Checking Current Version

```bash
# Using the version bump script
python scripts/version_bump.py current

# Or directly in Python
python -c "from automated_security_helper import __version__; print(__version__)"
```

### Updating Version

#### Semantic Version Bumping

```bash
# Bump patch version (e.g., 3.0.1 -> 3.0.2)
python scripts/version_bump.py bump patch

# Bump minor version (e.g., 3.0.1 -> 3.1.0)
python scripts/version_bump.py bump minor

# Bump major version (e.g., 3.0.1 -> 4.0.0)
python scripts/version_bump.py bump major
```

#### Setting Specific Version

```bash
# Set a specific version
python scripts/version_bump.py set 3.2.0
```

### Template Management

#### Converting Files to Templates (One-time setup)

```bash
# Convert all documentation files to templates
python scripts/version_template_manager.py convert
```

#### Generating Documentation from Templates

```bash
# Generate all documentation files from templates
python scripts/version_template_manager.py generate
```

#### Listing Templates

```bash
# List all existing template files
python scripts/version_template_manager.py list
```

### Build Integration

#### Pre-build Validation

```bash
# Run pre-build checks and generate documentation
python scripts/build_integration.py pre-build

# Validate build environment
python scripts/build_integration.py validate

# Create version info file
python scripts/build_integration.py version-info
```

## Template System

### How It Works

1. **Template Creation**: Original documentation files are converted to templates where version numbers are replaced with `{{VERSION}}` placeholders.

2. **Template Storage**: Templates are saved with a `.template` extension alongside the original files.

3. **Generation**: When needed, templates are processed to replace `{{VERSION}}` with the actual version from `pyproject.toml`.

### Supported Files

The template system automatically handles these files:

- `README.md`
- `docs/content/index.md`
- `docs/content/faq.md`
- `docs/content/docs/installation-guide.md`
- `docs/content/docs/quick-start-guide.md`
- `docs/content/docs/migration-guide.md`
- `docs/content/docs/advanced-usage.md`
- `docs/content/tutorials/running-ash-in-ci.md`
- `docs/content/tutorials/running-ash-locally.md`
- `examples/streamlit_ui/README.md`

### Version Patterns Detected

The system automatically detects and converts these patterns:

- `git+https://github.com/awslabs/automated-security-helper.git@v3.0.1`
- `--branch v3.0.1`
- `version 3.0.1`
- `ASH version 3.0.1`

## Development Workflow

### Making a Release

1. **Update Version**:
   ```bash
   python scripts/version_bump.py bump patch  # or minor/major
   ```

2. **Verify Changes**:
   ```bash
   python scripts/version_bump.py validate
   ```

3. **Commit and Tag**:
   ```bash
   git add .
   git commit -m "Bump version to $(python scripts/version_bump.py current)"
   git tag "v$(python scripts/version_bump.py current)"
   ```

### Adding New Documentation

When creating new documentation files that reference version numbers:

1. Include version references using the current version
2. Run the template conversion:
   ```bash
   python scripts/version_template_manager.py convert
   ```
3. The system will automatically detect and template the new file

## Integration with Build Process

### Pre-build Hook

Add this to your build process to ensure documentation is up-to-date:

```bash
python scripts/build_integration.py pre-build
```

### CI/CD Integration

Example GitHub Actions step:

```yaml
- name: Update documentation from templates
  run: python scripts/build_integration.py pre-build
```

## File Structure

```
project-root/
├── pyproject.toml                                    # Single source of truth for version
├── automated_security_helper/
│   ├── __init__.py                                   # Uses dynamic version detection
│   └── utils/
│       └── version_management.py                     # Core version utilities
├── scripts/
│   ├── version_template_manager.py                   # Template management
│   ├── version_bump.py                               # Version bumping
│   └── build_integration.py                          # Build integration
├── docs/
│   └── various-files.md                              # Generated from templates
├── templates/
│   └── various-files.md.template                     # Template files
└── tests/                                            # Updated to use dynamic versions
```

## Benefits

1. **Single Source of Truth**: Version is defined only in `pyproject.toml`
2. **Automated Updates**: All documentation automatically reflects current version
3. **Reduced Errors**: No more forgotten version updates in documentation
4. **Build Integration**: Version consistency enforced at build time
5. **Developer Friendly**: Simple commands for version management
6. **Template System**: Clean separation of content and version references

## Troubleshooting

### Common Issues

1. **"Unknown" version displayed**:
   - Ensure `pyproject.toml` exists and has a valid version
   - Check that the version format follows semantic versioning (e.g., "3.0.1")

2. **Templates not found**:
   - Run `python scripts/version_template_manager.py convert` to create templates
   - Templates are created automatically from existing files

3. **Version inconsistencies**:
   - Run `python scripts/version_bump.py validate` to check consistency
   - Regenerate documentation with `python scripts/version_template_manager.py generate`

### Debug Commands

```bash
# Check what version is being detected
python -c "from automated_security_helper.utils.version_management import get_version; print('Version:', get_version())"

# List all template files
python scripts/version_template_manager.py list

# Validate build environment
python scripts/build_integration.py validate
```

## Migration Guide

If you're upgrading from the old manual version management:

1. **Create Templates**: Run `python scripts/version_template_manager.py convert`
2. **Verify**: Check that templates were created correctly
3. **Test**: Run a version bump to test the system: `python scripts/version_bump.py bump patch`
4. **Update CI/CD**: Add pre-build hooks to your build process

The system is designed to be backward compatible and will work even if templates haven't been created yet.
