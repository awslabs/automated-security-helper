# Test File Naming Conventions

This document outlines the naming conventions for test files in the ASH project.

## Directory Structure

The test directory structure mirrors the main codebase structure:

```
tests/
├── unit/                  # Unit tests for individual components
│   ├── base/              # Tests for base classes and interfaces
│   ├── cli/               # Tests for CLI components
│   ├── config/            # Tests for configuration components
│   └── ...                # Other component directories
├── integration/           # Integration tests for component interactions
│   ├── cli/               # CLI integration tests
│   ├── scanners/          # Scanner integration tests
│   └── ...                # Other integration test directories
├── fixtures/              # Common test fixtures
├── utils/                 # Test utilities
└── test_data/             # Test data files
```

## File Naming

### Unit Tests

Unit test files should follow this naming pattern:

```
test_<module_name>.py
```

For example:
- `test_ash_config.py` for testing the `ash_config.py` module
- `test_sarif_utils.py` for testing the `sarif_utils.py` module

### Integration Tests

Integration test files should follow this naming pattern:

```
test_<feature_or_component>_integration.py
```

For example:
- `test_global_suppressions_integration.py` for testing global suppressions feature
- `test_scanner_workflow_integration.py` for testing scanner workflow

### Test Classes

Test classes should follow this naming pattern:

```python
class Test<ComponentName>:
    """Tests for <component description>."""
```

For example:
- `class TestAshConfig:` for testing the AshConfig class
- `class TestSarifUtils:` for testing SARIF utilities

### Test Methods

Test methods should follow this naming pattern:

```python
def test_<functionality_being_tested>(_<parameters>):
    """Test <description of what is being tested>."""
```

For example:
- `def test_parse_config_file():` for testing config file parsing
- `def test_apply_suppressions_to_sarif_with_rule_match():` for testing suppression application

## Fixtures

Fixture files should be named according to their domain:

```
<domain>_fixtures.py
```

For example:
- `config_fixtures.py` for configuration-related fixtures
- `scanner_fixtures.py` for scanner-related fixtures

## Utility Files

Utility files should be named according to their purpose:

```
<purpose>.py
```

For example:
- `assertions.py` for custom assertion helpers
- `mocks.py` for mock utilities
- `helpers.py` for general test helpers