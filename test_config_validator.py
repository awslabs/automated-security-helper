#!/usr/bin/env python3
"""Test script for config validator."""

from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from automated_security_helper.config.config_validator import ConfigValidator


def main():
    # Use absolute path based on current working directory
    config_path = Path(
        "/Users/rapg/Documents/source/one-observability-demo/.ash/.ash_bad_config.yaml"
    )

    if not config_path.exists():
        print(f"❌ Config file not found: {config_path}")
        return 1

    print(f"Validating: {config_path}")
    print("=" * 60)

    is_valid, errors = ConfigValidator.validate_config_file(config_path)

    if is_valid:
        print("✅ Configuration is VALID!")
    else:
        print(f"❌ Configuration is INVALID - {len(errors)} error(s) found:\n")
        for i, error in enumerate(errors, 1):
            print(f"  {i}. {error}")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
