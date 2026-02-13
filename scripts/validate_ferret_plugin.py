# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pre-push validation script for the ferret-scan plugin.

Checks for known CI failure patterns that suppressions cannot catch
(because CI runs with --ignore-suppressions). Run this before pushing
to catch issues locally.

Usage:
    uv run python scripts/validate_ferret_plugin.py
"""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Files to scan (relative to project root)
PLUGIN_FILES = list(
    (PROJECT_ROOT / "automated_security_helper" / "plugin_modules" / "ash_ferret_plugins").rglob("*")
)
TEST_FILES = list(
    (PROJECT_ROOT / "tests" / "unit" / "plugin_modules" / "ash_ferret_plugins").rglob("*")
)
SCRIPT_FILES = [PROJECT_ROOT / "scripts" / "generate_test_docx.py"]

ALL_FILES = [f for f in PLUGIN_FILES + TEST_FILES + SCRIPT_FILES if f.is_file()]

# ============================================================================
# Check definitions
# ============================================================================

CHECKS = []
failures = []


def check(name):
    """Decorator to register a check function."""
    def decorator(fn):
        CHECKS.append((name, fn))
        return fn
    return decorator


def fail(check_name, file, line_num, message):
    failures.append((check_name, file, line_num, message))


# ----------------------------------------------------------------------------
# 1. SECRET-SECRET-KEYWORD: variable names that trigger secret detection
# ----------------------------------------------------------------------------
SECRET_KEYWORD_PATTERN = re.compile(
    r"""(?ix)                       # case-insensitive, verbose
    (?:^|[\s,;:({])                 # preceded by whitespace or delimiter
    (?:                             # match these variable name patterns:
        API_KEY | API_SECRET |
        SECRET_KEY | SECRET_TOKEN |
        PRIVATE_KEY | ACCESS_KEY |
        PASSWORD | PASSWD |
        TOKEN(?:_SECRET)? |
        AUTH_TOKEN | BEARER_TOKEN |
        CLIENT_SECRET |
        ENCRYPTION_KEY |
        SIGNING_KEY
    )
    \s*[=:]                         # followed by assignment or colon
    """,
)

# Allowlist: lines that are documenting the problem (not introducing it)
SECRET_KEYWORD_ALLOWLIST = [
    "SECRET-SECRET-KEYWORD",        # references to the rule name itself
    "UNSUPPORTED_FERRET_OPTIONS",   # the dict defining blocked options
    "# List of unsupported",       # comment above the dict
]


@check("SECRET-SECRET-KEYWORD: variable names that trigger secret detection")
def check_secret_keywords():
    for filepath in ALL_FILES:
        if filepath.suffix not in (".py", ".md", ".yaml", ".yml"):
            continue
        try:
            lines = filepath.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines, 1):
            if SECRET_KEYWORD_PATTERN.search(line):
                if any(allow in line for allow in SECRET_KEYWORD_ALLOWLIST):
                    continue
                # Skip comments that discuss the pattern
                stripped = line.lstrip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    # Allow comments that mention these as examples of what NOT to do
                    if "e.g." in line or "example" in line.lower() or "don't" in line.lower():
                        continue
                fail(
                    "SECRET-SECRET-KEYWORD",
                    filepath.relative_to(PROJECT_ROOT),
                    i,
                    f"Variable name triggers SECRET-SECRET-KEYWORD rule: {line.strip()[:80]}",
                )


# ----------------------------------------------------------------------------
# 2. Hardcoded PII: credit card numbers, SSNs, etc. as string literals
# ----------------------------------------------------------------------------
CREDIT_CARD_PATTERN = re.compile(
    r"""(?x)
    (?<!\d)                         # not preceded by digit
    (?:
        4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4} |   # Visa
        5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4} |  # MasterCard
        3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5} |           # AMEX
        6011[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}        # Discover
    )
    (?!\d)                          # not followed by digit
    """,
)

SSN_PATTERN = re.compile(
    r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)'
)

PII_ALLOWLIST_FILES = {
    # The docx generator uses runtime-generated values, but the function
    # names and format strings are fine
    "scripts/generate_test_docx.py",
}


@check("HARDCODED-PII: credit card numbers or SSNs as string literals")
def check_hardcoded_pii():
    for filepath in ALL_FILES:
        if filepath.suffix not in (".py", ".md", ".yaml", ".yml"):
            continue
        rel = str(filepath.relative_to(PROJECT_ROOT))
        if rel in PII_ALLOWLIST_FILES:
            continue
        try:
            lines = filepath.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            # Check for credit card patterns inside string literals
            if CREDIT_CARD_PATTERN.search(line):
                # Only flag if it looks like a string literal (quoted)
                if '"' in line or "'" in line:
                    fail(
                        "HARDCODED-PII",
                        filepath.relative_to(PROJECT_ROOT),
                        i,
                        f"Possible hardcoded credit card number: {line.strip()[:80]}",
                    )
            if SSN_PATTERN.search(line):
                if '"' in line or "'" in line:
                    # Exclude format strings like f"{fake_ssn()}"
                    if "fake_ssn" not in line and "random" not in line:
                        fail(
                            "HARDCODED-PII",
                            filepath.relative_to(PROJECT_ROOT),
                            i,
                            f"Possible hardcoded SSN: {line.strip()[:80]}",
                        )


# ----------------------------------------------------------------------------
# 3. HEX-HIGH-ENTROPY-STRING: hex strings that trigger entropy detection
# ----------------------------------------------------------------------------
HEX_ENTROPY_PATTERN = re.compile(
    r'["\'][0-9a-fA-F]{32,}["\']'
)


@check("HEX-HIGH-ENTROPY-STRING: long hex strings in source")
def check_hex_entropy():
    for filepath in ALL_FILES:
        if filepath.suffix not in (".py", ".md", ".yaml", ".yml"):
            continue
        try:
            lines = filepath.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if HEX_ENTROPY_PATTERN.search(line):
                fail(
                    "HEX-HIGH-ENTROPY-STRING",
                    filepath.relative_to(PROJECT_ROOT),
                    i,
                    f"Long hex string may trigger entropy detector: {line.strip()[:80]}",
                )


# ----------------------------------------------------------------------------
# 4. Exclude pattern syntax: globs instead of simple names
# ----------------------------------------------------------------------------
GLOB_EXCLUDE_PATTERN = re.compile(r'\*\*/')


@check("EXCLUDE-GLOB-SYNTAX: exclude patterns using glob syntax instead of simple names")
def check_exclude_glob_syntax():
    config_files = [
        PROJECT_ROOT / ".ash" / ".ash_community_plugins.yaml",
        PROJECT_ROOT / ".ash" / ".ash.yaml",
    ]
    for filepath in config_files:
        if not filepath.exists():
            continue
        try:
            lines = filepath.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        in_exclude = False
        for i, line in enumerate(lines, 1):
            if "exclude_patterns" in line:
                in_exclude = True
                continue
            if in_exclude:
                if line.strip().startswith("-"):
                    value = line.strip().lstrip("- ").strip('"').strip("'")
                    if GLOB_EXCLUDE_PATTERN.search(value):
                        fail(
                            "EXCLUDE-GLOB-SYNTAX",
                            filepath.relative_to(PROJECT_ROOT),
                            i,
                            f"Ferret-scan uses simple name matching, not globs: '{value}' "
                            f"— remove '**/' prefix",
                        )
                elif not line.strip().startswith("#") and line.strip():
                    in_exclude = False


# ----------------------------------------------------------------------------
# 5. Unit test count regression
# ----------------------------------------------------------------------------
EXPECTED_MIN_TESTS = 67


@check(f"TEST-COUNT: at least {EXPECTED_MIN_TESTS} unit tests exist")
def check_test_count():
    test_file = (
        PROJECT_ROOT / "tests" / "unit" / "plugin_modules"
        / "ash_ferret_plugins" / "test_ferret_scanner.py"
    )
    if not test_file.exists():
        fail("TEST-COUNT", test_file.relative_to(PROJECT_ROOT), 0, "Test file not found")
        return
    content = test_file.read_text(encoding="utf-8")
    test_count = len(re.findall(r'def test_', content))
    if test_count < EXPECTED_MIN_TESTS:
        fail(
            "TEST-COUNT",
            test_file.relative_to(PROJECT_ROOT),
            0,
            f"Expected at least {EXPECTED_MIN_TESTS} tests, found {test_count}",
        )

# ----------------------------------------------------------------------------
# 6. Windows path separators: str(Path) instead of Path.as_posix()
# ----------------------------------------------------------------------------
# ferret-scan (and many CLI tools) don't handle backslash paths on Windows.
# All paths passed to subprocess args must use as_posix().
WINDOWS_PATH_PATTERN = re.compile(
    r'str\(\s*(?:Path\(|results_file|target|self\.context\.source_dir)'
)
# Pattern for args.append/extend with str() wrapping a Path
ARGS_STR_PATH_PATTERN = re.compile(
    r'args\.(?:append|extend)\(.*str\(\s*(?:Path|target|results_file)'
)


@check("WINDOWS-PATH: str(Path) instead of Path.as_posix() in CLI arguments")
def check_windows_paths():
    scanner_file = (
        PROJECT_ROOT / "automated_security_helper" / "plugin_modules"
        / "ash_ferret_plugins" / "ferret_scanner.py"
    )
    if not scanner_file.exists():
        return
    lines = scanner_file.read_text(encoding="utf-8").splitlines()
    in_resolve_args = False
    in_scan = False
    for i, line in enumerate(lines, 1):
        # Track when we're inside _resolve_arguments or scan methods
        if "def _resolve_arguments" in line:
            in_resolve_args = True
            in_scan = False
        elif "def scan(" in line:
            in_scan = True
            in_resolve_args = False
        elif line.strip().startswith("def ") and in_resolve_args:
            in_resolve_args = False
        elif line.strip().startswith("def ") and in_scan:
            in_scan = False

        if not (in_resolve_args or in_scan):
            continue

        # Check for str(Path(...)) or str(target) etc. in args building
        if WINDOWS_PATH_PATTERN.search(line) or ARGS_STR_PATH_PATTERN.search(line):
            # Allow if as_posix() is also on the same line
            if "as_posix()" in line:
                continue
            fail(
                "WINDOWS-PATH",
                scanner_file.relative_to(PROJECT_ROOT),
                i,
                f"Use Path.as_posix() instead of str() for CLI args: {line.strip()[:80]}",
            )



# ============================================================================
# Runner
# ============================================================================

def main():
    print(f"Validating ferret-scan plugin ({len(ALL_FILES)} files)...\n")

    for name, fn in CHECKS:
        fn()

    if failures:
        print(f"\n{'='*70}")
        print(f"FAILED: {len(failures)} issue(s) found\n")
        for check_name, filepath, line_num, message in failures:
            loc = f"{filepath}:{line_num}" if line_num else str(filepath)
            print(f"  [{check_name}] {loc}")
            print(f"    {message}\n")
        print(
            "These issues will cause CI failures because ASH runs with\n"
            "--ignore-suppressions. Fix them before pushing."
        )
        return 1
    else:
        print(f"All {len(CHECKS)} checks passed.")
        return 0

# ----------------------------------------------------------------------------
# 7. Multiple --exclude args instead of single comma-separated value
# ----------------------------------------------------------------------------
MULTIPLE_EXCLUDE_PATTERN = re.compile(
    r'for\s+\w+\s+in\s+.*exclude.*:\s*$'
)


@check("EXCLUDE-MULTIPLE-ARGS: multiple --exclude args instead of comma-joined single arg")
def check_exclude_multiple_args():
    scanner_file = (
        PROJECT_ROOT / "automated_security_helper" / "plugin_modules"
        / "ash_ferret_plugins" / "ferret_scanner.py"
    )
    if not scanner_file.exists():
        return
    lines = scanner_file.read_text(encoding="utf-8").splitlines()
    in_process_config = False
    for i, line in enumerate(lines, 1):
        if "def _process_config_options" in line:
            in_process_config = True
        elif line.strip().startswith("def ") and in_process_config:
            in_process_config = False

        if not in_process_config:
            continue

        # Flag: looping over exclude patterns to append individual --exclude args
        if MULTIPLE_EXCLUDE_PATTERN.search(line):
            # Check next few lines for --exclude append
            for j in range(i, min(i + 5, len(lines))):
                if "--exclude" in lines[j] and "append" in lines[j]:
                    fail(
                        "EXCLUDE-MULTIPLE-ARGS",
                        scanner_file.relative_to(PROJECT_ROOT),
                        i,
                        "Ferret-scan expects a single --exclude with comma-separated values, "
                        "not multiple --exclude args. Use ','.join(patterns).",
                    )
                    break


# ----------------------------------------------------------------------------
# 8. Ferret-scan registered in .ash.yaml instead of community plugins config
# ----------------------------------------------------------------------------


@check("FERRET-IN-ASH-YAML: ferret-scan should not be in .ash/.ash.yaml (use community plugins config)")
def check_ferret_not_in_ash_yaml():
    ash_yaml = PROJECT_ROOT / ".ash" / ".ash.yaml"
    if not ash_yaml.exists():
        return
    lines = ash_yaml.read_text(encoding="utf-8").splitlines()
    in_plugin_modules = False
    for i, line in enumerate(lines, 1):
        if "ash_plugin_modules" in line:
            in_plugin_modules = True
            # Check inline value
            if "ash_ferret_plugins" in line and not line.strip().startswith("#"):
                fail(
                    "FERRET-IN-ASH-YAML",
                    ash_yaml.relative_to(PROJECT_ROOT),
                    i,
                    "ferret-scan should be registered in .ash_community_plugins.yaml, "
                    "not .ash.yaml (it's a community plugin, not built-in)",
                )
            continue
        if in_plugin_modules:
            if line.strip().startswith("-"):
                if "ash_ferret_plugins" in line and not line.strip().startswith("#"):
                    fail(
                        "FERRET-IN-ASH-YAML",
                        ash_yaml.relative_to(PROJECT_ROOT),
                        i,
                        "ferret-scan should be registered in .ash_community_plugins.yaml, "
                        "not .ash.yaml (it's a community plugin, not built-in)",
                    )
            elif not line.strip().startswith("#") and line.strip():
                in_plugin_modules = False


# ----------------------------------------------------------------------------
# 9. use_default_config should be false when custom exclude_patterns are set
# ----------------------------------------------------------------------------


@check("CONFIG-OVERRIDE-EXCLUDES: use_default_config should be false when exclude_patterns are set")
def check_config_override_excludes():
    config_file = PROJECT_ROOT / ".ash" / ".ash_community_plugins.yaml"
    if not config_file.exists():
        return
    lines = config_file.read_text(encoding="utf-8").splitlines()
    in_ferret = False
    in_options = False
    has_excludes = False
    has_use_default_false = False
    ferret_start = 0
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Detect ferret-scan scanner section
        if stripped == "ferret-scan:" and in_ferret is False:
            in_ferret = True
            ferret_start = i
            continue
        # Detect next scanner section (end of ferret block)
        if in_ferret and re.match(r'^  \S', line) and "options:" not in line:
            break
        if in_ferret and "options:" in line:
            in_options = True
        if in_options:
            if "exclude_patterns" in line:
                has_excludes = True
            if "use_default_config" in line and "false" in line.lower():
                has_use_default_false = True

    if has_excludes and not has_use_default_false:
        fail(
            "CONFIG-OVERRIDE-EXCLUDES",
            config_file.relative_to(PROJECT_ROOT),
            ferret_start,
            "exclude_patterns are set but use_default_config is not false. "
            "The bundled config file will override CLI --exclude args.",
        )




if __name__ == "__main__":
    sys.exit(main())
