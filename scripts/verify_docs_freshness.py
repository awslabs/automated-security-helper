#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CI check: verify documentation stays in sync with source code.

Run with: uv run python scripts/verify_docs_freshness.py

Exit code 0 if all checks pass, exit code 1 with a detailed report if any fail.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_SCAN_PY = REPO_ROOT / "automated_security_helper" / "cli" / "scan.py"
MCP_SERVER_PY = REPO_ROOT / "automated_security_helper" / "cli" / "mcp_server.py"
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"
README_MD = REPO_ROOT / "README.md"
DOCS_DIR = REPO_ROOT / "docs"
CLI_REFERENCE_MD = DOCS_DIR / "content" / "docs" / "cli-reference.md"
OUTPUT_FORMATS_MD = DOCS_DIR / "content" / "docs" / "output-formats.md"
DOCS_INDEX_MD = DOCS_DIR / "content" / "index.md"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def get_version_from_pyproject() -> str:
    """Extract version from pyproject.toml."""
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        # Fallback for Python 3.10
        tomllib = None

    text = read_text(PYPROJECT_TOML)

    if tomllib:
        import io

        data = tomllib.loads(text)
        return data["project"]["version"]

    # Regex fallback
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise RuntimeError("Could not parse version from pyproject.toml")
    return m.group(1)


def collect_md_files() -> list[Path]:
    """Collect all .md files under docs/ and the repo-root README."""
    files = list(DOCS_DIR.rglob("*.md"))
    files.append(README_MD)
    return files


# ---------------------------------------------------------------------------
# Check 1: CLI flags in docs match source
# ---------------------------------------------------------------------------


def check_cli_flags() -> list[str]:
    """Parse scan.py for CLI option names and verify they appear in cli-reference.md."""
    failures: list[str] = []
    source = read_text(CLI_SCAN_PY)
    docs = read_text(CLI_REFERENCE_MD)

    # Extract explicit --flag-name strings from typer.Option() calls
    # Match quoted strings that start with --
    flag_pattern = re.compile(r'"(--[a-z][a-z0-9-]*)"')
    flags_in_source: set[str] = set(flag_pattern.findall(source))

    # Also derive flags from Python parameter names (snake_case -> --kebab-case)
    # Match the parameter name preceding the Annotated[...typer.Option block
    param_pattern = re.compile(
        r"^\s+([a-z_][a-z0-9_]*):\s*Annotated\[\s*\n?\s*.*?,\s*\n?\s*typer\.Option\(",
        re.MULTILINE,
    )
    for match in param_pattern.finditer(source):
        param_name = match.group(1)
        flag = "--" + param_name.replace("_", "-")
        flags_in_source.add(flag)

    # Flags that are internal/not user-facing or are short aliases only
    skip_flags = {"--no-build", "--no-run", "--no-progress", "--no-color"}

    docs_lower = docs.lower()
    for flag in sorted(flags_in_source):
        if flag in skip_flags:
            continue
        # Check if the flag appears in the docs (case-insensitive)
        if flag.lower() not in docs_lower:
            # Also try with backtick wrapping
            if f"`{flag}`".lower() not in docs_lower:
                failures.append(f"CLI flag {flag} found in source but missing from cli-reference.md")

    return failures


# ---------------------------------------------------------------------------
# Check 2: Reporter list in docs matches code
# ---------------------------------------------------------------------------


def check_reporters() -> list[str]:
    """Verify all reporter config fields appear in output-formats.md."""
    failures: list[str] = []

    from automated_security_helper.config.ash_config import ReporterConfigSegment

    docs = read_text(OUTPUT_FORMATS_MD).lower()

    for field_name, field_info in ReporterConfigSegment.model_fields.items():
        # Use alias if present, otherwise convert underscores to hyphens
        alias = None
        if field_info.alias:
            alias = field_info.alias
        display_name = alias if alias else field_name.replace("_", "-")

        if display_name.lower() not in docs:
            failures.append(
                f"Reporter '{display_name}' (field: {field_name}) missing from output-formats.md"
            )

    return failures


# ---------------------------------------------------------------------------
# Check 3: Scanner list in docs matches code
# ---------------------------------------------------------------------------


def check_scanners() -> list[str]:
    """Verify all scanner config fields appear in README.md scanner table."""
    failures: list[str] = []

    from automated_security_helper.config.ash_config import ScannerConfigSegment

    readme = read_text(README_MD).lower()

    for field_name, field_info in ScannerConfigSegment.model_fields.items():
        alias = None
        if field_info.alias:
            alias = field_info.alias
        display_name = alias if alias else field_name.replace("_", "-")

        # Check both the alias and the raw field name variants
        found = (
            display_name.lower() in readme
            or field_name.lower().replace("_", "-") in readme
            or field_name.lower().replace("_", "_") in readme
        )
        if not found:
            failures.append(
                f"Scanner '{display_name}' (field: {field_name}) missing from README.md"
            )

    return failures


# ---------------------------------------------------------------------------
# Check 4: MCP tool names in docs match code
# ---------------------------------------------------------------------------


def check_mcp_tools() -> list[str]:
    """Parse mcp_server.py for @mcp.tool() functions and check README."""
    failures: list[str] = []
    source = read_text(MCP_SERVER_PY)
    readme = read_text(README_MD).lower()

    # Find all functions decorated with @mcp.tool()
    # Pattern: @mcp.tool() followed by async def func_name(
    tool_pattern = re.compile(
        r"@mcp\.tool\(\)\s*\n\s*async\s+def\s+([a-z_][a-z0-9_]*)\s*\(",
        re.MULTILINE,
    )
    tool_names = tool_pattern.findall(source)

    for tool_name in tool_names:
        # Check if the tool name appears in the README (as-is or with underscores)
        if tool_name.lower() not in readme:
            # Also try a display form: replace underscores with spaces or other patterns
            # The README uses names like "scan_directory" which may differ from function names
            # Check a loose match: any word boundary match
            alt_name = tool_name.replace("_", " ")
            if alt_name not in readme and tool_name not in readme:
                failures.append(
                    f"MCP tool '{tool_name}' found in mcp_server.py but missing from README.md MCP tools table"
                )

    return failures


# ---------------------------------------------------------------------------
# Check 5: Version consistency
# ---------------------------------------------------------------------------


def check_version_consistency() -> list[str]:
    """Verify key docs files reference the current version."""
    failures: list[str] = []
    version = get_version_from_pyproject()
    version_tag = f"@v{version}"

    files_to_check = [
        (README_MD, "README.md"),
        (DOCS_INDEX_MD, "docs/content/index.md"),
    ]

    for path, label in files_to_check:
        if not path.exists():
            failures.append(f"File {label} does not exist")
            continue
        content = read_text(path)
        if version_tag not in content:
            # Check if ANY version tag is present (might just be outdated)
            old_tags = re.findall(r"@v\d+\.\d+\.\d+", content)
            if old_tags:
                outdated = set(old_tags) - {version_tag}
                if outdated:
                    failures.append(
                        f"{label} references outdated version(s) {sorted(outdated)} "
                        f"instead of {version_tag}"
                    )
            else:
                failures.append(f"{label} does not reference version {version_tag}")

    return failures


# ---------------------------------------------------------------------------
# Check 6: Config file path consistency
# ---------------------------------------------------------------------------


def check_config_path() -> list[str]:
    """Flag docs referencing .ash/ash.yaml instead of .ash/.ash.yaml."""
    failures: list[str] = []

    # Pattern: .ash/ash.yaml NOT preceded by a dot (i.e., not .ash/.ash.yaml)
    # We look for occurrences of ".ash/ash.yaml" that are NOT ".ash/.ash.yaml"
    bad_pattern = re.compile(r"(?<!\.)\.ash/ash\.yaml")

    for md_file in collect_md_files():
        content = read_text(md_file)
        matches = bad_pattern.findall(content)
        if matches:
            rel_path = md_file.relative_to(REPO_ROOT)
            failures.append(
                f"{rel_path} references '.ash/ash.yaml' (should be '.ash/.ash.yaml')"
            )

    return failures


# ---------------------------------------------------------------------------
# Check 7: Suppression field name
# ---------------------------------------------------------------------------


def check_suppression_field_name() -> list[str]:
    """Flag docs using 'file_path:' in suppression context (should be 'path:')."""
    failures: list[str] = []

    for md_file in collect_md_files():
        content = read_text(md_file)
        lines = content.splitlines()

        for i, line in enumerate(lines):
            # Look for file_path: in a line
            if "file_path:" not in line:
                continue

            # Check surrounding context (20 lines before/after) for suppression keywords
            context_start = max(0, i - 20)
            context_end = min(len(lines), i + 20)
            context_block = "\n".join(lines[context_start:context_end]).lower()

            if "suppress" in context_block or "rule_id" in context_block:
                rel_path = md_file.relative_to(REPO_ROOT)
                failures.append(
                    f"{rel_path}:{i + 1} uses 'file_path:' in suppression context "
                    f"(should be 'path:')"
                )

    return failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    checks = [
        ("CLI flags in docs match source", check_cli_flags),
        ("Reporter list in docs matches code", check_reporters),
        ("Scanner list in docs matches code", check_scanners),
        ("MCP tool names in docs match code", check_mcp_tools),
        ("Version consistency", check_version_consistency),
        ("Config file path consistency", check_config_path),
        ("Suppression field name", check_suppression_field_name),
    ]

    all_failures: list[tuple[str, list[str]]] = []
    passed = 0
    failed = 0

    for name, check_fn in checks:
        try:
            failures = check_fn()
        except Exception as e:
            failures = [f"Check raised an exception: {e}"]

        if failures:
            failed += 1
            all_failures.append((name, failures))
            print(f"FAIL  {name}")
            for f in failures:
                print(f"        - {f}")
        else:
            passed += 1
            print(f"PASS  {name}")

    print()
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")

    if all_failures:
        print()
        print("Documentation is out of sync with source code.")
        print("Fix the issues above and re-run this script.")
        return 1

    print()
    print("All documentation freshness checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
