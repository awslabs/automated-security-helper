# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pre-push validation script for the ferret-scan plugin.

Checks for known CI failure patterns before pushing. Also verifies that
any SECRET-SECRET-KEYWORD hits in documentation have matching suppressions
in .ash/.ash_community_plugins.yaml or .ash/.ash.yaml.

Usage:
    uv run python scripts/validate_ferret_plugin.py
"""

import ast
import fnmatch
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The validator judges suppressions the way ASH does, by calling ASH's own
# matcher, so the two never disagree about which hits a suppression covers.
sys.path.insert(0, str(PROJECT_ROOT))
from automated_security_helper.utils.suppression_matcher import (  # noqa: E402
    file_path_matches,
)

PLUGIN_DIR = (
    PROJECT_ROOT / "automated_security_helper" / "plugin_modules" / "ash_ferret_plugins"
)
SCANNER_FILE = PLUGIN_DIR / "ferret_scanner.py"
TEST_DIR = PROJECT_ROOT / "tests" / "unit" / "plugin_modules" / "ash_ferret_plugins"

# Files to scan (relative to project root)
PLUGIN_FILES = list(PLUGIN_DIR.rglob("*"))
TEST_FILES = list(TEST_DIR.rglob("*"))
SCRIPT_FILES = [PROJECT_ROOT / "scripts" / "generate_test_docx.py"]

ALL_FILES = [f for f in PLUGIN_FILES + TEST_FILES + SCRIPT_FILES if f.is_file()]

#: The config files whose suppressions apply to this repository's scans. The
#: validator used to read the community-plugins file alone, while the
#: repository keeps SECRET-SECRET-KEYWORD suppressions in .ash/.ash.yaml too.
SUPPRESSION_CONFIG_FILES = (
    PROJECT_ROOT / ".ash" / ".ash_community_plugins.yaml",
    PROJECT_ROOT / ".ash" / ".ash.yaml",
)

#: Suppression keys that narrow an entry to a symbol or a package rather than a
#: file region. ASH applies such an entry only with a symbol resolver or a
#: package match; this validator has neither, so the entry covers no text hit.
NARROWING_KEYS = ("symbol",)
NARROWING_KEY_PREFIXES = ("package_",)


def _read_lines(path: Path) -> Optional[List[str]]:
    """The lines of a UTF-8 text file, or None when it cannot be read as one.

    Several checks read with no decode handling, so one non-UTF-8 file aborted
    the whole validator with a traceback; a file that cannot be read is skipped
    the way the keyword check always skipped it.
    """
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        return None


# ============================================================================
# Suppression helpers
# ============================================================================


def parse_suppressions(text: str, source: str = "") -> List[Dict[str, Any]]:
    """The ``global_settings.suppressions`` entries of one config file's text.

    Read with the YAML parser, which the hand-written line scanner was not: that
    scanner kept an inline ``# comment`` and a stray quote inside a value, read a
    ``- `` or ``key:`` line of a folded ``reason: >-`` as a new entry or key,
    ended the block at the first key indented two spaces or less, dropped the
    ``symbol`` and ``package_*`` keys that narrow an entry, and kept a line_start
    it could not turn into an int as text, which later made ``line_num <
    s_start`` raise TypeError.

    Every key of an entry is kept. ``source`` names the file the entry came from.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(document, dict):
        return []
    entries = (document.get("global_settings") or {}).get("suppressions")
    if entries is None:
        entries = document.get("suppressions")
    if not isinstance(entries, list):
        return []
    suppressions = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        normalized: Dict[str, Any] = dict(entry)
        for key in ("line_start", "line_end"):
            value = normalized.get(key)
            if value is not None and not isinstance(value, int):
                try:
                    normalized[key] = int(str(value).strip())
                except ValueError:
                    # ASH refuses such an entry; it covers nothing, see
                    # suppression_covers.
                    normalized[key] = str(value)
        if source:
            normalized["source"] = source
        suppressions.append(normalized)
    return suppressions


def load_community_suppressions(
    config_files: Iterable[Path] = SUPPRESSION_CONFIG_FILES,
) -> List[Dict[str, Any]]:
    """The suppression entries of every config file this repository scans with."""
    suppressions: List[Dict[str, Any]] = []
    for config_file in config_files:
        if not config_file.exists():
            continue
        try:
            text = config_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        suppressions.extend(parse_suppressions(text, source=config_file.name))
    return suppressions


def _today_utc() -> date:
    """Today's date in UTC, the clock ASH's expiration rule reads."""
    return datetime.now(timezone.utc).date()


def suppression_has_expired(expiration, today: Optional[date] = None) -> bool:
    """ASH's rule for an entry's ``expiration``: YYYY-MM-DD, expired from the
    start of that day in UTC. A date ASH cannot read counts as expired too,
    because ASH refuses such an entry and never applies it.

    ``expiration`` was parsed from the config and never consulted, so this
    validator kept treating a suppression as active after ASH had stopped
    applying it, and a push went green that the CI scan then failed.

    *today* is the clock, UTC by default; the tests pass a fixed date so the
    boundary cases do not depend on the runner's timezone or the time of day.
    """
    if not expiration:
        return False
    if today is None:
        today = _today_utc()
    if isinstance(expiration, date):
        return expiration <= today
    try:
        return datetime.strptime(str(expiration), "%Y-%m-%d").date() <= today
    except ValueError:
        return True


def rule_id_matches(rule_id: str, pattern: Optional[str]) -> bool:
    """ASH's rule-id match: a case-insensitive glob, and no rule_id means any rule.

    The validator compared the two strings exactly, so an entry written in lower
    case, as a glob, or with no rule_id, each of which ASH applies, was not
    recognized and the hit it covers was reported as unsuppressed.
    """
    if pattern is None or pattern == "":
        return True
    return fnmatch.fnmatch(rule_id.lower(), str(pattern).lower())


def line_range_covers(
    line_num: int, line_start: Optional[int], line_end: Optional[int]
) -> bool:
    """ASH's line-range rule for a one-line finding (suppression_matcher).

    No range matches every line; a start alone is open-ended to the end of the
    file; an end alone covers every line up to it, which the validator used to
    ignore when there was no start, so it matched lines ASH does not suppress.
    """
    if line_start is None and line_end is None:
        return True
    if line_start is not None and line_end is None:
        return line_num >= line_start
    if line_start is None and line_end is not None:
        return line_num <= line_end
    return line_start <= line_num <= line_end  # type: ignore[operator]


def suppression_covers(suppression, rel_path, line_num, rule_id):
    """Check if one suppression entry covers a file:line:rule combo.

    The answer is ASH's: the rule id is a case-insensitive glob (none means any
    rule), the path goes through ASH's own ``file_path_matches`` (``**`` matches
    zero or more directories), the line range follows the matcher's rules, an
    expired entry covers nothing, a line number ASH cannot read covers nothing,
    and an entry narrowed to a symbol or a package covers no text hit.
    """
    if not rule_id_matches(rule_id, suppression.get("rule_id")):
        return False
    if suppression_has_expired(suppression.get("expiration")):
        return False
    if any(suppression.get(key) for key in NARROWING_KEYS) or any(
        key.startswith(NARROWING_KEY_PREFIXES) and suppression.get(key)
        for key in suppression
    ):
        return False
    s_start = suppression.get("line_start")
    s_end = suppression.get("line_end")
    if (s_start is not None and not isinstance(s_start, int)) or (
        s_end is not None and not isinstance(s_end, int)
    ):
        return False
    if not file_path_matches(
        Path(str(rel_path)).as_posix(), suppression.get("path", "")
    ):
        return False
    return line_range_covers(line_num, s_start, s_end)


def has_matching_suppression(rel_path, line_num, rule_id, suppressions):
    """Check if a file:line:rule combo is covered by a suppression entry."""
    return any(suppression_covers(s, rel_path, line_num, rule_id) for s in suppressions)


COMMUNITY_SUPPRESSIONS = load_community_suppressions()


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


def _rel_posix(filepath: Path) -> str:
    """The path relative to the repository, with forward slashes on every host."""
    return filepath.relative_to(PROJECT_ROOT).as_posix()


# ----------------------------------------------------------------------------
# 0. The files this validator inspects exist
# ----------------------------------------------------------------------------


@check("PLUGIN-PRESENT: the ferret plugin files this validator inspects exist")
def check_plugin_present():
    """A validator that scans nothing passes vacuously.

    PLUGIN_FILES is an rglob over a fixed directory and the scanner-file checks
    returned silently when the file was missing, so a moved plugin directory
    made every file-scanning check pass and the run end in "All checks passed".
    """
    if not any(f.is_file() for f in PLUGIN_FILES):
        fail(
            "PLUGIN-PRESENT",
            PLUGIN_DIR.relative_to(PROJECT_ROOT),
            0,
            "No plugin files found under this directory; the file-scanning checks "
            "below inspected nothing",
        )
    if not SCANNER_FILE.is_file():
        fail(
            "PLUGIN-PRESENT",
            SCANNER_FILE.relative_to(PROJECT_ROOT),
            0,
            "ferret_scanner.py not found; the WINDOWS-PATH and "
            "EXCLUDE-MULTIPLE-ARGS checks inspected nothing",
        )


# ----------------------------------------------------------------------------
# 1. SECRET-SECRET-KEYWORD: variable names that trigger secret detection
# ----------------------------------------------------------------------------
# The keyword may follow whitespace, a delimiter, a quote (a dict key such as
# "api_key":) or a dot (an attribute such as self.api_key =): the CI scanner
# flags every one of those, and a pattern that required whitespace or a
# delimiter in front of the keyword missed the quoted and dotted forms.
SECRET_KEYWORD_PATTERN = re.compile(
    r"""(?ix)                       # case-insensitive, verbose
    (?:^|[\s,;:({\[.'"])            # preceded by whitespace, a delimiter, a dot or a quote
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
    ['"]?\s*[=:]                    # followed by assignment or colon
    """,
)

# Allowlist: lines that are documenting the problem (not introducing it)
SECRET_KEYWORD_ALLOWLIST = [
    "SECRET-SECRET-KEYWORD",  # references to the rule name itself
    "UNSUPPORTED_FERRET_OPTIONS",  # the dict defining blocked options
    "# List of unsupported",  # comment above the dict
]


def _code_part(line: str, suffix: str) -> str:
    """The part of a source line the scanner reads as code.

    In a Python file a trailing ``# comment`` is not code, so an allowlist token
    that appears only in that comment cannot excuse a keyword assignment in
    front of it: ``password = "x"  # SECRET-SECRET-KEYWORD`` used to pass. In a
    documentation or YAML file the whole line is read.
    """
    if suffix == ".py":
        return line.split("#", 1)[0]
    return line


def keyword_hit_is_exempt(line: str, suffix: str) -> bool:
    """Whether a line the keyword pattern matched is documenting the problem.

    A comment line that names an example is exempt, and so is a line whose code
    part names the rule or the blocked-options dict.
    """
    stripped = line.lstrip()
    if stripped.startswith(("#", "//")):
        if "e.g." in line or "example" in line.lower() or "don't" in line.lower():
            return True
    code = _code_part(line, suffix)
    return any(allow in code for allow in SECRET_KEYWORD_ALLOWLIST)


@check("SECRET-SECRET-KEYWORD: variable names that trigger secret detection")
def check_secret_keywords():
    for filepath in ALL_FILES:
        if filepath.suffix not in (".py", ".md", ".yaml", ".yml"):
            continue
        lines = _read_lines(filepath)
        if lines is None:
            continue
        rel = filepath.relative_to(PROJECT_ROOT)
        for i, line in enumerate(lines, 1):
            if not SECRET_KEYWORD_PATTERN.search(_code_part(line, filepath.suffix)):
                continue
            if keyword_hit_is_exempt(line, filepath.suffix):
                continue
            # Skip hits that have a matching suppression with line number
            if has_matching_suppression(
                rel, i, "SECRET-SECRET-KEYWORD", COMMUNITY_SUPPRESSIONS
            ):
                continue
            fail(
                "SECRET-SECRET-KEYWORD",
                rel,
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

SSN_PATTERN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

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
        # Compared with forward slashes: str() of a relative Path uses the
        # host's separator, so the allowlist never matched on Windows.
        rel = _rel_posix(filepath)
        if rel in PII_ALLOWLIST_FILES:
            continue
        lines = _read_lines(filepath)
        if lines is None:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            # Skip comments
            if stripped.startswith(("#", "//")):
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
HEX_ENTROPY_PATTERN = re.compile(r'["\'][0-9a-fA-F]{32,}["\']')


@check("HEX-HIGH-ENTROPY-STRING: long hex strings in source")
def check_hex_entropy():
    for filepath in ALL_FILES:
        if filepath.suffix not in (".py", ".md", ".yaml", ".yml"):
            continue
        lines = _read_lines(filepath)
        if lines is None:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//")):
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
GLOB_EXCLUDE_PATTERN = re.compile(r"\*\*/")

#: The YAML key that opens an exclude_patterns list, as a key and not as a word
#: in a comment or prose: a comment that mentioned exclude_patterns used to arm
#: the check for whatever list followed it.
EXCLUDE_PATTERNS_KEY = re.compile(r"^(?P<indent>\s*)exclude_patterns\s*:(?P<rest>.*)$")
FLOW_LIST = re.compile(r"^\s*\[(?P<items>.*)\]\s*(?:#.*)?$")


def _scanner_of(lines: List[str], index: int) -> Optional[str]:
    """The scanner name whose block holds the key at ``index``, when under ``scanners``.

    Walks up the mapping ancestors of the line; the scanner name is the key
    directly under ``scanners``. None when the key sits under no ``scanners``
    block at all.
    """
    indent = len(lines[index]) - len(lines[index].lstrip())
    chain: List[str] = []
    j = index
    while True:
        key = None
        for k in range(j - 1, -1, -1):
            candidate = lines[k]
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate_indent < indent and ":" in candidate:
                key = candidate.split(":", 1)[0].strip().strip("'\"")
                indent = candidate_indent
                j = k
                break
        if key is None:
            break
        chain.append(key)
    for position, key in enumerate(chain):
        if key == "scanners" and position > 0:
            return chain[position - 1]
    return None


def exclude_glob_hits(lines: List[str]) -> List[Tuple[int, str]]:
    """``(line number, value)`` of every ferret-scan exclude pattern written as a glob.

    Only a real ``exclude_patterns:`` key arms the check, only a key inside a
    ferret-scan scanner block is read (another scanner's ``**/`` glob is that
    scanner's business), and a flow-style list on the key's own line is
    inspected too; the old scan skipped that line and read the next list.
    """
    hits: List[Tuple[int, str]] = []
    in_exclude = False
    exclude_indent = 0
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        key = EXCLUDE_PATTERNS_KEY.match(line)
        if key:
            in_exclude = False
            scanner = _scanner_of(lines, i - 1)
            if scanner is None or "ferret" not in scanner.lower():
                continue
            exclude_indent = len(key.group("indent"))
            flow = FLOW_LIST.match(key.group("rest"))
            if flow:
                for item in flow.group("items").split(","):
                    value = item.strip().strip('"').strip("'")
                    if value and GLOB_EXCLUDE_PATTERN.search(value):
                        hits.append((i, value))
                continue
            in_exclude = True
            continue
        if in_exclude:
            stripped = line.strip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip())
            if stripped.startswith("-") and indent > exclude_indent:
                value = (
                    stripped.lstrip("- ")
                    .split(" #", 1)[0]
                    .strip()
                    .strip('"')
                    .strip("'")
                )
                if GLOB_EXCLUDE_PATTERN.search(value):
                    hits.append((i, value))
            else:
                in_exclude = False
    return hits


@check(
    "EXCLUDE-GLOB-SYNTAX: exclude patterns using glob syntax instead of simple names"
)
def check_exclude_glob_syntax():
    config_files = [
        PROJECT_ROOT / ".ash" / ".ash_community_plugins.yaml",
        PROJECT_ROOT / ".ash" / ".ash.yaml",
    ]
    for filepath in config_files:
        if not filepath.exists():
            continue
        lines = _read_lines(filepath)
        if lines is None:
            continue
        for i, value in exclude_glob_hits(lines):
            fail(
                "EXCLUDE-GLOB-SYNTAX",
                filepath.relative_to(PROJECT_ROOT),
                i,
                f"Ferret-scan uses simple name matching, not globs: '{value}' "
                f"— remove '**/' prefix",
            )


# ----------------------------------------------------------------------------
# 5. Unit test count regression
# ----------------------------------------------------------------------------
EXPECTED_MIN_TESTS = 67


def count_test_functions(source: str) -> int:
    """The number of ``test_*`` functions and methods ``source`` defines.

    Counted from the parsed tree, not with a text search for ``def test_``,
    which also counted the words inside comments and strings.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    )


@check(f"TEST-COUNT: at least {EXPECTED_MIN_TESTS} unit tests exist")
def check_test_count():
    test_file = TEST_DIR / "test_ferret_scanner.py"
    if not test_file.exists():
        fail(
            "TEST-COUNT", test_file.relative_to(PROJECT_ROOT), 0, "Test file not found"
        )
        return
    lines = _read_lines(test_file)
    if lines is None:
        fail(
            "TEST-COUNT",
            test_file.relative_to(PROJECT_ROOT),
            0,
            "Test file is not readable as UTF-8",
        )
        return
    test_count = count_test_functions("\n".join(lines))
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
#
# Any str() of a path-shaped expression, anywhere in the scanner, on a line
# that builds a command-line argument. The old patterns named three identifiers
# inside two methods, so the --config values built with str(config_file_path)
# and str(self._empty_config_file()) in other methods passed.
STR_OF_PATH_PATTERN = re.compile(
    r"str\(\s*(?:Path\(|[\w.]*(?:path|file|dir|target|root)[\w.]*(?:\(\))?)\s*\)",
    re.IGNORECASE,
)
ARGUMENT_CONTEXT_PATTERN = re.compile(
    r"ToolExtraArg|args\.|\bargs\b|command|argv|\.append\(|\.extend\(|--\w"
)


def windows_path_hits(lines: List[str]) -> List[Tuple[int, str]]:
    """``(line number, line)`` of every CLI argument built with ``str()`` of a path."""
    hits: List[Tuple[int, str]] = []
    for i, line in enumerate(lines, 1):
        code = line.split("#", 1)[0]
        if not STR_OF_PATH_PATTERN.search(code):
            continue
        if not ARGUMENT_CONTEXT_PATTERN.search(code):
            continue
        # Allow if as_posix() is also on the same line
        if "as_posix()" in code:
            continue
        hits.append((i, line))
    return hits


@check("WINDOWS-PATH: str(Path) instead of Path.as_posix() in CLI arguments")
def check_windows_paths():
    if not SCANNER_FILE.exists():
        # PLUGIN-PRESENT reports the missing file; nothing to scan here.
        return
    lines = _read_lines(SCANNER_FILE)
    if lines is None:
        fail(
            "WINDOWS-PATH",
            SCANNER_FILE.relative_to(PROJECT_ROOT),
            0,
            "ferret_scanner.py is not readable as UTF-8",
        )
        return
    for i, line in windows_path_hits(lines):
        fail(
            "WINDOWS-PATH",
            SCANNER_FILE.relative_to(PROJECT_ROOT),
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
        print(f"\n{'=' * 70}")
        print(f"FAILED: {len(failures)} issue(s) found\n")
        for check_name, filepath, line_num, message in failures:
            loc = f"{filepath}:{line_num}" if line_num else str(filepath)
            print(f"  [{check_name}] {loc}")
            print(f"    {message}\n")
        print(
            "Fix these issues before pushing. A SECRET-SECRET-KEYWORD hit is\n"
            "cleared by eliminating the trigger from source or by adding a\n"
            "suppression with line numbers to .ash/.ash_community_plugins.yaml;\n"
            "every other check is cleared by changing the source it names."
        )
        return 1
    else:
        print(f"All {len(CHECKS)} checks passed.")
        return 0


# ----------------------------------------------------------------------------
# 7. Multiple --exclude args instead of single comma-separated value
# ----------------------------------------------------------------------------
MULTIPLE_EXCLUDE_PATTERN = re.compile(r"for\s+\w+\s+in\s+.*exclude.*:\s*$")


def multiple_exclude_hits(lines: List[str]) -> List[int]:
    """Line numbers of loops in ``_process_config_options`` appending one --exclude each.

    The loop's body is read as one window of the next five lines, so an
    ``append`` wrapped onto the line after ``--exclude`` is still seen; the old
    test needed both tokens on one physical line.
    """
    hits: List[int] = []
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
            window = "\n".join(lines[i : min(i + 5, len(lines))])
            if "--exclude" in window and ("append" in window or "extend" in window):
                hits.append(i)
    return hits


@check(
    "EXCLUDE-MULTIPLE-ARGS: multiple --exclude args instead of comma-joined single arg"
)
def check_exclude_multiple_args():
    if not SCANNER_FILE.exists():
        # PLUGIN-PRESENT reports the missing file; nothing to scan here.
        return
    lines = _read_lines(SCANNER_FILE)
    if lines is None:
        return
    for i in multiple_exclude_hits(lines):
        fail(
            "EXCLUDE-MULTIPLE-ARGS",
            SCANNER_FILE.relative_to(PROJECT_ROOT),
            i,
            "Ferret-scan expects a single --exclude with comma-separated values, "
            "not multiple --exclude args. Use ','.join(patterns).",
        )


# ----------------------------------------------------------------------------
# 8. Ferret-scan registered in .ash.yaml instead of community plugins config
# ----------------------------------------------------------------------------
PLUGIN_MODULES_KEY = re.compile(r"^\s*ash_plugin_modules\s*:(?P<rest>.*)$")


def ferret_in_ash_yaml_hits(lines: List[str]) -> List[int]:
    """Line numbers where .ash.yaml's ``ash_plugin_modules`` names the ferret plugin.

    Armed by the key itself, not by the words ``ash_plugin_modules`` anywhere on
    a line: a comment that named the key used to put the check into list mode
    for whatever list followed it.
    """
    hits: List[int] = []
    in_plugin_modules = False
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        key = PLUGIN_MODULES_KEY.match(line)
        if key:
            in_plugin_modules = True
            if "ash_ferret_plugins" in key.group("rest"):
                hits.append(i)
            continue
        if in_plugin_modules:
            if line.strip().startswith("-"):
                if "ash_ferret_plugins" in line:
                    hits.append(i)
            elif line.strip():
                in_plugin_modules = False
    return hits


@check(
    "FERRET-IN-ASH-YAML: ferret-scan should not be in .ash/.ash.yaml (use community plugins config)"
)
def check_ferret_not_in_ash_yaml():
    ash_yaml = PROJECT_ROOT / ".ash" / ".ash.yaml"
    if not ash_yaml.exists():
        return
    lines = _read_lines(ash_yaml)
    if lines is None:
        return
    for i in ferret_in_ash_yaml_hits(lines):
        fail(
            "FERRET-IN-ASH-YAML",
            ash_yaml.relative_to(PROJECT_ROOT),
            i,
            "ferret-scan should be registered in .ash_community_plugins.yaml, "
            "not .ash.yaml (it's a community plugin, not built-in)",
        )


# ----------------------------------------------------------------------------
# 9. (removed 2026-09-14) CONFIG-OVERRIDE-EXCLUDES — the premise was false.
#    It required use_default_config:false whenever exclude_patterns were set, on
#    the belief that the bundled ferret-config.yaml overrides CLI --exclude.
#    Verified against ferret-scan v2.4.5 that the OPPOSITE holds: CLI --exclude
#    and --recursive both win over the bundled config's defaults, so ASH's
#    exclude_patterns / global_ignore_paths are honoured regardless of
#    use_default_config. Check removed rather than kept enforcing false advice.
#    See ash_ferret_plugins/DEVELOPMENT.md §10.
# ----------------------------------------------------------------------------


# ----------------------------------------------------------------------------
# 10. SECRET-SECRET-KEYWORD hits must have matching suppressions
# ----------------------------------------------------------------------------


@check(
    "SUPPRESSION-COVERAGE: SECRET-SECRET-KEYWORD hits in ferret plugin files have matching suppressions"
)
def check_suppression_coverage():
    """Verify that every SECRET-SECRET-KEYWORD hit in ferret plugin files
    has a matching suppression with line_start/line_end in the community
    plugins config. This ensures CI code scanning annotations are suppressed.
    """
    for filepath in ALL_FILES:
        if filepath.suffix not in (".py", ".md", ".yaml", ".yml"):
            continue
        lines = _read_lines(filepath)
        if lines is None:
            continue
        rel = filepath.relative_to(PROJECT_ROOT)
        for i, line in enumerate(lines, 1):
            if not SECRET_KEYWORD_PATTERN.search(_code_part(line, filepath.suffix)):
                continue
            # Skip lines that are already safe (allowlisted or comments)
            if keyword_hit_is_exempt(line, filepath.suffix):
                continue
            # This line triggers SECRET-SECRET-KEYWORD. Check #1 already flags a
            # hit that no suppression covers, so this check only looks at hits
            # that one does cover, and verifies that a covering suppression has
            # line numbers. An entry without line_start excuses the rule for the
            # whole file, which also hides every later hit there.
            covering = [
                s
                for s in COMMUNITY_SUPPRESSIONS
                if suppression_covers(s, rel, i, "SECRET-SECRET-KEYWORD")
            ]
            if covering and all(s.get("line_start") is None for s in covering):
                fail(
                    "SUPPRESSION-COVERAGE",
                    rel,
                    i,
                    f"Suppression for SECRET-SECRET-KEYWORD at {rel}:{i} "
                    f"is missing line_start/line_end — add line numbers "
                    f"for precision",
                )


if __name__ == "__main__":
    sys.exit(main())
