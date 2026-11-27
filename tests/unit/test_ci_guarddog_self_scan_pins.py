# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The self-scan runs GuardDog with no hit limit, and every GuardDog suppression
names either one line that holds the flagged text, or one definition whose span does.

Why this exists
---------------
GuardDog stops a rule after 1, 3 or 5 hits per package root unless
``scanners.guarddog.options.max_hits`` says otherwise. With the default, the
repository's own self-scan (``.ash/.ash_alpha_plugins.yaml``) stopped
threat-filesystem-read at its 5th hit, so matches past it were never reported or
reviewed. The self-scan sets ``max_hits: 0`` so every hit is visible, and each hit
it reports that is a test or fixture doing what the rule describes is suppressed
on its own: by the named definition that holds it (``symbol``) where one exists,
on its own line at module level.

A GuardDog suppression in either ``.ash`` config names one rule, one file, and one
line or one definition, so a new hit anywhere else, even in the same file, is still
reported. A line pin also goes stale when the file changes above it: the entry then
suppresses nothing, the real hit is reported again, and the stale entry still reads
as fine to anyone looking at the config. Measured when that check was added: 8 of
the 13 pins in each config pointed at a blank line, a comment or an unrelated
statement. A ``symbol`` entry does not rot that way (the resolver follows the
definition), but it can still name a definition whose body no longer holds what the
rule flags, so it gets the marker check over its resolved span instead.

What this checks
----------------
* The self-scan config sets ``max_hits: 0`` for GuardDog.
* Every GuardDog suppression (``threat-*`` and ``capability-*`` rule ids) in either
  ``.ash`` config names one rule, one file, and either one line or one symbol, so a
  new hit anywhere else, even in the same file, is still reported.
* Every line pin names a line, and every symbol entry a definition span, that holds
  at least one of the markers for its rule id. A rule id with no row in
  ``_RULE_LINE_MARKERS`` fails, so the first entry for a new rule adds its row.
* The two configs agree on their GuardDog suppressions: every entry in the alpha
  config is also in ``.ash.yaml``, and every entry only ``.ash.yaml``
  holds sits under a path the alpha config excludes from GuardDog, where an entry
  could never match. The self-scan reads only the alpha config; ``.ash.yaml``
  keeps the full set for a scan that lists the GuardDog module there without the
  exclusion.

The symbol spans come from tree-sitter, the optional ``symbols`` extra. Without it
the span checks skip, unless ``ASH_REQUIRE_SYMBOLS_EXTRA`` is set, as CI sets it,
in which case a missing extra is a failure rather than a skip.
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

import pytest
import yaml

from automated_security_helper.utils import symbol_spans
from automated_security_helper.utils.suppression_matcher import file_path_matches

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_SCAN = REPO_ROOT / ".ash" / ".ash_alpha_plugins.yaml"
DEFAULT = REPO_ROOT / ".ash.yaml"
GLOB_CHARACTERS = set("*?[")


def _load(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _guarddog_pins(path: Path) -> List[Dict[str, Any]]:
    entries = (_load(path).get("global_settings") or {}).get("suppressions") or []
    return [
        entry
        for entry in entries
        if str(entry.get("rule_id") or "").startswith(("threat-", "capability-"))
    ]


def _key(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    # None values are replaced with sortable stand-ins so a list mixing line
    # pins and symbol entries still sorts (None and int do not compare).
    return (
        entry["rule_id"],
        entry["path"],
        entry.get("line_start") or 0,
        entry.get("line_end") or 0,
        entry.get("symbol") or "",
    )


def _symbol_spans(entry: Dict[str, Any]) -> List[Tuple[int, int]]:
    """The resolved spans of a symbol entry, skipping when the extra is missing."""
    try:
        from automated_security_helper.utils.symbol_spans import (
            grammar_for_path,
            index_symbols,
        )

        grammar = grammar_for_path(entry["path"])
        assert grammar is not None, f"no symbol grammar for {entry['path']}"
        spans = index_symbols((REPO_ROOT / entry["path"]).read_bytes(), grammar)
    except ImportError as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA", "").strip().upper() in (
            "1",
            "YES",
            "TRUE",
        ):
            pytest.fail(
                "ASH_REQUIRE_SYMBOLS_EXTRA is set but the [symbols] extra is not "
                f"importable ({exc})."
            )
        pytest.skip(f"[symbols] extra not installed ({exc})")
    resolved = spans.get(entry["symbol"], ())
    assert resolved, f"{entry['path']}: symbol {entry['symbol']!r} resolves to nothing"
    return list(resolved)


#: A symbol entry that names a definition in this very file, so the helper reads a
#: real path and a real symbol without depending on either config file.
_THIS_FILE: Dict[str, Any] = {
    "path": Path(__file__).resolve().relative_to(REPO_ROOT).as_posix(),
    "symbol": "_symbol_spans",
}


def _without_tree_sitter(monkeypatch: pytest.MonkeyPatch) -> None:
    """What an install without the [symbols] extra does to an import of tree-sitter."""
    monkeypatch.setitem(sys.modules, "tree_sitter", None)
    monkeypatch.setattr(symbol_spans, "_language_cache", {})


def test_the_simulated_missing_extra_raises_symbols_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: the simulation raises what a missing extra raises."""
    _without_tree_sitter(monkeypatch)
    grammar = symbol_spans.grammar_for_path("module.py")
    assert grammar is not None
    with pytest.raises(symbol_spans.SymbolsUnavailableError):
        symbol_spans.index_symbols(b"def f():\n    pass\n", grammar)


def test_a_missing_extra_skips_the_span_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the extra, and without the CI flag, the check skips and names it."""
    _without_tree_sitter(monkeypatch)
    monkeypatch.delenv("ASH_REQUIRE_SYMBOLS_EXTRA", raising=False)
    with pytest.raises(pytest.skip.Exception, match=r"\[symbols\] extra not installed"):
        _symbol_spans(_THIS_FILE)


def test_a_missing_extra_fails_the_span_check_under_the_ci_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the CI flag set, a missing extra fails the check instead of skipping."""
    _without_tree_sitter(monkeypatch)
    monkeypatch.setenv("ASH_REQUIRE_SYMBOLS_EXTRA", "1")
    with pytest.raises(pytest.fail.Exception, match="ASH_REQUIRE_SYMBOLS_EXTRA is set"):
        _symbol_spans(_THIS_FILE)


def test_a_parse_error_is_not_read_as_a_missing_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: only a missing extra skips; a file that does not parse still fails."""
    root = SimpleNamespace(
        has_error=True, is_error=True, is_missing=False, start_point=(0, 0), children=[]
    )
    parser = SimpleNamespace(parse=lambda source: SimpleNamespace(root_node=root))
    monkeypatch.setattr(symbol_spans, "_new_parser", lambda grammar: parser)
    monkeypatch.delenv("ASH_REQUIRE_SYMBOLS_EXTRA", raising=False)
    with pytest.raises(symbol_spans.SymbolParseError):
        _symbol_spans(_THIS_FILE)


#: Text the pinned line must contain, by rule id: the shape of what each GuardDog
#: rule flags. A pin whose line holds none of its rule's markers is pointing at the
#: wrong line (a fold or an edit moved the file under it), so it suppresses nothing
#: and the real hit goes unsuppressed in the self-scan. A rule id with no row here
#: fails below, so a new rule gets markers when its first pin is added. The same
#: idea already guards the ferret-scan line ranges.
_RULE_LINE_MARKERS = {
    "threat-filesystem-read": (
        "/etc/",
        ".git/",
        "file://",
        "traversal",
        "/root/",
        "/var/",
        "creds.env",  # a test writing a fake credentials file
        ".npmrc",  # a package manager's rc file, named in a docstring
        "container.env",  # the env file ASH writes for its own container run
        # The dotfile names are matched as source text quotes them: a bare .env
        # would be a substring of os.environ and self.environment, so a drifted
        # pin on almost any environment-touching line would still read as fine.
        "'.env'",  # a dotenv file's name in a scannable-names table or docs data
        '".env"',
        "'.git-credentials'",  # a credential file's name in a scannable-names table
        '".git-credentials"',
    ),
    "threat-filesystem-destruction": ("rm -rf", "/home/"),
    "threat-process-download-exec": ("subprocess.run", "urlopen", "curl", "pip"),
    "threat-runtime-obfuscation-base64exec": (
        "b64decode",
        "atob(",
        "exec(",
        "Buffer.from",
    ),
    "threat-runtime-environment-read": ("os.environ",),
}


def test_the_self_scan_reports_every_guarddog_hit() -> None:
    guarddog = (_load(SELF_SCAN).get("scanners") or {}).get("guarddog") or {}
    assert (guarddog.get("options") or {}).get("max_hits") == 0


@pytest.mark.parametrize("config", [SELF_SCAN, DEFAULT], ids=lambda p: p.name)
def test_every_guarddog_suppression_is_one_rule_one_file_one_line_or_one_symbol(
    config: Path,
) -> None:
    pins = _guarddog_pins(config)
    assert pins, f"{config.name} has no GuardDog suppressions to check"
    for entry in pins:
        where = f"{config.name}: {entry}"
        assert not GLOB_CHARACTERS & set(entry["rule_id"]), where
        assert not GLOB_CHARACTERS & set(entry.get("path") or "*"), where
        if entry.get("symbol") is not None:
            # One definition, never a definition AND a line range: stacking both
            # would narrow the entry to their intersection, which is neither
            # reference's documented meaning for these one-hit entries.
            assert isinstance(entry["symbol"], str) and entry["symbol"], where
            assert entry.get("line_start") is None, where
            assert entry.get("line_end") is None, where
        else:
            assert isinstance(entry.get("line_start"), int), where
            assert entry.get("line_end") == entry["line_start"], where
        assert str(entry.get("reason") or "").strip(), where


@pytest.mark.parametrize("config", [SELF_SCAN, DEFAULT], ids=lambda p: p.name)
def test_every_guarddog_line_pin_names_a_line_that_holds_the_flagged_text(
    config: Path,
) -> None:
    """A line pin's one line holds a marker for its rule.

    Needs no tree-sitter: the line pins are checked on every run, whether or not
    the optional ``symbols`` extra is installed.
    """
    pins = [e for e in _guarddog_pins(config) if e.get("symbol") is None]
    assert pins, f"{config.name} has no line-pinned GuardDog suppressions to check"
    for entry in pins:
        markers = _RULE_LINE_MARKERS.get(entry["rule_id"])
        lines = (REPO_ROOT / entry["path"]).read_text(encoding="utf-8").splitlines()
        where = (
            f"{config.name}: {entry['rule_id']} {entry['path']}:{entry['line_start']}"
        )
        assert markers, f"{where}: no line markers for this rule id; add a row above"
        number = entry["line_start"]
        assert 1 <= number <= len(lines), f"{where}: past the end of the file"
        line = lines[number - 1]
        assert any(marker in line for marker in markers), (
            f"{where}: the pinned line holds none of {markers}; it reads {line!r}. "
            "Re-measure the pin: the file moved under it."
        )


@pytest.mark.parametrize("config", [SELF_SCAN, DEFAULT], ids=lambda p: p.name)
def test_every_guarddog_symbol_entry_names_a_definition_that_holds_the_flagged_text(
    config: Path,
) -> None:
    """A symbol entry's resolved span holds a marker for its rule.

    A symbol follows its definition when the file moves, so it cannot point at a
    blank line the way a stale pin does; what it CAN do is keep naming a
    definition whose body no longer holds what the rule flags, after the flagged
    code moved to another function. This is a weaker check than the line pin's:
    a marker needs to appear on SOME line of the definition, not on one named
    line, so a definition that merely mentions the marker elsewhere still
    passes. Gated on the ``symbols`` extra (skips without it; fails when
    ``ASH_REQUIRE_SYMBOLS_EXTRA`` is set); the line pins above are not.
    """
    pins = [e for e in _guarddog_pins(config) if e.get("symbol") is not None]
    assert pins, f"{config.name} has no symbol-scoped GuardDog suppressions to check"
    for entry in pins:
        markers = _RULE_LINE_MARKERS.get(entry["rule_id"])
        lines = (REPO_ROOT / entry["path"]).read_text(encoding="utf-8").splitlines()
        where = f"{config.name}: {entry['rule_id']} {entry['path']} {entry['symbol']}"
        assert markers, f"{where}: no line markers for this rule id; add a row"
        held = [
            lines[n - 1]
            for start, end in _symbol_spans(entry)
            for n in range(start, min(end, len(lines)) + 1)
        ]
        assert any(marker in line for marker in markers for line in held), (
            f"{where}: no line of the definition holds any of {markers}. "
            "The flagged code moved out of this definition; re-measure the entry."
        )


def test_the_dotfile_markers_match_the_name_only_as_source_text_quotes_it() -> None:
    """A threat-filesystem-read pin that drifts onto an environment read must fail.

    The marker check is a substring test, and a bare ``.env`` marker is a
    substring of ``os.environ``, ``.environment`` and ``self.env``, so with it a
    drifted pin passed on almost any line touching the environment -- the
    stale-pin failure this module exists to catch -- and the ``creds.env`` and
    ``container.env`` markers were redundant. The quoted forms match the file's
    name as a table or data entry quotes it, and nothing else.
    """
    markers = _RULE_LINE_MARKERS["threat-filesystem-read"]
    drifted = "    value = os.environ.get(name)  # read the environment, not a file"
    assert ".env" in drifted, "the control must carry the retired broad form"
    assert not any(marker in drifted for marker in markers), (
        "a drifted pin on an os.environ line must hold no marker"
    )
    for pinned in ('        ".env",', '        ".git-credentials",'):
        assert any(marker in pinned for marker in markers), pinned


def _excluded_globs() -> List[str]:
    options = ((_load(SELF_SCAN).get("scanners") or {}).get("guarddog") or {}).get(
        "options"
    ) or {}
    return [str(item["path"]) for item in options.get("excluded_paths") or []]


def test_the_two_configs_agree_on_their_guarddog_suppressions() -> None:
    self_scan = [_key(e) for e in _guarddog_pins(SELF_SCAN)]
    default = [_key(e) for e in _guarddog_pins(DEFAULT)]
    assert len(set(self_scan)) == len(self_scan), "a GuardDog pin is listed twice"
    assert len(set(default)) == len(default), "a GuardDog pin is listed twice"
    assert set(self_scan) <= set(default), (
        "the alpha config has a GuardDog pin that .ash.yaml lacks: "
        f"{sorted(set(self_scan) - set(default), key=str)}"
    )
    excluded = _excluded_globs()
    assert excluded, "the alpha config excludes no path from GuardDog"
    only_default = set(default) - set(self_scan)
    uncovered = [
        key
        for key in sorted(only_default, key=str)
        if not any(file_path_matches(key[1], glob) for glob in excluded)
    ]
    assert uncovered == [], (
        "these pins are only in .ash.yaml and sit under no excluded path of the "
        f"alpha config, so the self-scan would report them unpinned: {uncovered}"
    )


def test_a_pin_under_an_excluded_path_is_read_as_one_that_could_never_match() -> None:
    excluded = _excluded_globs()
    assert any(file_path_matches("tests/unit/test_a.py", glob) for glob in excluded)
    assert not any(
        file_path_matches("automated_security_helper/utils/a.py", glob)
        for glob in excluded
    )
