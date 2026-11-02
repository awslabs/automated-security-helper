# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's output directories are excluded by patterns that match them and nothing else.

A scanner told to skip ASH's output directory gets the directory's path spelled as a
pattern in its tool's own syntax. Each glob or regex metacharacter in the path is
escaped, so an ``--output-dir`` named ``out[1]`` excludes ``out[1]`` and nothing
else, never a source directory such as ``out1``. Measured on grype 0.120.1 and syft
1.54.1 (doublestar v4.10.2): ``--exclude ./out[1]/**`` skipped ``out1``, ``./out*x/**``
skipped ``out*x`` and ``outAx``, ``./out{a,b}/**`` skipped ``outa`` and ``outb``.
semgrep 1.180.0 and opengrep 1.30.2 did the same with ``[``, ``*``, ``?`` and ``\\``;
ferret-scan 2.5.2 with the full path ``<root>/out[1]/``; checkov 3.3.26 with a ``.``,
which its ``--skip-path`` regex reads as any character.

Each tool's matching is modeled here by what was measured on those versions, not
taken from the tool at test time, so the tests need no scanner installed. The
models are written out below; the measurements are in the commit that added this
file.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from tests.unit import test_ash_output_dirs_are_not_scanned as named

AshConfig.model_rebuild()
PluginContext.model_rebuild()

# ``capture`` is the ``caplog`` fixture tests/unit/conftest.py defines for every
# unit test; it is no longer re-exported through test_ash_output_dirs_are_not_scanned.

#: The scanners built here start no tool (tests/unit/conftest.py).
pytestmark = pytest.mark.usefixtures("no_tool_probes")


# ---------------------------------------------------------------------------
# The tools' matching, as measured
# ---------------------------------------------------------------------------


def _glob_regex(pattern: str, *, braces: bool, separator: str = "/") -> re.Pattern:
    """A regex that matches what *pattern* matches as a glob.

    ``*`` and ``?`` do not cross *separator*; ``**`` does. ``[...]`` is a character
    class (``!`` or ``^`` first negates). With *braces*, ``{a,b}`` is an
    alternation, as in doublestar; without, ``{`` is literal, as in semgrep's
    gitignore patterns and Go's ``filepath.Match``. When *separator* is ``/``, a
    backslash escapes the next character; when it is ``\\``, a backslash is the
    separator (Go's ``filepath.Match`` on Windows).
    """
    sep = re.escape(separator)
    out, i = [], 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and separator == "/" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if char == "*":
            if pattern[i : i + 2] == "**":
                out.append(".*")
                i += 2
            else:
                out.append(f"[^{sep}]*")
                i += 1
            continue
        if char == "?":
            out.append(f"[^{sep}]")
            i += 1
            continue
        if char == "[":
            end = pattern.find("]", i + 2)
            if end != -1:
                body = pattern[i + 1 : end]
                negate = body[:1] in ("!", "^")
                body = body[1:] if negate else body
                out.append("[" + ("^" if negate else "") + re.escape(body) + "]")
                i = end + 1
                continue
        if char == "{" and braces:
            end = pattern.find("}", i)
            if end != -1:
                options = pattern[i + 1 : end].split(",")
                out.append("(?:" + "|".join(re.escape(o) for o in options) + ")")
                i = end + 1
                continue
        out.append(re.escape(char))
        i += 1
    return re.compile("".join(out))


def _doublestar_excludes(pattern: str, path: str) -> bool:
    """grype and syft: ``doublestar.Match`` on the whole ``./``-relative path."""
    return bool(_glob_regex(pattern, braces=True).fullmatch(path))


def _gitignore_excludes(pattern: str, relative: str) -> bool:
    """semgrep and opengrep: an anchored pattern names a directory and all under it."""
    regex = _glob_regex(pattern.lstrip("/"), braces=False)
    parts = relative.split("/")
    return any(regex.fullmatch("/".join(parts[:n])) for n in range(1, len(parts) + 1))


def _ferret_excludes(pattern: str, path: str) -> bool:
    """ferret-scan 2.5.x: a glob against the path and each of its ancestors, and
    against an ancestor with a trailing separator ("build/")."""
    regex = _glob_regex(pattern, braces=False, separator=os.sep)
    parts = path.split(os.sep)
    candidates = []
    for n in range(2, len(parts) + 1):
        candidates.append(os.sep.join(parts[:n]))
        candidates.append(os.sep.join(parts[:n]) + os.sep)
    return any(regex.fullmatch(c) for c in candidates)


def _checkov_excludes(value: str, path: str) -> bool:
    """checkov's ``filter_ignored_paths``: ``re.search`` or a substring."""
    try:
        matched = bool(re.search(value, path))
    except re.error:
        matched = False
    return matched or value in path


@pytest.mark.unit
def test_the_models_reproduce_the_measured_over_matches():
    """The defects as measured, so a model that cannot see them fails here."""
    assert _doublestar_excludes("./out[1]/**", "./out1/requirements.txt")
    assert _doublestar_excludes("./out{a,b}/**", "./outa/requirements.txt")
    assert _gitignore_excludes("/out[1]", "out1/x.py")
    assert _gitignore_excludes("/out*x", "outAx/x.py")
    root = os.path.abspath(os.sep + "t")
    assert _ferret_excludes(
        f"{root}{os.sep}out[1]{os.sep}", f"{root}{os.sep}out1{os.sep}x.txt"
    )
    assert _checkov_excludes("/t/out.1/", "/t/outx1/main.tf")


# ---------------------------------------------------------------------------
# What each scanner is told
# ---------------------------------------------------------------------------


def _tree(tmp_path: Path, output: str, look_alike: str, source_name: str = "repo"):
    source = tmp_path / source_name
    for relative in (look_alike, output, "src"):
        (source / relative).mkdir(parents=True, exist_ok=True)
        (source / relative / "x.py").write_text("x = 1\n", encoding="utf-8")
    return source, source / output


@pytest.mark.unit
@pytest.mark.parametrize(
    "output, look_alike",
    [("out[1]", "out1"), ("out{a,b}", "outa"), ("out[!x]", "out!")],
)
@pytest.mark.parametrize("scanner_name", ["grype", "syft"])
def test_grype_and_syft_exclude_exactly_an_output_dir_named_with_glob_syntax(
    tmp_path, monkeypatch, output, look_alike, scanner_name
):
    source, output_dir = _tree(tmp_path, output, look_alike)
    excludes = _excludes_for(scanner_name, source, output_dir, monkeypatch)

    def excluded(relative):
        return any(_doublestar_excludes(p, f"./{relative}/x.py") for p in excludes)

    assert excluded(output), (output, excludes)
    assert not excluded(look_alike), (look_alike, excludes)
    assert not excluded("src"), excludes


def _excludes_for(scanner_name, source, output_dir, monkeypatch):
    context = named._context(source, output_dir)
    if scanner_name == "grype":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )

        scanner = GrypeScanner(context=context, config=GrypeScannerConfig())
        argv, _, _ = scanner._execute_scan(source, "source", [])
        return named._values(argv, "--exclude")
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        syft_scanner,
    )

    scanner = syft_scanner.SyftScanner(
        context=context, config=syft_scanner.SyftScannerConfig()
    )
    scanner.dependencies_satisfied = True
    seen = {}

    def fake_run(command, results_dir, **kwargs):
        seen["argv"] = command
        raise RuntimeError("stop after the command is built")

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kwargs: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    with pytest.raises(Exception, match="stop after the command is built"):
        scanner.scan(target=source, target_type="source")
    return named._values(seen["argv"], "--exclude")


def _grep_scanner(kind, context):
    if kind == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner,
            SemgrepScannerConfig,
        )

        return SemgrepScanner(context=context, config=SemgrepScannerConfig())
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
        OpengrepScannerConfig,
    )

    return OpengrepScanner(context=context, config=OpengrepScannerConfig())


@pytest.mark.unit
@pytest.mark.parametrize("kind", ["semgrep", "opengrep"])
def test_semgrep_and_opengrep_exclude_exactly_an_output_dir_named_with_glob_syntax(
    tmp_path, kind
):
    source, output_dir = _tree(tmp_path, "out[1]", "out1")
    scanner = _grep_scanner(kind, named._context(source, output_dir))
    # Relative to where the tool anchors: the target, or the checkout tmp_path is in.
    above = source.relative_to(named._semgrep_anchor(source))

    excludes = scanner._output_dir_exclude_patterns(source)

    def excluded(relative):
        path = (above / relative / "x.py").as_posix()
        return any(_gitignore_excludes(p, path) for p in excludes)

    assert excluded("out[1]"), excludes
    assert not excluded("out1"), excludes
    assert not excluded("src"), excludes


@pytest.mark.integration
@pytest.mark.parametrize("kind", ["semgrep", "opengrep"])
def test_the_scanned_directorys_own_name_is_escaped_in_the_anchor(tmp_path, kind):
    """In a git repository the pattern is anchored at its root, so the scanned
    directory's name is part of the pattern too."""
    (tmp_path / ".git").mkdir()
    source, output_dir = _tree(tmp_path, "out", "out1", source_name="repo[2]")
    scanner = _grep_scanner(kind, named._context(source, output_dir))

    excludes = scanner._output_dir_exclude_patterns(source)

    assert any(_gitignore_excludes(p, "repo[2]/out/x.py") for p in excludes), excludes
    assert not any(_gitignore_excludes(p, "repo[2]/out1/x.py") for p in excludes)


def _ferret_excludes_for(source, output_dir, monkeypatch):
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfig,
        FerretScanScanner,
    )

    scanner = FerretScanScanner(
        context=named._context(source, output_dir), config=FerretScannerConfig()
    )
    scanner.dependencies_satisfied = True
    seen = {}

    def fake_run(command, results_dir, **kwargs):
        seen["argv"] = command
        raise RuntimeError("stop after the command is built")

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kwargs: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    with pytest.raises(Exception, match="stop after the command is built"):
        scanner.scan(target=source, target_type="source", global_ignore_paths=[])
    return ",".join(named._values(seen["argv"], "--exclude")).split(",")


@pytest.mark.unit
@pytest.mark.parametrize("source_name", ["repo", "repo[2]"])
def test_ferret_scan_excludes_exactly_an_output_dir_named_with_glob_syntax(
    tmp_path, monkeypatch, source_name
):
    """The value is the full path, so the scanned directory's name is in it too."""
    source, output_dir = _tree(tmp_path, "out[1]", "out1", source_name=source_name)

    values = _ferret_excludes_for(source, output_dir, monkeypatch)

    root = os.path.abspath(source)

    def excluded(relative):
        path = os.path.join(root, relative, "deep", "x.txt")
        return any(_ferret_excludes(v, path) for v in values if v)

    assert excluded("out[1]"), values
    assert not excluded("out1"), values
    assert not excluded("src"), values


@pytest.mark.unit
def test_ferret_scan_is_not_told_about_a_path_with_a_comma(
    tmp_path, monkeypatch, capture
):
    """Its --exclude value is comma-separated and has no escape for a comma, so the
    path is left to the drop after the scan, and the log says so."""
    source, output_dir = _tree(tmp_path, "out,c", "out")

    values = _ferret_excludes_for(source, output_dir, monkeypatch)

    root = os.path.abspath(source)
    assert not any(v.startswith(root) for v in values), values
    warned = [r.getMessage() for r in capture.records if r.levelname == "WARNING"]
    assert any("ferret-scan" in w and "comma" in w for w in warned), warned


def _checkov_skip_paths(source, output_dir):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )

    scanner = CheckovScanner(
        context=named._context(source, output_dir), config=CheckovScannerConfig()
    )
    argv, _, _ = scanner._execute_scan(source, "source", [])
    return named._values(argv, "--skip-path")


@pytest.mark.unit
@pytest.mark.parametrize(
    "output, look_alike",
    [
        ("out.1", "outx1"),
        ("out+1", "outt1"),
        ("out{2}", "outt"),
        ("out[1]", "out1"),
        ("out]z", "outz"),
        ("out|q", "q"),
    ],
)
def test_checkov_skips_exactly_an_output_dir_named_with_regex_syntax(
    tmp_path, output, look_alike
):
    """On Windows ASH tells checkov nothing; its --skip-path matching is unreliable
    there, and the executor drops those findings instead."""
    source, output_dir = _tree(tmp_path, output, look_alike)

    values = _checkov_skip_paths(source, output_dir)

    if os.sep != "/":
        assert values == [], values
        return
    root = source.as_posix()
    assert any(_checkov_excludes(v, f"{root}/{output}/main.tf") for v in values), values
    assert not any(_checkov_excludes(v, f"{root}/{look_alike}/main.tf") for v in values)
    assert not any(_checkov_excludes(v, f"{root}/src/main.tf") for v in values)


@pytest.mark.unit
@pytest.mark.parametrize("output", ["out(1)", "out]("])
def test_checkov_is_not_told_about_a_path_its_module_finder_cannot_take(
    tmp_path, capture, output
):
    """checkov's terraform module finder joins every --skip-path into one regex a
    character at a time, which a parenthesis can break whether or not it is
    escaped. Such a path is left to the drop after the scan, with a warning."""
    source, output_dir = _tree(tmp_path, output, "out1")

    values = _checkov_skip_paths(source, output_dir)

    assert not any(output in v or re.escape(output) in v for v in values), values
    if os.sep == "/":
        warned = [r.getMessage() for r in capture.records if r.levelname == "WARNING"]
        assert any("checkov" in w and output in w for w in warned), warned


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_glob_spelling_of_each_metacharacter_is_pinned():
    """As measured on doublestar v4.10.2 (grype, syft), semgrep 1.180.0, opengrep
    1.30.2 and ferret-scan 2.4.5 and 2.5.2: a character class works for each glob
    metacharacter in all of them, without relying on a backslash, which Go's
    filepath.Match treats as the separator on Windows."""
    from automated_security_helper.utils.scan_output_dirs import (
        PatternSyntax,
        escape_for_pattern,
    )

    glob = PatternSyntax.GLOB
    assert escape_for_pattern("out[1]", glob, separator="/") == "out[[]1]"
    assert escape_for_pattern("out*x", glob, separator="/") == "out[*]x"
    assert escape_for_pattern("out?y", glob, separator="/") == "out[?]y"
    assert escape_for_pattern("out{a,b}", glob, separator="/") == "out[{]a,b}"
    assert escape_for_pattern("out]z}w!#", glob, separator="/") == "out]z}w!#"
    assert escape_for_pattern("out\\v", glob, separator="/") == "out\\\\v"
    assert escape_for_pattern("C:\\src\\out[1]", glob, separator="\\") == (
        "C:\\src\\out[[]1]"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "name, look_alike",
    [
        ("out[1]", "out1"),
        ("out*x", "outAx"),
        ("out?y", "outBy"),
        ("out{a,b}", "outa"),
        ("out\\v", "outv"),
        ("out[!x]n", "out!n"),
    ],
)
def test_an_escaped_glob_matches_only_its_own_name(name, look_alike):
    from automated_security_helper.utils.scan_output_dirs import (
        PatternSyntax,
        escape_for_pattern,
    )

    pattern = f"./{escape_for_pattern(name, PatternSyntax.GLOB, separator='/')}/**"

    assert _doublestar_excludes(pattern, f"./{name}/x")
    assert not _doublestar_excludes(pattern, f"./{look_alike}/x")
    gitignore = "/" + escape_for_pattern(name, PatternSyntax.GLOB, separator="/")
    assert _gitignore_excludes(gitignore, f"{name}/x")
    assert not _gitignore_excludes(gitignore, f"{look_alike}/x")


@pytest.mark.unit
@pytest.mark.parametrize(
    "name, look_alike",
    [("out[1]", "out1"), ("out*x", "outAx"), ("out?y", "outBy"), ("out[!x]n", "out!n")],
)
def test_an_escaped_fnmatch_pattern_matches_only_its_own_name(name, look_alike):
    """bandit 1.9.4 tests -x values with fnmatch and as substrings, after adding /*
    only to a value that names an existing directory, which an escaped value
    does not. So a caller appends the separator and * itself."""
    import fnmatch

    from automated_security_helper.utils.scan_output_dirs import (
        PatternSyntax,
        escape_for_pattern,
    )

    pattern = escape_for_pattern(f"/t/{name}", PatternSyntax.FNMATCH) + "/*"

    assert fnmatch.fnmatchcase(f"/t/{name}/deep/x.py", pattern)
    assert not fnmatch.fnmatchcase(f"/t/{look_alike}/x.py", pattern)
    assert escape_for_pattern("out\\v", PatternSyntax.FNMATCH) == "out\\v"
    assert escape_for_pattern("out{a,b}", PatternSyntax.FNMATCH) == "out{a,b}"


@pytest.mark.unit
def test_the_regex_spelling_is_re_escape():
    from automated_security_helper.utils.scan_output_dirs import (
        PatternSyntax,
        escape_for_pattern,
    )

    value = escape_for_pattern("/t/out.1+(x)/", PatternSyntax.REGEX)

    assert value == re.escape("/t/out.1+(x)/")
    assert re.search(value, "/t/out.1+(x)/main.tf")
    assert not re.search(value, "/t/outx1+(x)/main.tf")


# ---------------------------------------------------------------------------
# Names a tool's option cannot hold: told nothing, read, and dropped after
# ---------------------------------------------------------------------------


def _planted(source: Path, output_dir: Path, planted: str, real: str):
    for path in (output_dir / planted, source / real):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    return output_dir / planted, source / real


def _kept_uris(scanner_name, scanner, context):
    from unittest.mock import MagicMock

    from automated_security_helper.core.phases.scanner_executor import ScannerExecutor

    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    containers = executor._execute_scanner(
        scanner_name, scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in containers[0].raw_results.runs[0].results
    )


def _sarif(tool: str, uris) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool}},
                "results": [
                    {
                        "ruleId": "R1",
                        "level": "error",
                        "message": {"text": "planted"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                        ],
                    }
                    for uri in uris
                ],
            }
        ],
    }


def _warnings(capture) -> list[str]:
    return [r.getMessage() for r in capture.records if r.levelname == "WARNING"]


@pytest.mark.unit
def test_a_finding_in_an_output_dir_with_a_comma_is_dropped_from_ferret_scans_results(
    tmp_path, monkeypatch, capture
):
    """ferret-scan is told nothing about the directory, reads it, and ASH drops what
    it reports there; both steps say so, naming ferret-scan and the directory."""
    import json

    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfig,
        FerretScanScanner,
    )

    source = tmp_path / "repo"
    output_dir = source / "out,c"
    planted, real = _planted(source, output_dir, "reports/notes.txt", "src/notes.txt")
    context = named._context(source, output_dir)
    scanner = FerretScanScanner(context=context, config=FerretScannerConfig())
    scanner.dependencies_satisfied = True
    seen = {}

    def fake_run(command, results_dir, **kwargs):
        seen["argv"] = command
        Path(results_dir, "ferret-scan.sarif").write_text(
            json.dumps(_sarif("ferret-scan", [planted.as_posix(), real.as_posix()])),
            encoding="utf-8",
        )
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kwargs: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)

    kept = _kept_uris("ferret-scan", scanner, context)

    assert kept == ["src/notes.txt"], kept
    values = ",".join(named._values(seen["argv"], "--exclude")).split(",")
    assert not any(v.startswith(os.path.abspath(source)) for v in values), values
    warned = _warnings(capture)
    output_text = os.fspath(output_dir)
    assert any(
        "ferret-scan" in w and output_text in w and "comma" in w for w in warned
    ), warned
    assert any(
        "Dropped 1 ferret-scan finding" in w and output_dir.as_posix() in w
        for w in warned
    ), warned


@pytest.mark.unit
def test_a_finding_in_an_output_dir_with_a_parenthesis_is_dropped_from_checkovs_results(
    tmp_path, monkeypatch, capture
):
    """checkov is told nothing about the directory, reads it, and ASH drops what it
    reports there. On Windows ASH tells checkov about no output directory at all,
    so only the drop's warning names it there."""
    import json

    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
        checkov_repo_file_path,
    )

    source = tmp_path / "repo"
    output_dir = source / "out(1)"
    planted, real = _planted(source, output_dir, "reports/planted.tf", "main.tf")
    context = named._context(source, output_dir)
    scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
    scanner.dependencies_satisfied = True
    seen = {}

    def written(path: Path) -> str:
        # What checkov writes, run from the filesystem root as ASH runs it.
        return checkov_repo_file_path(str(path), Path(path).anchor).lstrip("/")

    def fake_run(command, results_dir, **kwargs):
        seen["argv"] = command
        Path(results_dir, "results_sarif.sarif").write_text(
            json.dumps(_sarif("checkov", [written(planted), written(real)])),
            encoding="utf-8",
        )
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kwargs: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)

    kept = _kept_uris("checkov", scanner, context)

    assert kept == ["main.tf"], kept
    assert not [v for v in named._values(seen["argv"], "--skip-path") if "out" in v], (
        seen["argv"]
    )
    warned = _warnings(capture)
    if os.sep == "/":
        assert any(
            "checkov" in w and f"{output_dir.as_posix()}/" in w for w in warned
        ), warned
    assert any(
        "Dropped 1 checkov finding" in w and output_dir.as_posix() in w for w in warned
    ), warned


@pytest.mark.unit
def test_a_percent_encoded_uri_is_read_decoded_unless_it_names_a_file_as_written(
    tmp_path,
):
    """checkov writes out(1) as out%281%29. A source directory whose name really is
    "o%281%29" keeps its findings: the URI names a file as it is written."""
    source = tmp_path / "repo"
    output_dir = source / "o(1)"
    for relative in ("o(1)/reports/x.py", "o%281%29/real.py", "src/a.py"):
        (source / relative).parent.mkdir(parents=True, exist_ok=True)
        (source / relative).write_text("x = 1\n", encoding="utf-8")
    context = named._context(source, output_dir)
    context.ignore_suppressions = True

    kept = named._run_scripted(
        context,
        [
            named._result("o%281%29/reports/x.py"),
            named._result("o%281%29/real.py"),
            named._result("src/a.py"),
        ],
    )

    assert kept == ["o%281%29/real.py", "src/a.py"], kept
