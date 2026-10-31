# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How a grep-family scan that scanned no file is graded.

``_post_process_sarif`` reads the tool's ``paths.scanned`` and ``paths.skipped``.
Nothing scanned is one of three outcomes:

- every file the tool found was left out by ASH's own exclusions: the global
  ignore paths, the ASH output directories inside the target, or the tools' own
  default ignore list (``tests/``, ``vendor/``, ``node_modules/``, ``*.min.js``,
  ...) that ASH re-passes as ``--exclude`` because ``--x-ignore-semgrepignore-files``
  drops it. The tools graded such a target SKIPPED on their own, and ASH grades it
  SKIPPED (``targets_attempted`` 0). It used to raise: the re-passed defaults were
  read as the operator's patterns.
- every file the tool found was left out by the operator's ``exclude`` patterns:
  a scanner error, as before, since the scan says nothing about them and the
  operator can change the patterns.
- the tool found a file and did not read it: a parse failure (the tool chose a
  language, so the file is a covered one), or a size or permission skip (which
  the tool reports before it chooses a language, measured on semgrep 1.180.0 with
  a 2 MB .csv and .svg, so whether a rule covers the file cannot be told): a
  scanner error either way, worded for what the report proves. It used to be
  graded SKIPPED as "no file in a covered language", which it is not.
- the tool skipped a file for a reason outside the 17 its own enum carries: a
  scanner error naming the reason, never SKIPPED on a guess.

The grading is driven directly, with a paths file written the way the tools write
it; no tool starts here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    DEFAULT_EXCLUDES,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


_SARIF: dict = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}],
}


def _scanner(test_plugin_context, monkeypatch, exclude=None) -> SemgrepScanner:
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    options = (
        SemgrepScannerConfigOptions(offline=False, exclude=exclude)
        if exclude is not None
        else SemgrepScannerConfigOptions(offline=False)
    )
    return SemgrepScanner(
        context=test_plugin_context, config=SemgrepScannerConfig(options=options)
    )


def _grade(scanner, tmp_path: Path, skipped: list, scanned: list | None = None):
    """Run the grading over a paths file holding *scanned* and *skipped*."""
    paths_file = tmp_path / "paths.json"
    paths_file.write_text(
        json.dumps({"paths": {"scanned": list(scanned or []), "skipped": skipped}}),
        encoding="utf-8",
    )
    scanner.targets_attempted = None
    scanner._post_process_sarif(
        _SARIF, [f"--json-output={paths_file.as_posix()}"], tmp_path / "src"
    )
    return scanner.targets_attempted


def _excluded(*paths: str) -> list:
    return [{"path": path, "reason": "cli_exclude_flags_match"} for path in paths]


def _outside_every_repository(tmp_path: Path) -> None:
    """Skip a case whose target must be its own project root: with a ``.git``
    above the temporary directory (``--basetemp`` inside a checkout, say) the
    outer repository is the root, the target's components below it are read
    against the default list, and the case measures the wrong thing."""
    if any((parent / ".git").exists() for parent in (tmp_path, *tmp_path.parents)):
        pytest.skip("a repository holds the temporary directory; it would be the root")


@pytest.mark.parametrize(
    "paths",
    [
        pytest.param(["tests/test_app.py", "tests/unit/test_x.py"], id="tests"),
        pytest.param(["test/app_test.py"], id="test"),
        pytest.param(["vendor/lib/x.py"], id="vendor"),
        pytest.param(["node_modules/pkg/index.js"], id="node_modules"),
        pytest.param(["build/out.py", "dist/out.js"], id="build-dist"),
        pytest.param(["static/app.min.js"], id="min-js"),
        pytest.param(["pkg/handler_test.go"], id="go-test"),
        pytest.param(["{target}/tests/test_app.py"], id="absolute-under-target"),
    ],
)
def test_files_the_tools_default_ignore_list_left_out_grade_skipped(
    test_plugin_context, monkeypatch, tmp_path, paths
):
    """A target whose files all sit on the tools' own default ignore list is
    SKIPPED, as the tools graded it before ASH re-passed that list as --exclude.
    An absolute path is read below the target, so ``<target>/tests/x.py`` is on
    the list the way ``tests/x.py`` is.

    Fails at the base with ScannerError ("its --exclude patterns left out all N
    files it found"): every ``cli_exclude_flags_match`` entry outside the global
    ignore names counted as the operator's.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    target = (tmp_path / "src").as_posix()
    paths = [path.format(target=target) for path in paths]

    assert _grade(scanner, tmp_path, _excluded(*paths)) == 0


@pytest.mark.parametrize(
    "checkout",
    [
        pytest.param(("opt", "atlassian", "pipelines", "agent", "build"), id="build"),
        pytest.param(("home", "ci", "tests"), id="tests"),
        pytest.param(("srv", "vendor"), id="vendor"),
    ],
)
def test_directories_above_the_target_never_count_as_default_ignores(
    test_plugin_context, monkeypatch, tmp_path, checkout
):
    """A checkout under a directory named ``build``, ``tests`` or ``vendor`` (the
    Bitbucket Pipelines and Travis clone roots, say) does not make every excluded
    file one the tools' defaults left out: only the components below the target
    are read against the list, so an operator pattern that left out every file is
    still refused.

    Fails at the tip that matched every component of the absolute path: there
    ``/opt/atlassian/pipelines/agent/build/repo/app.py`` read as a default ignore
    and the scan was graded SKIPPED. (At the base every excluded file was the
    operator's, so the base refuses this case too.)
    """
    _outside_every_repository(tmp_path)
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])
    target = tmp_path.joinpath(*checkout, "repo")
    target.mkdir(parents=True)
    paths_file_dir = tmp_path / "grading"
    paths_file_dir.mkdir()
    reported = (target / "app.py").as_posix()

    paths_file = paths_file_dir / "paths.json"
    paths_file.write_text(
        json.dumps({"paths": {"scanned": [], "skipped": _excluded(reported)}}),
        encoding="utf-8",
    )
    scanner.targets_attempted = None
    with pytest.raises(ScannerError, match="--exclude patterns left out all 1 files"):
        scanner._post_process_sarif(
            _SARIF, [f"--json-output={paths_file.as_posix()}"], target
        )


def _git_marker(repo: Path, marker: str) -> None:
    """Mark ``repo`` as a git work tree: ``.git`` as a directory (a main checkout)
    or as the one-line file a linked worktree or a submodule carries."""
    repo.mkdir(parents=True, exist_ok=True)
    if marker == "directory":
        (repo / ".git").mkdir()
    else:
        (repo / ".git").write_text(
            "gitdir: ../repo.git/worktrees/x\n", encoding="utf-8"
        )


@pytest.mark.parametrize("marker", ["directory", "file"])
@pytest.mark.parametrize("under", ["tests", "build", "vendor"])
def test_a_target_nested_under_a_default_ignore_inside_a_git_work_tree_grades_skipped(
    test_plugin_context, monkeypatch, tmp_path, under, marker
):
    """A target such as ``<repo>/tests/e2e-app`` inside a git work tree: the tools
    anchor their patterns at the repository root, so ``--exclude tests/`` (ASH's
    re-passed default) leaves out every file of the target, and the files are
    reported under it. The ``tests`` component sits between the project root and
    the target; ``_left_out_by_ash`` prefixes the target's own components below the
    project root (``_parts_of_target_below_root``) to the reported path's
    components below the target, so it is read once and the target grades SKIPPED,
    as the tools graded it; nothing here was the operator's exclude. The root is
    found by a ``.git`` entry of either shape: a linked worktree or a submodule
    carries a ``.git`` FILE, and a root finder that asked for a directory would
    make such a target its own root and refuse it.

    A membership pin on that grading, green since the prefix was added, not a red
    at the base: it holds whichever side supplies the component, and it fails if
    the prefix is dropped without ``_parts_below`` reading the root itself.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    repo = tmp_path / "repo"
    _git_marker(repo, marker)
    target = repo / under / "e2e-app"
    target.mkdir(parents=True)
    paths_file = tmp_path / "paths.json"
    paths_file.write_text(
        json.dumps(
            {
                "paths": {
                    "scanned": [],
                    "skipped": _excluded(
                        (target / "app.py").as_posix(), (target / "lib.py").as_posix()
                    ),
                }
            }
        ),
        encoding="utf-8",
    )
    scanner.targets_attempted = None
    scanner._post_process_sarif(
        _SARIF, [f"--json-output={paths_file.as_posix()}"], target
    )
    assert scanner.targets_attempted == 0


def test_the_same_nested_target_outside_any_git_work_tree_is_the_operators_exclude(
    test_plugin_context, monkeypatch, tmp_path
):
    """The control: with no ``.git`` above it the target is its own project root,
    the tools match patterns below it, and a path under it carries no ``tests``
    component, so an exclude that left out every file is the operator's."""
    _outside_every_repository(tmp_path)
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])
    target = tmp_path / "checkout" / "tests" / "e2e-app"
    target.mkdir(parents=True)
    paths_file = tmp_path / "paths.json"
    paths_file.write_text(
        json.dumps(
            {
                "paths": {
                    "scanned": [],
                    "skipped": _excluded((target / "app.py").as_posix()),
                }
            }
        ),
        encoding="utf-8",
    )
    scanner.targets_attempted = None
    with pytest.raises(ScannerError, match="--exclude patterns left out"):
        scanner._post_process_sarif(
            _SARIF, [f"--json-output={paths_file.as_posix()}"], target
        )


def test_an_ignore_name_above_the_target_does_not_count(
    test_plugin_context, monkeypatch, tmp_path
):
    """The global ignore names are matched below the target too: a target under a
    directory that carries one of those names is not thereby all ASH's exclusion."""
    _outside_every_repository(tmp_path)
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])
    scanner._ignore_exclude_names = ["generated"]
    target = tmp_path / "generated" / "repo"
    target.mkdir(parents=True)
    paths_file = tmp_path / "paths.json"
    paths_file.write_text(
        json.dumps(
            {
                "paths": {
                    "scanned": [],
                    "skipped": _excluded((target / "app.py").as_posix()),
                }
            }
        ),
        encoding="utf-8",
    )
    scanner.targets_attempted = None
    with pytest.raises(ScannerError, match="--exclude patterns left out"):
        scanner._post_process_sarif(
            _SARIF, [f"--json-output={paths_file.as_posix()}"], target
        )


def test_an_ignore_name_below_the_target_is_ashs_own_exclusion(
    test_plugin_context, monkeypatch, tmp_path
):
    """The positive twin of the test above: the same name below the target is one
    of ASH's exclusions, so a target whose files all sit under it grades SKIPPED;
    without the name recorded the same paths are refused, which shows the recorded
    names are what the grading reads."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner._ignore_exclude_names = ["generated"]

    assert _grade(scanner, tmp_path, _excluded("generated/app.py")) == 0

    scanner._ignore_exclude_names = []
    with pytest.raises(ScannerError, match="left out all"):
        _grade(scanner, tmp_path, _excluded("generated/app.py"))


def test_an_absolute_path_outside_the_target_keeps_only_its_file_name(
    test_plugin_context, monkeypatch, tmp_path
):
    """A reported path under neither the target nor its project root is matched
    on its file name alone: a directory pattern cannot match it, a file glob can."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    target = tmp_path / "src"
    target.mkdir()

    assert _grade(scanner, tmp_path, _excluded("/elsewhere/static/app.min.js")) == 0
    with pytest.raises(ScannerError, match="left out all"):
        _grade(scanner, tmp_path, _excluded("/elsewhere/tests/test_app.py"))


def test_files_in_an_ash_output_directory_grade_skipped(
    test_plugin_context, monkeypatch, tmp_path
):
    """The ASH output directories the command excluded are ASH's own exclusions,
    whether the tool reports the path relative to the target or absolute under it
    (an output directory the command excluded is always inside the target:
    ``_ash_output_dirs_inside`` lists only those)."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner._output_dir_excluded = [Path(".ash/ash_output")]
    target = (tmp_path / "src").as_posix()

    skipped = _excluded(
        ".ash/ash_output/reports/report.py",
        f"{target}/.ash/ash_output/scanners/semgrep/x.py",
    )
    assert _grade(scanner, tmp_path, skipped) == 0

    # The control: with no output directory recorded the same paths are nobody's
    # exclusion but the operator's, so the recorded list is what admits them.
    scanner._output_dir_excluded = []
    with pytest.raises(ScannerError, match="left out all"):
        _grade(scanner, tmp_path, skipped)


def test_files_the_operators_patterns_left_out_are_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path
):
    """The control: an operator pattern that excludes every file is still refused."""
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])

    with pytest.raises(ScannerError, match="--exclude patterns left out all 2 files"):
        _grade(scanner, tmp_path, _excluded("src/app.py", "src/lib.py"))


def test_one_operator_excluded_file_among_default_ignored_ones_is_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path
):
    """One file outside ASH's own exclusions is enough: the scan says nothing
    about it."""
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])

    with pytest.raises(ScannerError, match="--exclude patterns left out"):
        _grade(scanner, tmp_path, _excluded("tests/test_app.py", "src/app.py"))


def test_a_directory_named_like_a_default_ignore_as_the_file_is_not_one(
    test_plugin_context, monkeypatch, tmp_path
):
    """The default list names directories; a file named ``tests`` with no
    directory above it is not on it."""
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["tests"])

    with pytest.raises(ScannerError, match="--exclude patterns left out"):
        _grade(scanner, tmp_path, _excluded("tests"))


@pytest.mark.parametrize(
    "reason",
    [
        "exceeded_size_limit",
        "too_big",
        "analysis_failed_parser_or_internal_error",
        "insufficient_permissions",
    ],
)
def test_a_file_the_tool_found_and_did_not_read_is_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path, reason
):
    """Nothing scanned while a file was skipped unread or unparsed is refused.

    Fails at the base: ``targets_attempted`` was set to 0 and the target graded
    SKIPPED, "none is in a language its rules cover", for a file that may be.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)

    with pytest.raises(ScannerError, match="did not read|could not parse"):
        _grade(scanner, tmp_path, [{"path": "src/big.py", "reason": reason}])


def test_a_size_skip_is_refused_without_claiming_the_language_is_covered(
    test_plugin_context, monkeypatch, tmp_path
):
    """semgrep 1.180.0 reports a 2 MB .csv as ``exceeded_size_limit`` (measured),
    so a size skip proves nothing about the file's language. The scan is still
    refused (the result says nothing about the file) but the refusal says the
    coverage cannot be told and names the remedies, instead of claiming the file is
    in a covered language.

    Fails at the tip that worded every unread reason as "in a language its rules
    cover".
    """
    scanner = _scanner(test_plugin_context, monkeypatch)

    with pytest.raises(ScannerError) as refused:
        _grade(
            scanner, tmp_path, [{"path": "big.csv", "reason": "exceeded_size_limit"}]
        )
    message = str(refused.value)
    assert "cannot be told" in message, message
    # The one remedy that ends in SKIPPED is named; the tool's size limit is not
    # reachable through ASH's configuration (neither options model exposes it),
    # and a scanner `exclude` pattern is the operator's, so the refusal names
    # neither as a way out.
    assert "global_settings.ignore_paths" in message, message
    assert "max-target-bytes" not in message, message
    assert "a language its rules cover" not in message, message


def test_a_parse_failure_is_refused_as_a_covered_file(
    test_plugin_context, monkeypatch, tmp_path
):
    """A parser ran, so the tool chose a language: the file is a covered one and
    the refusal says so."""
    scanner = _scanner(test_plugin_context, monkeypatch)

    with pytest.raises(
        ScannerError, match="a language its rules cover and could not parse"
    ):
        _grade(
            scanner,
            tmp_path,
            [
                {
                    "path": "src/odd.py",
                    "reason": "analysis_failed_parser_or_internal_error",
                }
            ],
        )


def test_a_capitalized_exclude_spelling_is_still_the_exclude_refusal(
    test_plugin_context, monkeypatch, tmp_path
):
    """The exclude test reads the lowercased spelling too: a capitalized
    ``Cli_exclude_flags_match`` (no tool measured writing it) is the operator's
    exclude refusal, not a reason that lowercases into the known list and grades
    SKIPPED.

    Fails at the tip that compared this one spelling as written.
    """
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])

    with pytest.raises(ScannerError, match="its --exclude patterns left out all 1"):
        _grade(
            scanner,
            tmp_path,
            [{"path": "src/app.py", "reason": "Cli_exclude_flags_match"}],
        )


def test_a_capitalized_unread_spelling_is_refused_as_unread(
    test_plugin_context, monkeypatch, tmp_path
):
    """The tool's enum capitalizes three spellings, and opengrep's own spellings
    beyond the three it wrote are unmeasured, so a reason is compared lowercased
    in every test: ``Too_big`` is the size refusal, not a reason that lowercases
    into the known list and grades SKIPPED.

    Fails at the tip that compared the unread and unparsed sets as written and
    only the known set lowercased: ``Too_big`` graded SKIPPED.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)

    with pytest.raises(ScannerError, match="did not read 1 file"):
        _grade(scanner, tmp_path, [{"path": "src/big.py", "reason": "Too_big"}])


def test_an_unknown_skip_reason_is_refused_not_graded_skipped(
    test_plugin_context, monkeypatch, tmp_path
):
    """A reason outside the tool's measured enum could mean a covered file went
    unread; nothing scanned is then refused naming the reason, never SKIPPED on a
    guess.

    Fails at the base and at every earlier tip: an unlisted reason fell into the
    "none is in a language its rules cover" arm and graded SKIPPED.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)

    with pytest.raises(ScannerError, match="does not know \\(some_new_reason\\)"):
        _grade(scanner, tmp_path, [{"path": "src/app.py", "reason": "some_new_reason"}])


@pytest.mark.parametrize(
    "reason",
    [
        "always_skipped",
        "semgrepignore_patterns_match",
        "cli_include_flags_do_not_match",
        "excluded_by_config",
        "irrelevant_rule",
        "too_many_matches",
        "Gitignore_patterns_match",
        "Dotfile",
        "Nonexistent_file",
    ],
)
def test_every_other_reason_of_the_tools_enum_grades_skipped(
    test_plugin_context, monkeypatch, tmp_path, reason
):
    """The control for the unknown-reason refusal: each remaining member of
    semgrep 1.180.0's SkipReason enum, the three capitalized spellings as the
    package writes them included, is a file the tool chose not to scan."""
    scanner = _scanner(test_plugin_context, monkeypatch)

    assert _grade(scanner, tmp_path, [{"path": "x.py", "reason": reason}]) == 0


def test_an_exclusion_ash_does_not_recognize_is_named_when_no_operator_pattern_exists(
    test_plugin_context, monkeypatch, tmp_path
):
    """With no operator pattern configured the command carries only ASH's own
    patterns, so a ``cli_exclude_flags_match`` outside ASH's recognized
    exclusions is one ASH added and cannot place; the refusal says so and names
    the files, instead of blaming patterns the operator never wrote. The
    operator's own pattern keeps the wording that names it, beside the defaults
    or in their place.

    "No operator pattern" is the default configuration: its ``exclude`` value is
    the two default patterns (``DEFAULT_EXCLUDES``), which are ASH's own. A test on
    "any exclude configured" read them as the operator's and blamed the operator
    on every default scan (measured on the venue; fixed here).

    Fails at the base: every case reads "its --exclude patterns left out".
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    with pytest.raises(ScannerError) as refused:
        _grade(scanner, tmp_path, _excluded("src/app.py"))
    assert "does not recognize as its own" in str(refused.value), str(refused.value)
    assert "src/app.py" in str(refused.value), str(refused.value)

    for exclude in (["*.py"], [*DEFAULT_EXCLUDES, "*.py"]):
        with_pattern = _scanner(test_plugin_context, monkeypatch, exclude=exclude)
        with pytest.raises(ScannerError, match="its --exclude patterns left out all 1"):
            _grade(with_pattern, tmp_path, _excluded("src/app.py"))


def test_a_file_the_default_exclude_value_left_out_grades_skipped(
    test_plugin_context, monkeypatch, tmp_path
):
    """A source target holding only a converted notebook copy and a report file:
    both are left out by the default ``exclude`` value, ASH's own patterns, so the
    target is SKIPPED, not refused as the operator's doing.

    Fails at the base: refused as "its --exclude patterns left out all 2".
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = _excluded("notebook-converted.py", "run_report_result.txt")

    assert _grade(scanner, tmp_path, skipped) == 0


def test_a_default_pattern_the_operator_removed_is_no_longer_ashs(
    test_plugin_context, monkeypatch, tmp_path
):
    """``exclude: []`` takes the default patterns off the command, so a converted
    copy the tool still reports as excluded matched nothing ASH passed: the
    refusal says the pattern is one ASH does not recognize, and names the file.

    Fails at the base: "its --exclude patterns left out all 1".
    """
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=[])
    with pytest.raises(ScannerError) as refused:
        _grade(scanner, tmp_path, _excluded("notebook-converted.py"))

    assert "does not recognize as its own" in str(refused.value), str(refused.value)
    assert "notebook-converted.py" in str(refused.value), str(refused.value)


def test_on_the_converted_target_the_converted_file_pattern_is_the_operators(
    test_plugin_context, monkeypatch, tmp_path
):
    """The converted target drops the converted-file default from its command, so
    a converted copy the tool excluded there matched a pattern the operator wrote
    (``*.py`` here), and the refusal names the operator's patterns. A recognition
    by file name alone would grade this SKIPPED with no notebook scanned.

    Fails at the base: "its --exclude patterns left out all 1", the same text,
    by the base's blame-every-exclude route; the row pins the converted-target
    arm against the cure, not the base.
    """
    scanner = _scanner(
        test_plugin_context, monkeypatch, exclude=[*DEFAULT_EXCLUDES, "*.py"]
    )
    scanner._scan_target_type = "converted"
    with pytest.raises(ScannerError, match="its --exclude patterns left out all 1"):
        _grade(scanner, tmp_path, _excluded("notebook-converted.py"))

    # The control: the same report on the source target under the default value
    # alone, where the converted-file pattern travels as ASH's own, is SKIPPED.
    source = _scanner(test_plugin_context, monkeypatch, exclude=list(DEFAULT_EXCLUDES))
    assert _grade(source, tmp_path, _excluded("notebook-converted.py")) == 0


def test_an_operator_pattern_that_cannot_name_the_file_does_not_take_the_blame(
    test_plugin_context, monkeypatch, tmp_path
):
    """The operator wrote ``*.md``; the tool reports ``src/app.py`` as excluded by a
    command-line pattern. No pattern of the operator's can name that file, so the
    exclusion is one ASH does not recognize, and the refusal says so and names the
    file instead of blaming the operator's patterns. A pattern that names a
    directory of the path (``src/``) or the whole path is the operator's, and so
    is one anchored at the project root with a leading slash (``/src/``,
    ``/src``, ``/src/app.py``), which the tools honor as written.

    Fails at the base: every configured pattern took the blame, whatever it named.
    The anchored rows fail at the previous tip: the glob kept its leading slash
    (``rstrip("/")`` only), so ``/src`` matched neither the ``src`` component nor
    the path ``src/app.py``, and the refusal said "does not recognize as its own"
    for a pattern the operator wrote.
    The directory-qualified rows fail at the tip before this one: the candidates
    were each component alone and the path as reported, so ``sub/*.py`` and
    ``sub/app.py`` matched nothing when the tool reported the path absolute, and
    ``sub/deeper/`` (glob ``sub/deeper``) matched neither a component nor the
    whole path ``sub/deeper/app.py``; the refusal said "does not recognize as its
    own" for a pattern the operator wrote. The ``sub/``, ``sub/*/app.py`` rows
    already matched there and pin that the leading joins add no loss.
    """
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.md"])
    with pytest.raises(ScannerError) as refused:
        _grade(scanner, tmp_path, _excluded("src/app.py"))
    assert "does not recognize as its own" in str(refused.value), str(refused.value)
    assert "src/app.py" in str(refused.value), str(refused.value)

    for exclude in (
        ["src/"],
        ["src"],
        ["src/app.py"],
        ["*.py"],
        ["/src/"],
        ["/src"],
        ["/src/app.py"],
    ):
        named = _scanner(test_plugin_context, monkeypatch, exclude=exclude)
        with pytest.raises(ScannerError, match="its --exclude patterns left out all 1"):
            _grade(named, tmp_path, _excluded("src/app.py"))

    # A pattern with a directory component names the file whichever way the tool
    # spelled its path: an absolute one (the target here is ``tmp_path / "src"``)
    # or a relative one below a nested directory.
    absolute = (tmp_path / "src" / "sub" / "app.py").as_posix()
    for exclude, reported in (
        (["sub/*.py"], absolute),
        (["sub/app.py"], absolute),
        (["sub/"], absolute),
        (["sub/deeper/"], "sub/deeper/app.py"),
        (["/sub/deeper"], "sub/deeper/app.py"),
        (["sub/*/app.py"], "sub/deeper/app.py"),
    ):
        named = _scanner(test_plugin_context, monkeypatch, exclude=exclude)
        with pytest.raises(ScannerError, match="its --exclude patterns left out all 1"):
            _grade(named, tmp_path, _excluded(reported))

    # The control: an inner-slash pattern that names another directory still
    # cannot name the file, and the refusal says so.
    other = _scanner(test_plugin_context, monkeypatch, exclude=["other/*.py"])
    with pytest.raises(ScannerError) as unnamed:
        _grade(other, tmp_path, _excluded(absolute))
    assert "does not recognize as its own" in str(unnamed.value), str(unnamed.value)


@pytest.mark.parametrize("marker", ["directory", "file"])
def test_a_converted_target_under_a_default_ignore_is_graded_by_the_operators_pattern(
    test_plugin_context, monkeypatch, tmp_path, marker
):
    """``--output-dir build/ash`` inside a git work tree puts the converted target
    at ``<repo>/build/ash/converted``. Its command drops ``--exclude build/``
    (_extra_args_for_target), so a converted copy the tool excluded there was left
    out by the operator's ``*.py``, and the scan is refused as the operator's
    doing; the grading no longer credits the dropped ``build/`` default.

    Fails at the base: every excluded file carried the ``build`` component, the
    grading read it as the tools' default and graded the target SKIPPED with no
    notebook scanned, for a pattern the command never carried.
    """
    scanner = _scanner(
        test_plugin_context, monkeypatch, exclude=[*DEFAULT_EXCLUDES, "*.py"]
    )
    scanner._scan_target_type = "converted"
    repo = tmp_path / "repo"
    _git_marker(repo, marker)
    target = repo / "build" / "ash" / "converted"
    target.mkdir(parents=True)
    paths_file = tmp_path / "paths.json"
    paths_file.write_text(
        json.dumps(
            {
                "paths": {
                    "scanned": [],
                    "skipped": _excluded((target / "notebook-converted.py").as_posix()),
                }
            }
        ),
        encoding="utf-8",
    )
    scanner.targets_attempted = None
    with pytest.raises(ScannerError, match="its --exclude patterns left out all 1"):
        scanner._post_process_sarif(
            _SARIF, [f"--json-output={paths_file.as_posix()}"], target
        )

    # The control: the source target keeps every default on its command, so a
    # source tree under build/ excluded whole is the tools' own default, SKIPPED.
    source = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])
    source_target = repo / "build" / "generated"
    source_target.mkdir(parents=True)
    paths_file.write_text(
        json.dumps(
            {
                "paths": {
                    "scanned": [],
                    "skipped": _excluded((source_target / "app.py").as_posix()),
                }
            }
        ),
        encoding="utf-8",
    )
    source.targets_attempted = None
    source._post_process_sarif(
        _SARIF, [f"--json-output={paths_file.as_posix()}"], source_target
    )
    assert source.targets_attempted == 0


def test_unread_files_beside_uncovered_ones_are_still_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = [
        {"path": "README.md", "reason": "wrong_language"},
        {"path": "src/big.py", "reason": "too_big"},
    ]

    with pytest.raises(ScannerError, match="1 file\\(s\\)"):
        _grade(scanner, tmp_path, skipped)


def test_only_uncovered_files_grade_skipped(test_plugin_context, monkeypatch, tmp_path):
    """The control: nothing in a covered language is SKIPPED, as before."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = [
        {"path": "README.md", "reason": "wrong_language"},
        {"path": "image.png", "reason": "binary"},
        {"path": "app.min.js", "reason": "minified"},
    ]

    assert _grade(scanner, tmp_path, skipped) == 0


def test_default_ignored_files_beside_uncovered_ones_grade_skipped(
    test_plugin_context, monkeypatch, tmp_path
):
    """A repository holding only ``tests/`` and documents: the tests are the tools'
    own default exclusion and the documents are in no covered language, so nothing
    here is the operator's and nothing was left unread; the target is SKIPPED."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = [
        *_excluded("tests/test_app.py"),
        {"path": "README.md", "reason": "wrong_language"},
    ]

    assert _grade(scanner, tmp_path, skipped) == 0


def test_a_scanned_file_counts_whatever_was_skipped(
    test_plugin_context, monkeypatch, tmp_path
):
    """The control: with a file scanned the count is the scanned count, and the
    skipped entries, unread ones included, change nothing."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = [{"path": "src/big.py", "reason": "too_big"}]

    assert _grade(scanner, tmp_path, skipped, scanned=["src/app.py"]) == 1


def test_the_output_directories_the_command_excluded_are_recorded(
    tmp_path, monkeypatch
):
    """``_output_dir_exclude_patterns`` records the directories it excluded, so
    the grading can tell their files apart from the operator's patterns."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config

    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    scanner = SemgrepScanner(
        context=context,
        config=SemgrepScannerConfig(options=SemgrepScannerConfigOptions(offline=False)),
    )

    patterns = scanner._output_dir_exclude_patterns(source)

    assert patterns, "premise: the output directory inside the target is excluded"
    assert scanner._output_dir_excluded == [Path(".ash/ash_output")]

    # A second target on the same instance replaces the record: ASH resolves the
    # source and the converted target on one scanner, and the grading of the
    # second must not read the first's directories.
    other = tmp_path / "other"
    other.mkdir()
    (other / "lib.py").write_text("y = 2\n", encoding="utf-8")
    assert scanner._output_dir_exclude_patterns(other) == []
    assert scanner._output_dir_excluded == []


@pytest.mark.parametrize(
    "reported",
    [
        pytest.param("test_app.py", id="relative-to-the-target"),
        pytest.param("tests/test_app.py", id="relative-to-the-root"),
        pytest.param("{target}/test_app.py", id="absolute"),
    ],
)
def test_a_target_that_is_a_default_ignored_directory_of_its_repository_grades_skipped(
    test_plugin_context, monkeypatch, tmp_path, reported
):
    """A target that is itself the repository's ``tests/`` directory is excluded
    whole by the tools' own default list, which they anchor at the repository
    root, so its files are ASH's exclusions however the tool reports them:
    relative to the target, relative to the root, or absolute.

    Fails at the tip that read only the components below the target, on the
    relative-to-the-target and absolute rows: those hold no ``tests``, so the files
    counted as the operator's and the scan was refused. (The base refused every
    excluded file as the operator's, so it is red on every row.)
    """
    scanner = _scanner(test_plugin_context, monkeypatch)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    target = repo / "tests"
    target.mkdir()
    paths_file_dir = tmp_path / "grading"
    paths_file_dir.mkdir()
    paths_file = paths_file_dir / "paths.json"
    paths_file.write_text(
        json.dumps(
            {
                "paths": {
                    "scanned": [],
                    "skipped": _excluded(reported.format(target=target.as_posix())),
                }
            }
        ),
        encoding="utf-8",
    )
    scanner.targets_attempted = None

    scanner._post_process_sarif(
        _SARIF, [f"--json-output={paths_file.as_posix()}"], target
    )

    assert scanner.targets_attempted == 0


def test_a_target_under_an_ordinary_directory_of_its_repository_is_still_refused(
    test_plugin_context, monkeypatch, tmp_path
):
    """The control: the target's own components below the root count only when
    they are on the default list; ``src`` is not, so an operator pattern that left
    out every file is refused as before."""
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    target = repo / "src"
    target.mkdir()
    paths_file_dir = tmp_path / "grading"
    paths_file_dir.mkdir()
    paths_file = paths_file_dir / "paths.json"
    paths_file.write_text(
        json.dumps({"paths": {"scanned": [], "skipped": _excluded("app.py")}}),
        encoding="utf-8",
    )
    scanner.targets_attempted = None

    with pytest.raises(ScannerError, match="--exclude patterns left out all 1 files"):
        scanner._post_process_sarif(
            _SARIF, [f"--json-output={paths_file.as_posix()}"], target
        )
