# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Files committed to git inside one of ASH's output directories are scanned.

ASH leaves out the directories it names as its own output (this scan's output
directory, and ``.ash/ash_output`` under the scanned directory and under the
working directory). A repository can commit files there, and those are scanned
also with ``--output-dir`` outside the tree, as container mode runs: a B602 and an
AWS key committed under ``.ash/ash_output/hidden/``, and a file committed under
``sub/.ash/ash_output`` for ``cd sub && ash scan --source-dir ..``.

In a git checkout, a file git tracks inside a named directory is scanned, and ASH
warns that its output directory holds committed files. Its tool exclusions skip
only the named directories that hold no tracked file, and the executor's drop and
the suppression step keep the results located in a tracked file. Outside git,
nothing tells ASH's files from committed ones: this run's output directory is
left out whole, and an earlier run's ``.ash/ash_output`` is scanned whole, with a
warning (tests/unit/test_leftover_output_dir_without_git_is_scanned.py). Leaving
that one out too would leave every file in it unscanned.

That holds when the committed files are in this run's own output directory, as
they are with the default ``.ash/ash_output``: detect-secrets and bandit report a
file committed there as they report the same file with ``--output-dir``
elsewhere.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import (
    output_dirs_to_exclude,
    tracked_files_in,
)
from tests.unit import test_ash_output_dirs_are_not_scanned as named
from tests.unit import test_output_dir_patterns_are_escaped as patterns
from tests.unit.workspace.test_execution import _git

# ``capture`` is the ``caplog`` fixture tests/unit/conftest.py defines for every
# unit test; it is no longer re-exported through test_ash_output_dirs_are_not_scanned.

#: The scanners built here start no tool, and a tree built without ``git init`` is
#: outside git wherever tmp_path is (tests/unit/conftest.py).
pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("no_tool_probes", "no_checkout_above_tmp_path"),
]

COMMITTED = (
    ".ash/ash_output/hidden/app.py",
    ".ash/ash_output/hidden/settings.py",
)
ASH_WROTE = (
    ".ash/ash_output/reports/ash.sarif",
    ".ash/ash_output/ash_aggregated_results.json",
)


def _tree(root: Path, *, in_git: bool) -> Path:
    source = root / "repo"
    for relative in ("app.py", *COMMITTED, *ASH_WROTE):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = 'x'\n", encoding="utf-8")
    if in_git:
        assert _git(source, "init", "-q").returncode == 0
        added = _git(source, "add", "app.py", *COMMITTED)
        assert added.returncode == 0, added.stderr
    return source


def _relative(source: Path, files) -> set[str]:
    return {Path(f).relative_to(source).as_posix() for f in files}


def _warnings(capture) -> list[str]:
    return [r.getMessage() for r in capture.records if r.levelname == "WARNING"]


def test_git_says_which_files_are_tracked_and_none_outside_a_checkout(tmp_path):
    tracked = _tree(tmp_path / "git", in_git=True)
    untracked = _tree(tmp_path / "plain", in_git=False)

    found = tracked_files_in(tracked / ".ash" / "ash_output")

    assert found is not None
    assert sorted(p.relative_to(tracked).as_posix() for p in found) == sorted(COMMITTED)
    assert tracked_files_in(untracked / ".ash" / "ash_output") is None


def test_committed_files_are_in_the_scan_set_with_the_output_dir_elsewhere(
    tmp_path, capture
):
    """``--source-dir X --output-dir Y``, as container mode runs it."""
    source = _tree(tmp_path, in_git=True)

    found = _relative(
        source, scan_set(source=str(source), output=str(tmp_path / "out"))
    )

    assert set(COMMITTED) <= found, found
    assert not set(ASH_WROTE) & found, found
    warned = [w for w in _warnings(capture) if "committed" in w]
    assert len(warned) == 1 and "/.ash/ash_output" in warned[0], warned
    assert "2 files" in warned[0], warned


def test_outside_git_an_earlier_runs_output_dir_is_scanned_whole(tmp_path, capture):
    """Nothing tells the repository's files there from ASH's, so all are scanned,
    with one warning naming the directory, rather than all hidden."""
    source = _tree(tmp_path, in_git=False)

    found = _relative(
        source, scan_set(source=str(source), output=str(tmp_path / "out"))
    )

    assert (set(COMMITTED) | set(ASH_WROTE)) <= found, found
    assert "app.py" in found
    warnings = [w for w in _warnings(capture) if "ignore_paths" in w]
    assert len(warnings) == 1 and ".ash/ash_output" in warnings[0], warnings


def test_outside_git_this_runs_output_dir_is_left_out(tmp_path, capture):
    source = _tree(tmp_path, in_git=False)

    found = _relative(
        source,
        scan_set(source=str(source), output=str(source / ".ash" / "ash_output")),
    )

    assert not (set(COMMITTED) | set(ASH_WROTE)) & found, found
    assert "app.py" in found
    assert not [w for w in _warnings(capture) if "committed" in w]


def test_the_working_directorys_default_output_is_scanned_when_committed(
    tmp_path, monkeypatch
):
    """``cd sub && ash scan --source-dir ..`` with ``sub/.ash/ash_output`` committed."""
    source = _tree(tmp_path, in_git=True)
    sub = source / "sub"
    hidden = sub / ".ash" / "ash_output" / "hidden" / "handler.py"
    hidden.parent.mkdir(parents=True)
    hidden.write_text("import subprocess\n", encoding="utf-8")
    (sub / ".ash" / "ash_output" / "ash.log").write_text("log\n", encoding="utf-8")
    _git(source, "add", "sub/.ash/ash_output/hidden/handler.py")
    monkeypatch.chdir(sub)

    found = _relative(
        source, scan_set(source=str(source), output=str(tmp_path / "out"))
    )

    assert "sub/.ash/ash_output/hidden/handler.py" in found
    assert "sub/.ash/ash_output/ash.log" not in found


def test_this_runs_output_dir_with_committed_files_is_scanned_for_them(tmp_path):
    source = _tree(tmp_path, in_git=True)
    committed = source / "out" / "notes.py"
    committed.parent.mkdir()
    committed.write_text("x = 1\n", encoding="utf-8")
    (source / "out" / "ash.log").write_text("log\n", encoding="utf-8")
    _git(source, "add", "out/notes.py")

    found = _relative(source, scan_set(source=str(source), output=str(source / "out")))

    assert "out/notes.py" in found
    assert "out/ash.log" not in found


@pytest.mark.parametrize("in_git", [True, False])
def test_a_tool_is_told_to_skip_a_named_directory_only_without_committed_files(
    tmp_path, in_git
):
    source = _tree(tmp_path, in_git=in_git)
    files = scan_set(source=str(source), output=str(source / "shard-1"))

    excluded = output_dirs_to_exclude(source, source / "shard-1", scanned_files=files)

    default = source / ".ash" / "ash_output"
    # In git it holds committed files; outside git it is an earlier run's output
    # directory nothing can be said about, and is scanned whole.
    assert default not in excluded, excluded
    if not in_git:
        assert not [path for path in excluded if path.is_relative_to(default)]
    assert source / "shard-1" in excluded


def test_the_checkov_command_line_keeps_a_directory_with_committed_files(tmp_path):
    """The directory holding the committed files is not skipped; ASH's own
    working directories in it, none of which holds one, are."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
    )
    from automated_security_helper.utils.scan_output_dirs import ash_own_dir_names

    source = _tree(tmp_path, in_git=True)
    scanner = CheckovScanner(context=named._context(source, tmp_path / "out"))

    skipped = scanner._ash_output_dirs_inside(source)

    assert sorted(skipped) == sorted(
        Path(".ash", "ash_output", name) for name in ash_own_dir_names()
    ), skipped


@pytest.mark.parametrize("ignore_suppressions", [False, True])
@pytest.mark.parametrize("output", ["elsewhere", "this-run"])
def test_the_drop_keeps_findings_in_committed_files(
    tmp_path, ignore_suppressions, output
):
    """With the output directory outside the tree, and with ``.ash/ash_output``,
    which holds the committed files, as this run's output directory: the default."""
    source = _tree(tmp_path, in_git=True)
    context = named._context(
        source,
        tmp_path / "out" if output == "elsewhere" else source / ".ash" / "ash_output",
    )
    context.ignore_suppressions = ignore_suppressions

    kept = named._run_scripted(
        context,
        [named._result(uri) for uri in ("app.py", *COMMITTED, *ASH_WROTE)],
    )

    assert kept == sorted(["app.py", *COMMITTED]), kept


# ---------------------------------------------------------------------------
# This run's output directory holds the committed files
# ---------------------------------------------------------------------------
#
# The default layout: no --output-dir, so this run writes to .ash/ash_output, the
# directory the repository committed files to. detect-secrets left every scan-set
# file under the output directory out of its file list, and the suppression step
# excluded every result located there, committed or not.


def _this_run(tmp_path: Path):
    """The tree of ``_tree``, in git, with ``.ash/ash_output`` as this run's output."""
    source = _tree(tmp_path, in_git=True)
    return source, named._context(source, source / ".ash" / "ash_output")


def _bandit_excludes(value: str, path: str) -> bool:
    """bandit 1.9.4's ``--exclude``: ``fnmatch`` against the path, or a substring;
    a value naming an existing directory also matches the files in it."""
    import fnmatch

    if os.path.isdir(value) and fnmatch.fnmatch(path, value.rstrip("/") + "/*"):
        return True
    return fnmatch.fnmatch(path, value) or value in path


def _tool_scanner(kind: str, context):
    """The scanner for *kind*, and the name of the SARIF file it reads back."""
    if kind == "bandit":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
            BanditScannerConfig,
        )

        return BanditScanner(context=context, config=BanditScannerConfig()), (
            "bandit.sarif"
        )
    if kind in ("semgrep", "opengrep"):
        return patterns._grep_scanner(kind, context), "results_sarif.sarif"
    if kind == "grype":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )

        return GrypeScanner(context=context, config=GrypeScannerConfig()), (
            "results_sarif.sarif"
        )
    if kind == "checkov":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
            CheckovScannerConfig,
        )

        return CheckovScanner(context=context, config=CheckovScannerConfig()), (
            "results_sarif.sarif"
        )
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfig,
        FerretScanScanner,
    )

    return FerretScanScanner(context=context, config=FerretScannerConfig()), (
        "ferret-scan.sarif"
    )


def _exclusion_values(kind: str, argv) -> list[str]:
    """The values of the option *kind*'s tool skips paths with, as ASH passed them."""
    flag = {"bandit": "--exclude", "checkov": "--skip-path"}.get(kind, "--exclude")
    values = named._values(argv, flag)
    values += [arg.split("=", 1)[1] for arg in argv if arg.startswith(f"{flag}=")]
    if kind in ("bandit", "ferret-scan"):
        values = [v for value in values for v in value.split(",")]
    return [v for v in values if v]


def _skipped_by_tool(kind: str, values, source: Path, relative: str) -> bool:
    """Whether *kind*'s tool skips *relative*, read the way it was measured to."""
    absolute = os.path.join(os.path.abspath(source), *relative.split("/"))
    if kind == "bandit":
        return any(_bandit_excludes(v, absolute) for v in values)
    if kind in ("semgrep", "opengrep"):
        return any(patterns._gitignore_excludes(v, relative) for v in values)
    if kind == "grype":
        return any(patterns._doublestar_excludes(v, f"./{relative}") for v in values)
    if kind == "checkov":
        posix = Path(absolute).as_posix()
        return any(patterns._checkov_excludes(v, posix) for v in values)
    return any(patterns._ferret_excludes(v, absolute) for v in values)


#: A named directory holding nothing git tracks: the working directory's default
#: output, with ASH's log in it.
_UNTRACKED_NAMED = "sub/.ash/ash_output/ash.log"

#: The scanners whose tool is told to skip such a directory: every one here.
_TOLD_TO_SKIP = frozenset(
    {"bandit", "semgrep", "opengrep", "grype", "checkov", "ferret-scan"}
)


@pytest.mark.parametrize("ignore_suppressions", [False, True])
@pytest.mark.parametrize(
    "kind", ["bandit", "semgrep", "opengrep", "grype", "checkov", "ferret-scan"]
)
def test_each_tool_reads_the_committed_files_in_this_runs_output_dir(
    tmp_path, monkeypatch, kind, ignore_suppressions
):
    """Each scanner that walks a directory, with its tool stubbed to report a finding
    in every file. No tool is told to skip the committed file, and each skips the
    named directory holding no tracked file. The results keep the committed file's
    finding and lose those in files ASH wrote."""
    import json

    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        checkov_repo_file_path,
    )

    source, context = _this_run(tmp_path)
    log = source / _UNTRACKED_NAMED
    log.parent.mkdir(parents=True)
    log.write_text("log\n", encoding="utf-8")
    monkeypatch.chdir(source / "sub")
    context.ignore_suppressions = ignore_suppressions
    scanner, results_name = _tool_scanner(kind, context)
    scanner.dependencies_satisfied = True
    reported = ["app.py", COMMITTED[0], ASH_WROTE[0], _UNTRACKED_NAMED]
    seen = {}

    def uri(relative: str) -> str:
        path = (source / relative).as_posix()
        if kind == "checkov":
            # What checkov writes, run from the filesystem root as ASH runs it.
            return checkov_repo_file_path(path, Path(path).anchor).lstrip("/")
        if kind == "grype":
            # grype writes a path below the scanned directory with a leading "/".
            return f"/{relative}"
        return path

    def fake_run(command, results_dir, **kwargs):
        seen["argv"] = command
        Path(results_dir, results_name).write_text(
            json.dumps(patterns._sarif(kind, [uri(r) for r in reported])),
            encoding="utf-8",
        )
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kwargs: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    # grype's database age is read by running grype; it has no bearing here.
    monkeypatch.setattr(
        ScannerExecutor, "_assess_content_databases", lambda self, *args: None
    )

    kept = patterns._kept_uris(kind, scanner, context)

    values = _exclusion_values(kind, seen["argv"])
    assert not _skipped_by_tool(kind, values, source, COMMITTED[0]), values
    assert _skipped_by_tool(kind, values, source, _UNTRACKED_NAMED) is (
        kind in _TOLD_TO_SKIP
    ), values
    assert kept == sorted(["app.py", COMMITTED[0]]), kept


@pytest.mark.parametrize("ignore_suppressions", [False, True])
def test_detect_secrets_reports_a_key_committed_to_this_runs_output_dir(
    tmp_path, ignore_suppressions
):
    """detect-secrets reads the scan set, which lists the committed file; ASH's own
    report quoting the key is not in it."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    # Assembled at runtime in that module, so this file holds no key-shaped literal
    # for ASH's own self-scan to report.
    from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_scanner_behavior import (
        PLANTED_KEY,
    )

    source, context = _this_run(tmp_path)
    secret = f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n"
    for relative in ("settings.py", COMMITTED[1], ASH_WROTE[0]):
        (source / relative).write_text(secret, encoding="utf-8")
    _git(source, "add", "settings.py")
    context.ignore_suppressions = ignore_suppressions
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    kept = patterns._kept_uris("detect-secrets", scanner, context)

    assert kept == sorted(["settings.py", COMMITTED[1]]), kept


@pytest.mark.parametrize("in_git", [True, False])
def test_the_suppression_pass_keeps_findings_in_committed_files(
    tmp_path, capture, in_git
):
    """``apply_suppressions_to_sarif`` runs per scanner, again on the aggregated
    results before the reporters read them, and in ``ash merge``. It keeps the
    results located in committed files there and excludes the rest of the output
    directory. Outside git nothing in the directory is committed, and all of it
    is excluded."""
    from automated_security_helper.schemas.sarif_schema_model import (
        Run,
        SarifReport,
        Tool,
        ToolComponent,
    )
    from automated_security_helper.utils.sarif_utils import (
        apply_suppressions_to_sarif,
    )

    source = _tree(tmp_path, in_git=in_git)
    context = named._context(source, source / ".ash" / "ash_output")
    report = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=[
                    named._result(uri) for uri in ("app.py", *COMMITTED, *ASH_WROTE)
                ],
            )
        ]
    )

    kept = apply_suppressions_to_sarif(report, context)

    uris = sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in kept.runs[0].results
    )
    expected = ["app.py", *COMMITTED] if in_git else ["app.py"]
    assert uris == sorted(expected), uris
    excluded = len(COMMITTED) + len(ASH_WROTE) + 1 - len(expected)
    warned = [w for w in _warnings(capture) if w.startswith("Excluded")]
    assert len(warned) == 1, warned
    assert f"Excluded {excluded} finding(s)" in warned[0], warned
