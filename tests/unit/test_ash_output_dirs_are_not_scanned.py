# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH does not scan its own output, whether or not .gitignore names it.

Scanned, the output would swell a second scan: a second ``ash scan`` of a two-file
tree, with ``--output-dir shard-1`` and the first run's ``.ash/ash_output`` still
present, would report 21 actionable findings where the first reports 4. The other
17 would be detect-secrets matches in ``.ash/ash_output/reports/`` and the scanner
results there, and the scan set would list 31 files under ``.ash/ash_output`` plus
``shard-1/ash.log``, the run's own log.

ASH's output is named, not recognized: this run's output directory and
``.ash/ash_output`` under the scan root and under the working directory. The files
in a directory don't make it ASH output, since any repository can commit
``src/ash_aggregated_results.json``: a directory that only looks like ASH output is
scanned, and ASH warns about it.

Every tree here has nothing gitignored, and is in a git checkout with nothing in
its output directories committed: git then says that none of the files in the
previous run's ``.ash/ash_output`` are the repository's. Outside a checkout only
this run's output directory is left out, and the previous run's is scanned with
a warning (tests/unit/test_leftover_output_dir_without_git_is_scanned.py). The
tree holds:

* ``.ash/ash_output/``: a previous run's default output, with results;
* ``shard-1/``: the output directory of the scan in progress;
* ``shard-0/``: another shard's output, which holds ``ash_aggregated_results.json``;
* ``partial/``: a run that never finished, holding the two files every scan writes
  before any scanner starts;
* ``src/``: the user's code, with a planted ``ash_aggregated_results.json``;
* ``out/`` and ``notes/``: the user's own code, ``notes/`` holding one file that
  only shares a name with an ASH file.

The repository is the tree's parent, so a tool that anchors at the repository
root does not anchor at the scanned directory.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import (
    drop_results_in_ash_output_dirs,
    named_output_dirs,
    output_dir_candidates,
)
from tests.unit.workspace.test_execution import _git

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()
PluginContext.model_rebuild()

# The ``capture`` fixture comes from tests/unit/conftest.py by name, so warnings
# are captured the way test_merge.py captures them.

#: Integration because every tree here is a real git checkout (``_git`` starts git);
#: the scanners built here start no tool (tests/unit/conftest.py).
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("no_tool_probes")]

#: Directories ASH names as its own output in this tree.
NAMED = (".ash/ash_output", "shard-1")
#: Directories that only look like ASH output, and are scanned.
LOOK_ALIKES = ("partial", "shard-0", "src")

NAMED_FILES = (
    ".ash/ash_output/ash_aggregated_results.json",
    ".ash/ash_output/reports/ash.sarif",
    ".ash/ash_output/converted/jupyter/notebook.py",
    "shard-1/ash.log",
)
LOOK_ALIKE_FILES = (
    "shard-0/ash_aggregated_results.json",
    "shard-0/reports/ash.csv",
    "partial/ash-ignore-report.txt",
    "partial/ash-scan-set-files-list.txt",
    "partial/scanners/detect-secrets/source/results_sarif.sarif",
    "src/ash_aggregated_results.json",
    "src/app.py",
)
USER_FILES = (
    "app.py",
    "out/handler.py",
    "notes/ash-ignore-report.txt",
    "src/shard-0/kept.py",
)


def _populate(source: Path) -> None:
    for relative in NAMED_FILES + LOOK_ALIKE_FILES + USER_FILES:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = 'x'\n", encoding="utf-8")
    (source / "src" / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")


@pytest.fixture
def tree(tmp_path):
    source = tmp_path / "repo"
    _populate(source)
    assert _git(tmp_path, "init", "-q").returncode == 0
    return source, source / "shard-1"


def _relative(source: Path, files) -> set[str]:
    return {Path(f).relative_to(source).as_posix() for f in files}


def test_the_scan_set_leaves_out_only_the_named_output_directories(tree, capture):
    source, current_output = tree

    found = _relative(source, scan_set(source=str(source), output=str(current_output)))

    leaked = sorted(found & set(NAMED_FILES))
    assert not leaked, f"ASH output files in the scan set: {leaked}"
    expected = set(LOOK_ALIKE_FILES) | set(USER_FILES)
    assert expected <= found, f"missing from the scan set: {sorted(expected - found)}"


def test_a_directory_that_only_looks_like_ash_output_is_warned_about(tree, capture):
    source, current_output = tree

    scan_set(source=str(source), output=str(current_output))

    warnings = [r.getMessage() for r in capture.records if r.levelname == "WARNING"]
    for directory in LOOK_ALIKES:
        assert any(f"/{directory}" in w and "scanned" in w for w in warnings), (
            directory,
            warnings,
        )
    assert not any("notes" in w for w in warnings), warnings


def test_a_planted_results_file_does_not_hide_code(tmp_path):
    """The case that made marker files unusable: a repository commits
    ``ash_aggregated_results.json`` next to its code."""
    source = tmp_path / "repo"
    (source / "src").mkdir(parents=True)
    (source / "src" / "ash_aggregated_results.json").write_text("{}")
    (source / "src" / "app.py").write_text("import subprocess\n")

    found = _relative(
        source, scan_set(source=str(source), output=str(tmp_path / "out"))
    )

    assert "src/app.py" in found


def test_the_written_scan_set_list_is_what_plugins_read_back(tree):
    """cdk-nag, cfn-nag, npm-audit, detect-secrets and the converters call
    scan_set with the run's output directory and ID and get the persisted list.
    The second call cannot walk, so what it returns was read back."""
    from unittest.mock import patch

    from automated_security_helper.utils import get_scan_set as gss

    source, current_output = tree
    run_id = "c" * 32
    scan_set(source=str(source), output=str(current_output), run_id=run_id)

    with patch.object(
        gss,
        "_collect_ignorefiles_and_all_files",
        side_effect=AssertionError("walked the tree"),
    ):
        reread = _relative(
            source,
            scan_set(source=str(source), output=str(current_output), run_id=run_id),
        )

    assert not reread & set(NAMED_FILES)
    assert set(LOOK_ALIKE_FILES) <= reread


def test_the_default_output_under_the_working_directory_is_left_out(tree, monkeypatch):
    """``ash scan --source-dir ..`` run from a subdirectory writes to that
    subdirectory's ``.ash/ash_output`` by default, which is inside the tree."""
    source, current_output = tree
    sub = source / "sub"
    (sub / ".ash" / "ash_output" / "reports").mkdir(parents=True)
    (sub / ".ash" / "ash_output" / "reports" / "ash.sarif").write_text("{}")
    (sub / "code.py").write_text("x = 1\n")
    monkeypatch.chdir(sub)

    found = _relative(source, scan_set(source=str(source), output=str(current_output)))

    assert "sub/.ash/ash_output/reports/ash.sarif" not in found
    assert "sub/code.py" in found


def test_an_output_directory_that_is_the_scan_root_is_not_named(tree, capture):
    """``--output-dir .``: naming the root would leave out, and drop, everything."""
    source, _current_output = tree
    context = _context(source, source)
    context.ignore_suppressions = True

    assert source not in named_output_dirs(source, source)
    kept = _run_scripted(context, [_result("app.py"), _result("src/app.py")])
    assert kept == ["app.py", "src/app.py"]
    found = _relative(source, scan_set(source=str(source), output=str(source)))
    assert {"app.py", "src/app.py", "out/handler.py"} <= found


def test_the_candidates_are_every_named_directory_wherever_it_is(
    tree, tmp_path, monkeypatch
):
    """A walk that recognizes directories by identity matches against all of
    them; the exclusions take the ones inside the scanned directory as spelled."""
    source, current_output = tree
    elsewhere = tmp_path / "out-elsewhere"
    monkeypatch.chdir(tmp_path)

    assert output_dir_candidates(source, elsewhere) == [
        elsewhere,
        source / ".ash" / "ash_output",
    ]
    assert named_output_dirs(source, elsewhere) == [source / ".ash" / "ash_output"]
    assert named_output_dirs(source, current_output) == [
        source / ".ash" / "ash_output",
        current_output,
    ]


# ---------------------------------------------------------------------------
# Scanners that hand their tool a directory
# ---------------------------------------------------------------------------


def _context(source: Path, output: Path) -> PluginContext:
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _values(argv, flag):
    return [argv[i + 1] for i, item in enumerate(argv[:-1]) if item == flag]


def test_checkov_skips_every_ash_output_directory(tree):
    """On Windows ASH emits no output-directory --skip-path for checkov, whose
    matching is unreliable there; the executor drops those findings instead."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )

    source, output = tree
    scanner = CheckovScanner(
        context=_context(source, output), config=CheckovScannerConfig()
    )
    argv, _, _ = scanner._execute_scan(source, "source", [])

    patterns = _values(argv, "--skip-path")
    if os.sep != "/":
        assert not [p for p in patterns if Path(p).is_absolute()], patterns
        return

    def skipped(path: str) -> bool:
        return any(re.search(p, path) or p in path for p in patterns)

    root = source.as_posix()
    for relative in NAMED:
        assert skipped(os.path.join(root, relative, "reports", "ash.sarif")), (
            f"{relative} is not skipped by {patterns}"
        )
    for relative in LOOK_ALIKES + ("out",):
        assert not skipped(os.path.join(root, relative, "x.py")), (relative, patterns)


def _semgrep_anchor(target: Path) -> Path:
    """Where semgrep anchors a leading-slash ``--exclude`` for *target*: the nearest
    of it and its ancestors holding ``.git``, else *target*.

    tmp_path can sit inside a git checkout, a developer's or a CI workspace's, and
    semgrep then anchors there for a tree a test builds without a repository. Measured
    on semgrep 1.180.0, with the target two levels below a repository's root:
    ``--exclude /out`` left the target's ``out/`` scanned and ``--exclude
    /<path from the root>/out`` excluded it, and the same with GIT_CEILING_DIRECTORIES
    naming the directory between the two, so a ceiling cannot take that checkout out
    of these tests.
    """
    target = Path(os.path.abspath(target))
    return next(
        (path for path in (target, *target.parents) if (path / ".git").exists()),
        target,
    )


@pytest.mark.parametrize("in_git", [True, False])
def test_semgrep_excludes_each_directory_anchored_where_semgrep_anchors(
    tree, in_git, tmp_path, monkeypatch
):
    """semgrep anchors a leading-slash --exclude at the git root, else the target.

    In the tree's checkout the root is its parent, so the anchor is not the
    target. Outside a checkout, which a tree under ``plain/`` stands for with
    ``GIT_CEILING_DIRECTORIES`` there, ASH names only this run's output
    directory, and the previous run's ``.ash/ash_output`` is scanned. semgrep does
    not read that variable (measured on 1.180.0), so it anchors at the nearest
    ``.git`` above the target, if any, else at the target (_semgrep_anchor)."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
        SemgrepScannerConfig,
    )
    from automated_security_helper.utils.scan_output_dirs import (
        PatternSyntax,
        escape_for_pattern,
    )

    source, output = tree
    excluded_dirs = NAMED
    if not in_git:
        plain = tmp_path / "plain"
        source = plain / "repo"
        _populate(source)
        output = source / "shard-1"
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(plain))
        excluded_dirs = ("shard-1",)
    above = source.relative_to(_semgrep_anchor(source)).as_posix()
    prefix = (
        ""
        if above == "."
        else "/" + escape_for_pattern(above, PatternSyntax.GLOB, separator="/")
    )
    if in_git:
        assert prefix == "/repo", prefix
    scanner = SemgrepScanner(
        context=_context(source, output), config=SemgrepScannerConfig()
    )
    argv, _, _ = scanner._execute_scan(source, "source", [])

    excludes = set(_values(argv, "--exclude"))
    assert {f"{prefix}/{d}" for d in excluded_dirs} <= excludes, excludes
    assert not {f"{prefix}/{d}" for d in LOOK_ALIKES} & excludes, excludes
    if not in_git:
        assert f"{prefix}/.ash/ash_output" not in excludes, excludes


def test_the_semgrep_patterns_do_not_accumulate(tree):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
        SemgrepScannerConfig,
    )

    source, output = tree
    scanner = SemgrepScanner(
        context=_context(source, output), config=SemgrepScannerConfig()
    )
    before = list(scanner.args.extra_args)
    first, _, _ = scanner._execute_scan(source, "source", [])
    second, _, _ = scanner._execute_scan(source, "source", [])

    assert first == second
    assert scanner.args.extra_args == before


def test_grype_excludes_each_directory_relative_to_the_scanned_directory(tree):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    source, output = tree
    scanner = GrypeScanner(
        context=_context(source, output), config=GrypeScannerConfig()
    )
    argv, _, _ = scanner._execute_scan(source, "source", [])

    excludes = set(_values(argv, "--exclude"))
    assert {f"./{d}/**" for d in NAMED} == excludes, excludes


def test_the_converted_target_gets_no_output_exclusions(tree):
    """work_dir sits inside the run's output directory."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    source, output = tree
    work = output / "converted"
    work.mkdir(parents=True)
    scanner = GrypeScanner(
        context=_context(source, output), config=GrypeScannerConfig()
    )
    argv, _, _ = scanner._execute_scan(work, "converted", [])

    assert _values(argv, "--exclude") == []


def test_syft_excludes_each_directory_relative_to_the_scanned_directory(
    tree, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        syft_scanner,
    )

    source, output = tree
    scanner = syft_scanner.SyftScanner(
        context=_context(source, output), config=syft_scanner.SyftScannerConfig()
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

    excludes = set(_values(seen["argv"], "--exclude"))
    assert {f"./{d}/**" for d in NAMED} == excludes, excludes


def test_ferret_scan_excludes_each_directory_by_its_full_path(tree, monkeypatch):
    """The escaped full path, the separator and ``*``: a glob for ferret-scan 2.5.x,
    and for 2.4.x a glob as well, its substring branch matching nothing. See
    test_output_dir_patterns_are_escaped.py for what each version was measured
    to do with it."""
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfig,
        FerretScanScanner,
    )

    source, output = tree
    scanner = FerretScanScanner(
        context=_context(source, output), config=FerretScannerConfig()
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

    values = ",".join(_values(seen["argv"], "--exclude")).split(",")
    root = os.path.abspath(source)
    for relative in NAMED:
        expected = os.path.join(root, *relative.split("/")) + os.sep + "*"
        assert expected in values, f"{expected} missing from {values}"
    for relative in LOOK_ALIKES:
        assert not any(os.path.join(root, relative) in value for value in values), (
            values
        )


# ---------------------------------------------------------------------------
# Findings a scanner reports there anyway
# ---------------------------------------------------------------------------


class _ScriptedConfig(ScannerPluginConfigBase):
    name: str = "scripted"


class _ScriptedScanner(ScannerPluginBase):
    """Stands in for a scanner whose tool cannot be told to skip a directory."""

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        return self.scripted_result


def _result(uri: str) -> Result:
    return Result(
        ruleId="R1",
        level="error",
        message=Message(text=f"finding in {uri}"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(artifactLocation=ArtifactLocation(uri=uri))
                )
            )
        ],
    )


def _run_scripted_results(context, results, target=None, target_type="source"):
    report = SarifReport(
        runs=[Run(tool=Tool(driver=ToolComponent(name="scripted")), results=results)]
    )
    scanner = _ScriptedScanner(config=_ScriptedConfig(), context=context)
    scanner.scripted_result = report
    scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
    scanner.end_time = datetime(2026, 1, 1, 10, 0, 1)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    containers = executor._execute_scanner(
        "scripted",
        scanner,
        [{"path": target or context.source_dir, "type": target_type}],
    )
    return containers[0].raw_results.runs[0].results


def _run_scripted(context, results, target=None, target_type="source"):
    report = SarifReport(
        runs=[Run(tool=Tool(driver=ToolComponent(name="scripted")), results=results)]
    )
    scanner = _ScriptedScanner(config=_ScriptedConfig(), context=context)
    scanner.scripted_result = report
    scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
    scanner.end_time = datetime(2026, 1, 1, 10, 0, 1)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    containers = executor._execute_scanner(
        "scripted",
        scanner,
        [{"path": target or context.source_dir, "type": target_type}],
    )
    return sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in containers[0].raw_results.runs[0].results
    )


@pytest.mark.parametrize("ignore_suppressions", [False, True])
def test_the_drop_says_how_many_findings_it_dropped_at_warning(
    tree, capture, ignore_suppressions
):
    """As the suppression step's exclusion of the output directory did: a pass that
    can remove any number of results says so where an operator sees it."""
    source, output = tree
    context = _context(source, output)
    context.ignore_suppressions = ignore_suppressions

    _run_scripted(
        context,
        [
            _result("app.py"),
            _result(".ash/ash_output/reports/ash.sarif"),
            _result("shard-1/ash.log"),
        ],
    )

    dropped = [
        record.getMessage()
        for record in capture.records
        if record.levelname == "WARNING" and "Dropped" in record.getMessage()
    ]
    assert len(dropped) == 1, dropped
    assert "Dropped 2 scripted findings" in dropped[0], dropped


@pytest.mark.parametrize("ignore_suppressions", [False, True])
def test_findings_in_the_named_output_directories_are_dropped(
    tree, ignore_suppressions
):
    """Whatever --ignore-suppressions says: ASH's output is not suppressed, it is
    not part of the scanned tree."""
    source, output = tree
    context = _context(source, output)
    context.ignore_suppressions = ignore_suppressions

    kept = _run_scripted(
        context,
        [
            _result("app.py"),
            _result(".ash/ash_output/converted/jupyter/notebook.py"),
            # A file:// URI into a named directory that is not this run's output.
            _result(
                (source / ".ash" / "ash_output" / "reports" / "ash.sarif").as_uri()
            ),
            _result((source / "shard-1" / "ash.log").as_posix()),
            _result("shard-0/reports/ash.csv"),
            _result("partial/ash-ignore-report.txt"),
            _result("src/app.py"),
        ],
    )

    assert kept == [
        "app.py",
        "partial/ash-ignore-report.txt",
        "shard-0/reports/ash.csv",
        "src/app.py",
    ], kept


def test_the_drop_reads_a_file_uri_as_the_path_it_names(tmp_path):
    """The executor makes URIs relative before it drops anything, so the test
    above cannot tell whether the drop reads ``file://`` URIs itself. This calls
    it on a report nothing sanitized, from a source directory whose name the URI
    percent-encodes, with the URI pointing into ``.ash/ash_output`` rather than
    into this run's output. In a checkout, as the module's other trees are, so
    that ``.ash/ash_output`` is named."""
    source = tmp_path / "my repo"
    reported = source / ".ash" / "ash_output" / "reports" / "ash.sarif"
    code = source / "src" / "app.py"
    for path in (reported, code):
        path.parent.mkdir(parents=True)
        path.write_text("{}\n", encoding="utf-8")
    assert _git(tmp_path, "init", "-q").returncode == 0
    report = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=[_result(reported.as_uri()), _result(code.as_uri())],
            )
        ]
    )
    assert "%20" in reported.as_uri()

    removed = drop_results_in_ash_output_dirs(
        report, _context(source, source / "shard-1"), scanner_name="scripted"
    )

    assert removed == 1
    assert [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    ] == [code.as_uri()]


def _link_directory(link: Path, target: Path) -> None:
    """A link to a directory: a symlink, or on Windows a junction, which needs no
    privilege to create and is the link a repository checkout can carry there."""
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def _linked_tree(tmp_path: Path, link: str, target: str) -> Path:
    source = tmp_path / "repo"
    for relative in ("src/app.py", "src/ash_output/deep.py"):
        (source / relative).parent.mkdir(parents=True, exist_ok=True)
        (source / relative).write_text("import subprocess\n", encoding="utf-8")
    (source / link).parent.mkdir(parents=True, exist_ok=True)
    _link_directory(source / link, source / target)
    return source


LINKED_FINDINGS = ["src/app.py", "src/ash_output/deep.py"]


@pytest.mark.parametrize(
    "link, target",
    [(".ash/ash_output", "."), (".ash/ash_output", "src"), (".ash", "src")],
)
@pytest.mark.parametrize("ignore_suppressions", [False, True])
def test_a_linked_default_output_name_hides_nothing(
    tmp_path, link, target, ignore_suppressions
):
    """A repository can commit a link where ASH's default output goes. The drop
    does not treat a name reached through a link inside the tree as ASH's, so a
    ``.ash/ash_output`` committed as a link to the root drops no finding."""
    source = _linked_tree(tmp_path, link, target)
    context = _context(source, tmp_path / "out")
    context.ignore_suppressions = ignore_suppressions

    kept = _run_scripted(context, [_result(uri) for uri in LINKED_FINDINGS])

    assert kept == LINKED_FINDINGS
    assert named_output_dirs(source, tmp_path / "out") == []


def test_the_drop_does_not_follow_a_linked_output_dir_into_the_tree(tmp_path):
    """``--output-dir out`` where the repository committed ``out`` as a link to
    ``src``. No context is built for such an output directory, sandboxed or not:
    ASH's writes below it never follow a link, so the directory is refused when
    the context registers it (base/plugin_context.py, ``_guard_output_dir``, and
    utils/sandbox/fs_guard.py, ``register_writable_root``), and no drop runs. The
    link itself names nothing, so a drop given it would keep every finding.

    The refusal reaches the caller as the exit-3 class itself: ``PluginContext``
    unwraps a single link refusal from pydantic's ``ValidationError`` and raises
    it (``base/plugin_context.py``, ``_raise_link_refusal``), so a caller handling
    ``OutputDirLinkRefused`` sees a refused output directory the way it sees a
    refused write below one."""
    from automated_security_helper.utils.output_dir_links import (
        OutputDirLinkRefused,
    )

    source = _linked_tree(tmp_path, "out", "src")

    with pytest.raises(OutputDirLinkRefused, match="symlink"):
        _context(source, source / "out")

    assert named_output_dirs(source, source / "out") == []


def test_a_converted_finding_keeps_its_id_wherever_the_output_dir_is(tmp_path):
    """``--output-dir out1`` and ``out2`` give a converted notebook's finding one
    id: its file is not keyed by its absolute path."""
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability

    source = tmp_path / "repo"
    source.mkdir()
    ids = []
    for name in ("out1", "out2"):
        context = _context(source, tmp_path / name)
        converted = context.work_dir / "jupyter" / "nb-converted.py"
        converted.parent.mkdir(parents=True)
        converted.write_text("x = 1\n", encoding="utf-8")
        (result,) = _run_scripted_results(
            context,
            [_result(converted.as_posix())],
            target=context.work_dir,
            target_type="converted",
        )
        assert result.properties.converted_path == "jupyter/nb-converted.py"
        ids.append(FlatVulnerability.from_sarif_result(result, "scripted", "SAST").id)

    assert ids[0] == ids[1], ids


def test_findings_in_the_converted_files_are_kept(tree):
    source, output = tree
    context = _context(source, output)
    converted = context.work_dir / "jupyter" / "notebook.py"
    converted.parent.mkdir(parents=True)
    converted.write_text("x = 1\n")

    kept = _run_scripted(
        context,
        [_result(converted.as_posix())],
        target=context.work_dir,
        target_type="converted",
    )

    assert len(kept) == 1
