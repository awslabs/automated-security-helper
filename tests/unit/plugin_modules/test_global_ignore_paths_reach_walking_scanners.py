# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each scanner is told to leave out the files the global ignore paths ignore.

ASH drops the findings in ``global_settings.ignore_paths`` after the scan, but a
scanner that walks the directory it is given, or reads every file the scan set
holds, would read the ignored files anyway, with its own results holding them.
Each is given those paths, picked with ASH's own matcher, a fully ignored
directory as one entry, in the form it takes:

- npm-audit reads the scan set, without the ignored files (``drop_ignored``), and so
  does its ``nothing_to_scan_reason``;
- checkov: an anchored ``--skip-path``, a directory open at its end, and none for a
  value checkov's terraform module finder could not compile with the others;
- trivy: ``--skip-files`` and ``--skip-dirs``;
- grype and syft: ``--exclude ./<path>``, a directory ``./<dir>/**``;
- semgrep and opengrep: ``--exclude=<name>``, only for a name nothing else has.

bandit is covered in test_bandit_exclude_built_per_scan.py; cfn-nag and cdk-nag in
tests/unit/utils/test_cfn_candidates_leave_out_ignore_paths.py; and the whole scan
in tests/integration/scanners/test_global_ignore_paths_reach_every_scanner.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils import link_exclusions

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="the entries are POSIX paths here"
    ),
]

FILES = [
    "app.py",
    "requirements.txt",
    "main.tf",
    "thirdparty/bad.py",
    "thirdparty/sub/deep.tf",
    "thirdparty2/keep.py",
    "pkg/gen_a.py",
    "pkg/real.py",
]


def _ignore(*paths: str) -> list[IgnorePathWithReason]:
    return [IgnorePathWithReason(path=path, reason="ignored") for path in paths]


IGNORES = _ignore("thirdparty/**", "pkg/gen_*.py")


def _tree(base: Path, files: list[str] = FILES) -> Path:
    source = base / "source"
    for rel in files:
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text("x = 1\n", encoding="utf-8")
    source.mkdir(exist_ok=True)
    return source


def _context(source: Path, base: Path, ignores=()) -> PluginContext:
    """The scan's context; ``ignores`` are its global ignore paths."""
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    config = AshConfig()
    config.global_settings.ignore_paths = list(ignores)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )


class _Stop(Exception):
    """Raised in place of running the tool, once its argv is recorded."""


# ---------------------------------------------------------------------------
# The scan-set readers
# ---------------------------------------------------------------------------


def test_the_readers_drop_the_ignored_paths(tmp_path):
    source = _tree(tmp_path)
    scan_set = [str(source / rel) for rel in FILES]

    kept = link_exclusions.drop_ignored(scan_set, source, IGNORES)

    assert sorted(Path(p).relative_to(source).as_posix() for p in kept) == [
        "app.py",
        "main.tf",
        "pkg/real.py",
        "requirements.txt",
        "thirdparty2/keep.py",
    ]


def _npm_audit(source: Path, base: Path, ignores):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
        NpmAuditScannerConfig,
    )

    return NpmAuditScanner(
        context=_context(source, base, ignores), config=NpmAuditScannerConfig()
    )


def test_npm_audit_filters_its_scan_set(tmp_path, monkeypatch):
    """The scan set npm-audit goes on to use is the filtered one."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        npm_audit_scanner as module,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = _tree(tmp_path)
    scanner = _npm_audit(source, tmp_path, IGNORES)
    handed: list[list[str]] = []
    real = module.drop_ignored

    def _spy(*args, **kwargs):
        kept = real(*args, **kwargs)
        handed.append(kept)
        raise _Stop

    scanner.dependencies_satisfied = True
    with (
        patch.object(module, "drop_ignored", side_effect=_spy),
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_Stop),
    ):
        try:
            scanner.scan(
                target=source, target_type="source", global_ignore_paths=IGNORES
            )
        except (_Stop, ScannerError):
            pass

    assert handed, "npm-audit did not filter its scan set"
    assert not [p for p in handed[0] if "/thirdparty/" in p or p.endswith("gen_a.py")]
    assert any(p.endswith("/app.py") for p in handed[0])


def _package(source: Path, rel: str) -> None:
    (source / rel).mkdir(parents=True, exist_ok=True)
    (source / rel / "package.json").write_text('{"name": "p"}', encoding="utf-8")
    (source / rel / "package-lock.json").write_text("{}\n", encoding="utf-8")


def test_npm_audit_has_nothing_to_scan_when_its_only_package_is_ignored(tmp_path):
    source = _tree(tmp_path, ["app.py"])
    _package(source, "thirdparty/web")

    scanner = _npm_audit(source, tmp_path, IGNORES)

    assert scanner.nothing_to_scan_reason() is not None


def test_control_npm_audit_has_a_package_to_scan_outside_the_ignore_paths(tmp_path):
    source = _tree(tmp_path, ["app.py"])
    _package(source, "thirdparty/web")
    _package(source, "web")

    scanner = _npm_audit(source, tmp_path, IGNORES)

    assert scanner.nothing_to_scan_reason() is None
    assert [Path(p).parent.name for p in scanner._package_manifests("source")] == [
        "web"
    ]


def test_an_expired_ignore_path_no_longer_leaves_out_a_package(tmp_path):
    source = _tree(tmp_path, ["app.py"])
    _package(source, "thirdparty/web")
    expired = [
        IgnorePathWithReason(
            path="thirdparty/**", reason="ignored", expiration="2000-01-01"
        )
    ]

    scanner = _npm_audit(source, tmp_path, expired)

    assert scanner.nothing_to_scan_reason() is None


# ---------------------------------------------------------------------------
# checkov
# ---------------------------------------------------------------------------


def _values(argv: list[str], flag: str) -> list[str]:
    values = []
    for index, arg in enumerate(argv):
        if arg == flag and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif str(arg).startswith(f"{flag}="):
            values.append(str(arg)[len(flag) + 1 :])
    return values


def _checkov(source: Path, base: Path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )

    return CheckovScanner(context=_context(source, base), config=CheckovScannerConfig())


def test_checkov_is_given_anchored_skip_paths(tmp_path):
    import re

    source = _tree(tmp_path)
    scanner = _checkov(source, tmp_path)

    patterns = scanner._ignore_skip_patterns(source, IGNORES)

    root = source.as_posix()
    by_path = {
        rel: [p for p in patterns if re.search(p, f"{root}/{rel}")] for rel in FILES
    }
    assert by_path["thirdparty/bad.py"] and by_path["thirdparty/sub/deep.tf"]
    assert by_path["pkg/gen_a.py"]
    for kept in ("app.py", "main.tf", "thirdparty2/keep.py", "pkg/real.py"):
        assert by_path[kept] == [], kept
    # checkov joins every value into one regex: no group may be opened.
    assert not any("(" in p.replace("\\(", "") for p in patterns)


def test_checkov_reaches_the_command_with_them(tmp_path):
    source = _tree(tmp_path)
    scanner = _checkov(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", IGNORES)

    skips = _values(argv, "--skip-path")
    assert any("thirdparty/" in skip for skip in skips), skips
    assert any("gen_a" in skip for skip in skips), skips


def _module_finder_compiles(values: list[str]) -> bool:
    """checkov 3.3.26's terraform module finder regex over every --skip-path value:
    ``re.compile('|'.join(f"({excluded_paths})"))``."""
    import re

    try:
        re.compile("|".join(f"({values})"))
    except re.error:
        return False
    return True


def _skipped(path: str, values: list[str]) -> bool:
    """checkov 3.3.26's ``filter_ignored_paths`` test for one walked path."""
    import re

    return any(
        re.search(re.escape(v) if re.match(r"^\.[^\.]", v) else v, path) or v in path
        for v in values
    )


def test_checkov_leaves_out_only_the_ignored_path_that_breaks_the_module_finder(
    tmp_path,
):
    """A value that would fail checkov's terraform module finder's regex is left
    out: checkov reads that file, and ASH drops its findings. A balanced pair of
    parentheses does not fail it, so that path is skipped."""
    source = _tree(tmp_path, ["app.py", "gen(1)/x.py", "a.tf", "b(c.tf"])
    scanner = _checkov(source, tmp_path)

    argv, _, _ = scanner._execute_scan(
        source, "source", _ignore("gen(1)/**", "b(c.tf", "a.tf")
    )

    values = _values(argv, "--skip-path")
    root = source.as_posix()
    assert _module_finder_compiles(values), values
    assert _skipped(f"{root}/a.tf", values), values
    assert _skipped(f"{root}/gen(1)/x.py", values), values
    assert not _skipped(f"{root}/app.py", values), values


@pytest.mark.parametrize("parent", ["proj (1)", "base(1", "d.ir/base(1"])
def test_checkov_is_given_an_ignored_directory_under_a_target_with_a_parenthesis(
    tmp_path, parent
):
    """Every value holds the target's own path, the temporary directory's
    included. The ignored file is skipped where its value compiles in the module
    finder's regex together with the values before it, and left out where it does
    not: a dot is written ``[.]``, and its ``]`` can leave a later parenthesis an
    open group. So the outcome turns on the characters of the temporary path, a
    dotted user name for one, and is computed here rather than assumed. The
    ``d.ir`` parent puts a dot above the parenthesis, so the value is always left
    out there."""
    import re

    base = tmp_path / parent
    base.mkdir(parents=True)
    source = _tree(base, ["app.py", "vendor/a.tf", "vendor/b.tf", "keep.tf"])
    scanner = _checkov(source, base)
    ignores = _ignore("vendor/a.tf", "vendor/b.tf")

    argv, _, _ = scanner._execute_scan(source, "source", ignores)

    values = _values(argv, "--skip-path")
    root = source.as_posix()
    patterns = scanner._ignore_skip_patterns(source, ignores)
    (value_for_a,) = [p for p in patterns if re.search(p, f"{root}/vendor/a.tf")]
    before_it = [v for v in values if v not in patterns]
    compiles = _module_finder_compiles([*before_it, value_for_a])
    assert _module_finder_compiles(values), values
    assert _skipped(f"{root}/vendor/a.tf", values) is compiles, (values, compiles)
    assert not _skipped(f"{root}/keep.tf", values), values
    if parent == "d.ir/base(1":
        assert not compiles, value_for_a


def _recorded_argv(scanner, target: Path, ignore_paths) -> list[str]:
    recorded: list[list[str]] = []

    def _record(*args, **kwargs):
        recorded.append(list(kwargs.get("command") or args[0]))
        raise _Stop

    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_record),
    ):
        with pytest.raises((_Stop, ScannerError)):
            scanner.scan(
                target=target, target_type="source", global_ignore_paths=ignore_paths
            )
    assert recorded, "the tool was not started"
    return recorded[0]


# ---------------------------------------------------------------------------
# grype and syft
# ---------------------------------------------------------------------------


def test_grype_is_given_the_ignored_paths(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    source = _tree(tmp_path)
    scanner = GrypeScanner(
        context=_context(source, tmp_path), config=GrypeScannerConfig()
    )

    argv, _, _ = scanner._execute_scan(source, "source", IGNORES)

    assert set(_values(argv, "--exclude")) == {"./thirdparty/**", "./pkg/gen_a.py"}


def test_syft_is_given_the_ignored_paths(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
        SyftScannerConfig,
    )

    source = _tree(tmp_path)
    scanner = SyftScanner(
        context=_context(source, tmp_path), config=SyftScannerConfig()
    )

    argv = _recorded_argv(scanner, source, IGNORES)

    assert set(_values(argv, "--exclude")) == {"./thirdparty/**", "./pkg/gen_a.py"}


def test_a_doublestar_character_in_an_ignored_path_is_escaped(tmp_path):
    source = _tree(tmp_path, ["app.py", "gen[1]/x.py"])

    values = link_exclusions.syft_excludes(source, source, _ignore("gen[[]1]/**"))

    assert values == ["./gen\\[1\\]/**"]


# ---------------------------------------------------------------------------
# trivy
# ---------------------------------------------------------------------------


def test_trivy_is_given_the_ignored_files_and_directories(tmp_path, monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _trivy_scanner_base,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins import (
        trivy_repo_scanner,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    # No database update: the recorder replaces the run that would make one.
    monkeypatch.setattr(
        _trivy_scanner_base, "prepare_content_db", lambda *args, **kwargs: None
    )
    source = _tree(tmp_path)
    scanner = trivy_repo_scanner.TrivyRepoScanner(
        context=_context(source, tmp_path),
        config=trivy_repo_scanner.TrivyRepoScannerConfig(),
    )

    argv = _recorded_argv(scanner, source, IGNORES)

    assert _values(argv, "--skip-dirs") == ["thirdparty"]
    assert _values(argv, "--skip-files") == ["pkg/gen_a.py"]


def test_trivy_is_not_given_an_ignored_path_with_a_comma(tmp_path):
    source = _tree(tmp_path, ["app.py", "a,b/x.py", "c,d.py"])

    ignores = _ignore("a,b/**", "c,d.py")

    assert link_exclusions.trivy_skip_dirs(source, source, ignores) == []
    assert link_exclusions.trivy_skip_files(source, source, ignores) == []


# ---------------------------------------------------------------------------
# semgrep and opengrep
# ---------------------------------------------------------------------------


@pytest.fixture(params=["semgrep", "opengrep"])
def grep_scanner(request, tmp_path, monkeypatch):
    """A semgrep or opengrep scanner over the fixture tree.

    opengrep's patterns mode is no longer a row here: the scanner refuses the
    option at construction (opengrep runs a ``--pattern`` search only with a
    language, which no option of the scanner supplies), so there is no second
    argument resolution left to cover.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = _tree(tmp_path)
    context = _context(source, tmp_path)
    if request.param == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner,
            SemgrepScannerConfig,
        )

        return source, SemgrepScanner(context=context, config=SemgrepScannerConfig())
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
        OpengrepScannerConfig,
    )

    return source, OpengrepScanner(context=context, config=OpengrepScannerConfig())


@pytest.fixture(params=["semgrep", "opengrep"])
def grep_scanner_class(request):
    if request.param == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner,
            SemgrepScannerConfig,
        )

        return SemgrepScanner, SemgrepScannerConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
        OpengrepScannerConfig,
    )

    return OpengrepScanner, OpengrepScannerConfig


def test_a_grep_scanner_is_given_names_nothing_else_has(grep_scanner):
    source, scanner = grep_scanner

    argv, _, _ = scanner._execute_scan(source, "source", IGNORES)

    assert "--exclude=thirdparty" in argv
    assert "--exclude=gen_a.py" in argv


def test_a_grep_scanner_is_given_them_for_this_resolution_only(grep_scanner):
    source, scanner = grep_scanner
    before = [(a.key, a.value) for a in scanner.args.extra_args]

    scanner._execute_scan(source, "source", IGNORES)
    argv, _, _ = scanner._execute_scan(source, "source", [])

    # The operator's own exclude patterns travel joined too (``--exclude=<p>``),
    # so the check is for the ignore names given to the first resolution, not
    # for the joined form as such.
    assert "--exclude=thirdparty" not in argv, argv
    assert "--exclude=gen_a.py" not in argv, argv
    assert [(a.key, a.value) for a in scanner.args.extra_args] == before


def test_a_name_another_path_has_is_not_given(tmp_path):
    """bad.py is ignored under thirdparty/, and another bad.py is not."""
    source = _tree(tmp_path, ["thirdparty/bad.py", "thirdparty/x.py", "src/bad.py"])

    names = link_exclusions.grep_ignore_names(
        source, source, _ignore("thirdparty/bad.py")
    )

    assert names == []


def test_a_name_in_the_targets_own_path_is_not_given(tmp_path):
    """It could be below the git work tree's root, and leave out the whole target."""
    project = tmp_path / "vendor" / "proj"
    for rel in ("app.py", "vendor/x.py"):
        (project / rel).parent.mkdir(parents=True, exist_ok=True)
        (project / rel).write_text("x = 1\n", encoding="utf-8")

    names = link_exclusions.grep_ignore_names(project, project, _ignore("vendor/**"))

    assert names == []


def test_a_name_with_a_pattern_character_is_not_given(tmp_path):
    source = _tree(tmp_path, ["app.py", "gen[1]/x.py"])

    assert link_exclusions.grep_ignore_names(source, source, _ignore("gen*/**")) == []


EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "tool"}}, "results": []}],
}


def _flag_value(argv: list[str], flag: str) -> str | None:
    for arg in argv:
        if str(arg).startswith(f"{flag}="):
            return str(arg)[len(flag) + 1 :]
    return None


def _run_grep(scanner, source: Path, ignore_paths, skipped: list[str]):
    """scan() with a tool run that reports ``skipped`` as left out by --exclude."""

    def _fake_run(*args, **kwargs):
        argv = list(kwargs.get("command") or args[0])
        sarif = Path(argv[argv.index("--sarif-output") + 1])
        sarif.write_text(json.dumps(EMPTY_SARIF))
        paths = {
            "scanned": [],
            "skipped": [
                {"path": str(source / rel), "reason": "cli_exclude_flags_match"}
                for rel in skipped
            ],
        }
        Path(_flag_value(argv, "--json-output")).write_text(
            json.dumps({"results": [], "paths": paths})
        )
        return {"stdout": "", "stderr": "", "returncode": 0}

    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_fake_run),
    ):
        return scanner.scan(
            target=source, target_type="source", global_ignore_paths=ignore_paths
        )


def test_a_tree_of_only_ignored_files_is_skipped_not_an_error(
    tmp_path, monkeypatch, grep_scanner_class
):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner_class, config_class = grep_scanner_class
    source = _tree(tmp_path, ["thirdparty/a.py", "thirdparty/b.py"])
    scanner = scanner_class(context=_context(source, tmp_path), config=config_class())
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / "grep"

    _run_grep(
        scanner,
        source,
        _ignore("thirdparty/**"),
        ["thirdparty/a.py", "thirdparty/b.py"],
    )

    assert scanner.targets_attempted == 0


def test_a_file_left_out_for_another_reason_is_still_an_error(
    tmp_path, monkeypatch, grep_scanner_class
):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner_class, config_class = grep_scanner_class
    source = _tree(tmp_path, ["thirdparty/a.py", "src/b.py"])
    scanner = scanner_class(context=_context(source, tmp_path), config=config_class())
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / "grep"

    with pytest.raises(ScannerError, match="scanned no file"):
        _run_grep(
            scanner, source, _ignore("thirdparty/**"), ["thirdparty/a.py", "src/b.py"]
        )
