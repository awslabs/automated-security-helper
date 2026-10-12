# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each scanner that walks its target is told to leave out the global ignore paths.

ASH drops the findings in ``global_settings.ignore_paths`` after the scan, but a
scanner that walks the directory it is given read the ignored files anyway, and its
own results held them. Each is now given those paths in its own option, as exact
paths picked with ASH's own matcher, a fully ignored directory as one entry:

- grype and syft: ``--exclude ./<path>``, a directory ``./<dir>/**``;
- trivy: ``--skip-files`` and ``--skip-dirs``;
- checkov: an anchored ``--skip-path``, a directory open at its end;
- semgrep and opengrep: ``--exclude=<name>``, only for a name nothing else has;
- cfn-nag, cdk-nag and npm-audit read the scan set, which is filtered.

bandit is covered in test_bandit_exclude_built_per_scan.py, and the whole scan in
tests/integration/scanners/test_global_ignore_paths_reach_every_scanner.py.
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

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the entries are POSIX paths here"
)

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


def _context(source: Path, base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _values(argv: list[str], flag: str) -> list[str]:
    values = []
    for index, arg in enumerate(argv):
        if arg == flag and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif str(arg).startswith(f"{flag}="):
            values.append(str(arg)[len(flag) + 1 :])
    return values


class _Stop(Exception):
    """Raised in place of running the tool, once its argv is recorded."""


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
    from automated_security_helper.plugin_modules.ash_trivy_plugins import (
        trivy_repo_scanner,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(trivy_repo_scanner, "sandboxed_online", lambda offline: False)
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
# checkov
# ---------------------------------------------------------------------------


def test_checkov_is_given_anchored_skip_paths(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )

    source = _tree(tmp_path)
    scanner = CheckovScanner(
        context=_context(source, tmp_path), config=CheckovScannerConfig()
    )

    patterns = scanner._ignore_skip_patterns(source, IGNORES)

    import re

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
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )

    source = _tree(tmp_path)
    scanner = CheckovScanner(
        context=_context(source, tmp_path), config=CheckovScannerConfig()
    )

    argv, _, _ = scanner._execute_scan(source, "source", IGNORES)

    skips = _values(argv, "--skip-path")
    assert any("thirdparty/" in skip for skip in skips), skips
    assert any("gen_a" in skip for skip in skips), skips


# ---------------------------------------------------------------------------
# semgrep and opengrep
# ---------------------------------------------------------------------------


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


def test_a_grep_scanner_is_given_names_nothing_else_has(
    tmp_path, monkeypatch, grep_scanner_class
):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner_class, config_class = grep_scanner_class
    source = _tree(tmp_path)
    scanner = scanner_class(context=_context(source, tmp_path), config=config_class())

    argv, _, _ = scanner._execute_scan(source, "source", IGNORES)

    assert "--exclude=thirdparty" in argv
    assert "--exclude=gen_a.py" in argv


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


@pytest.mark.parametrize("name", ["cfn-nag", "cdk-nag", "npm-audit"])
def test_each_reader_filters_its_scan_set(tmp_path, monkeypatch, name):
    """The scan set a reader goes on to use is the filtered one."""
    import importlib

    modules = {
        "cfn-nag": ("cfn_nag_scanner", "CfnNagScanner", "CfnNagScannerConfig"),
        "cdk-nag": ("cdk_nag_scanner", "CdkNagScanner", "CdkNagScannerConfig"),
        "npm-audit": ("npm_audit_scanner", "NpmAuditScanner", "NpmAuditScannerConfig"),
    }
    module_name, class_name, config_name = modules[name]
    module = importlib.import_module(
        f"automated_security_helper.plugin_modules.ash_builtin.scanners.{module_name}"
    )
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = _tree(tmp_path)
    scanner = getattr(module, class_name)(
        context=_context(source, tmp_path), config=getattr(module, config_name)()
    )
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

    assert handed, f"{name} did not filter its scan set"
    assert not [p for p in handed[0] if "/thirdparty/" in p or p.endswith("gen_a.py")]
    assert any(p.endswith("/app.py") for p in handed[0])
