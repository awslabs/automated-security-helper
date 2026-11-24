# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real checkov: no config file from the scanned tree, and finding paths unchanged.

checkov reads ``.checkov.yaml`` and ``.checkov.yml`` from the directory it scans
and from its working directory. ASH now runs it from the filesystem root with
``--directory=<target>`` as one token, and rewrites the paths checkov reports
relative to its working directory back to what a run from the source directory
reports (checkov_scanner.rewrite_checkov_paths). These tests run the checkov ASH
uses, so a checkov release that changes either behavior fails here.
"""

import ast
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import get_args

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _KNOWN_VCS_CONFIGURATION_FRAMEWORKS,
    _VCS_CONFIGURATION_FRAMEWORKS,
    CheckFrameworks,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]

# Fails CKV_AWS_20 (public-read ACL).
_INSECURE_BUCKET = """
resource "aws_s3_bucket" "b" {
  bucket = "example"
  acl    = "public-read"
}
"""

# A setting whose effect is visible in the results: it hides CKV_AWS_20.
_SKIP_CKV_AWS_20 = "skip-check:\n  - CKV_AWS_20\n"


def _checkov() -> str:
    found = shutil.which("checkov")
    if found is None:
        pytest.skip("checkov is not installed")
    return found


def _scanner(source: Path, output: Path) -> CheckovScanner:
    return CheckovScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=AshConfig(),
        ),
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(frameworks=["terraform"])
        ),
    )


def _ash_raw(source: Path, output: Path, target: Path, target_type: str):
    """The SARIF ASH reads for this target, after its path rewrite."""
    scanner = _scanner(source, output)
    scanner.scan(target=target, target_type=target_type)
    results = scanner.results_dir / target_type / "results_sarif.sarif"
    return scanner._read_results_file(results)


def _run_from(cwd: Path, target: Path, out: Path) -> dict:
    """checkov as ASH ran it before: from ``cwd``, ``--directory`` as two tokens."""
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(  # nosec B603 - fixed argv, checkov from PATH
        [
            _checkov(),
            "--directory",
            target.as_posix(),
            "--framework",
            "terraform",
            "-o",
            "sarif",
            "--output-file-path",
            out.as_posix(),
        ],
        cwd=cwd,
        capture_output=True,
        check=False,
    )
    return json.loads((out / "results_sarif.sarif").read_text())


def _rule_ids(document) -> set:
    return {r["ruleId"] for run in document["runs"] for r in run.get("results", [])}


def _uris(document) -> list:
    return sorted(
        location["physicalLocation"]["artifactLocation"]["uri"]
        for run in document["runs"]
        for result in run.get("results", [])
        for location in result.get("locations", [])
    )


@pytest.mark.parametrize("name", [".checkov.yaml", ".checkov.yml"])
def test_a_checkov_config_in_the_scanned_tree_is_not_loaded(tmp_path, name):
    _checkov()
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.tf").write_text(_INSECURE_BUCKET)
    (source / name).write_text(_SKIP_CKV_AWS_20)

    # The control: run the way ASH used to, and the file hides the finding.
    assert "CKV_AWS_20" not in _rule_ids(_run_from(source, source, tmp_path / "old"))

    raw = _ash_raw(source, tmp_path / "out", source, "source")
    assert "CKV_AWS_20" in _rule_ids(raw)


@pytest.mark.parametrize("parent", ["", "..odd"])
def test_finding_paths_match_a_run_from_the_source_directory(tmp_path, parent):
    _checkov()
    source = tmp_path / parent / "src" if parent else tmp_path / "src"
    for relative in ("top.tf", "a/b/nested.tf", "dir with space/x.tf"):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_INSECURE_BUCKET)

    before = _uris(_run_from(source, source, tmp_path / "old"))
    after = _uris(_ash_raw(source, tmp_path / "out", source, "source"))
    assert before, "the fixture must produce findings"
    assert after == before


def test_paths_for_a_target_outside_the_source_match_too(tmp_path):
    _checkov()
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    converted = output / "converted" / "nb"
    converted.mkdir(parents=True)
    (converted / "c.tf").write_text(_INSECURE_BUCKET)

    before = _uris(_run_from(source, converted, tmp_path / "old"))
    after = _uris(_ash_raw(source, output, converted, "converted"))
    assert before
    # checkov removes every ``/..`` from the path it writes, so a run from the
    # source directory names this file ``out/converted/nb/c.tf``, a path that
    # reads as inside the source and names nothing there. ASH keeps the ``..``
    # (checkov_scanner._source_relative_path), so the same findings are reported
    # at ``../out/converted/nb/c.tf``, relative to the source directory.
    assert before == ["out/converted/nb/c.tf"] * len(before)
    assert after == ["../out/converted/nb/c.tf"] * len(before)


@pytest.mark.parametrize(
    "relative_file,relative_cwd",
    [
        ("src/a/b.tf", "src"),
        ("src/a/b.tf", "."),
        ("out/converted/c.tf", "src"),
        ("src/a/b.tf", "src/.ash/out/scanners/checkov"),
    ],
)
def test_ash_copy_of_repo_file_path_matches_checkovs(
    tmp_path, relative_file, relative_cwd
):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        checkov_repo_file_path,
    )
    from automated_security_helper.utils.pre_installed_tool import (
        find_tool_interpreter,
    )

    interpreter = find_tool_interpreter(_checkov())
    if interpreter is None:
        pytest.skip("checkov's interpreter could not be located")
    file_path = (tmp_path / relative_file).as_posix()
    cwd = tmp_path / relative_cwd
    cwd.mkdir(parents=True, exist_ok=True)
    checkovs = subprocess.run(  # nosec B603 - fixed argv
        [
            interpreter,
            "-I",
            "-c",
            (
                "import sys; from checkov.common.output.record import Record; "
                "print(Record._determine_repo_file_path(sys.argv[1]))"
            ),
            file_path,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert checkov_repo_file_path(file_path, os.path.realpath(cwd)) == checkovs


def test_a_cwd_one_level_below_the_root_writes_the_same_paths_as_the_root(tmp_path):
    """The basis for the fallback working directory under a drive root.

    path_trust.cwd_outside_scanned_tree falls back to a new directory directly
    under the target's root. Here ``tmp_path`` stands in for that root: checkov
    run from a fresh child of it must write the same paths as checkov run from it.
    """
    _checkov()
    source = tmp_path / "src"
    for relative in ("main.tf", "build/foo.tf", "a/b/nested.tf"):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_INSECURE_BUCKET)
    child = tmp_path / "ash-tool-cwd-x"
    child.mkdir()

    from_root = _uris(_run_from(tmp_path, source, tmp_path / "o1"))
    from_child = _uris(_run_from(child, source, tmp_path / "o2"))
    assert from_root
    assert from_child == from_root


def _installed_checkov_frameworks(checkov_path: str) -> set:
    """The framework names the installed checkov enumerates, read statically.

    checkov builds ``checkov_runners`` (its --framework and --skip-framework
    vocabulary) from the string constants of the ``CheckType`` class in
    ``checkov/common/bridgecrew/check_type.py``. This locates that file through
    the console script's own interpreter and parses it with ``ast``, executing
    no checkov code. A missing file or an empty parse FAILS rather than skips:
    checkov is installed (``_checkov()`` passed), so either means a checkov
    refactor moved the registry and the VCS-configuration derivation in
    checkov_scanner.py must be re-measured.
    """
    with open(checkov_path, "rb") as handle:
        first_line = handle.readline().strip()
    if not first_line.startswith(b"#!"):
        pytest.skip("checkov console script has no shebang; cannot find its env")
    interpreter = first_line[2:].decode("utf-8", errors="replace").split()[0]
    if os.path.basename(interpreter) == "env" or not os.path.isfile(interpreter):
        pytest.skip(f"cannot resolve checkov's interpreter from shebang {interpreter}")
    purelib = subprocess.run(  # nosec B603 - fixed argv, interpreter from shebang
        [
            interpreter,
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    check_type_py = (
        Path(purelib) / "checkov" / "common" / "bridgecrew" / "check_type.py"
    )
    if not check_type_py.is_file():
        pytest.fail(
            f"checkov is installed but {check_type_py} does not exist: checkov "
            "moved its framework registry; re-measure the VCS-configuration "
            "derivation in checkov_scanner.py against this checkov"
        )
    tree = ast.parse(check_type_py.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "CheckType":
            frameworks = {
                statement.value.value
                for statement in node.body
                if isinstance(statement, ast.Assign)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            }
            if frameworks:
                return frameworks
    pytest.fail(
        f"{check_type_py} no longer holds a CheckType class with string "
        "constants: checkov refactored its framework registry; re-measure the "
        "VCS-configuration derivation in checkov_scanner.py"
    )


def test_framework_mirror_and_vcs_derivation_match_installed_checkov():
    """ASH's framework mirror, and the VCS-configuration skip set derived from
    it, agree with the checkov ASH runs.

    Three directions, each loud on a different drift. The mirror equals
    checkov's registry, so a checkov release that adds, removes or renames a
    framework fails here (an added ``*_configuration`` framework then enters
    the derived skip set the moment the mirror is updated). The installed
    registry's ``*_configuration`` names equal the measured floor, so a new
    VCS framework in checkov is flagged even before the mirror changes. And
    every name ASH derives exists in the installed checkov, because checkov
    rejects an unknown ``--skip-framework`` value outright
    (``normalize_framework_arg`` calls ``parser.error``), which would end the
    scan rather than skip nothing.
    """
    installed = _installed_checkov_frameworks(_checkov())
    mirrored = set(get_args(CheckFrameworks)) - {"all"}

    assert mirrored == installed, (
        "CheckFrameworks in checkov_scanner.py no longer mirrors the installed "
        f"checkov's registry; only in ASH: {sorted(mirrored - installed)}, "
        f"only in checkov: {sorted(installed - mirrored)}"
    )
    assert {
        framework for framework in installed if framework.endswith("_configuration")
    } == set(_KNOWN_VCS_CONFIGURATION_FRAMEWORKS), (
        "the installed checkov's VCS configuration frameworks differ from the "
        "measured floor in checkov_scanner.py; re-measure the derivation (env "
        "var pattern included) and update _KNOWN_VCS_CONFIGURATION_FRAMEWORKS"
    )
    assert set(_VCS_CONFIGURATION_FRAMEWORKS) <= installed
