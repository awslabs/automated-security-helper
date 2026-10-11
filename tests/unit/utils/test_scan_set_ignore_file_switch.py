# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scan_set`` with and without the scanned repository's ignore files, in process.

The whole-scan tests in ``tests/unit/interactions/test_scan_ignore_file_switch.py``
cover the CLI flag, the config tiers and the reports. These cover what they cannot
reach from outside:

- the record ``scan_set`` hands back through ``exclusions``, including the files
  under a directory the root ``.gitignore`` prunes (never walked for the scan set,
  so counted separately) and the files ASH would leave out anyway;
- ``ash-ignore-report.txt`` saying the ignore files were not honored;
- every scanner and converter that calls ``scan_set`` passing the switch on, so a
  scan set computed outside the orchestrator does not quietly honor the ignore
  files the operator turned off;
- the standalone ``get_scan_set`` command's flag.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Dict
from unittest.mock import patch

import pytest

from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import (
    NOT_HONORED_REPORT_LINE,
    honors_ignore_files,
    scan_set,
)

PACKAGE_ROOT = Path(gss.__file__).resolve().parents[1]


def _build(root: Path, files: Dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _names(root: Path, files) -> set[str]:
    return {Path(f).relative_to(root).as_posix() for f in files}


def _record(root: Path, **kwargs) -> dict:
    exclusions: dict = {}
    scan_set(source=str(root), exclusions=exclusions, **kwargs)
    return exclusions


class TestPrunedDirectoriesAreCounted:
    """The root ``.gitignore`` prunes ``build/`` before the walk descends into it."""

    TREE = {
        ".gitignore": "build/\n*.log\n",
        "app.py": "x = 1\n",
        "a.log": "log\n",
        "build/one.txt": "out\n",
        "build/two.txt": "out\n",
        "build/deep/three.txt": "out\n",
    }

    def test_the_root_gitignore_counts_the_files_under_the_pruned_directory(
        self, tmp_path
    ):
        root = _build(tmp_path / "src", self.TREE)
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 4}, record
        assert record["excluded_file_count"] == 4, record

    def test_the_count_matches_the_files_actually_missing(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        found = _names(root, scan_set(source=str(root)))
        missing = set(self.TREE) - found
        assert missing == {
            "a.log",
            "build/one.txt",
            "build/two.txt",
            "build/deep/three.txt",
        }
        assert _record(root)["excluded_file_count"] == len(missing)

    def test_the_log_line_carries_the_pruned_files_too(self, tmp_path):
        """The INFO line read 1 here before: only a.log was walked and dropped."""
        root = _build(tmp_path / "src", self.TREE)
        with patch.object(gss.ASH_LOGGER, "info") as info:
            scan_set(source=str(root))
        logged = {
            call.args[1]: call.args[2]
            for call in info.call_args_list
            if len(call.args) >= 3 and "excluded" in str(call.args[0])
        }
        assert logged.get("${SOURCE_DIR}/.gitignore") == 4, logged

    def test_files_ash_leaves_out_on_its_own_are_not_counted(self, tmp_path):
        """A ``.git`` and CDK assets under a pruned directory were not the ignore file's doing.

        The template under ``cdk.out`` is counted: without the ignore file it would be
        in the scan set, so the ignore file is what removed it.
        """
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "vendor/\ncdk.out/\n",
                "app.py": "x = 1\n",
                "vendor/lib.py": "y = 2\n",
                "vendor/.git/HEAD": "ref: refs/heads/main\n",
                "cdk.out/asset.abc/handler.py": "z = 3\n",
                "cdk.out/Stack.template.json": "{}\n",
            },
        )
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 2}, record

        unhonored = _names(root, scan_set(source=str(root), honor_ignore_files=False))
        assert {"vendor/lib.py", "cdk.out/Stack.template.json"} <= unhonored
        assert "vendor/.git/HEAD" not in unhonored
        assert "cdk.out/asset.abc/handler.py" not in unhonored

    def test_an_ignore_file_inside_a_pruned_directory_is_not_listed(self, tmp_path):
        """git never reads it, and neither does ASH, so it removed nothing."""
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "build/\n",
                "app.py": "x = 1\n",
                "build/.gitignore": "*\n",
                "build/out.txt": "out\n",
            },
        )
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 2}, record


class TestTheBundledCdkTreeIsAshsOwnExclusion:
    def test_an_ignore_rule_matching_it_is_not_credited_with_removing_it(
        self, tmp_path
    ):
        root = _build(
            tmp_path / "src",
            {
                "app.py": "x = 1\n",
                "pkg/.gitignore": "*.json\n",
                "pkg/node_modules/aws-cdk/fixture.json": "{}\n",
                "pkg/other.json": "{}\n",
            },
        )
        record = _record(root)
        assert record["by_ignore_file"] == {"pkg/.gitignore": 1}, record


class TestNotHonored:
    TREE = {
        ".gitignore": "build/\n*.log\n",
        ".ignore": "notes.txt\n",
        ".git/HEAD": "ref: refs/heads/main\n",
        "app.py": "x = 1\n",
        "a.log": "log\n",
        "notes.txt": "notes\n",
        "build/out.txt": "out\n",
        "vendor/.gitignore": "*\n",
        "vendor/dep.py": "y = 2\n",
    }

    def test_every_file_but_ashs_own_exclusions_is_in_the_scan_set(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        found = _names(root, scan_set(source=str(root), honor_ignore_files=False))
        assert found == set(self.TREE) - {".git/HEAD"}

    def test_the_record_says_so(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        assert _record(root, honor_ignore_files=False) == {
            "honored": False,
            "excluded_file_count": 0,
            "by_ignore_file": {},
        }

    def test_the_ignore_report_says_so(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        output = tmp_path / "out"
        scan_set(source=str(root), output=str(output), honor_ignore_files=False)
        report = (output / "ash-ignore-report.txt").read_text(encoding="utf-8")
        assert report.splitlines()[0] == NOT_HONORED_REPORT_LINE
        assert "START CONTENTS: ${SOURCE_DIR}/.gitignore" not in report
        assert "START CONTENTS: ASH_INCLUSIONS" in report

    def test_no_ignore_files_were_found_is_not_claimed(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        with patch.object(gss.ASH_LOGGER, "info") as info:
            scan_set(source=str(root), honor_ignore_files=False)
        messages = [str(call.args[0]) for call in info.call_args_list if call.args]
        assert not any("No ignore files were found" in m for m in messages), messages
        assert any("not honored" in m for m in messages), messages

    def test_control_honored_by_default(self, tmp_path):
        """vendor/.gitignore's ``*`` matches the ignore file itself as well."""
        root = _build(tmp_path / "src", self.TREE)
        record = _record(root)
        assert record["honored"] is True
        assert record["by_ignore_file"] == {
            ".gitignore": 2,
            ".ignore": 1,
            "vendor/.gitignore": 2,
        }, record

    def test_a_reused_scan_set_records_nothing(self, tmp_path):
        """Nothing was matched, so there is nothing to attribute."""
        root = _build(tmp_path / "src", self.TREE)
        output = tmp_path / "out"
        scan_set(source=str(root), output=str(output))
        assert _record(root, output=str(output)) == {}


class TestAshsOwnOutputDirectory:
    """ASH's log and reports are not part of the code being scanned.

    The default output directory is ``.ash/ash_output`` inside the source
    directory, and only ``.ash/.gitignore`` (written by ``ash config init``) kept
    it out of the scan set. With the ignore files not honored, ASH's own log
    entered it.
    """

    TREE = {
        "app.py": "x = 1\n",
        ".ash/.gitignore": "ash_output*\n",
        ".ash/ash_output/ash.log": "log\n",
        ".ash/ash_output/reports/ash.summary.txt": "summary\n",
    }

    @pytest.mark.parametrize("honor", [True, False])
    def test_it_is_never_in_the_scan_set(self, tmp_path, honor):
        root = _build(tmp_path / "src", self.TREE)
        output = root / ".ash" / "ash_output"
        found = _names(
            root,
            scan_set(source=str(root), output=str(output), honor_ignore_files=honor),
        )
        assert not any(name.startswith(".ash/ash_output/") for name in found), found
        assert "app.py" in found and ".ash/.gitignore" in found

    def test_the_ignore_file_is_not_credited_with_it(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        output = root / ".ash" / "ash_output"
        exclusions: dict = {}
        scan_set(source=str(root), output=str(output), exclusions=exclusions)
        assert exclusions["by_ignore_file"] == {".ash/.gitignore": 0}, exclusions

    def test_not_counted_under_a_directory_the_root_gitignore_prunes(self, tmp_path):
        root = _build(tmp_path / "src", {**self.TREE, ".gitignore": ".ash/\n"})
        output = root / ".ash" / "ash_output"
        exclusions: dict = {}
        scan_set(source=str(root), output=str(output), exclusions=exclusions)
        # .ash/.gitignore itself, and nothing from the output directory.
        assert exclusions["by_ignore_file"] == {".gitignore": 1}, exclusions

    def test_control_a_directory_of_that_name_elsewhere_is_scanned(self, tmp_path):
        root = _build(
            tmp_path / "src", {"app.py": "x = 1\n", "docs/ash_output/note.md": "n\n"}
        )
        found = _names(
            root,
            scan_set(
                source=str(root),
                output=str(tmp_path / "out"),
                honor_ignore_files=False,
            ),
        )
        assert "docs/ash_output/note.md" in found


class TestHonorsIgnoreFiles:
    @pytest.mark.parametrize(
        "config, expected",
        [
            (SimpleNamespace(honor_ignore_files=False), False),
            (SimpleNamespace(honor_ignore_files=True), True),
            (SimpleNamespace(), True),
            (None, True),
        ],
    )
    def test_only_a_real_false_turns_them_off(self, config, expected):
        assert honors_ignore_files(config) is expected


def _scan_set_calls(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "scan_set"
        ):
            yield node


def _consumers():
    found = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if path.name == "get_scan_set.py":
            continue
        for call in _scan_set_calls(path):
            found.append((path.relative_to(PACKAGE_ROOT).as_posix(), call))
    return found


class TestEveryConsumerPassesTheSwitch:
    """A scan set recomputed outside the orchestrator must follow the operator's switch.

    The orchestrator writes the list first and the consumers reuse it, but a
    consumer that recomputes it (no list on disk, a plugin run on its own) would
    otherwise honor the ignore files whatever the config says.
    """

    def test_the_consumers_are_found(self):
        modules = {module for module, _call in _consumers()}
        assert {
            "core/orchestrator.py",
            "plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
            "plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
            "plugin_modules/ash_builtin/scanners/cdk_nag_scanner.py",
            "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
            "plugin_modules/ash_builtin/converters/archive_converter.py",
            "plugin_modules/ash_builtin/converters/jupyter_converter.py",
        } <= modules, sorted(modules)

    def test_each_call_passes_honor_ignore_files(self):
        missing = [
            f"{module}:{call.lineno}"
            for module, call in _consumers()
            if "honor_ignore_files" not in {keyword.arg for keyword in call.keywords}
        ]
        assert missing == [], missing


class TestAConverterFollowsItsConfig:
    """One consumer end to end: the jupyter converter's own scan set."""

    def test_a_notebook_an_ignore_file_matches_is_found_when_not_honored(
        self, tmp_path
    ):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
            JupyterConverter,
        )

        root = _build(
            tmp_path / "src",
            {".gitignore": "*.ipynb\n", "nb.ipynb": "{}\n", "app.py": "x = 1\n"},
        )

        def notebooks(honor: bool):
            output = tmp_path / f"out-{honor}"
            context = PluginContext(
                source_dir=root,
                output_dir=output,
                work_dir=output / "converted",
                config=AshConfig(project_name="t", honor_ignore_files=honor),
            )
            converter = JupyterConverter(context=context)
            return [Path(n).name for n in converter._notebooks_in_scan_set()]

        assert notebooks(True) == []
        assert notebooks(False) == ["nb.ipynb"]


class TestTheStandaloneCommand:
    def test_no_honor_ignore_files_lists_the_ignored_files(self, tmp_path, capsys):
        root = _build(tmp_path / "src", {".gitignore": "*.log\n", "a.log": "x\n"})
        argv = ["get_scan_set", "--source", str(root), "--no-honor-ignore-files"]
        with patch.object(sys, "argv", argv):
            assert gss.main() == 0
        assert str(root / "a.log") in capsys.readouterr().out.splitlines()

    def test_control_honored_by_default(self, tmp_path, capsys):
        root = _build(tmp_path / "src", {".gitignore": "*.log\n", "a.log": "x\n"})
        with patch.object(sys, "argv", ["get_scan_set", "--source", str(root)]):
            assert gss.main() == 0
        assert str(root / "a.log") not in capsys.readouterr().out.splitlines()
