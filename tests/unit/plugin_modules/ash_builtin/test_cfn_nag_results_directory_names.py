"""cfn-nag: the results directory made for each template.

The directory is named from the template's path by ``get_normalized_filename``.
Two things about that name are pinned here, each against ``CfnNagScanner.scan``
with only its dependency probe and subprocess boundary faked:

* two templates whose paths differ in case alone (``Stack.yaml`` and
  ``stack.yaml``) got names that differ in case alone, which one directory on a
  filesystem that ignores case (APFS and NTFS by default); the name folds case now,
  so the two stay apart whatever the filesystem;
* a template nested deeply enough made a name past the 255 bytes one path
  component may take, the directory could not be made and the template was counted
  as a failed target; the name is held to a budget now, and two long names that
  share their first bytes stay apart.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)

pytestmark = pytest.mark.unit

CFN_TEMPLATE = """Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: placeholder-role
"""

#: A real file name holds at most this many bytes.
NAME_MAX = 255


def _empty_sarif() -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cfn_nag"}}, "results": []}],
        }
    )


@pytest.fixture
def scanner(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    return CfnNagScanner(context=context, config=CfnNagScannerConfig())


@pytest.fixture
def results_dirs(scanner):
    """Scan the work directory and return the results directory of each run."""
    with (
        patch.object(
            CfnNagScanner,
            "validate_plugin_dependencies",
            autospec=True,
            return_value=True,
        ),
        patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as double,
    ):
        double.return_value = {"stdout": _empty_sarif(), "stderr": "", "returncode": 0}

        def scan() -> list[Path]:
            double.reset_mock()
            scanner.scan(target=scanner.context.work_dir, target_type="converted")
            return [Path(call.kwargs["results_dir"]) for call in double.call_args_list]

        yield scan


def _deep_directory(root: Path, levels: int = 5, width: int = 60) -> Path:
    """A chain of ``levels`` directories under ``root``, each ``width`` characters
    long: each takes ``width`` + 2 characters of a normalized name."""
    directory = root
    for level in range(levels):
        directory = directory / (str(level) * width)
    directory.mkdir(parents=True)
    return directory


def test_two_templates_that_differ_in_case_alone_get_directories_that_do_not(
    scanner, results_dirs
):
    work = scanner.context.work_dir
    (work / "Stack.yaml").write_text(CFN_TEMPLATE)
    (work / "stack.yaml").write_text(CFN_TEMPLATE)
    names = [path.name for path in results_dirs()]
    assert len(names) == 2, names
    assert len({name.lower() for name in names}) == 2, names


def test_a_deeply_nested_template_still_gets_a_results_directory(
    scanner, results_dirs
):
    deep = _deep_directory(scanner.context.work_dir)
    (deep / "stack.yaml").write_text(CFN_TEMPLATE)
    names = [path.name for path in results_dirs()]
    # Past the budget the directory could not be made, the template was a failed
    # target and cfn_nag never ran on it.
    assert len(names) == 1, (names, scanner.errors)
    assert len(names[0].encode("utf-8")) <= NAME_MAX, names
    assert not scanner.errors, scanner.errors


def test_two_long_names_that_share_their_first_bytes_stay_apart(scanner, results_dirs):
    deep = _deep_directory(scanner.context.work_dir)
    (deep / "first.yaml").write_text(CFN_TEMPLATE)
    (deep / "second.yaml").write_text(CFN_TEMPLATE)
    names = [path.name for path in results_dirs()]
    assert len(names) == 2, (names, scanner.errors)
    assert len({name.lower() for name in names}) == 2, names
    assert all(len(name.encode("utf-8")) <= NAME_MAX for name in names), names
