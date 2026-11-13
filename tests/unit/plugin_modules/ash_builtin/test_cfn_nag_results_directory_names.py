"""cfn-nag: the results directory made for each template.

The directory is named from the template's path by ``get_normalized_filename``.
Two things about that name are pinned here, each against ``CfnNagScanner.scan``
with only its dependency probe and subprocess boundary faked:

* two templates whose paths differ in case alone (``Stack.yaml`` and
  ``stack.yaml``) got names that differ in case alone, which one directory on a
  filesystem that ignores case (APFS and NTFS by default); the name folds case now,
  so the two stay apart whatever the filesystem (the scan is handed the two paths
  and no second file is written, since there is only one file on such a
  filesystem);
* a template nested deeply enough made a name past the 255 bytes one path
  component may take, the directory could not be made and the template was counted
  as a failed target; the name is held to a budget now, and two long names that
  share their first bytes stay apart.
"""

from __future__ import annotations

import errno
import json
import sys
from pathlib import Path
from types import SimpleNamespace
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

#: The module the scan reads its candidate list and template text through.
SCANNER_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner"
)


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
    long: each takes ``width`` + 2 characters of a normalized name.

    The chain is about 300 characters on top of the temporary directory. A Windows
    host without long path support refuses it, and that is the host's limit, not a
    result for the name budget these tests pin, so the test is skipped there. On any
    other host a failure to make the directory (a full disk, a permission) is an
    error: a skip would leave the name budget unguarded without anyone seeing it.
    """
    directory = root
    for level in range(levels):
        directory = directory / (str(level) * width)
    try:
        directory.mkdir(parents=True)
    except OSError as error:
        if sys.platform != "win32":
            raise
        pytest.skip(f"this host cannot make a path this long: {type(error).__name__}")
    return directory


def _mkdir_fails(monkeypatch, platform: str) -> None:
    """``Path.mkdir`` fails with a full disk, on the host named ``platform``.

    Only this module reads the platform as ``platform``: its own name for ``sys`` is
    replaced, not the process's."""

    def _full_disk(self, *args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(Path, "mkdir", _full_disk)
    monkeypatch.setattr(
        sys.modules[__name__], "sys", SimpleNamespace(platform=platform)
    )


def test_a_directory_that_cannot_be_made_off_windows_is_an_error_not_a_skip(
    tmp_path, monkeypatch
):
    """The deep tests skip for a Windows host that refuses a long path. A full disk
    or a permission error elsewhere used to skip them too, which left the name
    budget unguarded with nothing but a skip in the report."""
    _mkdir_fails(monkeypatch, "linux")

    with pytest.raises(OSError) as raised:
        _deep_directory(tmp_path)

    assert raised.value.errno == errno.ENOSPC, raised.value


def test_control_a_long_path_a_windows_host_refuses_is_skipped(tmp_path, monkeypatch):
    _mkdir_fails(monkeypatch, "win32")

    with pytest.raises(pytest.skip.Exception) as raised:
        _deep_directory(tmp_path)

    assert "cannot make a path this long" in str(raised.value), raised.value


def test_two_templates_that_differ_in_case_alone_get_directories_that_do_not(
    scanner, results_dirs
):
    # The two spellings are handed to the scan as paths and no file is written
    # under the second one: on a filesystem that ignores case (APFS and NTFS by
    # default) ``Stack.yaml`` and ``stack.yaml`` are one file, so writing both
    # left one template and the count below failed before the name was measured.
    # The name is made from the path alone, so the test does not need the files.
    work = scanner.context.work_dir
    (work / "Stack.yaml").write_text(CFN_TEMPLATE)
    spellings = [str(work / "Stack.yaml"), str(work / "stack.yaml")]
    with (
        patch(
            f"{SCANNER_MODULE}.cloudformation_candidate_files",
            return_value=spellings,
        ),
        patch(f"{SCANNER_MODULE}.read_template_text", return_value=CFN_TEMPLATE),
    ):
        names = [path.name for path in results_dirs()]
    assert len(names) == 2, names
    assert len({name.lower() for name in names}) == 2, names


def test_a_deeply_nested_template_still_gets_a_results_directory(scanner, results_dirs):
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
