# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: SecretsCollection.root must be anchored on every scan.

``SecretsCollection.scan_files()`` has two branches. A single file goes through
``scan_file()`` and is keyed by the path it was handed. Two or more files go
through a multiprocessing pool and are keyed by
``os.path.relpath(secret.filename, self.root)`` -- only that branch computes a
relative path, so only that branch can fail.

``SecretsCollection.__init__`` defaults ``root`` to ``''``, and
``os.path.abspath('')`` is the process working directory. The scanner used to
assign ``root`` only for source scans that had a baseline file, so every other
scan keyed its findings against wherever ASH happened to be launched from. Two
consequences:

* reported finding paths moved when the working directory moved, and
* on Windows there is no relative path between two drives at all, so a scan
  target on a different drive from the ASH process raised
  ``ValueError: path is on mount 'C:', start on mount 'D:'`` -- reaching the user
  as a ScannerError in place of their findings.

The fix anchors ``root`` to the directory the scan set was enumerated from
(``source_dir``, or ``work_dir`` for converted targets), which is an ancestor of
every scanned file by construction, and hands ``scan_files()`` absolute names so
the ``os.path.join(root, name)`` it performs internally stays a no-op.

Windows cannot be executed here, so ``ntpath`` -- the pure-Python Windows flavour
of ``os.path``, whose semantics are the ones that run on Windows regardless of
host -- stands in for it.
"""

import json
import ntpath
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)

# A fake value. Written to a file it trips detect-secrets' keyword plugin, which
# is all these tests need from it.
_KEYWORD_LINE = 'secret = "base64_encoded_secret=="'  # pragma: allowlist secret

# Where _write_secret_files puts them, relative to the directory it is given.
_EXPECTED_KEYS = {"first.py", "nested/second.py"}


def _write_secret_files(directory: Path) -> None:
    """Write two secret-bearing files, one of them nested.

    Two is the load-bearing number: a scan set of one file takes the
    ``scan_file()`` branch, which never consults ``root``.
    """
    nested = directory / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    (directory / "first.py").write_text(_KEYWORD_LINE)
    (nested / "second.py").write_text(_KEYWORD_LINE)


def _scanner(
    source_dir: Path, output_dir: Path, work_dir: Path | None = None
) -> DetectSecretsScanner:
    return DetectSecretsScanner(
        context=PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=work_dir if work_dir is not None else output_dir / "converted",
            config=get_default_config(),
        ),
        config=DetectSecretsScannerConfig(),
    )


def _keys(scanner: DetectSecretsScanner) -> set:
    """Collection keys, separator-normalised.

    ``os.path.relpath`` returns backslashes on Windows and the assertions are
    about which file each finding names, not about which separator this platform
    spells it with.
    """
    return {Path(key).as_posix() for key in scanner._secrets_collection.data}


def test_source_scan_anchors_root_to_the_source_dir(tmp_path):
    """A source scan with no baseline file must still anchor root."""
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    _write_secret_files(source_dir)
    output_dir.mkdir()

    scanner = _scanner(source_dir, output_dir)
    report = scanner.scan(target=source_dir, target_type="source")

    assert report is not False
    assert scanner._secrets_collection.root == source_dir.absolute()
    assert _keys(scanner) == _EXPECTED_KEYS


def test_converted_scan_anchors_root_to_the_work_dir(tmp_path):
    """A converted scan reads from work_dir, so that is what root must name.

    ``target`` and ``work_dir`` coincide in production, but the scan set is
    enumerated from ``work_dir``, and root has to agree with the file list rather
    than with the caller's argument.
    """
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    work_dir = output_dir / "converted"
    source_dir.mkdir()
    _write_secret_files(work_dir)

    scanner = _scanner(source_dir, output_dir, work_dir=work_dir)
    report = scanner.scan(target=work_dir, target_type="converted")

    assert report is not False
    assert scanner._secrets_collection.root == work_dir.absolute()
    assert _keys(scanner) == _EXPECTED_KEYS


def test_baseline_scan_anchors_root(tmp_path):
    """The baseline branch replaces the collection object, so it must be anchored
    after the swap, not before it -- ``load_from_baseline`` returns a fresh
    ``SecretsCollection`` whose root is back at ``''``."""
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    _write_secret_files(source_dir)
    output_dir.mkdir()
    baseline = source_dir / ".secrets.baseline"
    baseline.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [],
                "filters_used": [],
                "results": {},
            }
        )
    )

    scanner = _scanner(source_dir, output_dir)
    scanner.config.options.baseline_file = baseline
    report = scanner.scan(target=source_dir, target_type="source")

    assert report is not False
    assert scanner._secrets_collection.root == source_dir.absolute()


def test_keys_do_not_depend_on_the_working_directory(tmp_path, monkeypatch):
    """Same tree, working directory outside it: the keys must not move.

    This is the pre-fix defect in its POSIX form. With root at ``''`` the keys
    were computed against the working directory, so they came back as a chain of
    parent hops and changed whenever ASH was launched from somewhere else.
    """
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    _write_secret_files(source_dir)
    output_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    scanner = _scanner(source_dir, output_dir)
    scanner.scan(target=source_dir, target_type="source")

    assert _keys(scanner) == _EXPECTED_KEYS


def test_keys_stay_inside_root_so_relpath_cannot_fail_on_windows(tmp_path, monkeypatch):
    """The property that makes the Windows failure unreachable.

    ``ntpath.relpath`` raises only when the two paths are on different drives,
    and it cannot do that when root is an ancestor of the file -- which is
    exactly the case where the key comes back relative and free of parent hops.
    Asserted from a working directory outside the scanned tree, because the
    pre-fix root of ``''`` was the working directory.
    """
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    _write_secret_files(source_dir)
    output_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    scanner = _scanner(source_dir, output_dir)
    scanner.scan(target=source_dir, target_type="source")

    assert scanner._secrets_collection.data, "expected the scan to find secrets"
    for key in scanner._secrets_collection.data:
        assert not os.path.isabs(key), f"key escaped root as an absolute path: {key}"
        assert os.pardir not in Path(key).parts, f"key escaped root: {key}"


def test_relative_source_dir_still_reports_findings(tmp_path, monkeypatch):
    """A relative ``source_dir`` reaches the scanner as given, and the scan set
    inherits it.

    Not through the CLI, which anchors it in ``run_ash_scan``. Through a library
    caller: ``ASHScanOrchestrator.model_post_init`` coerces a ``str`` to ``Path``
    without anchoring it, so ``source_dir="./sub"`` stays relative all the way
    into ``PluginContext``. That is the door this test comes through, which is
    why it builds the scanner directly rather than invoking the CLI.

    ``scan_files()`` reads each name as ``os.path.join(self.root, name)``, so an
    anchored root plus a relative name would send detect-secrets looking for
    ``<root>/<root>/<file>`` and quietly report nothing at all.
    """
    _write_secret_files(tmp_path / "sub")
    (tmp_path / "out").mkdir()
    monkeypatch.chdir(tmp_path)

    scanner = _scanner(Path("sub"), Path("out"))
    report = scanner.scan(target=Path("sub"), target_type="source")

    assert report is not False
    assert report.runs[0].results, "a relative source_dir reported no findings"
    assert _keys(scanner) == _EXPECTED_KEYS


def test_ntpath_relpath_has_no_answer_across_drives():
    """The Windows mechanism itself, pinned so the reason for the fix is legible.

    This is the call ``scan_files()`` makes on every secret it finds in its
    multiprocessing branch.
    """
    scanned = r"C:\some\tree\first.py"

    with pytest.raises(ValueError, match="path is on mount"):
        ntpath.relpath(scanned, r"D:\checkout")

    # Anchored on the directory the file was enumerated from, the same call is a
    # plain filename.
    assert ntpath.relpath(scanned, r"C:\some\tree") == "first.py"
