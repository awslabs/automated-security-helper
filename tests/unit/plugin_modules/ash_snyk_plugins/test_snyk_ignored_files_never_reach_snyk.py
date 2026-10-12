# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ignored file never reaches the snyk program, on either target type.

``snyk code test`` uploads the files it reads, and has no option that leaves out a
path, so snyk-code refuses a target holding a file the operator's
``global_settings.ignore_paths`` match: the row is ERROR, the message names the first
such file and the pattern that matched it, and snyk is not started.

These tests run the scanner through the executor with a stand-in ``snyk`` first on
PATH. The stand-in records its arguments and the text of every file below the
directory it is given, which is what the real program would read and upload. A canary
file sits
under the ignored path. When the target is refused, the stand-in never runs and the
canary is in nothing it recorded. The control, where no ignore path matches, shows
the stand-in does receive the canary, so its absence in the refused case means
something.

snyk-code has no exclusion option of its own, so the operator's ignore paths are the
only rule the refusal checks; the last test fails if the scanner gains one.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.client_scanner_exclusions import (
    SCANNER_EXCLUSION_OPTIONS,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
    SnykCodeScannerConfigOptions,
)

CANARY = "snyk-canary-4b1f0e9d7c"

#: The stand-in snyk. It reads every file below the directory it is given, as the
#: real program reads what it uploads, and writes its arguments and each file's
#: path and text to ``received.json`` in the record directory.
_STAND_IN = """#!{python} -I
import json, os, sys

args = sys.argv[1:]
output = next(a for a in args if a.startswith("--sarif-file-output="))
target = args[args.index(output) - 1]
files = {{}}
for directory, _subdirectories, names in os.walk(target):
    for name in names:
        path = os.path.join(directory, name)
        with open(path, encoding="utf-8", errors="replace") as handle:
            files[os.path.relpath(path, target)] = handle.read()
os.makedirs({record!r}, exist_ok=True)
with open(os.path.join({record!r}, "received.json"), "w", encoding="utf-8") as handle:
    json.dump({{"argv": args, "files": files}}, handle)
sarif = {{"version": "2.1.0", "runs": [
    {{"tool": {{"driver": {{"name": "SnykCode", "rules": []}}}}, "results": []}}
]}}
with open(output.split("=", 1)[1], "w", encoding="utf-8") as handle:
    json.dump(sarif, handle)
"""


@pytest.fixture
def record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Where the stand-in snyk, first on PATH, records what it was given."""
    record = tmp_path / "snyk-record"
    binary = tmp_path / "bin" / "snyk"
    binary.parent.mkdir()
    binary.write_text(
        _STAND_IN.format(python=sys.executable, record=str(record)), encoding="utf-8"
    )
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", f"{binary.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    return record


def _context(tmp_path: Path, ignore_paths: List[str]) -> PluginContext:
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=path, reason="vendored") for path in ignore_paths
    ]
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )
    (source / "thirdparty").mkdir(parents=True)
    Path(context.work_dir).mkdir(parents=True)
    (source / "app.js").write_text("const a = 1;\n", encoding="utf-8")
    (source / "thirdparty" / "lib.js").write_text("const b = 2;\n", encoding="utf-8")
    (source / "thirdparty" / "zz-canary.js").write_text(
        f"const canary = '{CANARY}';\n", encoding="utf-8"
    )
    return context


def _run(context: PluginContext, target: Path, target_type: str):
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    # As the scan phase sets it: the operator's ignore paths.
    executor._global_ignore_paths = ignore_paths_that_skip_scanning(
        context.config.global_settings.ignore_paths, ignore_suppressions=False
    )
    (container,) = executor._execute_scanner(
        "snyk-code", scanner, [{"path": target, "type": target_type}]
    )
    return container


def _errors(container) -> str:
    return "\n".join(str(error) for error in container.errors)


def _received(record: Path) -> Optional[Dict[str, Any]]:
    """What the stand-in snyk was given, or None when it never ran."""
    path = record / "received.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _canary_in(received: Optional[Dict[str, Any]]) -> List[str]:
    """Where the canary reached the stand-in: ``argv``, or each file holding it."""
    if received is None:
        return []
    found = ["argv"] if CANARY in json.dumps(received["argv"]) else []
    return found + sorted(
        name for name, text in received["files"].items() if CANARY in text
    )


def test_a_refused_source_target_never_starts_snyk(tmp_path, record):
    context = _context(tmp_path, ["thirdparty/**"])

    container = _run(context, Path(context.source_dir), "source")

    received = _received(record)
    assert _canary_in(received) == []
    assert received is None, "the stand-in snyk ran"
    assert container.status == ScannerStatus.ERROR
    errors = _errors(container)
    assert "the first 'thirdparty/lib.js', which 'thirdparty/**' matches" in errors
    assert "2 files there are in global_settings.ignore_paths" in errors
    assert "--exclude-scanners snyk-code" in errors
    assert "snyk code test was not started" in errors
    assert CANARY not in errors


def test_without_an_ignored_file_snyk_runs_and_receives_every_file(tmp_path, record):
    """The control: the stand-in reads the canary when nothing ignores it."""
    context = _context(tmp_path, ["docs/**"])

    container = _run(context, Path(context.source_dir), "source")

    assert container.status != ScannerStatus.ERROR, _errors(container)
    received = _received(record)
    assert received is not None, "the stand-in snyk did not run"
    assert received["argv"][:2] == ["code", "test"]
    assert Path(context.source_dir).as_posix() in received["argv"]
    assert _canary_in(received) == ["thirdparty/zz-canary.js"]


def test_a_refused_converted_target_never_starts_snyk(tmp_path, record):
    """A converted file is matched by its path below the source directory."""
    context = _context(tmp_path, ["**/generated/**"])
    work = Path(context.work_dir)
    (work / "archive" / "bundle" / "generated").mkdir(parents=True)
    (work / "archive" / "bundle" / "app.py").write_text("a = 1\n", encoding="utf-8")
    (work / "archive" / "bundle" / "generated" / "client.py").write_text(
        f"canary = '{CANARY}'\n", encoding="utf-8"
    )

    container = _run(context, work, "converted")

    received = _received(record)
    assert _canary_in(received) == []
    assert received is None, "the stand-in snyk ran"
    assert container.status == ScannerStatus.ERROR
    errors = _errors(container)
    assert (
        "the first 'archive/bundle/generated/client.py', which '**/generated/**' "
        "matches" in errors
    ), errors
    assert "1 file there is in global_settings.ignore_paths" in errors
    assert "so it would upload it." in errors


def test_a_converted_target_with_no_ignored_file_runs(tmp_path, record):
    context = _context(tmp_path, ["**/generated/**"])
    work = Path(context.work_dir)
    (work / "archive" / "bundle").mkdir(parents=True)
    (work / "archive" / "bundle" / "app.py").write_text("a = 1\n", encoding="utf-8")

    container = _run(context, work, "converted")

    assert container.status != ScannerStatus.ERROR, _errors(container)
    received = _received(record)
    assert received is not None, "the stand-in snyk did not run"
    assert sorted(received["files"]) == ["archive/bundle/app.py"]


def test_the_first_path_is_shown_with_its_controls_escaped(tmp_path, record):
    context = _context(tmp_path, ["thirdparty/**"])
    name = "a\nb\x1b[31m.js"
    (Path(context.source_dir) / "thirdparty" / name).write_text(
        "const e = 5;\n", encoding="utf-8"
    )

    container = _run(context, Path(context.source_dir), "source")

    errors = _errors(container)
    assert "the first 'thirdparty/a\\nb\\x1b[31m.js'" in errors, errors
    assert name not in errors
    assert _received(record) is None, "the stand-in snyk ran"


def test_snyk_code_has_no_exclusion_option_the_refusal_does_not_check():
    """A tripwire. The refusal checks the operator's ignore paths only, because
    snyk-code has no exclusion option of its own. If it gains one, an entry in
    SCANNER_EXCLUSION_OPTIONS or an options field that leaves files out, snyk would
    still read and upload those files: check them in
    ``SnykCodeScanner._refuse_ignored_files`` and update this test.
    """
    assert [
        option for option in SCANNER_EXCLUSION_OPTIONS if option.scanner == "snyk-code"
    ] == []
    assert set(SnykCodeScannerConfigOptions.model_fields) == {
        "severity_threshold",
        "scan_timeout",
        "honor_tree_exclusions",
    }
