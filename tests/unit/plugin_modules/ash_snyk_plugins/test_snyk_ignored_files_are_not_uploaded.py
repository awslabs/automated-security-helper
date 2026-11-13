# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk-code does not run on a target holding a file the operator ignores.

``snyk code test`` uploads the files it reads to Snyk, and has no option that
leaves out a path. Every other scanner is told to leave out the files in
``global_settings.ignore_paths``, or drops their findings; for snyk that is not
enough, since an operator who ignores a path expects its files not to leave the
host. So snyk is not started when an ignore path the config sets matches a file in
its target, and the error gives the count, the patterns and the remedy.

ASH's own default exclusions are not ignore paths: the default config sets none,
and the scanner-level defaults (``KNOWN_IGNORE_PATHS``, such as ``node_modules/``)
never reach this check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
)

pytestmark = pytest.mark.unit

SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "SnykCode", "rules": []}}, "results": []}
        ],
    }
)


@pytest.fixture
def context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True)
    source = Path(context.source_dir)
    (source / "app.js").write_text("const a = 1;\n", encoding="utf-8")
    (source / "thirdparty").mkdir()
    (source / "thirdparty" / "lib.js").write_text("const b = 2;\n", encoding="utf-8")
    (source / "thirdparty" / "other.js").write_text("const c = 3;\n", encoding="utf-8")
    (source / "node_modules").mkdir()
    (source / "node_modules" / "dep.js").write_text("const d = 4;\n", encoding="utf-8")
    return context


@pytest.fixture(autouse=True)
def snyk_on_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "bin" / "snyk"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: str(binary))
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


@pytest.fixture
def runs() -> List[List[str]]:
    """The argv of each snyk run, which writes an empty SARIF where it is told."""
    calls: List[List[str]] = []

    def run(self, command, **kwargs):
        calls.append(list(command))
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--sarif-file-output=")
        )
        Path(output).write_text(SARIF, encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with patch.object(SnykCodeScanner, "_run_subprocess", autospec=True) as double:
        double.side_effect = run
        yield calls


def _scan(context: PluginContext, ignore_paths: List[IgnorePathWithReason]):
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    return scanner.scan(
        target=Path(context.source_dir),
        target_type="source",
        global_ignore_paths=ignore_paths,
    )


def _ignore(*paths: str) -> List[IgnorePathWithReason]:
    return [IgnorePathWithReason(path=path, reason="vendored") for path in paths]


def test_an_ignored_file_in_the_target_means_snyk_is_not_started(context, runs):
    with pytest.raises(ScannerError) as refused:
        _scan(context, _ignore("thirdparty/**", "docs/**"))

    message = str(refused.value)
    assert runs == []
    assert "was not started" in message
    assert "2 files" in message
    assert "'thirdparty/**'" in message
    assert "'docs/**'" not in message
    assert "--exclude-scanners snyk-code" in message
    assert "ignore_paths" in message


def test_an_ignore_path_matching_no_file_lets_snyk_run(context, runs):
    _scan(context, _ignore("docs/**"))

    assert len(runs) == 1


def test_asks_own_default_exclusions_do_not_stop_snyk(context, runs):
    """node_modules/ is a scanner-level default, not an ignore path."""
    assert get_default_config().global_settings.ignore_paths == []

    _scan(context, [])

    assert len(runs) == 1
