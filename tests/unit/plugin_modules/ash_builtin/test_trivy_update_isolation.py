# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trivy database update reads nothing the scanned repository wrote.

The update commands (``trivy image --download-db-only``, and ``trivy config`` of an
empty directory for the checks bundle) run outside the scanner sandbox and with a
network. trivy loads ``trivy.yaml`` from its working directory unless ``--config``
names another file, and a ``db.repository`` there changes where the database is
downloaded from (measured with trivy 0.75.0: without ``--config``, a ``trivy.yaml``
in the working directory naming ``sentinel.invalid`` made trivy fetch from it). So
each update command runs from a directory outside the scanned tree and is always
given ``--config``: the operator's file, or an empty one ASH writes outside the tree
(``utils/content_db_refresh.prepare_content_db``).

The spawns are recorded wherever the update runs them, so the test also fails on a
version that ran the update itself from ASH's working directory.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)

try:
    from automated_security_helper.utils import content_db_refresh as refresh
except ImportError:  # a revision before utils/content_db_refresh.py
    refresh = None
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)

PluginContext.model_rebuild()

SENTINEL = "sentinel.invalid"
PLANTED = (
    f"db:\n  repository: {SENTINEL}/ash-db\n"
    f"misconfiguration:\n  checks-bundle-repository: {SENTINEL}/ash-checks\n"
)


def _scanner(kind: str, source: Path, output: Path):
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=resolve_config(source_dir=source),
    )
    if kind == "trivy":
        return TrivyScanner(
            context=context,
            config=TrivyScannerConfig(
                enabled=True,
                options=TrivyScannerConfigOptions(
                    offline=False, scanners=["vuln", "misconfig"]
                ),
            ),
        )
    return TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions()),
    )


def _configs(argv: List[str]) -> List[Tuple[str, str]]:
    """Each ``--config`` in ``argv``, either spelling, with the file's content."""
    found = []
    for i, arg in enumerate(argv):
        if arg.startswith("--config="):
            found.append(arg.split("=", 1)[1])
        elif arg == "--config" and i + 1 < len(argv):
            found.append(argv[i + 1])
    return [
        (path, Path(path).read_text(encoding="utf-8") if Path(path).is_file() else "")
        for path in found
    ]


def _inside(path: Any, tree: Path) -> bool:
    return Path(os.path.realpath(path)).is_relative_to(Path(os.path.realpath(tree)))


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(None, id="as-the-scanner-builds-it"),
        pytest.param([], id="with-no-config-flag"),
    ],
)
@pytest.mark.parametrize("kind", ["trivy", "trivy-repo"])
def test_a_repository_trivy_yaml_does_not_reach_the_database_update(
    tmp_path, monkeypatch, kind, command
):
    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    (source / "trivy.yaml").write_text(PLANTED, encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    # ASH started from inside the repository it scans, as `cd repo && ash scan`.
    monkeypatch.chdir(source)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "trivy-cache"))
    monkeypatch.setattr(trivy_base, "find_executable", lambda name: f"/bin/{name}")
    updates: List[Tuple[List[str], Dict[str, Any], List[Tuple[str, str]]]] = []

    def fake_spawn_run(argv, **kwargs):
        # The config's content now: the update may remove its own afterwards.
        updates.append((list(argv), kwargs, _configs(argv)))
        return subprocess.CompletedProcess(argv, 0, "", "")

    for module in (trivy_base, refresh):
        if module is not None and hasattr(module, "spawn_run"):
            monkeypatch.setattr(module, "spawn_run", fake_spawn_run)
    if refresh is not None:
        refresh.forget_prepared()
    monkeypatch.setattr(
        trivy_base.ScannerPluginBase,
        "_run_subprocess",
        lambda self, command, *a, **k: {"returncode": 0},
    )
    scanner = _scanner(kind, source, output)
    results = output / "scanners" / kind / "source"
    results.mkdir(parents=True)
    if command is None:
        scan_command = ["trivy", "fs" if kind == "trivy" else "repository"]
        scan_command += [f"--config={(results / 'trivy-config.yaml').as_posix()}"]
        (results / "trivy-config.yaml").write_text("", encoding="utf-8")
        scan_command.append(source.as_posix())
    else:
        scan_command = ["trivy", "fs", source.as_posix()]

    scanner._run_subprocess(command=scan_command, results_dir=results)

    # Not vacuous: the database update and the checks bundle update both ran.
    assert [argv[1] for argv, _, _ in updates] == ["image", "config"]
    for argv, kwargs, configs in updates:
        assert SENTINEL not in " ".join(argv)
        cwd = kwargs.get("cwd")
        assert cwd is not None, f"{argv[1]} runs in ASH's working directory, {source}"
        assert not _inside(cwd, source)
        assert not (Path(cwd) / "trivy.yaml").exists()
        assert len(configs) == 1, argv
        ((path, content),) = configs
        assert Path(path).is_absolute() and not _inside(path, source)
        assert SENTINEL not in content
        env = kwargs.get("env") or {}
        assert not any(SENTINEL in str(v) for v in env.values())
