# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace --config in another git checkout is limited the same way in a
container as on the host.

On the host, a workspace scan with ``--config`` in a git checkout that is not the
workspace's own (an ops repository beside it) confines that file as
repository-written: every project that has no config of its own and uses it alone,
and every project it is layered over, loses the five settings such a file may not
choose (the sandbox grants, ``ash_plugin_modules``, detect-secrets' verification,
``honor_ignore_files`` and a higher archive extraction limit), with a warning that
names each and says how to keep it. Its ``sandbox.mode`` still sets the floor.

In container mode the host mounts that file at ``/ash-config`` and passes
``--config-from-scanned-repository``. The scan inside the container, which sees
the workspace at ``/src`` and the config in no checkout, treats the marked config
and the files it extends as repository-written for as long as it runs. These
tests resolve each project's config both ways and compare what every confinement
leaves, and the warnings. They compare the config as it resolves: the scan inside
a container then runs with ``sandbox.mode=off``, the last override run_ash_scan
hands it, because the container is the boundary, so no file's mode applies there.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    _project_config_with_policy,
)
from automated_security_helper.workspace.resolver import resolve_workspace

REMEDY = (
    "move the file outside every git checkout, or pass the setting with "
    "--config-overrides"
)
VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
OPERATOR = {
    "project_name": "operator",
    "sandbox": {
        "mode": "bwrap",
        "network_scanners": ["grype"],
        "extra_read_paths": ["/opt/operator-grant"],
        "read_path_scanners": ["zizmor"],
        "env_scanners": ["zizmor"],
    },
    "ash_plugin_modules": ["not_installed_ash_plugins"],
    "honor_ignore_files": False,
    "converters": {"archive": {"options": {"max_members": 10_000_000}}},
    "scanners": {
        "detect-secrets": {
            "enabled": True,
            "options": {
                "scan_settings": {
                    "version": "1.5.0",
                    "plugins_used": [{"name": "AWSKeyDetector"}],
                    "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}],
                }
            },
        }
    },
}


def _workspace(root: Path) -> Path:
    """A workspace with one project that has no config and one that has its own."""
    (root / "bare").mkdir(parents=True)
    (root / "bare" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "own" / ".ash").mkdir(parents=True)
    (root / "own" / "b.py").write_text("y = 2\n", encoding="utf-8")
    (root / "own" / ".ash" / ".ash.yaml").write_text(
        "project_name: own\n", encoding="utf-8"
    )
    definition = root / "ash.code-workspace"
    definition.write_text(
        json.dumps({"folders": [{"path": "bare"}, {"path": "own"}]}),
        encoding="utf-8",
    )
    return definition


def _settings_of(config) -> Dict[str, object]:
    sandbox = config.sandbox
    scan_settings = config.scanners.detect_secrets.options.scan_settings
    return {
        "sandbox.mode": sandbox.mode,
        "sandbox.network_scanners": sandbox.network_scanners,
        "sandbox.extra_read_paths": list(sandbox.extra_read_paths),
        "sandbox.read_path_scanners": list(sandbox.read_path_scanners),
        "sandbox.env_scanners": list(sandbox.env_scanners),
        "sandbox.network_limit": sandbox.network_limit,
        "ash_plugin_modules": list(config.ash_plugin_modules),
        "honor_ignore_files": config.honor_ignore_files,
        "max_members": config.converters.archive.options.max_members,
        "filters_used": [str(item.path) for item in scan_settings.filters_used],
    }


def _resolve_each(definition: Path, config: Path, tmp_path: Path) -> Dict[str, tuple]:
    """Each project's resolved settings and warnings, as the workspace run makes them."""
    messages: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            messages.append(" ".join(record.getMessage().split()))

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        plan = resolve_workspace(definition, default_config=str(config))
        results = {}
        for project in plan.projects:
            messages.clear()
            resolved = _project_config_with_policy(
                project,
                ProjectScanSettings(
                    output_dir=tmp_path / "out", default_config_path=str(config)
                ),
            )
            results[project.key] = (
                _settings_of(resolved),
                # Each remedied warning up to the file it names, which is at a
                # different path inside the container.
                sorted(
                    re.split(r" from | set by ", message)[0]
                    for message in messages
                    if REMEDY in message
                ),
                [message for message in messages if message.startswith("Ignoring")],
            )
        return results
    finally:
        ASH_LOGGER.removeHandler(handler)


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _layouts(tmp_path: Path, operator: dict = OPERATOR) -> tuple:
    """The host's layout, and the one the scan inside the container sees."""
    # Host: W/repo is the workspace's checkout, W/ops another checkout beside it.
    host_root = tmp_path / "W" / "repo" / "ws"
    host_definition = _workspace(host_root)
    (tmp_path / "W" / "repo" / ".git").mkdir()
    (tmp_path / "W" / "ops" / ".git").mkdir(parents=True)
    host_config = tmp_path / "W" / "ops" / "ash.yaml"
    host_config.write_text(json.dumps(operator), encoding="utf-8")
    # Container: the workspace at /src, outside every checkout, and the config
    # mounted on its own at /ash-config.
    inner_root = tmp_path / "inner" / "src"
    shutil.copytree(host_root, inner_root)
    inner_config = tmp_path / "inner" / "ash-config" / "ash.yaml"
    inner_config.parent.mkdir(parents=True)
    shutil.copy(host_config, inner_config)
    return host_definition, host_config, inner_root / "ash.code-workspace", inner_config


#: For the controls: a module the operator's own config names is kept, and a
#: workspace whose projects end up with different modules is refused at planning.
GRANT_ONLY = {k: v for k, v in OPERATOR.items() if k != "ash_plugin_modules"}


def test_every_project_gets_the_same_settings_and_warnings(tmp_path):
    host_definition, host_config, inner_definition, inner_config = _layouts(tmp_path)

    host = _resolve_each(host_definition, host_config, tmp_path)
    with sandbox_grants.marked_repository_written(inner_config):
        inner = _resolve_each(inner_definition, inner_config, tmp_path)

    assert set(host) == set(inner) and len(host) == 2
    for key in host:
        assert inner[key][0] == host[key][0], key
        assert inner[key][1] == host[key][1], key
    # The config falls back for the project with none, so every confinement
    # applies there, with the remedy in each warning, and the operator's mode is
    # kept as the floor.
    (bare,) = [key for key in host if "bare" in key]
    settings, remedied, _ = host[bare]
    assert settings["sandbox.mode"] == "bwrap"
    assert settings["sandbox.extra_read_paths"] == []
    assert settings["sandbox.network_scanners"] is None
    assert settings["ash_plugin_modules"] == []
    assert settings["honor_ignore_files"] is True
    assert VERIFICATION_FILTER not in settings["filters_used"]
    assert (
        settings["max_members"]
        < OPERATOR["converters"]["archive"]["options"]["max_members"]
    )
    assert len(remedied) == 5, remedied


def test_without_the_mark_the_scan_inside_would_grant(tmp_path):
    """Control: the mounted copy is in no checkout inside the container."""
    _, _, inner_definition, inner_config = _layouts(tmp_path, GRANT_ONLY)

    inner = _resolve_each(inner_definition, inner_config, tmp_path)

    (bare,) = [key for key in inner if "bare" in key]
    assert inner[bare][0]["sandbox.extra_read_paths"] == ["/opt/operator-grant"]


def test_the_mark_ends_with_the_block(tmp_path):
    _, _, inner_definition, inner_config = _layouts(tmp_path, GRANT_ONLY)
    with sandbox_grants.marked_repository_written(inner_config):
        pass

    inner = _resolve_each(inner_definition, inner_config, tmp_path)

    (bare,) = [key for key in inner if "bare" in key]
    assert inner[bare][0]["sandbox.extra_read_paths"] == ["/opt/operator-grant"]
