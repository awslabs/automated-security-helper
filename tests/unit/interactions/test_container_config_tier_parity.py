# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A --config is confined the same way in a container as on the host.

Each test runs one layout two ways and compares what the five confinements leave
(the sandbox settings, ``ash_plugin_modules``, detect-secrets' filters,
``honor_ignore_files`` and the archive limit) and which warnings give the remedy:

- on the host, as a local scan resolves it (``resolve_config``, or each workspace
  project's config as the workspace run resolves it);
- in container mode: ``run_ash_container`` assembles the run command against a
  recording runner, the files it mounts are copied to the container paths under a
  directory outside every checkout, and the scan inside is the real ``ash`` command
  line given the run command's arguments, which resolves the mounted config.

The layouts, under W, with W/repo the checkout the scanned directory is in:

- a root config outside every checkout that extends a base inside one: the host
  keeps the root's own sandbox section and drops what the base grants;
- a root config in another checkout, and one in the scanned checkout: neither
  grants anything;
- a config outside every checkout with no extends: it is the operator's.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import scan as scan_cli
from automated_security_helper.cli.main import app
from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import create_completed_process
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
#: Settings only the operator may choose, each from a different confinement.
CHOSEN = {
    "sandbox": {
        "network_scanners": ["grype"],
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
#: The sandbox section a root config writes itself.
OWN = {"sandbox": {"mode": "bwrap", "extra_read_paths": ["/opt/operator-own"]}}
#: A plugin scanner's option that names a file its tool reads (config/path_trust.py).
TOOL_SCANNER = "example-plugin"
TOOL_KEY = f"scanners.{TOOL_SCANNER}.options.rules_file"
CONTAINER_ROOTS = ("/src", "/out", "/ash-config", "/ash-workspace-config")


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _merge(*parts: dict) -> dict:
    merged: dict = {}
    for part in parts:
        for key, value in part.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
    return merged


def _tree(w: Path) -> None:
    """W/repo, a checkout, with the workspace W/repo/ws of two projects."""
    (w / "repo" / ".git").mkdir(parents=True)
    ws = w / "repo" / "ws"
    (ws / "bare").mkdir(parents=True)
    (ws / "bare" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (ws / "own" / ".ash").mkdir(parents=True)
    (ws / "own" / "b.py").write_text("y = 2\n", encoding="utf-8")
    (ws / "own" / ".ash" / ".ash.yaml").write_text("project_name: own\n")
    (ws / "ash.code-workspace").write_text(
        json.dumps({"folders": [{"path": "bare"}, {"path": "own"}]}),
        encoding="utf-8",
    )


def _config(layout: str, w: Path) -> Path:
    if layout == "root-outside-every-checkout-with-a-base-in-one":
        (w / "ops" / "vendor" / ".git").mkdir(parents=True)
        _write(w / "ops" / "vendor" / "base.yaml", {"project_name": "base", **CHOSEN})
        return _write(
            w / "ops" / "ash.yaml",
            {"project_name": "operator", "extends": "vendor/base.yaml", **OWN},
        )
    if layout == "root-in-another-checkout":
        (w / "ops" / ".git").mkdir(parents=True)
        return _write(
            w / "ops" / "ash.yaml", _merge({"project_name": "o"}, CHOSEN, OWN)
        )
    if layout == "root-in-the-scanned-checkout":
        return _write(
            w / "repo" / "ci" / "ash.yaml", _merge({"project_name": "o"}, CHOSEN, OWN)
        )
    if layout == "root-outside-every-checkout":
        unchosen = {k: v for k, v in CHOSEN.items() if k != "ash_plugin_modules"}
        return _write(
            w / "ops" / "ash.yaml", _merge({"project_name": "o"}, unchosen, OWN)
        )
    raise AssertionError(layout)


def _tool_path(config, source: Optional[Path]) -> Dict[str, object]:
    """Whether the scan may hand a tool the file ``TOOL_KEY`` names, when the config
    names one (config/path_trust.py)."""
    named = config.scanners.model_dump().get(TOOL_SCANNER, {}).get("options", {})
    value = named.get("rules_file") if isinstance(named, dict) else None
    if value is None or source is None:
        return {}
    # Each refusal warns once per process; both sides have to warn.
    reset_path_refusal_warnings()
    honored = honored_path(value, source_dir=source, key=TOOL_KEY, config=config)
    return {TOOL_KEY: honored is not None}


def _settings_of(config, source: Optional[Path] = None) -> Dict[str, object]:
    sandbox = config.sandbox
    scan_settings = config.scanners.detect_secrets.options.scan_settings
    return {
        **_tool_path(config, source),
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


class _Warnings(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages: List[str] = []

    def emit(self, record):
        self.messages.append(" ".join(record.getMessage().split()))

    def remedied(self) -> List[str]:
        # Up to the file each names, which has another path in the container.
        return sorted(
            re.split(r" from | set by ", message)[0]
            for message in self.messages
            if REMEDY in message
        )


def _resolved(
    resolve, source: Optional[Path] = None
) -> Tuple[Dict[str, object], List[str]]:
    warnings = _Warnings()
    ASH_LOGGER.addHandler(warnings)
    try:
        config = resolve()
        settings = _settings_of(config, source)
    finally:
        ASH_LOGGER.removeHandler(warnings)
    return settings, warnings.remedied()


def _host_one_directory(config: Path, source: Path) -> dict:
    return {
        "scan": _resolved(
            lambda: resolve_config(config_path=config, source_dir=source), source
        )
    }


def _host_workspace(config: Path, definition: Path, out: Path) -> dict:
    plan = resolve_workspace(definition, default_config=str(config))
    settings = ProjectScanSettings(output_dir=out, default_config_path=str(config))
    return {
        Path(project.path).name: _resolved(
            lambda project=project: _project_config_with_policy(project, settings),
            Path(project.path),
        )
        for project in plan.projects
    }


@pytest.fixture
def container(monkeypatch, tmp_path):
    """Run container mode against a recording runner; return the scan inside's results."""
    commands: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        commands.append([str(item) for item in cmd_list if item is not None])
        return create_completed_process(
            args=cmd_list, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)

    def run(**kwargs) -> dict:
        commands.clear()
        result = rac.run_ash_container(build=False, run=True, **kwargs)
        assert result.returncode != 3, result.stderr
        (cmd,) = [cmd for cmd in commands if cmd[1] == "run"]
        return _scan_inside(cmd, tmp_path / "container", monkeypatch)

    return run


def _scan_inside(cmd: List[str], fs: Path, monkeypatch) -> dict:
    """The scan inside the container: the run command's mounts as copies under fs,
    and its arguments given to the ash command line."""
    for i, arg in enumerate(cmd[:-1]):
        if arg != "--mount":
            continue
        fields = dict(part.partition("=")[::2] for part in cmd[i + 1].split(","))
        source, destination = (
            Path(fields["source"]),
            fs / fields["destination"].lstrip("/"),
        )
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source, destination)
    (fs / "out").mkdir(parents=True, exist_ok=True)

    def inside(arg: str) -> str:
        for root in CONTAINER_ROOTS:
            if arg == root or arg.startswith(root + "/"):
                return str(fs / arg.lstrip("/"))
        return arg

    args = [inside(arg) for arg in cmd[cmd.index("ash") + 1 :]]
    results: dict = {}

    def run_ash_scan(**kwargs):
        if kwargs.get("workspace_plan") is not None:
            settings = ProjectScanSettings(
                output_dir=Path(kwargs["output_dir"]),
                default_config_path=kwargs["config"],
                config_overrides=list(kwargs["config_overrides"] or []),
            )
            for project in kwargs["workspace_plan"].projects:
                results[Path(project.path).name] = _resolved(
                    lambda project=project: _project_config_with_policy(
                        project, settings
                    ),
                    Path(project.path),
                )
        else:
            results["scan"] = _resolved(
                lambda: resolve_config(
                    config_path=kwargs["config"],
                    source_dir=kwargs["source_dir"],
                    config_overrides=list(kwargs["config_overrides"] or []),
                    # As the orchestrator passes it on: the scan inside sets it for
                    # no container mark, which it holds in sandbox_grants instead.
                    untrusted_config=kwargs.get("untrusted_config", False),
                ),
                Path(kwargs["source_dir"]),
            )

    monkeypatch.setattr(scan_cli, "run_ash_scan", run_ash_scan)
    monkeypatch.chdir(fs)
    outcome = CliRunner().invoke(app, args)
    assert outcome.exit_code == 0, outcome.output
    return results


LAYOUTS = [
    "root-outside-every-checkout-with-a-base-in-one",
    "root-in-another-checkout",
    "root-in-the-scanned-checkout",
    "root-outside-every-checkout",
]


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_one_directory_scan(layout, container, tmp_path):
    w = tmp_path / "W"
    _tree(w)
    config = _config(layout, w)
    source = w / "repo" / "ws" / "bare"

    host = _host_one_directory(config, source)
    inside = container(
        source_dir=str(source), output_dir=str(tmp_path / "out"), config=str(config)
    )

    assert inside == host
    _expect(layout, host["scan"])


@pytest.mark.parametrize(
    "layout", [layout for layout in LAYOUTS if layout != "root-in-the-scanned-checkout"]
)
def test_a_workspace_scan(layout, container, tmp_path):
    """The workspace's own checkout is refused in container mode (see
    test_container_workspace_config_tier.py), so that layout is not here."""
    w = tmp_path / "W"
    _tree(w)
    config = _config(layout, w)
    ws = w / "repo" / "ws"

    host = _host_workspace(config, ws / "ash.code-workspace", tmp_path / "out")
    inside = container(
        source_dir=str(ws),
        output_dir=str(tmp_path / "out"),
        config=str(config),
        workspace_relative_file="ash.code-workspace",
    )

    assert inside == host
    _expect(layout, host["bare"])


def _expect(layout: str, result: Tuple[Dict[str, object], List[str]]) -> None:
    """What the host gives, so a test cannot pass by both sides going wrong."""
    settings, remedied = result
    if layout == "root-outside-every-checkout":
        assert settings["sandbox.extra_read_paths"] == ["/opt/operator-own"]
        assert settings["sandbox.network_scanners"] == ["grype"]
        assert remedied == []
        return
    assert settings["sandbox.mode"] == "bwrap"
    assert settings["sandbox.network_scanners"] is None
    assert settings["ash_plugin_modules"] == []
    assert settings["honor_ignore_files"] is True
    assert VERIFICATION_FILTER not in settings["filters_used"]
    assert len(remedied) == 5, remedied
    own = ["/opt/operator-own"]
    if layout == "root-outside-every-checkout-with-a-base-in-one":
        assert settings["sandbox.extra_read_paths"] == own
    else:
        assert settings["sandbox.extra_read_paths"] == []


def _tool_path_layout(w: Path) -> Tuple[Path, Path]:
    """A config in another checkout (W/ops) that names a tool file in that checkout."""
    (w / "ops" / ".git").mkdir(parents=True)
    rules = w / "ops" / "rules.yaml"
    rules.write_text("", encoding="utf-8")
    config = _write(
        w / "ops" / "ash.yaml",
        {
            "project_name": "o",
            "scanners": {
                TOOL_SCANNER: {"enabled": True, "options": {"rules_file": str(rules)}}
            },
        },
    )
    return config, rules


@pytest.mark.parametrize("scan", ["one-directory", "workspace"])
def test_a_tool_path_a_config_in_another_checkout_names(scan, container, tmp_path):
    """On the host the tool paths a config file names follow that file's tier
    (resolve_config._operator_wrote, sandbox_grants.untrusted_path): a config in
    another checkout names them as the repository does, so a file in that checkout
    is refused, with the remedy. The scan inside, given the mark, decides the same.
    The tool file is at the same path here on both sides; in a real container the
    host does not mount it, so a scanner there could not read it either way."""
    w = tmp_path / "W"
    _tree(w)
    config, _ = _tool_path_layout(w)
    ws = w / "repo" / "ws"
    if scan == "one-directory":
        source = ws / "bare"
        host = _host_one_directory(config, source)
        inside = container(
            source_dir=str(source), output_dir=str(tmp_path / "out"), config=str(config)
        )
        key, inner_source = "scan", tmp_path / "container" / "src"
    else:
        host = _host_workspace(config, ws / "ash.code-workspace", tmp_path / "out")
        inside = container(
            source_dir=str(ws),
            output_dir=str(tmp_path / "out"),
            config=str(config),
            workspace_relative_file="ash.code-workspace",
        )
        key, inner_source = "bare", tmp_path / "container" / "src" / "bare"

    assert inside == host
    settings, remedied = host[key]
    assert settings[TOOL_KEY] is False
    assert any(message.startswith(f"Ignoring {TOOL_KEY}") for message in remedied)
    # Control: without the mark, the scan inside would hand the tool that file.
    mounted = tmp_path / "container" / "ash-config" / "ash.yaml"
    unmarked = _resolved(
        lambda: resolve_config(config_path=mounted, source_dir=inner_source),
        inner_source,
    )
    assert unmarked[0][TOOL_KEY] is True
