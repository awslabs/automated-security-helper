# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file in any git checkout names tool paths as the repository, not the operator.

A config file inside a git checkout or the scanned directory may not grant sandbox
access or choose the other confined settings (``sandbox_grants.repository_written``),
because someone other than the operator may have written it. That includes an
operator's own ops checkout beside the scanned one. The tool config and plugin paths
such a file names follow the same tier (config/path_trust.py): they are the
repository's, refused anywhere in a git checkout or the scanned directory, and the
warning says how to keep the setting. A path named from a config file outside every
checkout, with ``--config-overrides`` or by an environment variable is the
operator's, refused only inside the scanned tree itself.

Most tests ask ``path_trust.honored_path`` directly, as a scanner does, for an
option of a plugin scanner (``PLUGIN_KEY``), so the answer comes from who named the
path and nothing else. One drives checkov's ``config_file`` end to end.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.uv_tool_runner import UVToolRunner
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

PLUGIN = "example-plugin"
PLUGIN_KEY = f"scanners.{PLUGIN}.options.rules_file"
REMEDY = (
    "move the file outside every git checkout, or pass the setting with "
    "--config-overrides"
)


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture(autouse=True)
def _no_uv_probe():
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path, monkeypatch):
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


class Layout:
    def __init__(self, root: Path):
        self.scanned = root / "repo"
        self.ops = root / "ops"
        self.outside = root / "etc"
        for checkout in (self.scanned, self.ops):
            mark_git_checkout(checkout)
        self.outside.mkdir()
        (self.scanned / "app.py").write_text("x = 1\n", encoding="utf-8")
        self.ops_file = self.ops / "rules.yaml"
        self.ops_file.write_text("", encoding="utf-8")
        self.output = root / "out"
        (self.output / ASH_WORK_DIR_NAME).mkdir(parents=True)

    def config_naming(
        self, directory: Path, path: Path, scanner: str = PLUGIN, option: str = ""
    ) -> Path:
        option = option or "rules_file"
        config = directory / "ash.yaml"
        config.write_text(
            "project_name: p\n"
            "scanners:\n"
            f"  {scanner}:\n"
            "    enabled: true\n"
            "    options:\n"
            f"      {option}: {path.as_posix()}\n",
            encoding="utf-8",
        )
        return config


@pytest.fixture
def layout(tmp_path) -> Layout:
    return Layout(tmp_path)


def _honored(layout: Layout, path: Path, **resolve):
    config = resolve_config(source_dir=layout.scanned, **resolve)
    return honored_path(
        path.as_posix(), source_dir=layout.scanned, key=PLUGIN_KEY, config=config
    )


def test_a_config_in_an_ops_checkout_cannot_name_a_file_in_it(layout, caplog):
    config = layout.config_naming(layout.ops, layout.ops_file)

    with caplog.at_level(logging.WARNING):
        honored = _honored(layout, layout.ops_file, config_path=config)

    assert honored is None
    warning = " ".join(m for m in caplog.messages if m.startswith("Ignoring"))
    assert PLUGIN_KEY in warning, caplog.messages
    assert f"git checkout at {layout.ops.as_posix()}" in warning, warning
    assert REMEDY in warning, warning


def test_the_same_config_outside_every_checkout_keeps_the_path(layout):
    config = layout.config_naming(layout.outside, layout.ops_file)

    assert _honored(layout, layout.ops_file, config_path=config) == (
        layout.ops_file.resolve()
    )


@pytest.mark.parametrize(
    "with_ops_config", [False, True], ids=["alone", "with-ops-config"]
)
def test_config_overrides_naming_a_path_in_an_ops_checkout_keep_it(
    layout, with_ops_config
):
    resolve = {"config_overrides": [f"{PLUGIN_KEY}={layout.ops_file.as_posix()}"]}
    if with_ops_config:
        other = layout.ops / "other.yaml"
        other.write_text("", encoding="utf-8")
        resolve["config_path"] = layout.config_naming(layout.ops, other)

    assert _honored(layout, layout.ops_file, **resolve) == layout.ops_file.resolve()


def test_an_environment_variable_naming_a_path_in_an_ops_checkout_keeps_it(layout):
    config = layout.config_naming(layout.ops, layout.ops / "other.yaml")
    resolved = resolve_config(source_dir=layout.scanned, config_path=config)

    assert honored_path(
        layout.ops_file.as_posix(),
        source_dir=layout.scanned,
        key="EXAMPLE_RULES_FILE",
        config=resolved,
    ) == (layout.ops_file.resolve())


@pytest.mark.parametrize("where", ["ops-checkout", "scanned-checkout"])
def test_a_config_in_the_scanned_checkout_naming_a_checkout_path_is_refused(
    layout, where, caplog
):
    path = layout.ops_file if where == "ops-checkout" else layout.scanned / "r.yaml"
    path.write_text("", encoding="utf-8")
    (layout.scanned / ".ash").mkdir()
    config = layout.config_naming(layout.scanned / ".ash", path)

    with caplog.at_level(logging.WARNING):
        honored = _honored(layout, path, config_path=config)

    assert honored is None
    assert REMEDY in " ".join(caplog.messages)


def test_a_config_outside_every_checkout_extending_one_in_a_checkout(layout):
    """The selected file is the operator's and the base it extends is not, so only
    the selected file's own paths are the operator's. The base sits in a checkout
    below the selected file's directory, where its ``extends`` may reach."""
    shared = layout.outside / "shared"
    mark_git_checkout(shared)
    layout.config_naming(shared, layout.ops_file)
    config = layout.outside / "ash.yaml"
    config.write_text("extends: shared/ash.yaml\nproject_name: p\n", encoding="utf-8")

    assert _honored(layout, layout.ops_file, config_path=config) is None


def test_checkov_is_not_handed_a_tool_config_an_ops_checkout_config_names(layout):
    """End to end: the argument list ASH hands checkov."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
    )

    tool_config = layout.ops / "checkov.yaml"
    tool_config.write_text("", encoding="utf-8")
    config_file = layout.config_naming(
        layout.ops, tool_config, scanner="checkov", option="config_file"
    )
    config = resolve_config(source_dir=layout.scanned, config_path=config_file)
    scanner = CheckovScanner(
        config=config.get_plugin_config("scanner", "checkov"),
        context=PluginContext(
            source_dir=layout.scanned,
            output_dir=layout.output,
            work_dir=layout.output / ASH_WORK_DIR_NAME,
            config=config,
        ),
    )

    argv = scanner._resolve_arguments(layout.scanned, layout.output / "r.sarif")

    assert "--config-file" not in argv, argv
    assert not any(tool_config.as_posix() in arg for arg in argv), argv
