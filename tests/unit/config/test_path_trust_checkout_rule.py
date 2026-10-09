# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tool config files, plugin modules and uploaded configs follow the checkout rule.

config/path_trust.py and config/plugin_module_trust.py decide whether the scanned
repository could have written a file with ``sandbox_grants.untrusted_path``, the same
rule config files are judged by: inside any git checkout, or inside the scan root.
"""

import sys
from pathlib import Path

import pytest

from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.config.plugin_module_trust import refusal_reason
from automated_security_helper.config.resolve_config import resolve_config


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path):
    # A basetemp inside a repository, or a home that is a checkout with TMPDIR
    # under it, would make every refusal here pass for the wrong reason.
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


def _checkout(path: Path) -> Path:
    (path / ".git").mkdir(parents=True)
    return path


def test_a_tool_config_in_another_checkout_is_not_passed(tmp_path):
    # Outside the scanned tree, but in a checkout: someone other than the operator
    # can push to it.
    other = _checkout(tmp_path / "rules-repo")
    rules = other / "semgrep.yml"
    rules.write_text("rules: []\n")
    target = tmp_path / "target"
    target.mkdir()
    assert honored_path(str(rules), source_dir=target, key="config") is None


@pytest.mark.parametrize("marker", ["directory", "file"])
def test_a_tool_config_in_a_neighbouring_checkout_is_not_passed(tmp_path, marker):
    # The scan root is mono/app; the file sits in mono/vendor/lib, a checkout
    # outside the scan root with no .git above mono. Only the checkout rule can
    # refuse it. A submodule or linked worktree has a .git file, not a directory.
    mono = tmp_path / "mono"
    app = mono / "app"
    app.mkdir(parents=True)
    lib = mono / "vendor" / "lib"
    lib.mkdir(parents=True)
    if marker == "directory":
        (lib / ".git").mkdir()
    else:
        (lib / ".git").write_text("gitdir: ../../.git/modules/lib\n")
    rules = lib / "semgrep.yml"
    rules.write_text("rules: []\n")
    assert honored_path(str(rules), source_dir=app, key="config") is None


def test_without_the_checkout_the_neighbouring_tool_config_is_passed(tmp_path):
    mono = tmp_path / "mono"
    app = mono / "app"
    app.mkdir(parents=True)
    lib = mono / "vendor" / "lib"
    lib.mkdir(parents=True)
    rules = lib / "semgrep.yml"
    rules.write_text("rules: []\n")
    assert honored_path(str(rules), source_dir=app, key="config") == rules.resolve()


def test_a_name_outside_every_checkout_that_resolves_into_one_is_not_passed(
    tmp_path,
):
    other = _checkout(tmp_path / "rules-repo")
    (other / "semgrep.yml").write_text("rules: []\n")
    elsewhere = tmp_path / "etc"
    elsewhere.mkdir()
    link = elsewhere / "semgrep.yml"
    _link(link, other / "semgrep.yml")
    target = tmp_path / "target"
    target.mkdir()
    assert honored_path(str(link), source_dir=target, key="config") is None


def _link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")


def test_a_link_in_the_target_to_a_file_outside_is_not_passed(tmp_path):
    # The repository plants a link and so chooses which host file the tool reads.
    host = tmp_path / "host" / "semgrep.yml"
    host.parent.mkdir()
    host.write_text("rules: []\n")
    target = tmp_path / "target"
    target.mkdir()
    _link(target / ".semgrep.yml", host)
    assert (
        honored_path(str(target / ".semgrep.yml"), source_dir=target, key="config")
        is None
    )


def test_a_link_inside_another_checkout_to_a_file_outside_is_not_passed(tmp_path):
    host = tmp_path / "host" / "semgrep.yml"
    host.parent.mkdir()
    host.write_text("rules: []\n")
    other = _checkout(tmp_path / "rules-repo")
    _link(other / "semgrep.yml", host)
    target = tmp_path / "target"
    target.mkdir()
    assert (
        honored_path(str(other / "semgrep.yml"), source_dir=target, key="config")
        is None
    )


def test_a_tool_config_outside_every_checkout_and_the_target_is_passed(tmp_path):
    rules = tmp_path / "etc" / "semgrep.yml"
    rules.parent.mkdir()
    rules.write_text("rules: []\n")
    target = tmp_path / "target"
    target.mkdir()
    assert honored_path(str(rules), source_dir=target, key="config") == rules.resolve()


def test_a_plugin_module_in_another_checkout_is_refused(tmp_path, monkeypatch):
    other = _checkout(tmp_path / "plugins-repo")
    package = other / "acme_ash_plugin_checkoutrule"
    package.mkdir()
    (package / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(other))
    target = tmp_path / "target"
    target.mkdir()
    try:
        reason = refusal_reason("acme_ash_plugin_checkoutrule", target)
    finally:
        sys.modules.pop("acme_ash_plugin_checkoutrule", None)
    assert reason == (
        f"it is at {package.as_posix()}, and it is inside the git checkout at "
        f"{other.absolute().as_posix()}"
    )


def test_an_installed_module_in_a_virtualenv_inside_a_checkout_is_refused(
    tmp_path, monkeypatch
):
    # A virtualenv kept inside some unrelated checkout: its packages are inside
    # that checkout, so a repository's config cannot import them.
    project = _checkout(tmp_path / "project")
    site = project / ".venv" / "lib" / "python3" / "site-packages"
    package = site / "acme_ash_plugin_venv"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(site))
    target = tmp_path / "target"
    target.mkdir()
    try:
        reason = refusal_reason("acme_ash_plugin_venv", target)
    finally:
        sys.modules.pop("acme_ash_plugin_venv", None)
    assert reason is not None
    assert f"the git checkout at {project.absolute().as_posix()}" in reason


def test_an_uploaded_config_outside_every_checkout_cannot_grant(tmp_path, caplog):
    upload = tmp_path / "upload" / "ash.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: x\nsandbox:\n  mode: bwrap\n"
        "  network_scanners: [checkov]\n  extra_read_paths: ['/']\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    caplog.set_level("WARNING")
    sandbox = resolve_config(
        config_path=upload, source_dir=target, untrusted_config=True
    ).sandbox
    assert sandbox.network_scanners is None
    assert sandbox.extra_read_paths == []
    # The warning gives the reason that applies: a client supplied the file.
    assert any(
        "MCP client supplied" in record.getMessage() for record in caplog.records
    )


def _plugin_package(root: Path, name: str) -> None:
    package = root / name
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")


@pytest.mark.parametrize("supplied_by", ["checkout", "mcp-upload"])
def test_one_config_is_confined_by_both_rules(tmp_path, monkeypatch, supplied_by):
    # One config that asks for sandbox grants and for a plugin module the scanned
    # repository could have written. Both rules apply in the same resolution: the
    # grants come from the trusted base, and the module is not imported.
    target = tmp_path / "target"
    target.mkdir()
    module = f"acme_combined_{supplied_by.replace('-', '_')}"
    _plugin_package(target / "plugins", module)
    monkeypatch.syspath_prepend(str(target / "plugins"))
    text = (
        "project_name: x\nsandbox:\n  mode: bwrap\n"
        "  network_scanners: [checkov]\n  extra_read_paths: ['/']\n"
        f"ash_plugin_modules: [{module}]\n"
    )
    if supplied_by == "checkout":
        config_path = _checkout(tmp_path / "ops") / "ash.yaml"
        untrusted = False
    else:
        config_path = tmp_path / "upload" / "ash.yaml"
        config_path.parent.mkdir()
        untrusted = True
    config_path.write_text(text)
    try:
        config = resolve_config(
            config_path=config_path, source_dir=target, untrusted_config=untrusted
        )
    finally:
        sys.modules.pop(module, None)
    assert config.sandbox.mode == "bwrap"
    assert config.sandbox.network_scanners is None
    assert config.sandbox.extra_read_paths == []
    assert module not in config.ash_plugin_modules
