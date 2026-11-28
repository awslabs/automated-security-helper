# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative GITLEAKS_CONFIG is resolved where ASH runs, not where gitleaks runs.

With GITLEAKS_CONFIG in the environment and no sandbox, the scanner passed no
``--config`` and left the resolution to gitleaks. gitleaks resolves a relative
path against its working directory, which ASH sets to the scanned source
directory, so a relative value the operator set in ASH's own working directory
was read from the scanned tree: the repository supplied the config file.

The relative value is now anchored to the directory ASH runs in and passed as
``--config``, which gitleaks reads before the variable. An absolute path is passed
as ``--config`` as given, and GITLEAKS_CONFIG_TOML (the config's text, not a path)
is written to a file outside the tree and passed as ``--config`` too. By default ASH
scans the directory it runs in, so in the default run the anchor is the scanned tree
itself and the tree can supply the file; an absolute path is the form that keeps
the tree from supplying it. These tests run ASH from a directory outside the tree.

The test is on the value AS GIVEN. A first shape tested ``os.path.isabs`` on the
value after ``expanduser``, so ``~/rules.toml`` read as absolute and was left to
gitleaks with the literal ``~``: a shell expands ``~`` only in some positions,
and a CI ``env:`` block, a ``.env`` file or ``--env-file`` never do, while
gitleaks does not expand it either, so it named a ``~`` directory inside the
scanned tree. The re-scan's environment anchored a relative value against the
scanned source directory, the one place it must not come from; it now uses the
same anchor as the first run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ScannerError
from tests.unit.plugin_modules.ash_builtin.test_gitleaks_scanner import _scanner

pytestmark = pytest.mark.unit


def test_a_relative_config_env_is_anchored_to_ashs_working_directory(
    tmp_path, monkeypatch
):
    operator_dir = tmp_path / "operator"
    operator_dir.mkdir()
    (operator_dir / "rules.toml").write_text('title = "operator"\n')
    monkeypatch.chdir(operator_dir)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.setenv("GITLEAKS_CONFIG", "rules.toml")
    scanner = _scanner(tmp_path)
    # The scanned tree holds a file of the same name, the one gitleaks would
    # have read from its working directory.
    (scanner.context.source_dir / "rules.toml").write_text('title = "repo"\n')

    chosen = scanner._resolve_config_file()

    assert chosen == Path(os.path.abspath("rules.toml"))
    assert chosen.read_text() == 'title = "operator"\n'
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert f"--config={chosen.as_posix()}" in args


def test_a_relative_config_env_the_operator_lacks_is_never_read_from_the_tree(
    tmp_path, monkeypatch
):
    """The operator's directory has no ``rules.toml`` and the scanned tree does.
    The value is still anchored where the operator set it. ASH reads that file to
    check its ``[extend]`` path, finds none, and refuses the run naming the path
    it anchored; leaving the value to gitleaks would have had it read the tree's
    copy and run the repository's rules."""
    operator_dir = tmp_path / "operator"
    operator_dir.mkdir()
    monkeypatch.chdir(operator_dir)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.setenv("GITLEAKS_CONFIG", "rules.toml")
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    (source / "rules.toml").write_text('title = "repo"\n')
    anchored = Path(os.path.abspath("rules.toml"))

    with pytest.raises(ScannerError, match="could not be read") as refused:
        scanner._resolve_config_file()

    message = str(refused.value)
    assert repr(str(anchored)) in message or str(anchored) in message, message
    assert str(source / "rules.toml") not in message
    assert (source / "rules.toml").as_posix() not in message
    assert not anchored.exists()


def _operator_home(tmp_path, monkeypatch) -> Path:
    """A home directory for ``~`` to expand to, on every platform's spelling."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def test_a_home_relative_config_env_is_anchored_to_the_operators_home(
    tmp_path, monkeypatch
):
    home = _operator_home(tmp_path, monkeypatch)
    (home / "rules.toml").write_text('title = "operator"\n')
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.setenv("GITLEAKS_CONFIG", "~/rules.toml")
    scanner = _scanner(tmp_path)
    # The scanned tree holds a directory literally named "~": where gitleaks,
    # which does not expand the character, would have read the value as given.
    repo_tilde = scanner.context.source_dir / "~"
    repo_tilde.mkdir()
    (repo_tilde / "rules.toml").write_text('title = "repo"\n')

    chosen = scanner._resolve_config_file()

    assert chosen == home / "rules.toml"
    assert chosen.read_text() == 'title = "operator"\n'
    args = scanner._build_arguments(scanner.context.source_dir, tmp_path / "o.sarif")
    assert f"--config={chosen.as_posix()}" in args


def test_the_rescan_anchors_the_variable_where_the_first_run_did(tmp_path, monkeypatch):
    """A run that reaches gitleaks with the variable alone (no ``--config`` in
    its arguments) re-scans the copies under the same file: anchored to the
    directory ASH runs in, ``~`` expanded, never to the scanned source
    directory."""
    home = _operator_home(tmp_path, monkeypatch)
    operator_dir = tmp_path / "operator"
    operator_dir.mkdir()
    monkeypatch.chdir(operator_dir)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir

    monkeypatch.setenv("GITLEAKS_CONFIG", "rules.toml")
    env = scanner._rescan_env(["--report-format=sarif"])
    assert env is not None
    assert env["GITLEAKS_CONFIG"] == (operator_dir / "rules.toml").as_posix()
    assert env["GITLEAKS_CONFIG"] != (source / "rules.toml").as_posix()

    monkeypatch.setenv("GITLEAKS_CONFIG", "~/rules.toml")
    env = scanner._rescan_env(["--report-format=sarif"])
    assert env is not None
    assert env["GITLEAKS_CONFIG"] == (home / "rules.toml").as_posix()
    assert "~" not in env["GITLEAKS_CONFIG"]

    # With --config passed, or an absolute value, there is nothing to anchor.
    assert scanner._rescan_env(["--config=/elsewhere/rules.toml"]) is None
    monkeypatch.setenv("GITLEAKS_CONFIG", str(tmp_path / "operator.toml"))
    assert scanner._rescan_env(["--report-format=sarif"]) is None


def test_an_absolute_config_env_is_passed_as_it_is(tmp_path, monkeypatch):
    """Control: an absolute path is passed unchanged, now as ``--config``."""
    (tmp_path / "operator.toml").write_text('title = "operator"\n')
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.setenv("GITLEAKS_CONFIG", str(tmp_path / "operator.toml"))
    scanner = _scanner(tmp_path)
    assert scanner._resolve_config_file() == tmp_path / "operator.toml"


def test_config_toml_text_in_the_environment_is_passed_as_a_file(tmp_path, monkeypatch):
    """The text is written to a file outside the scanned tree and passed as
    ``--config``, so gitleaks does not set its config path inside the tree."""
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", 'title = "inline"\n')
    scanner = _scanner(tmp_path)
    chosen = scanner._resolve_config_file()
    assert chosen is not None and chosen.read_text() == 'title = "inline"\n'
    assert not chosen.resolve().is_relative_to(scanner.context.source_dir.resolve())
