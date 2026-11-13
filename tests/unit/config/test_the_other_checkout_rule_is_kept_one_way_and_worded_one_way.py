# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rule for a file in another git checkout, kept in one direction and worded to its judgment.

Four places where the rule and what the code says about it drifted:

* ``honor_ignore_files: false`` widens the scan to the paths the repository's
  ignore files leave out (``node_modules/``, ``.venv/``, ``.env``), so a file in
  another checkout does not keep it, as it keeps a lowered archive limit and
  ``metrics: off``. The key is the operator's: ``--config-overrides`` or a file
  outside every checkout and the scanned directory sets it, and the warning names
  only the files that write it.
* the network limit a ``network_scanners`` list in such a file leaves is a private
  attribute of the sandbox settings, and each rebuild of those settings lost it.
  ``confine_to_trusted_base`` passed none on, and the operator's own sandbox
  section was rebuilt without it.
* the sentence for a file outside the trees named "the scanned tree" first, also
  on a load that has no scanned tree and so must never claim one.
* the closing clause of the plugin-module warning said "outside the tree" for a
  judgment that refuses a module installed in any checkout.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.restrictions_kept import keep_restrictions
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _loaded(document: dict) -> AshConfig:
    return AshConfig.model_validate(document)


# --- honor_ignore_files: false is not a restriction ---------------------------


def _warnings(caplog: pytest.LogCaptureFixture, start: str) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and record.getMessage().startswith(start)
    ]


def _resolve(route: str, monkeypatch: pytest.MonkeyPatch, file: Path, repository: Path):
    if route == "config":
        return resolve_config(config_path=file, source_dir=repository)
    monkeypatch.setenv("ASH_CONFIG", str(file))
    return resolve_config(source_dir=repository)


def _repository(tmp_path: Path, config: str = "project_name: repo\n") -> Path:
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    _write(repository / ".ash" / ".ash.yaml", config)
    return repository


def test_a_false_honor_ignore_files_in_the_source_is_not_kept() -> None:
    """False widens the scan to the paths the ignore files leave out, so unlike
    a lowered limit it is not a setting that only restricts."""
    base = _loaded({})

    keep_restrictions(base, _loaded({"honor_ignore_files": False}))

    assert base.honor_ignore_files is True


def test_a_true_or_unwritten_honor_ignore_files_changes_nothing() -> None:
    base = _loaded({})

    keep_restrictions(base, _loaded({"honor_ignore_files": True}))
    keep_restrictions(base, _loaded({}))

    assert base.honor_ignore_files is True
    already_off = _loaded({"honor_ignore_files": False})
    keep_restrictions(already_off, _loaded({"honor_ignore_files": True}))
    assert already_off.honor_ignore_files is False


def test_the_trusted_file_in_another_checkout_does_not_set_a_false_honor_ignore_files(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The file is the trusted config of a workspace, not part of the project's
    configuration, so its value is not applied: the configuration keeps the
    default. One warning names the trusted file for the key it wrote, and none
    blames the project's own file for a key it does not write."""
    repository = _repository(tmp_path)
    mark_git_checkout(tmp_path / "ops")
    trusted = _write(tmp_path / "ops" / "ash.yaml", "honor_ignore_files: false\n")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository, trusted_config_path=trusted)

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert "/ops/ash.yaml" in line, line
    assert ".ash.yaml" not in line, line
    assert KEEP_A_SETTING in line, line


def test_control_the_trusted_file_outside_every_checkout_sets_honor_ignore_files(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    trusted = _write(tmp_path / "plain" / "ash.yaml", "honor_ignore_files: false\n")

    config = resolve_config(source_dir=repository, trusted_config_path=trusted)

    assert config.honor_ignore_files is False


@pytest.mark.parametrize("route", ["config", "ash_config"])
def test_a_false_honor_ignore_files_in_a_file_in_another_checkout_is_ignored_with_a_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """Selected with ``--config``, or named by ASH_CONFIG when nothing is
    selected: the file is not the operator's, the key stays ``true``, and one
    warning names the file and says how to turn the key off."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    mark_git_checkout(tmp_path / "ops")
    file = _write(tmp_path / "ops" / "ash.yaml", "honor_ignore_files: false\n")

    with caplog.at_level(logging.WARNING):
        config = _resolve(route, monkeypatch, file, repository)

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert "/ops/ash.yaml" in line, line
    assert KEEP_A_SETTING in line, line
    assert "--no-honor-ignore-files" in line, line


@pytest.mark.parametrize("route", ["config", "ash_config"])
def test_an_override_still_turns_honor_ignore_files_off_past_a_file_in_another_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """``--no-honor-ignore-files`` reaches the scan as an override: it is the
    operator's whatever the file says, so nothing is ignored."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    mark_git_checkout(tmp_path / "ops")
    file = _write(tmp_path / "ops" / "ash.yaml", "honor_ignore_files: false\n")
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(file))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=file if route == "config" else None,
            source_dir=repository,
            config_overrides=["honor_ignore_files=false"],
        )

    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text


def test_the_warning_names_only_the_file_that_writes_the_key(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The project's config extends a base; only the base writes the key. The
    warning names the base, not the file that writes ``project_name``."""
    repository = _repository(tmp_path, "project_name: repo\nextends:\n  - lower.yaml\n")
    _write(repository / ".ash" / "lower.yaml", "honor_ignore_files: false\n")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository)

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert "lower.yaml" in line, line
    assert ".ash.yaml" not in line, line


def test_the_warning_blames_no_file_for_a_key_it_does_not_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The operator's ASH_CONFIG, outside every checkout, turns the key off; the
    project's own config, which replaces ASH_CONFIG, writes only its name. The
    operator's value applies, and no warning accuses the project's file of
    writing it (or suggests turning off what is already off)."""
    repository = _repository(tmp_path)
    operator = _write(tmp_path / "plain" / "ash.yaml", "honor_ignore_files: false\n")
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository)

    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text


def test_control_a_false_the_projects_own_file_writes_is_ignored_and_named(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repository = _repository(tmp_path, "honor_ignore_files: false\n")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository)

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert ".ash.yaml" in line, line


# --- the network limit survives the rebuilds ----------------------------------


def test_confine_to_trusted_base_passes_the_network_limit_on(tmp_path: Path) -> None:
    from automated_security_helper.config.resolve_config import confine_to_trusted_base

    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    config = AshConfig()
    trusted = AshConfig()
    trusted.sandbox.network_limit = ["semgrep"]

    confine_to_trusted_base(
        config, trusted, [], repository, [repository / ".ash" / ".ash.yaml"]
    )

    assert config.sandbox.network_limit == ["semgrep"]
    assert config.sandbox.network_scanners is None


def test_the_operators_own_sandbox_section_keeps_the_network_limit(
    tmp_path: Path,
) -> None:
    from automated_security_helper.config.resolve_config import _with_own_sandbox

    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator = _write(
        tmp_path / "plain" / "ash.yaml",
        "sandbox:\n  extra_read_paths:\n    - /opt/own\n",
    )
    trusted = AshConfig()
    trusted.sandbox.network_limit = ["semgrep"]
    documents = {operator.resolve(): {"sandbox": {"extra_read_paths": ["/opt/own"]}}}

    updated, _wrote_mode = _with_own_sandbox(
        trusted, operator, repository, [operator], [repository], {}, documents=documents
    )

    assert updated.sandbox.extra_read_paths == ["/opt/own"]
    assert updated.sandbox.network_limit == ["semgrep"]


# --- the sentence for a file outside the trees --------------------------------


def test_the_outside_sentence_claims_no_scanned_tree_on_a_load_without_one() -> None:
    from automated_security_helper.config.sandbox_grants import membership_clause

    given_root = membership_clause(
        checkout_membership=False, given_root=True, outside=True
    )
    rootless = membership_clause(checkout_membership=True, outside=True)

    for clause in (given_root, rootless):
        assert "scanned tree" not in clause, clause
        assert "git checkout" in clause, clause
        assert clause.endswith("an MCP client delivered it"), clause


def test_control_the_outside_sentence_on_a_load_with_a_scanned_tree() -> None:
    from automated_security_helper.config.sandbox_grants import membership_clause

    assert membership_clause(checkout_membership=False, outside=True) == (
        "the file is inside the scanned tree or a git checkout, or an MCP "
        "client delivered it"
    )


# --- the plugin-module warning's closing clause -------------------------------


def test_the_module_warning_closes_with_the_rule_the_judgment_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A scan of a tree refuses a module installed in the tree or in any other
    checkout (``refusal_reason``), so the clause says both."""
    from automated_security_helper.config import plugin_module_trust
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    monkeypatch.setattr(
        plugin_module_trust,
        "_spec_without_importing",
        lambda _prefix, _parent: object(),
    )
    monkeypatch.setattr(
        plugin_module_trust,
        "_spec_locations",
        lambda _spec: [repository / "mods" / "mod.py"],
    )
    config = AshConfig()
    # A name in the plugin namespace: one outside it is kept for the scan's
    # namespace refusal and never reaches this warning.
    config.ash_plugin_modules = ["their_ash_plugins"]

    with caplog.at_level(logging.WARNING):
        confine_plugin_modules(
            config,
            AshConfig(),
            [],
            repository,
            [tmp_path / "ops" / "ash.yaml"],
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
            outside_membership=True,
        )

    [line] = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert (
        "so only installed modules outside the scanned tree and every git "
        "checkout are imported from it"
    ) in line, line
    assert "outside the tree are imported" not in line, line
    assert config.ash_plugin_modules == []
