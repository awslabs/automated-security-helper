# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``honor_ignore_files`` is replaced only when a file that may not choose it wrote it.

``resolve_config`` takes the setting from the trusted base when a file inside a
git checkout, or one an MCP client delivered, set it differently
(``confine_honor_ignore_files``). The setting is the operator's, so the
replacement has to follow the file that wrote the value in force:

* a file outside every checkout that extends a base inside one keeps what it
  writes itself, as it keeps its own sandbox section;
* a value only a base in a checkout wrote is replaced, and the warning names that
  base;
* a value that came from the trusted base, because no file of the chain writes
  the key, is applied without a warning;
* a trusted chain in another checkout that is dropped whole is reported when its
  value differs from the one in force and from the trusted base's, even when the
  operator's own file decided the value in force, and the report names that file.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.resolve_config import resolve_config
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


def _warnings(caplog: pytest.LogCaptureFixture, start: str) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and record.getMessage().startswith(start)
    ]


def _operator_file_over_a_checkout_base(
    tmp_path: Path, base_text: str, operator_text: str
) -> Path:
    """An operator file outside every checkout whose base sits inside one."""
    mark_git_checkout(tmp_path / "ops")
    _write(tmp_path / "ops" / "base.yaml", base_text)
    return _write(
        tmp_path / "ash.yaml", "extends:\n  - ops/base.yaml\n" + operator_text
    )


def _resolve(
    route: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, operator: Path
):
    """The operator file selected with ``--config``, or named by ASH_CONFIG when
    the scanned repository has no config of its own."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    if route == "config":
        return resolve_config(config_path=operator, source_dir=repository)
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    return resolve_config(source_dir=repository)


ROUTES = ["config", "ash_config"]


@pytest.mark.parametrize("route", ROUTES)
def test_an_operator_file_outside_every_checkout_keeps_the_false_it_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The operator's own file turns the key off and extends a base in a
    checkout that does not write it: the value in force is the operator's, so it
    is kept and nothing is said."""
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: false\n"
    )

    with caplog.at_level(logging.WARNING):
        config = _resolve(route, monkeypatch, tmp_path, operator)

    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text


@pytest.mark.parametrize("route", ROUTES)
def test_the_operator_file_that_writes_the_key_last_wins_over_a_checkout_base_that_wrote_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """Both files write ``false``; the operator's file is the later one in the
    chain, so the value in force is its own, and the base is not blamed for it."""
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "honor_ignore_files: false\n", "honor_ignore_files: false\n"
    )

    with caplog.at_level(logging.WARNING):
        config = _resolve(route, monkeypatch, tmp_path, operator)

    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text


@pytest.mark.parametrize("route", ROUTES)
def test_control_a_false_only_the_checkout_base_wrote_is_replaced_and_names_the_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The operator's file writes nothing for the key, so the value in force is
    the base's: it is replaced by the trusted base's, and the warning names the
    base and not the operator's file."""
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "honor_ignore_files: false\n", "project_name: operator\n"
    )

    with caplog.at_level(logging.WARNING):
        config = _resolve(route, monkeypatch, tmp_path, operator)

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert "/ops/base.yaml" in line, line
    assert "/ash.yaml" not in line, line


# --- the client's overrides are a writer only when they set the key ----------


def _repository_with_a_config(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    _write(repository / ".ash" / ".ash.yaml", "project_name: repo\n")
    return repository


def test_unrelated_client_overrides_are_not_named_as_a_writer_of_the_key(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The session's trusted profile turns the key off, the client's file does
    not write it, and the client sends overrides for another setting. The value
    comes from the trusted profile, so no file or override is blamed for it and
    nobody is told to turn off what is already off."""
    repository = _repository_with_a_config(tmp_path)
    trusted = _write(tmp_path / "plain" / "ash.yaml", "honor_ignore_files: false\n")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=repository,
            trusted_config_path=trusted,
            config_overrides=["project_name=client"],
            client_overrides=True,
        )

    assert config.project_name == "client"
    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text


def test_control_a_client_override_of_the_key_is_replaced_and_named(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The client's overrides do set the key: the trusted value stays, and the
    warning names the overrides as the source."""
    repository = _repository_with_a_config(tmp_path)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=repository,
            config_overrides=["honor_ignore_files=false"],
            client_overrides=True,
        )

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert "config_overrides" in line, line


# --- a dropped ASH_CONFIG chain says so when the project has a config ----------


def test_a_false_in_an_ash_config_file_in_a_checkout_is_ignored_with_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The project has a config of its own, which replaces ASH_CONFIG's file, so
    ASH_CONFIG only supplies the trusted base. Its file sits in another checkout
    and turns the key off: the base does not take that, and one warning names
    the file and how to keep the setting."""
    repository = _repository_with_a_config(tmp_path)
    mark_git_checkout(tmp_path / "ops")
    file = _write(tmp_path / "ops" / "ash.yaml", "honor_ignore_files: false\n")
    monkeypatch.setenv("ASH_CONFIG", str(file))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository)

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert "/ops/ash.yaml" in line, line
    assert ".ash.yaml" not in line, line
    assert KEEP_A_SETTING in line, line
    assert "--no-honor-ignore-files" in line, line


def test_the_operator_file_that_extends_a_checkout_base_is_named_when_its_false_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """ASH_CONFIG names an operator file outside every checkout that extends a
    base inside one. The project's config replaces it, and the base puts the
    whole ASH_CONFIG chain under the rule, so the false the operator's file wrote
    is dropped too and the warning names that file."""
    repository = _repository_with_a_config(tmp_path)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: false\n"
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository)

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert "/ash.yaml" in line, line


def test_the_dropped_operator_file_is_not_put_under_the_membership_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The membership sentence is true of the base in the checkout and false of
    the operator's own file that wrote the key. It is said of the base, and the
    operator's file is named in a clause of its own."""
    repository = _repository_with_a_config(tmp_path)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: false\n"
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    with caplog.at_level(logging.WARNING):
        resolve_config(source_dir=repository)

    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    before, found, after = line.partition(
        "so someone other than the operator may have written it"
    )
    assert found, line
    subject = before.rsplit(": ", 1)[-1]
    assert "/ops/base.yaml" in subject, line
    assert "/ash.yaml" not in subject, line
    assert "/ash.yaml" in after, line


@pytest.mark.parametrize("route", ["ash_config", "trusted_config_path"])
def test_a_dropped_chain_is_not_said_to_be_replaced_by_a_value_the_scan_does_not_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The base drops a file in another checkout that turns the key off. The scan's
    config is the operator's own file outside every checkout, which extends a base
    in a checkout and turns the key off itself, so its value is kept: the scan runs
    with false. A warning that says the dropped file's false was replaced by true
    would be wrong, and the value in force is false, so nothing was left out."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: false\n"
    )
    mark_git_checkout(tmp_path / "other")
    dropped = _write(tmp_path / "other" / "ash.yaml", "honor_ignore_files: false\n")
    trusted = dropped if route == "trusted_config_path" else None
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(dropped))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator, source_dir=repository, trusted_config_path=trusted
        )

    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files from "), caplog.text
    assert "Using honor_ignore_files: true" not in caplog.text, caplog.text


@pytest.mark.parametrize("route", ["ash_config", "trusted_config_path"])
def test_a_dropped_chain_is_not_reported_when_the_operators_own_file_decided_the_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The scan's config is the operator's own file outside every checkout, which
    extends a base in a checkout and turns the key off itself, so its value is kept
    whatever the trusted base would give. The dropped file in another checkout
    turns the key on, which the trusted base would also give, so it lost to nothing
    and no warning is true: the key is already off, and moving that file out of a
    checkout would change nothing."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: false\n"
    )
    mark_git_checkout(tmp_path / "other")
    dropped = _write(tmp_path / "other" / "ash.yaml", "honor_ignore_files: true\n")
    trusted = dropped if route == "trusted_config_path" else None
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(dropped))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator, source_dir=repository, trusted_config_path=trusted
        )

    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files from "), caplog.text
    assert "Using honor_ignore_files: false" not in caplog.text, caplog.text


@pytest.mark.parametrize("route", ["ash_config", "trusted_config_path"])
def test_a_dropped_chain_that_the_trusted_base_does_not_agree_with_is_named_beside_the_operators_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The scan's config is the operator's own file outside every checkout, which
    extends a base in a checkout and writes ``true`` itself. The dropped file in
    another checkout writes ``false``, the trusted base gives ``true``, so the
    dropped file's value was left out and its report is true. The operator's
    file decides the value, so the warning names it as the source of the value in
    force beside the dropped file, which it also names."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: true\n"
    )
    mark_git_checkout(tmp_path / "other")
    dropped = _write(tmp_path / "other" / "ash.yaml", "honor_ignore_files: false\n")
    trusted = dropped if route == "trusted_config_path" else None
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(dropped))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator, source_dir=repository, trusted_config_path=trusted
        )

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    before, found, after = line.partition("Using honor_ignore_files: ")
    assert found, line
    assert dropped.as_posix() in before, line
    assert operator.as_posix() not in before, line
    assert after.startswith("true"), line
    assert operator.as_posix() in after, line


@pytest.mark.parametrize("route", ["ash_config", "trusted_config_path"])
def test_control_a_dropped_chain_that_writes_the_operators_value_says_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The operator's own file writes ``true`` and so does the dropped file in
    another checkout: nothing was left out, so nothing is said."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: true\n"
    )
    mark_git_checkout(tmp_path / "other")
    dropped = _write(tmp_path / "other" / "ash.yaml", "honor_ignore_files: true\n")
    trusted = dropped if route == "trusted_config_path" else None
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(dropped))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator, source_dir=repository, trusted_config_path=trusted
        )

    assert config.honor_ignore_files is True
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text


def test_control_an_override_turns_the_key_off_past_a_dropped_ash_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``--no-honor-ignore-files`` is the operator's whatever ASH_CONFIG's file
    says, so nothing was dropped and nothing is said."""
    repository = _repository_with_a_config(tmp_path)
    mark_git_checkout(tmp_path / "ops")
    file = _write(tmp_path / "ops" / "ash.yaml", "honor_ignore_files: false\n")
    monkeypatch.setenv("ASH_CONFIG", str(file))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=repository, config_overrides=["honor_ignore_files=false"]
        )

    assert config.honor_ignore_files is False
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text


def test_control_a_true_in_an_ash_config_file_in_a_checkout_drops_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The file writes the default, so there is no value to drop."""
    repository = _repository_with_a_config(tmp_path)
    mark_git_checkout(tmp_path / "ops")
    file = _write(tmp_path / "ops" / "ash.yaml", "honor_ignore_files: true\n")
    monkeypatch.setenv("ASH_CONFIG", str(file))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repository)

    assert config.honor_ignore_files is True
    assert not _warnings(caplog, "Ignoring honor_ignore_files"), caplog.text
