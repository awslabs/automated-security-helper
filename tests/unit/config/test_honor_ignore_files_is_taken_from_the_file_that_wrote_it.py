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
  operator's own file decided the value in force, and the report names that file;
* that file is named as the selected chain names it, so a file an ``extends``
  entry chose with a value read from the environment is ``<value>``, never its
  path, whichever chain was dropped;
* when the operator's overrides set the key, the report says the override decides
  the value and names no file as the decider, since the file may have written
  the other value;
* a process that resolves the same config again says each ending of the report
  once for a file, so one ending does not keep the other from being said.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
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
    _write(repository / ".ash.yaml", "project_name: repo\n")
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


# --- the sentence that says who decided the value ----------------------------

#: The variable one ``extends`` entry reads the deciding base's directory from,
#: and that directory's name, which no other path in these cases holds.
DECIDER_VARIABLE = "ASH_TEST_HONOR_DECIDER_BASES"
DECIDER_DIRECTORY = "qzhonordecider4417"

#: How the trusted chain that is dropped whole reaches the load.
DROPPED_CHAIN_ROUTES = ["ash_config", "trusted_config_path"]


def _operator_file_with_a_deciding_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, from_environment: bool
) -> tuple[Path, Path]:
    """An operator file outside every checkout that extends a base inside one
    and, past it, a base outside every checkout that writes ``true``: the last
    file of the chain to write the key, so the one that decides the value.

    The deciding base is named by an ``extends`` entry that reads its directory
    from the environment, or by one that spells the path out. Returns the
    operator file and the deciding base."""
    mark_git_checkout(tmp_path / "ops")
    _write(tmp_path / "ops" / "base.yaml", "project_name: base\n")
    decider = _write(
        tmp_path / DECIDER_DIRECTORY / "decider.yaml", "honor_ignore_files: true\n"
    )
    if from_environment:
        monkeypatch.setenv(DECIDER_VARIABLE, DECIDER_DIRECTORY)
        entry = f"${{{DECIDER_VARIABLE}}}/decider.yaml"
    else:
        entry = f"{DECIDER_DIRECTORY}/decider.yaml"
    operator = _write(
        tmp_path / "ash.yaml", f"extends:\n  - ops/base.yaml\n  - {entry}\n"
    )
    return operator, decider


def _a_trusted_chain_the_base_drops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str, text: str
) -> tuple[Path, Path | None]:
    """A file in another checkout, which the trusted base leaves out whole: the
    file ASH_CONFIG names, or the trusted config. Returns the file and what to
    pass as ``trusted_config_path``."""
    mark_git_checkout(tmp_path / "other")
    dropped = _write(tmp_path / "other" / "ash.yaml", text)
    if route == "ash_config":
        monkeypatch.setenv("ASH_CONFIG", str(dropped))
        return dropped, None
    return dropped, dropped


def _the_sentence_after_the_value(line: str) -> str:
    """What the warning says from ``Using honor_ignore_files: `` on: the value in
    force, then its ending."""
    _, found, after = line.partition("Using honor_ignore_files: ")
    assert found, line
    return after


@pytest.mark.parametrize("route", DROPPED_CHAIN_ROUTES)
def test_a_deciding_file_an_environment_entry_chose_is_named_by_place(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The operator's file that decides the value is a base of the selected
    chain that an ``extends`` entry named with a value read from the
    environment, so its path IS that value. The warning for the dropped file
    names it ``<value>``, as every other warning names such a file, and its path
    is nowhere in the line. The dropped chain's own files hold no such base, so
    the set that knows the base is the selected chain's."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator, decider = _operator_file_with_a_deciding_base(
        tmp_path, monkeypatch, from_environment=True
    )
    dropped, trusted = _a_trusted_chain_the_base_drops(
        tmp_path, monkeypatch, route, "honor_ignore_files: false\n"
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator, source_dir=repository, trusted_config_path=trusted
        )

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    before, _, _ = line.partition("Using honor_ignore_files: ")
    assert dropped.resolve().as_posix() in before, line
    after = _the_sentence_after_the_value(line)
    assert after.startswith(
        f"true. {ENVIRONMENT_VALUE_SHOWN} is the operator's own file"
    ), line
    assert decider.resolve().as_posix() not in line, line
    assert DECIDER_DIRECTORY not in line, line


@pytest.mark.parametrize("route", DROPPED_CHAIN_ROUTES)
def test_control_a_deciding_file_a_plain_entry_named_keeps_its_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The same chain with the deciding base spelled out in its ``extends``
    entry: nothing chose it from the environment, so the warning names it by its
    path, as it always did."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator, decider = _operator_file_with_a_deciding_base(
        tmp_path, monkeypatch, from_environment=False
    )
    _, trusted = _a_trusted_chain_the_base_drops(
        tmp_path, monkeypatch, route, "honor_ignore_files: false\n"
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator, source_dir=repository, trusted_config_path=trusted
        )

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    after = _the_sentence_after_the_value(line)
    assert after.startswith(
        f"true. {decider.resolve().as_posix()} is the operator's own file"
    ), line
    assert ENVIRONMENT_VALUE_SHOWN not in line, line


def test_the_deciding_file_is_returned_as_the_chain_names_it(tmp_path: Path) -> None:
    """A chain can name the operator's file by a link. The answer to the warning
    is that name and not the file the link leads to, so the set of files the
    environment chose, which holds the names the chain gave them, still knows
    it: the file is shown ``<value>`` when that set holds it."""
    real = _write(tmp_path / "real" / "ash.yaml", "honor_ignore_files: true\n")
    link = tmp_path / "linked.yaml"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")
    inside = _write(tmp_path / "ops" / "base.yaml", "project_name: base\n")

    decided = resolve_config_module.confine_honor_ignore_files(
        AshConfig(honor_ignore_files=True),
        AshConfig(honor_ignore_files=True),
        None,
        [inside],
        documents={
            inside.resolve(): {"project_name": "base"},
            real.resolve(): {"honor_ignore_files": True},
        },
        chain=[inside, link],
        environment_paths={link},
    )

    assert decided is not None
    assert decided[0] == link, decided
    assert decided.shown == ENVIRONMENT_VALUE_SHOWN, decided


@pytest.mark.parametrize("route", DROPPED_CHAIN_ROUTES)
def test_an_override_of_the_key_is_the_decider_not_the_file_that_wrote_the_other_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The operator's own file writes ``true`` and ``--no-honor-ignore-files``
    (the override ``honor_ignore_files=false``) turns the key off, so the value in
    force is the override's. The dropped file writes ``true``. The warning says
    the override decides the value, and names no file as the decider: the
    operator's file wrote the other value."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: true\n"
    )
    _, trusted = _a_trusted_chain_the_base_drops(
        tmp_path, monkeypatch, route, "honor_ignore_files: true\n"
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator,
            source_dir=repository,
            trusted_config_path=trusted,
            config_overrides=["honor_ignore_files=false"],
        )

    assert config.honor_ignore_files is False
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    after = _the_sentence_after_the_value(line)
    assert after.startswith(
        "false. The operator's override sets honor_ignore_files, so it decides "
        "the value, and moving the dropped file out of a checkout would not "
        "change it."
    ), line
    assert operator.resolve().as_posix() not in after, line
    assert "is the operator's own file" not in line, line


@pytest.mark.parametrize("route", DROPPED_CHAIN_ROUTES)
def test_an_override_of_the_key_is_the_decider_when_no_file_wrote_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The project's own config writes nothing for the key and the operator turns
    it off with an override, while the dropped file writes ``true``. The value in
    force is the override's, so the warning does not tell the operator to turn it
    off with ``--no-honor-ignore-files``, which they did: it says the override
    decides and that moving the dropped file would not change it."""
    repository = _repository_with_a_config(tmp_path)
    _, trusted = _a_trusted_chain_the_base_drops(
        tmp_path, monkeypatch, route, "honor_ignore_files: true\n"
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=repository,
            trusted_config_path=trusted,
            config_overrides=["honor_ignore_files=false"],
        )

    assert config.honor_ignore_files is False
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    after = _the_sentence_after_the_value(line)
    assert after.startswith(
        "false. The operator's override sets honor_ignore_files, so it decides "
        "the value, and moving the dropped file out of a checkout would not "
        "change it."
    ), line
    assert KEEP_A_SETTING not in line, line


@pytest.mark.parametrize("route", DROPPED_CHAIN_ROUTES)
def test_control_an_override_of_another_setting_leaves_the_file_as_the_decider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The operator's overrides set another key, so the value of this one is the
    operator's file's, and the warning names that file as it always did."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    operator = _operator_file_over_a_checkout_base(
        tmp_path, "project_name: base\n", "honor_ignore_files: true\n"
    )
    _, trusted = _a_trusted_chain_the_base_drops(
        tmp_path, monkeypatch, route, "honor_ignore_files: false\n"
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator,
            source_dir=repository,
            trusted_config_path=trusted,
            config_overrides=["project_name=other"],
        )

    assert config.honor_ignore_files is True
    [line] = _warnings(caplog, "Ignoring honor_ignore_files from ")
    after = _the_sentence_after_the_value(line)
    assert after.startswith(
        f"true. {operator.resolve().as_posix()} is the operator's own file"
    ), line
    assert "The operator's override sets" not in after, line


def _decided_by_a_file(tmp_path: Path) -> resolve_config_module.HonorIgnoreFilesDecider:
    """What ``confine_honor_ignore_files`` answers when the operator's own file
    decides the value (the last file of the chain to write the key is not one of
    the confined files), as it hands it to the warning for a dropped chain."""
    inside = _write(tmp_path / "ops" / "base.yaml", "project_name: base\n")
    operator = _write(tmp_path / "ash.yaml", "honor_ignore_files: true\n")
    decided = resolve_config_module.confine_honor_ignore_files(
        AshConfig(honor_ignore_files=True),
        AshConfig(honor_ignore_files=True),
        None,
        [inside],
        documents={
            inside.resolve(): {"project_name": "base"},
            operator.resolve(): {"honor_ignore_files": True},
        },
        chain=[inside, operator],
    )
    assert decided is not None
    return decided


def _say_that_a_file_was_dropped(
    tmp_path: Path, decided: resolve_config_module.HonorIgnoreFilesDecider | None
) -> None:
    """The warning for a dropped chain whose one file writes ``false`` where the
    scan runs with ``true``; *decided* is what ``confine_honor_ignore_files``
    answered, or None when the operator decided nothing."""
    writer = _write(tmp_path / "other" / "ash.yaml", "honor_ignore_files: false\n")
    resolve_config_module._warn_dropped_honor_ignore_files(
        AshConfig(honor_ignore_files=False),
        [writer],
        [writer],
        {writer.resolve(): {"honor_ignore_files": False}},
        AshConfig(honor_ignore_files=True),
        [],
        frozenset(),
        given_root_membership=False,
        rootless_wording=False,
        decided_by_operator=decided,
    )


@pytest.mark.parametrize("first", ["a decider first", "no decider first"])
def test_each_ending_of_the_warning_for_a_dropped_file_is_said_once_in_a_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    first: str,
) -> None:
    """A long-lived process (the MCP server) resolves the same config again and
    again, and the warning for a file is said once. Its two endings are different
    sentences: one says the operator's own file decides the value, and nothing
    can be done about the dropped file, the other says how to keep the setting.
    Having said one must not keep the other from being said when a later
    resolution calls for it."""
    monkeypatch.setattr(
        resolve_config_module, "_DROPPED_OPERATOR_REPORTERS_WARNED", set()
    )
    decided = _decided_by_a_file(tmp_path)
    answers = [decided, None] if first == "a decider first" else [None, decided]

    with caplog.at_level(logging.WARNING, logger="ash"):
        for answer in answers:
            _say_that_a_file_was_dropped(tmp_path, answer)

    lines = _warnings(caplog, "Ignoring honor_ignore_files from ")
    assert len(lines) == 2, lines
    assert sum("so it decides the value" in line for line in lines) == 1, lines
    assert sum("--no-honor-ignore-files." in line for line in lines) == 1, lines


@pytest.mark.parametrize("answer", ["a decider", "no decider"])
def test_control_the_same_ending_for_the_same_file_is_still_said_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    answer: str,
) -> None:
    """Said again for the same file with the same ending, it stays said once."""
    monkeypatch.setattr(
        resolve_config_module, "_DROPPED_OPERATOR_REPORTERS_WARNED", set()
    )
    decided = _decided_by_a_file(tmp_path) if answer == "a decider" else None

    with caplog.at_level(logging.WARNING, logger="ash"):
        for _ in range(3):
            _say_that_a_file_was_dropped(tmp_path, decided)

    assert len(_warnings(caplog, "Ignoring honor_ignore_files from ")) == 1, caplog.text
