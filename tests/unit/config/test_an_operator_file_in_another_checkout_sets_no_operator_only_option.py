# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file in another git checkout, or one an MCP client delivered, leaves out the operator-only options too.

``resolve_config`` holds a chain file inside ANY git checkout, or one an MCP
client delivered, to the trusted base: its sandbox grants, its archive limits and
its tool settings come from the base (``_with_outside_files``). The options only
the operator sets (``scanners.detect-secrets.options.max_worker_output_mib``,
the Security Hub scope options) are read from the chain before anything is
validated, by the membership ``RepositorySettings`` holds. That membership was the
scanned trees alone, so the same file was the repository's for one memory bound
(the archive limit) and the operator's for another (the worker output limit), and
the reference the file wrote for the limit was dropped while its value stayed.

Every cell resolves the real chain. The limit is the probe: its default is 256,
the file writes 1024, and 4096 is the most any file may ask for. Each cell with a
file in another checkout or a delivered file has a control with the same text
outside every checkout and outside the MCP workspace root.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.config import client_config_policy
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError
from tests.utils.helpers import mark_git_checkout

OPTION = "scanners.detect-secrets.options.max_worker_output_mib"

#: The sentence a warning explains the drop of a file outside the scanned trees with.
OUTSIDE_SENTENCE = (
    "the file is inside the scanned tree or a git checkout, or an MCP client "
    "delivered it, so someone other than the operator may have written it"
)

DEFAULT_LIMIT = 256
FILE_LIMIT = 1024

#: Where the selected config comes from: ``--config``, or the file ASH_CONFIG
#: names when no config file is selected.
ROUTES = ["config", "ash_config"]


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    # A basetemp inside a checkout would put every file here inside it.
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


def _setting(limit: "int | str") -> str:
    return (
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        f"      max_worker_output_mib: {limit}\n"
    )


def _repository(tmp_path: Path, config: str = "") -> Path:
    """The scanned repository: a checkout, with a config of its own when given one."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    if config:
        _write(repository / ".ash" / ".ash.yaml", config)
    return repository


def _operator_file(tmp_path: Path, where: str, text: str) -> Path:
    """The file under test: in another checkout (``ops``), delivered under the MCP
    workspace root, or outside every checkout (``plain``)."""
    if where == "ops":
        mark_git_checkout(tmp_path / "ops")
        return _write(tmp_path / "ops" / "ash.yaml", text)
    if where == "delivered":
        return _write(
            tmp_path / "mcp-workspaces" / "session-1" / "source" / "ash.yaml", text
        )
    return _write(tmp_path / "plain" / "ash.yaml", text)


def _resolve(
    route: str, monkeypatch: pytest.MonkeyPatch, file: Path, repository: Path
) -> Any:
    if route == "config":
        return resolve_config(config_path=file, source_dir=repository)
    monkeypatch.setenv("ASH_CONFIG", str(file))
    return resolve_config(source_dir=repository)


def _limit(config: Any) -> int:
    return config.scanners.detect_secrets.options.max_worker_output_mib


def _about_the_limit(caplog: pytest.LogCaptureFixture) -> List[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and "max_worker_output_mib" in record.getMessage()
    ]


def _at_the_limit(reference: Any) -> bool:
    """Whether an environment reference sits at the limit's place, spelled as the
    confinement compares places."""
    path = (*reference.path, reference.resolved) if reference.key else reference.path
    shown = tuple(
        part.replace("-", "_").lower() if isinstance(part, str) else part
        for part in path
    )
    return shown[:4] == (
        "scanners",
        "detect_secrets",
        "options",
        "max_worker_output_mib",
    )


@pytest.mark.parametrize("route", ROUTES)
def test_a_file_in_another_checkout_does_not_raise_the_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    """The archive limit of the same file is capped; so is this one, and one
    warning names the option, the file and the remedy."""
    repository = _repository(tmp_path)
    file = _operator_file(tmp_path, "ops", _setting(FILE_LIMIT))

    with caplog.at_level(logging.WARNING):
        config = _resolve(route, monkeypatch, file, repository)

    assert _limit(config) == DEFAULT_LIMIT
    named = [m for m in _about_the_limit(caplog) if m.startswith(f"Ignoring {OPTION}")]
    assert named, caplog.text
    assert "/ops/ash.yaml" in named[0], named[0]
    assert OUTSIDE_SENTENCE in named[0], named[0]
    assert named[0].endswith(KEEP_A_SETTING), named[0]


@pytest.mark.parametrize("route", ROUTES)
def test_the_reference_goes_with_the_value_the_limit_takes_from_the_operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """The file writes the limit as ${VAR}. The limit is the operator's default,
    read from no variable, so the configuration's record of what its files read
    from the environment holds no reference at the limit: value and reference
    are left out together, never the reference alone."""
    monkeypatch.setenv("ASH_TEST_OPGRANT_LIMIT", "3071")
    repository = _repository(tmp_path)
    file = _operator_file(tmp_path, "ops", _setting("${ASH_TEST_OPGRANT_LIMIT}"))

    config = _resolve(route, monkeypatch, file, repository)

    assert _limit(config) == DEFAULT_LIMIT
    assert not [r for r in config._environment_references if _at_the_limit(r)]
    assert not [r for r in config._displayed_environment_references if _at_the_limit(r)]
    assert not [
        rewrite
        for rewrite in config._written_references or []
        if rewrite.kind == "value" and rewrite.resolved == "3071"
    ]


@pytest.mark.parametrize("route", ROUTES)
def test_control_a_file_outside_every_checkout_keeps_the_limit_it_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    repository = _repository(tmp_path)
    file = _operator_file(tmp_path, "plain", _setting(3071))

    config = _resolve(route, monkeypatch, file, repository)

    assert _limit(config) == 3071
    assert not [r for r in config._environment_references if _at_the_limit(r)]


@pytest.mark.parametrize("route", ROUTES)
def test_control_a_file_outside_every_checkout_cannot_write_the_typed_limit_as_a_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """The limit is an integer, and an integer cannot be shown by the variable
    it was read from (``utils/redacted_model.py``), for the operator's file as
    for any other: the model refuses the reference and names the variable. The
    file in another checkout never reaches that refusal, because the
    confinement removes the value and its reference before the model validates
    them (``test_the_reference_goes_with_the_value_the_limit_takes_from_the_operator``)."""
    monkeypatch.setenv("ASH_TEST_OPGRANT_LIMIT", "3071")
    repository = _repository(tmp_path)
    file = _operator_file(tmp_path, "plain", _setting("${ASH_TEST_OPGRANT_LIMIT}"))

    with pytest.raises(ASHConfigValidationError) as refusal:
        _resolve(route, monkeypatch, file, repository)

    assert "ASH_TEST_OPGRANT_LIMIT" in str(refusal.value), str(refusal.value)
    assert "Write the value in the file instead" in str(refusal.value)


@pytest.mark.parametrize("route", ROUTES)
def test_control_a_file_outside_every_checkout_sets_the_limit_without_a_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
) -> None:
    repository = _repository(tmp_path)
    file = _operator_file(tmp_path, "plain", _setting(FILE_LIMIT))

    with caplog.at_level(logging.WARNING):
        config = _resolve(route, monkeypatch, file, repository)

    assert _limit(config) == FILE_LIMIT
    assert not _about_the_limit(caplog), caplog.text


def test_control_the_trusted_file_in_another_checkout_gives_the_default(
    tmp_path: Path,
) -> None:
    """The workspace route already took the limit from the defaults: the file is
    not the trusted base, so the repository's config meets the default."""
    repository = _repository(tmp_path, "project_name: repo\n")
    file = _operator_file(tmp_path, "ops", _setting(FILE_LIMIT))

    config = resolve_config(source_dir=repository, trusted_config_path=file)

    assert _limit(config) == DEFAULT_LIMIT


def test_an_override_still_sets_the_limit_past_a_file_in_another_checkout(
    tmp_path: Path,
) -> None:
    """The operator's --config-overrides is the operator's whatever the file says."""
    repository = _repository(tmp_path)
    file = _operator_file(tmp_path, "ops", _setting(FILE_LIMIT))

    config = resolve_config(
        config_path=file, source_dir=repository, config_overrides=[f"{OPTION}=512"]
    )

    assert _limit(config) == 512


@pytest.mark.parametrize("route", ROUTES)
def test_a_delivered_file_does_not_set_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """The client-policy step is replaced by a pass-through, so what is measured
    is the operator-only step alone: it works from the RepositorySettings that
    read the chain, which knew trees and checkouts but not delivery."""
    monkeypatch.setattr(
        client_config_policy,
        "apply_client_config_rules",
        lambda config, *args, **kwargs: config,
    )
    repository = _repository(tmp_path)
    file = _operator_file(tmp_path, "delivered", _setting(FILE_LIMIT))

    config = _resolve(route, monkeypatch, file, repository)

    assert _limit(config) == DEFAULT_LIMIT


def test_a_repository_settings_that_read_a_delivered_file_record_what_it_wrote(
    tmp_path: Path,
) -> None:
    """The membership itself: a delivered file is the repository's for the
    options only the operator sets, with no tree and no checkout flag."""
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
    )

    delivered = _operator_file(tmp_path, "delivered", _setting(FILE_LIMIT))
    plain = _operator_file(tmp_path, "plain", _setting(FILE_LIMIT))
    settings = RepositorySettings([tmp_path / "repo"])

    assert settings.is_repository_file(delivered, delivered) is True
    assert settings.is_repository_file(plain, plain) is False
