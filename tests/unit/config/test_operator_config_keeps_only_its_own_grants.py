# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An operator config that extends a base keeps its own sandbox grants, not the base's.

The operator's ``--config`` sits outside the scanned tree and extends a base. When
the base is in a git checkout, the scanned one or any other, the base grants
nothing and a warning names it, while the sandbox settings the operator's file
writes itself still apply. Each file grants under its own key (the operator's
file ``sandbox.extra_read_paths``, the base ``sandbox.network_scanners``), so the
result shows whose grant survived.

The layouts are under a directory ``W`` that holds the scanned checkout ``W/repo``:

- the config in ``W``, extending ``repo/.ash/base.yaml``;
- the config in ``W/.ash``, extending ``../repo/.ash/base.yaml``;
- the config in ``W``, extending ``other/base.yaml``, where ``W/other`` is a
  checkout that is not scanned;
- the config in ``W``, extending ``base.yaml``, a link to ``repo/.ash/base.yaml``;
- the config in ``W/ops``, extending ``base.yaml``, a link to a file outside
  ``W/ops``. A chain may not leave the config's own directory, so resolving it
  fails.

The controls are a config with no ``extends``, which keeps its grant, and a config
inside the scanned tree, which keeps neither grant.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigSourceError
from automated_security_helper.utils.log import ASH_LOGGER

OWN_GRANT = "/opt/operator-own-grant"
BASE_SCANNER = "grype"
OPERATOR = f"sandbox:\n  extra_read_paths:\n    - {OWN_GRANT}\n"
BASE = f"project_name: base\nsandbox:\n  network_scanners:\n    - {BASE_SCANNER}\n"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")


def _scanned_checkout(w: Path) -> Path:
    repo = w / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    return repo


def _operator_config(shape: str, w: Path) -> Path:
    """The operator's config for one layout; W/repo is the scanned checkout."""
    repo = _scanned_checkout(w)
    if shape == "config-above-the-checkout":
        _write(repo / ".ash" / "base.yaml", BASE)
        return _write(
            w / "ash-config.yaml", "extends: repo/.ash/base.yaml\n" + OPERATOR
        )
    if shape == "config-in-a-dot-ash-beside-the-checkout":
        _write(repo / ".ash" / "base.yaml", BASE)
        return _write(
            w / ".ash" / "ash-config.yaml",
            "extends: ../repo/.ash/base.yaml\n" + OPERATOR,
        )
    if shape == "base-in-a-checkout-that-is-not-scanned":
        (w / "other" / ".git").mkdir(parents=True)
        _write(w / "other" / "base.yaml", BASE)
        return _write(w / "ash-config.yaml", "extends: other/base.yaml\n" + OPERATOR)
    if shape == "base-through-a-link-into-the-checkout":
        _symlink(w / "base.yaml", _write(repo / ".ash" / "base.yaml", BASE))
        return _write(w / "ash-config.yaml", "extends: base.yaml\n" + OPERATOR)
    if shape == "base-linked-out-of-the-configs-directory":
        elsewhere = w.parent / "elsewhere" / "repo2"
        (elsewhere / ".git").mkdir(parents=True)
        (w / "ops").mkdir()
        _symlink(w / "ops" / "base.yaml", _write(elsewhere / "base.yaml", BASE))
        return _write(w / "ops" / "ash-config.yaml", "extends: base.yaml\n" + OPERATOR)
    raise AssertionError(shape)


def _ignored_keys(message: str) -> set:
    """The settings a confinement warning names, from its "Ignoring ... from" clause."""
    return {
        key.strip() for key in message[len("Ignoring ") :].split(" from ")[0].split(",")
    }


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(" ".join(record.getMessage().split()))


@pytest.fixture
def sandbox_warnings():
    """The "Ignoring sandbox..." warnings ASH logs while a test resolves a config."""
    handler = _Collect()
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler.messages
    finally:
        ASH_LOGGER.removeHandler(handler)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    # ASH_CONFIG would add a file of its own to the resolution, and a basetemp
    # inside a checkout would put every layout inside that checkout too.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


def _dropped(messages: List[str]) -> List[str]:
    return [message for message in messages if message.startswith("Ignoring sandbox.")]


@pytest.mark.parametrize(
    "shape",
    [
        "config-above-the-checkout",
        "config-in-a-dot-ash-beside-the-checkout",
        "base-in-a-checkout-that-is-not-scanned",
        "base-through-a-link-into-the-checkout",
    ],
)
def test_the_operators_own_grant_is_kept_and_the_bases_is_dropped(
    shape, tmp_path, sandbox_warnings
):
    w = tmp_path / "W"
    config = _operator_config(shape, w)

    sandbox = resolve_config(config_path=config, source_dir=w / "repo").sandbox

    assert list(sandbox.extra_read_paths) == [OWN_GRANT]
    assert BASE_SCANNER not in (sandbox.network_scanners or [])
    dropped = _dropped(sandbox_warnings)
    assert dropped, "no warning names the base whose grant was dropped"
    for message in dropped:
        assert _ignored_keys(message) == {"sandbox.network_scanners"}, message
        assert "base.yaml" in message, message
        assert config.name not in message, message


def test_a_base_linked_out_of_the_configs_directory_is_refused(tmp_path):
    w = tmp_path / "W"
    config = _operator_config("base-linked-out-of-the-configs-directory", w)

    with pytest.raises(ASHConfigSourceError):
        resolve_config(config_path=config, source_dir=w / "repo")


def test_a_config_with_no_extends_keeps_its_grant(tmp_path, sandbox_warnings):
    """Control."""
    w = tmp_path / "W"
    _scanned_checkout(w)
    config = _write(w / "ash-config.yaml", OPERATOR)

    sandbox = resolve_config(config_path=config, source_dir=w / "repo").sandbox

    assert list(sandbox.extra_read_paths) == [OWN_GRANT]
    assert _dropped(sandbox_warnings) == []


def test_a_config_inside_the_scanned_tree_keeps_neither_grant(
    tmp_path, sandbox_warnings
):
    """Control."""
    w = tmp_path / "W"
    repo = _scanned_checkout(w)
    config = _write(
        repo / ".ash" / "ash-config.yaml",
        BASE + f"  extra_read_paths:\n    - {OWN_GRANT}\n",
    )

    sandbox = resolve_config(config_path=config, source_dir=repo).sandbox

    assert list(sandbox.extra_read_paths) == []
    assert BASE_SCANNER not in (sandbox.network_scanners or [])
    assert any(
        _ignored_keys(message)
        == {"sandbox.network_scanners", "sandbox.extra_read_paths"}
        for message in _dropped(sandbox_warnings)
    ), sandbox_warnings
