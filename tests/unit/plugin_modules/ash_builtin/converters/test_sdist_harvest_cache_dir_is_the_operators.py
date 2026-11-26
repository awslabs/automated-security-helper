# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the operator chooses where the sdist harvest keeps its cache.

``scanners.syft.options.sdist_harvest.cache_dir`` says where verified harvests are
cached between runs. The operator sets it, with ``--config-overrides`` or in a config
file outside every git checkout and outside the scanned directory. A value a config
file inside the scanned repository writes is not used, wherever it points: the cache
falls back to the user-level default (``default_harvest_cache_root``).

These tests resolve real config files the way a scan does, then read the cache root
the harvester picks from the resolved configuration and the warning it logs when it
does not use the configured value.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    SdistLockHarvester,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sdist_harvest import (
    default_harvest_cache_root,
    harvest_options_of,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

KEY = "scanners.syft.options.sdist_harvest.cache_dir"


def _harvest_config(cache_dir: Path) -> str:
    """A config file's text that sets the harvest cache directory and nothing else."""
    return yaml.safe_dump(
        {
            "scanners": {
                "syft": {
                    "options": {"sdist_harvest": {"cache_dir": cache_dir.as_posix()}}
                }
            }
        }
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A git checkout to scan, with the user-level cache inside the test's directory.

    ``XDG_CACHE_HOME`` is pinned under ``tmp_path``, so the default cache root is a
    known directory that never touches the developer's own cache, and ``ASH_OFFLINE``
    is cleared so the environment cannot change what the harvester does.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    root = tmp_path / "repo"
    mark_git_checkout(root)
    return root


@pytest.fixture
def logged_warnings():
    """The messages of the warnings ASH logs while the test runs."""
    messages: list[str] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _cache_root(config, repo: Path, tmp_path: Path) -> Path | None:
    """The cache root the harvester picks for ``config`` when it scans ``repo``."""
    context = PluginContext(source_dir=repo, output_dir=tmp_path / "out", config=config)
    converter = SdistLockHarvester(context=context)
    return converter._cache_root(harvest_options_of(config)["cache_dir"])


def test_a_cache_dir_a_config_inside_the_scanned_tree_names_is_not_used(repo, tmp_path):
    """A cache directory the scanned repository's own config names is not used.

    The value reaches the resolved configuration, yet the cache root is the
    user-level default and not the directory the repository chose, which sits
    outside the repository and outside every git checkout.
    """
    elsewhere = tmp_path / "elsewhere-cache"
    (repo / ".ash.yaml").write_text(_harvest_config(elsewhere))

    config = resolve_config(source_dir=repo)

    assert Path(str(harvest_options_of(config)["cache_dir"])) == elsewhere, (
        "the repository's cache_dir reaches the resolved configuration"
    )
    root = _cache_root(config, repo, tmp_path)
    assert root == default_harvest_cache_root(), (
        "the cache falls back to the user-level default; the repository's value "
        "must not be used"
    )
    assert root is not None, "the user-level default cache root is available here"
    assert root.resolve() != elsewhere.resolve(), (
        "the repository's cache_dir must not be used as the cache root"
    )
    assert elsewhere.resolve() not in root.resolve().parents, (
        "the cache root must not sit under the directory the repository's "
        "cache_dir names"
    )


@pytest.mark.parametrize("how", ["override", "operator-file"])
def test_the_operators_cache_dir_is_used(how, repo, tmp_path):
    """The operator's own cache directory is the cache root.

    The operator sets it with ``--config-overrides`` (over a different value the
    repository's config writes) or in a config file outside every git checkout and
    the scanned directory.
    """
    operator_dir = tmp_path / "operator-cache"
    if how == "override":
        (repo / ".ash.yaml").write_text(_harvest_config(tmp_path / "elsewhere-cache"))
        config = resolve_config(
            source_dir=repo, config_overrides=[f"{KEY}={operator_dir.as_posix()}"]
        )
    else:
        operator_file = tmp_path / "operator.yaml"
        operator_file.write_text(_harvest_config(operator_dir))
        config = resolve_config(config_path=operator_file, source_dir=repo)

    assert _cache_root(config, repo, tmp_path) == operator_dir.resolve(), (
        "the operator's cache_dir is the cache root"
    )


def test_a_cache_dir_a_config_in_another_git_checkout_names_is_not_used(repo, tmp_path):
    """A cache directory a config file in another git checkout names is not used.

    The rule says outside every git checkout, so a config kept in a checkout of its
    own, beside the scanned one, does not choose the cache directory either; the
    operator passes such a value with ``--config-overrides``.
    """
    elsewhere = tmp_path / "elsewhere-cache"
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    (ops / "ash.yaml").write_text(_harvest_config(elsewhere))

    config = resolve_config(config_path=ops / "ash.yaml", source_dir=repo)

    assert Path(str(harvest_options_of(config)["cache_dir"])) == elsewhere, (
        "the config file's cache_dir reaches the resolved configuration"
    )
    assert _cache_root(config, repo, tmp_path) == default_harvest_cache_root(), (
        "the cache falls back to the user-level default; a value from a config "
        "file inside any git checkout must not be used"
    )


def test_the_refusal_names_the_option_and_not_its_value(
    repo, tmp_path, logged_warnings
):
    """The warning names the option and how to keep it, and never prints the value.

    The configured directory is the repository's own text, and it can be a value the
    config read from the environment, so it stays out of the log.
    """
    elsewhere = tmp_path / "elsewhere-cache"
    (repo / ".ash.yaml").write_text(_harvest_config(elsewhere))
    config = resolve_config(source_dir=repo)
    # What resolving the config logs is not under test; the harvester's warnings are.
    logged_warnings.clear()

    _cache_root(config, repo, tmp_path)

    naming_the_option = [message for message in logged_warnings if KEY in message]
    assert len(naming_the_option) == 1, f"warnings logged: {logged_warnings!r}"
    assert KEEP_A_SETTING in naming_the_option[0], (
        "the warning ends with how to keep the setting"
    )
    printing_the_value = [
        message
        for message in logged_warnings
        if elsewhere.as_posix() in message or str(elsewhere) in message
    ]
    assert not printing_the_value, "no warning prints the configured directory"
