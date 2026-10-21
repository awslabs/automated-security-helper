# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A hand-written ``mode: off`` under ``sandbox`` loads.

YAML 1.1 (PyYAML) reads an unquoted ``off`` as the boolean False. The mode's
type refused it, and the message told the operator to write exactly what they
had written. Every other test in this directory writes its documents through
``yaml.safe_dump``, which quotes ``off``, so none of them wrote the spelling an
operator types. These cells write the YAML text by hand.

The decisions the cells pin: boolean False is the mode "off" (so ``no`` and
``false`` load as "off" too, being the same YAML 1.1 scalar), boolean True
names no mode and is refused with a hint to quote the value, and the
operator-owned-file walk reads a file's mode the same way the model does.
"""

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from tests.utils.helpers import mark_git_checkout

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)


def _write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _load(tmp_path, monkeypatch, route, mode_line):
    """Resolve a config file outside the scanned tree whose sandbox section is
    the hand-written *mode_line*, through --config or through ASH_CONFIG."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    config = _write_text(
        tmp_path / "plain" / "ash.yaml",
        f"project_name: handwritten\nsandbox:\n  mode: {mode_line}\n",
    )
    monkeypatch.chdir(src)
    if route == "config_file":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        return resolve_config(
            config_path=config,
            source_dir=src,
            trusted_config_path=config,
        )
    monkeypatch.setenv("ASH_CONFIG", str(config))
    return resolve_config(source_dir=src)


_ROUTES = ["config_file", "ash_config"]


@pytest.mark.parametrize("route", _ROUTES)
def test_an_unquoted_off_loads_as_off(tmp_path, monkeypatch, route):
    config = _load(tmp_path, monkeypatch, route, "off")
    assert config.sandbox.mode == "off"


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.parametrize("spelling", ["no", "false", "False"])
def test_the_other_yaml_false_spellings_load_as_off(
    tmp_path, monkeypatch, route, spelling
):
    """YAML 1.1 defines these as the same scalar as an unquoted ``off``."""
    config = _load(tmp_path, monkeypatch, route, spelling)
    assert config.sandbox.mode == "off"


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.parametrize("spelling", ["on", "true", "yes"])
def test_an_unquoted_true_is_refused_with_the_quoting_hint(
    tmp_path, monkeypatch, route, spelling
):
    with pytest.raises(_REFUSED) as refused:
        _load(tmp_path, monkeypatch, route, spelling)
    message = str(refused.value)
    assert "YAML boolean" in message and "in quotes" in message, message


@pytest.mark.parametrize("route", _ROUTES)
def test_control_a_quoted_off_still_loads(tmp_path, monkeypatch, route):
    config = _load(tmp_path, monkeypatch, route, '"off"')
    assert config.sandbox.mode == "off"


@pytest.mark.parametrize("route", _ROUTES)
def test_control_an_unquoted_bwrap_still_loads(tmp_path, monkeypatch, route):
    config = _load(tmp_path, monkeypatch, route, "bwrap")
    assert config.sandbox.mode == "bwrap"


def _chain(tmp_path, owned_mode_line):
    """An operator root whose own base writes *owned_mode_line* by hand and
    whose later base, in the scanned checkout, writes firejail."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    owned = _write_text(
        tmp_path / "plain" / "mode.yaml", f"sandbox:\n  mode: {owned_mode_line}\n"
    )
    lower = _write_text(src / "cfg" / "lower.yaml", "sandbox:\n  mode: firejail\n")
    root = _write_text(
        tmp_path / "ash-root.yaml",
        "project_name: handwritten\nextends:\n"
        f"- {owned.as_posix()}\n- {lower.as_posix()}\n",
    )
    return src, root


def _voices(tmp_path, monkeypatch, owned_mode_line):
    """The local scan's resolved mode and the container floor for the chain."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    src, root = _chain(tmp_path, owned_mode_line)
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    local = resolve_config(source_dir=src).sandbox.mode
    options = run_ash_scan.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
    )
    return local, run_ash_scan._sandbox_mode_without_the_config(options)


def test_an_owned_file_reads_an_unquoted_off_like_its_quoted_spelling(
    tmp_path, monkeypatch
):
    """The operator's own file writes off by hand and an in-tree file after it
    writes firejail. The owned-file walk must read the boolean the way the
    model does: the local scan and the container floor answer what they
    answer for the quoted spelling, neither refusing the load."""
    unquoted = _voices(tmp_path / "unquoted", monkeypatch, "off")
    quoted = _voices(tmp_path / "quoted", monkeypatch, '"off"')
    assert unquoted == quoted, (unquoted, quoted)


def test_an_owned_file_with_an_unquoted_true_is_refused_with_the_hint(
    tmp_path, monkeypatch
):
    with pytest.raises(_REFUSED) as refused:
        _voices(tmp_path, monkeypatch, "on")
    assert "in quotes" in str(refused.value), str(refused.value)
