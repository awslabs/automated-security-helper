# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode's marks carry the host's checkout verdict into the scan inside.

The host finds the ``--config`` it mounts read-only into the container, so only
the host knows whether that file sits in a git checkout. The mounted copy sits
in no checkout inside the container, so without a carried verdict the scan
inside would grant a repository-written config what ASH refuses it on the host.
The carry is a pair of marks (``sandbox_grants.marked_repository_written``,
``marked_files_repository_written``) set by three hidden ``ash scan`` options
that only container mode passes. The grants side is read by ``in_a_checkout``
and ``files_inside``, the membership judgments every repository-written rule
goes through (resolve_config's ``in_tree`` and its any-checkout extension).

The CLI cells pin the option contract: the marks are a usage error with exit 3
outside local mode and without a config to mark, a marked file must belong to
the chain of ``--config`` or of the file ASH_CONFIG names, and
``--ash-config-from-host`` is read as ASH_CONFIG for the whole command, after
click has parsed ``--config`` (whose environment variable ASH_CONFIG is), so it
is the base the scan reads and never the ``--config``.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.sandbox_grants import (
    files_inside,
    in_a_checkout,
    marked_files_repository_written,
    marked_repository_written,
)


def test_a_marked_config_counts_as_in_a_checkout(tmp_path):
    """The mark is the host's checkout verdict: it holds wherever the file is,
    and it ends with the block, so one scan's mark cannot outlive it."""
    config = tmp_path / "cfg.yaml"
    config.write_text("{}\n", encoding="utf-8")
    assert not in_a_checkout(config)
    with marked_repository_written(config):
        assert in_a_checkout(config)
    assert not in_a_checkout(config)


def test_a_chain_marked_root_pulls_its_whole_chain_inside(tmp_path):
    """--config-from-scanned-repository marks the root and every file it
    extends: the whole chain is judged repository-written, as the host's
    membership rules judge a chain rooted inside a tree."""
    root = tmp_path / "cfg.yaml"
    base = tmp_path / "base.yaml"
    for path in (root, base):
        path.write_text("{}\n", encoding="utf-8")
    assert files_inside([root, base], [], named=[base]) == []
    with marked_repository_written(root):
        inside = files_inside([root, base], [], named=[base])
    assert inside == [root, base], inside
    assert files_inside([root, base], [], named=[base]) == []


def test_a_file_marked_on_its_own_joins_without_its_chain(tmp_path):
    """--config-file-from-scanned-repository marks one chain member: a root
    outside every checkout keeps the settings it writes itself, as on the
    host, and only the marked base grants nothing."""
    root = tmp_path / "cfg.yaml"
    base = tmp_path / "base.yaml"
    for path in (root, base):
        path.write_text("{}\n", encoding="utf-8")
    with marked_files_repository_written([base]):
        inside = files_inside([root, base], [], named=[base])
        assert inside == [base], inside
        assert in_a_checkout(base)
        assert not in_a_checkout(root)


def _scan(args: list[str], tmp_path: Path) -> "CliRunner.Result":
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    return CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            *args,
        ],
    )


def test_the_marks_are_refused_outside_local_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    result = _scan(
        ["--mode", "container", "--config-from-scanned-repository"], tmp_path
    )
    assert result.exit_code == 3, result.output
    assert "apply only to a scan in local mode" in result.output, result.output


def test_a_mark_with_no_config_to_mark_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    result = _scan(["--config-from-scanned-repository"], tmp_path)
    assert result.exit_code == 3, result.output
    assert "this scan has none" in result.output, result.output


def test_a_marked_file_outside_both_chains_is_refused(tmp_path, monkeypatch):
    """A name that misses the chain of --config and of the file ASH_CONFIG
    names would leave that file's grants in place unnoticed."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "cfg.yaml"
    config.write_text("{}\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere.yaml"
    elsewhere.write_text("{}\n", encoding="utf-8")
    result = _scan(
        [
            "--config",
            str(config),
            "--config-file-from-scanned-repository",
            str(elsewhere),
        ],
        tmp_path,
    )
    assert result.exit_code == 3, result.output
    assert "not a file of the chain" in result.output, result.output


def test_ash_config_from_host_is_read_as_ash_config(tmp_path, monkeypatch):
    """The option's value lands as ASH_CONFIG for the command: a directory
    there is refused in ASH_CONFIG's own words, which only the base-config
    reader speaks. Set as --config instead -- the mistake the hidden option
    exists to avoid, since --config's environment variable is ASH_CONFIG --
    the refusal would be --config's."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    named = tmp_path / "config-directory"
    named.mkdir()
    result = _scan(["--ash-config-from-host", str(named)], tmp_path)
    assert result.exit_code == 3, result.output
    assert "ASH_CONFIG names it, and it is not a file" in result.output, result.output
