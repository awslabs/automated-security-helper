# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode hands the inner scan a config it can read, or refuses.

The container mounts the source directory at /src and the output directory at
/out. The ``--config`` file (which, on the CLI path, typer fills from
ASH_CONFIG) is handed over by ``run_ash_container``: a file inside the source
directory is read through /src, and one outside it is mounted read-only, so
the scan inside loads the operator's file instead of refusing the run as a
missing named config only after the image was built (the warn-and-default
fallback for a missing named file remains only for direct resolve_config
callers that allow it; the scan entrypoints refuse first).

``run_ash_scan`` forwards the host path and refuses, with exit 3 and before
the runner, only what cannot be handed over at all: a ``--config`` (or
ASH_CONFIG) that names no existing file -- which a mount cannot carry -- and a
path inside the scanned tree that is a link to a file outside it, which ASH
does not mount because the repository being scanned chose the target. These
cells pin that seam; the mounts and the container paths themselves are pinned
at the assembled-command seam, in run_ash_container's own tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils.inner_run_outcome import completion_marker

pytestmark = pytest.mark.unit

CONFIG_TEXT = "project_name: operator-config\n"


def _make_opts(tmp_path, **update):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    opts = ScanOptions(source_dir=src, output_dir=out, mode=RunMode.container)
    return opts.model_copy(update=update) if update else opts


def _refused(opts, capsys):
    from automated_security_helper.interactions.run_ash_scan import (
        _run_container_mode,
    )

    runner = MagicMock()
    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        runner,
    ):
        with pytest.raises(SystemExit) as refused:
            _run_container_mode(opts, MagicMock())

    assert refused.value.code == 3
    assert runner.call_count == 0, "the runner was started for a refused config"
    return capsys.readouterr().err


def _ran(opts):
    """Run container mode with a stand-in runner; return its keyword args."""
    from automated_security_helper.interactions.run_ash_scan import (
        _run_container_mode,
    )

    results_file = Path(opts.output_dir) / "ash_aggregated_results.json"
    seen = {}

    def fake_run_ash_container(**kwargs):
        seen.update(kwargs)
        # With the record that the run with the host's ID completed, as the scan
        # inside writes it (utils/inner_run_outcome.py): the host reads the file
        # back only when it holds that record.
        document = {
            "sarif": None,
            "scanners": [],
            "validation_checkpoints": [completion_marker(kwargs["outer_run_id"])],
        }
        results_file.write_text(json.dumps(document), encoding="utf-8")
        done = MagicMock()
        done.returncode = 0
        return done

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            fake_run_ash_container,
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan._compute_exit_code",
            return_value=0,
        ),
    ):
        _run_container_mode(opts, MagicMock())
    return seen


def test_an_ash_config_outside_the_source_dir_is_carried_to_the_runner(
    tmp_path, monkeypatch
):
    """The file ASH_CONFIG names sits outside the source directory. The runner
    mounts it read-only for the scan inside, so the handoff carries the host
    path to run_ash_container as it is -- honored, never refused for being
    outside the mounts and never silently dropped."""
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(CONFIG_TEXT, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))
    opts = _make_opts(tmp_path, config=str(config))

    seen = _ran(opts)

    assert seen.get("config") == str(config), seen.get("config")


def test_a_config_option_outside_the_source_dir_is_carried_the_same_way(
    tmp_path, monkeypatch
):
    """The same carry for a path given with --config and no ASH_CONFIG: the
    option's file is the runner's to mount, whichever input named it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(CONFIG_TEXT, encoding="utf-8")
    opts = _make_opts(tmp_path, config=str(config))

    seen = _ran(opts)

    assert seen.get("config") == str(config), seen.get("config")


def test_an_in_source_config_is_carried_as_the_host_path(tmp_path, monkeypatch):
    """A config inside the source directory is a file the container reads
    through /src. The handoff still carries the host path: run_ash_container
    translates it to its /src form when it assembles the run command, so one
    seam owns the translation for every caller."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _make_opts(tmp_path)
    config = Path(opts.source_dir) / "cfg" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(CONFIG_TEXT, encoding="utf-8")
    opts = opts.model_copy(update={"config": str(config)})

    seen = _ran(opts)

    assert seen.get("config") == str(config), seen.get("config")


def test_a_missing_config_path_refuses_before_the_runner(tmp_path, monkeypatch, capsys):
    """A --config path that names no existing file is refused with exit 3
    before any runner or image build: container mode mounts the file read-only
    for the scan inside, and a path with no file gives it nothing to mount.
    The refusal says the file was not found and names both inputs that can
    carry one, so the operator knows which to change."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _make_opts(tmp_path)
    missing = tmp_path / "ops" / "never-written.yaml"
    opts = opts.model_copy(update={"config": str(missing)})

    message = _refused(opts, capsys)

    assert "Config file not found" in message, message
    assert "--config" in message, message
    assert "ASH_CONFIG" in message, message


def test_an_in_source_symlink_to_an_outside_file_refuses(tmp_path, monkeypatch, capsys):
    """A config whose path sits inside the source directory but which is a
    symbolic link to a file outside it: mounting the target would hand the
    scan a file the repository being scanned points it at, so the run is
    refused with exit 3 before the runner, naming the link and the rule."""
    import os as _os

    if _os.name == "nt":
        pytest.skip("needs POSIX symlinks")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    outside = tmp_path / "ops" / "ash.yaml"
    outside.parent.mkdir()
    outside.write_text(CONFIG_TEXT, encoding="utf-8")
    opts = _make_opts(tmp_path)
    link = Path(opts.source_dir) / "linked.yaml"
    link.symlink_to(outside)
    opts = opts.model_copy(update={"config": str(link)})

    message = _refused(opts, capsys)

    assert "is inside the scanned tree but is a link" in message, message
    assert str(link) in message, message
    assert "does not mount a file the repository being scanned points it at" in (
        message
    ), message
