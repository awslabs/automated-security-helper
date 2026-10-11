# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ASH reads a config file: never blocking, never unbounded, never the defaults.

A config file is opened without blocking and read only when the opened file is
a regular file, up to ``ASH_CONFIG_MAX_FILE_BYTES``. So a FIFO or a device at a
config name, whether it was there when the name was checked or swapped in
afterwards, is refused at once rather than blocking the scan or reading until
memory runs out. Describing a config path for a message reads nothing from a
file that is not a regular file. A failure ASH did not foresee while resolving a
config is refused too, not answered with the defaults.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    describe_config_path,
    read_config_file,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)

needs_fifo = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX file type"
)
needs_dev_zero = pytest.mark.skipif(
    not os.path.exists("/dev/zero"), reason="needs a /dev/zero character device"
)


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _returns_promptly(call: Callable[[], object], fifo: Path) -> BaseException | None:
    """Run ``call`` in a thread; fail when it is still running after 10 seconds.

    A call blocked opening ``fifo`` for reading is released by opening its write
    end, so a failing test does not leave a thread behind. Returns what ``call``
    raised, or None.
    """
    outcome: dict = {}

    def _run() -> None:
        try:
            outcome["value"] = call()
        except BaseException as exc:  # recorded for the assertion below
            outcome["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(10)
    blocked = thread.is_alive()
    if blocked:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        thread.join(10)
    assert not blocked, f"reading {fifo.name} blocked"
    return outcome.get("error")


class TestSpecialFilesAreNotRead:
    @needs_fifo
    def test_a_fifo_named_pyproject_toml_given_as_the_config_is_refused_at_once(
        self, tmp_path
    ):
        fifo = tmp_path / "pyproject.toml"
        os.mkfifo(fifo)

        error = _returns_promptly(
            lambda: resolve_config(config_path=fifo, source_dir=tmp_path), fifo
        )

        assert isinstance(error, ASHConfigSourceError), error
        assert "not a regular file" in str(error)

    @needs_fifo
    def test_describing_a_fifo_named_pyproject_toml_reads_nothing(self, tmp_path):
        fifo = tmp_path / "pyproject.toml"
        os.mkfifo(fifo)

        assert _returns_promptly(lambda: describe_config_path(fifo), fifo) is None

    @needs_fifo
    @pytest.mark.parametrize("name", ["cfg.yaml", "cfg.json", "cfg.toml"])
    def test_a_fifo_reached_after_the_regular_file_check_is_not_read(
        self, tmp_path, name
    ):
        """read_config_file is what runs after a caller checked the name."""
        fifo = tmp_path / name
        os.mkfifo(fifo)

        error = _returns_promptly(lambda: read_config_file(fifo), fifo)

        assert isinstance(error, OSError), error
        assert "not a regular file" in str(error)

    @needs_dev_zero
    @pytest.mark.parametrize("name", ["cfg.json", "cfg.yaml", "pyproject.toml"])
    def test_a_link_to_a_device_is_not_read(self, tmp_path, monkeypatch, name):
        """Refused by the file type. The bound is lowered so that, should the type
        check go, the read still stops at 1 MiB and this fails on the size
        instead of reading /dev/zero until memory runs out."""
        monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 1 << 20)
        link = tmp_path / name
        link.symlink_to("/dev/zero")

        with pytest.raises(OSError, match="not a regular file"):
            read_config_file(link)

    def test_a_file_larger_than_the_bound_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 64)
        big = tmp_path / ".ash.yaml"
        big.write_text("project_name: x\n" + "# padding\n" * 20, encoding="utf-8")

        with pytest.raises(ASHConfigSourceError, match="larger than 64 bytes"):
            resolve_config(source_dir=tmp_path)

    def test_control_a_file_at_the_bound_is_read(self, tmp_path, monkeypatch):
        content = "project_name: x\n"
        monkeypatch.setattr(
            config_sources, "ASH_CONFIG_MAX_FILE_BYTES", len(content.encode())
        )
        (tmp_path / ".ash.yaml").write_text(content, encoding="utf-8")

        assert resolve_config(source_dir=tmp_path).project_name == "x"

    def test_a_yaml_syntax_error_still_names_the_file_and_line(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: x\nscanners: [bandit\n", encoding="utf-8")

        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(config_path=path, source_dir=tmp_path)

        assert f'in "{path}", line 2' in str(excinfo.value)


class TestEncodings:
    def test_a_json_config_with_a_utf8_byte_order_mark_is_read(self, tmp_path):
        """As YAML and TOML already are; Windows PowerShell 5 writes the mark."""
        (tmp_path / ".ash.json").write_bytes(
            b'\xef\xbb\xbf{"project_name": "with-bom"}'
        )

        assert resolve_config(source_dir=tmp_path).project_name == "with-bom"

    def test_control_a_yaml_config_with_a_byte_order_mark_is_read(self, tmp_path):
        (tmp_path / ".ash.yaml").write_bytes(b"\xef\xbb\xbfproject_name: with-bom\n")

        assert resolve_config(source_dir=tmp_path).project_name == "with-bom"


class TestMessages:
    def test_a_symbolic_link_to_itself_is_reported_as_a_loop(self, tmp_path):
        link = tmp_path / ".ash.yaml"
        link.symlink_to(link)

        with pytest.raises(ASHConfigSourceError, match="leads back to itself"):
            resolve_config(source_dir=tmp_path)

    def test_an_ash_config_variable_of_only_whitespace_is_named_as_such(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_CONFIG", "  ")

        with pytest.raises(ASHConfigSourceError, match="only whitespace"):
            resolve_config(source_dir=tmp_path)


class TestUnforeseenFailuresAreRefused:
    """resolve_config's catch-all refuses rather than returning the defaults.

    A flow sequence nested 50,000 deep is a config file a YAML parser gives up on
    with RecursionError, which is not a YAML error, so it reaches the catch-all.
    """

    DEEP = "project_name: x\nscanners: " + "[" * 50_000 + "\n"

    def test_a_discovered_file_is_refused(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(self.DEEP, encoding="utf-8")

        with pytest.raises(ASHConfigValidationError, match="RecursionError"):
            resolve_config(source_dir=tmp_path)

    def test_a_named_file_is_refused(self, tmp_path):
        path = tmp_path / "deep.yaml"
        path.write_text(self.DEEP, encoding="utf-8")

        with pytest.raises(ASHConfigValidationError, match="RecursionError"):
            resolve_config(config_path=path, source_dir=tmp_path)
