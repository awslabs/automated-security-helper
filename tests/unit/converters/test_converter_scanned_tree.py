# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Converters read only files that are really inside the scanned tree.

The archive and Jupyter converters copy what they read, or what they derive from it,
into ``output_dir/converted``. These tests put converter inputs in the tree as symlinks
to files in a separate "host" directory holding a marker string, and check that:

- the marker never reaches the converter's output,
- each refused input is named in one warning,
- each refused input is recorded on the converter, for its results row,
- archive members that are links, or whose names leave the destination, are refused,
- a regular in-tree input still converts as before.

``tests/unit/interactions/test_scan_does_not_follow_tree_symlinks.py`` runs the same
shapes through a whole ``ashx scan``.
"""

from __future__ import annotations

import io
import json
import logging
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
)

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)
JUPYTER_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter"
)

MARKER = "HOST-ONLY-CONTENT-3b9d"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture
def ash_warnings():
    """Every WARNING the 'ash' logger emits during the test.

    ASH_LOGGER does not propagate, so caplog never sees it; a handler is attached
    directly instead.
    """
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def warnings_text(records) -> list[str]:
    return [r.getMessage() for r in records if r.levelno == logging.WARNING]


@pytest.fixture
def tree(test_plugin_context):
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    return source


@pytest.fixture
def host(tmp_path):
    directory = tmp_path / "host"
    directory.mkdir()
    return directory


def output_contains_marker(context) -> list[str]:
    """Files ASH wrote that hold the marker, and any link it wrote.

    A link is reported whatever it points at: something that later copies the output
    directory, such as an artifact upload, would follow it.
    """
    hits = []
    for root in (Path(context.output_dir), Path(context.work_dir)):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_symlink():
                hits.append(f"link: {path}")
            elif path.is_file() and MARKER.encode() in path.read_bytes():
                hits.append(str(path))
    return hits


def refused(converter) -> list:
    """The converter's recorded refusals, or a sentinel where it records none."""
    return list(getattr(converter, "refused_inputs", ["<no refused_inputs field>"]))


def make_zip(path: Path, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return path


def make_tar(path: Path, members: dict[str, str]) -> Path:
    with tarfile.open(path, "w") as archive:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def notebook_json(code: str) -> str:
    return json.dumps(
        {
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": None,
                    "outputs": [],
                    "source": [code],
                }
            ],
            "metadata": {"language_info": {"name": "python"}},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
    )


def archive_converter(context, monkeypatch, scan_set_paths):
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(p) for p in scan_set_paths]
    )
    return ArchiveConverter(context=context, config=ArchiveConverterConfig())


class TestArchiveInputs:
    @pytest.mark.parametrize("kind", ["zip", "tar"])
    def test_a_symlinked_archive_is_refused_warned_and_recorded(
        self, kind, tree, host, test_plugin_context, monkeypatch, ash_warnings
    ):
        maker = make_zip if kind == "zip" else make_tar
        maker(host / f"a.{kind}", {"inner.py": f"X = '{MARKER}'\n"})
        link = tree / f"a.{kind}"
        link.symlink_to(host / f"a.{kind}")
        converter = archive_converter(test_plugin_context, monkeypatch, [link])

        results = converter.convert()

        assert results == []
        assert output_contains_marker(test_plugin_context) == []
        assert warnings_text(ash_warnings) == [
            f"Skipped converter input 'a.{kind}': it is a symbolic link"
        ]
        assert [r.model_dump() for r in refused(converter)] == [
            {"path": f"a.{kind}", "member": None, "reason": "it is a symbolic link"}
        ]

    def test_an_archive_under_a_symlinked_directory_is_refused(
        self, tree, host, test_plugin_context, monkeypatch, ash_warnings
    ):
        (host / "dir").mkdir()
        make_zip(host / "dir" / "a.zip", {"inner.py": f"X = '{MARKER}'\n"})
        (tree / "linked").symlink_to(host / "dir", target_is_directory=True)
        converter = archive_converter(
            test_plugin_context, monkeypatch, [tree / "linked" / "a.zip"]
        )

        assert converter.convert() == []
        assert output_contains_marker(test_plugin_context) == []
        assert refused(converter)[0].reason == (
            "its parent directory 'linked' is a symbolic link"
        )

    def test_an_archive_outside_the_tree_is_refused(
        self, tree, host, test_plugin_context, monkeypatch
    ):
        """A scan set that names a path outside the root is not trusted either."""
        make_zip(host / "a.zip", {"inner.py": f"X = '{MARKER}'\n"})
        converter = archive_converter(
            test_plugin_context, monkeypatch, [host / "a.zip"]
        )

        assert converter.convert() == []
        assert output_contains_marker(test_plugin_context) == []
        assert refused(converter)[0].reason == "it is outside the scanned tree"

    @pytest.mark.parametrize("kind", ["zip", "tar"])
    def test_a_regular_archive_beside_a_symlinked_one_still_extracts(
        self, kind, tree, host, test_plugin_context, monkeypatch, ash_warnings
    ):
        """The positive control: the in-tree archive extracts byte for byte."""
        maker = make_zip if kind == "zip" else make_tar
        archive = maker(
            tree / f"ok.{kind}",
            {"ok.py": "print('in tree')\n", "pkg/mod.py": "VALUE = 1\n"},
        )
        maker(host / f"a.{kind}", {"inner.py": f"X = '{MARKER}'\n"})
        (tree / f"a.{kind}").symlink_to(host / f"a.{kind}")
        converter = archive_converter(
            test_plugin_context, monkeypatch, [archive, tree / f"a.{kind}"]
        )

        (extracted,) = converter.convert()

        assert (extracted / "ok.py").read_text() == "print('in tree')\n"
        assert (extracted / "pkg" / "mod.py").read_text() == "VALUE = 1\n"
        assert sorted(p.name for p in extracted.rglob("*") if p.is_file()) == [
            "mod.py",
            "ok.py",
        ]
        assert output_contains_marker(test_plugin_context) == []
        assert [r.path for r in refused(converter)] == [f"a.{kind}"]
        assert len(warnings_text(ash_warnings)) == 1


class TestArchiveMembers:
    def _zip_with(self, path: Path, *infos: tuple[zipfile.ZipInfo, str]) -> Path:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("ok.py", "print('kept')\n")
            for info, text in infos:
                archive.writestr(info, text)
        return path

    def _tar_with(self, path: Path, *infos: tarfile.TarInfo) -> Path:
        with tarfile.open(path, "w") as archive:
            data = b"print('kept')\n"
            info = tarfile.TarInfo("ok.py")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            for member in infos:
                if member.isreg():
                    payload = f"Y = '{MARKER}'\n".encode()
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                else:
                    archive.addfile(member)
        return path

    def _convert(self, archive, context, monkeypatch):
        converter = archive_converter(context, monkeypatch, [archive])
        (extracted,) = converter.convert()
        assert (extracted / "ok.py").read_text() == "print('kept')\n"
        return converter, extracted

    def test_a_zip_symlink_member_is_refused(
        self, tree, host, test_plugin_context, monkeypatch, ash_warnings
    ):
        (host / "secret.py").write_text(f"Z = '{MARKER}'\n")
        info = zipfile.ZipInfo("link.py")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive = self._zip_with(tree / "a.zip", (info, str(host / "secret.py")))

        converter, extracted = self._convert(archive, test_plugin_context, monkeypatch)

        assert not (extracted / "link.py").exists()
        assert [r.model_dump() for r in refused(converter)] == [
            {
                "path": "a.zip",
                "member": "link.py",
                "reason": "it is a symbolic or hard link",
            }
        ]
        assert warnings_text(ash_warnings) == [
            "Skipped member 'link.py' of archive 'a.zip': it is a symbolic or hard link"
        ]

    @pytest.mark.parametrize(
        "name, reason",
        [
            ("../escape.py", "its path contains a '..' component"),
            ("sub/../../escape.py", "its path contains a '..' component"),
            ("..\\escape.py", "its path contains a '..' component"),
            ("/abs/escape.py", "its path is absolute"),
            ("C:/abs/escape.py", "its path is absolute"),
        ],
    )
    def test_a_zip_member_whose_name_leaves_the_destination_is_refused(
        self, name, reason, tree, test_plugin_context, monkeypatch
    ):
        archive = self._zip_with(
            tree / "a.zip", (zipfile.ZipInfo(name), f"Y = '{MARKER}'\n")
        )

        converter, extracted = self._convert(archive, test_plugin_context, monkeypatch)

        assert output_contains_marker(test_plugin_context) == []
        assert not (tree.parent / "escape.py").exists()
        assert [(r.member, r.reason) for r in refused(converter)] == [(name, reason)]

    def test_tar_link_members_are_refused(
        self, tree, host, test_plugin_context, monkeypatch, ash_warnings
    ):
        (host / "secret.py").write_text(f"Z = '{MARKER}'\n")
        symlink = tarfile.TarInfo("link.py")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = str(host / "secret.py")
        hardlink = tarfile.TarInfo("hard.py")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "ok.py"
        archive = self._tar_with(tree / "a.tar", symlink, hardlink)

        converter, extracted = self._convert(archive, test_plugin_context, monkeypatch)

        assert not (extracted / "link.py").exists()
        assert not (extracted / "hard.py").exists()
        assert [(r.member, r.reason) for r in refused(converter)] == [
            ("link.py", "it is a symbolic or hard link"),
            ("hard.py", "it is a symbolic or hard link"),
        ]
        assert output_contains_marker(test_plugin_context) == []
        assert len(warnings_text(ash_warnings)) == 2

    def test_a_tar_device_or_fifo_member_is_refused(
        self, tree, test_plugin_context, monkeypatch
    ):
        fifo = tarfile.TarInfo("pipe.py")
        fifo.type = tarfile.FIFOTYPE
        archive = self._tar_with(tree / "a.tar", fifo)

        converter, extracted = self._convert(archive, test_plugin_context, monkeypatch)

        assert not (extracted / "pipe.py").exists()
        assert [(r.member, r.reason) for r in refused(converter)] == [
            ("pipe.py", "it is not a regular file")
        ]

    @pytest.mark.parametrize("name", ["../escape.py", "/abs/escape.py"])
    def test_a_tar_member_whose_name_leaves_the_destination_is_refused(
        self, name, tree, test_plugin_context, monkeypatch
    ):
        archive = self._tar_with(tree / "a.tar", tarfile.TarInfo(name))

        converter, _ = self._convert(archive, test_plugin_context, monkeypatch)

        assert output_contains_marker(test_plugin_context) == []
        assert not (tree.parent / "escape.py").exists()
        assert [r.member for r in refused(converter)] == [name]

    def test_without_the_data_filter_members_are_copied_without_their_metadata(
        self, tree, host, test_plugin_context, monkeypatch
    ):
        """A Python whose tarfile has no "data" filter still gets no mode bits or links."""
        monkeypatch.setattr(
            f"{ARCHIVE_MODULE}._TAR_HAS_DATA_FILTER", False, raising=True
        )
        (host / "secret.py").write_text(f"Z = '{MARKER}'\n")
        setuid = tarfile.TarInfo("pkg/tool.py")
        setuid.mode = 0o4755
        symlink = tarfile.TarInfo("link.py")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = str(host / "secret.py")
        archive = self._tar_with(tree / "a.tar", setuid, symlink)

        converter, extracted = self._convert(archive, test_plugin_context, monkeypatch)

        copied = extracted / "pkg" / "tool.py"
        assert copied.read_text() == f"Y = '{MARKER}'\n"
        assert copied.stat().st_mode & 0o7000 == 0
        assert not (extracted / "link.py").exists()
        assert [r.member for r in refused(converter)] == ["link.py"]

    def test_members_without_a_scannable_extension_are_left_out_silently(
        self, tree, test_plugin_context, monkeypatch, ash_warnings
    ):
        """Only a member that would otherwise have been extracted is reported."""
        link = tarfile.TarInfo("README")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/hostname"
        archive = self._tar_with(tree / "a.tar", link)

        converter, _ = self._convert(archive, test_plugin_context, monkeypatch)

        assert refused(converter) == []
        assert warnings_text(ash_warnings) == []


def notebook_double(calls: list):
    """Stand in for ``subprocess.run`` over ``jupyter nbconvert``.

    Reads the notebook named on the command line the way nbconvert does and writes
    its code cells to the output path, so whatever the converter handed it ends up in
    the converted file.
    """

    def _run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        notebook = json.loads(Path(cmd[6]).read_text(encoding="utf-8"))
        code = "".join("".join(c["source"]) for c in notebook["cells"])
        Path(cmd[cmd.index("--output") + 1] + ".py").write_text(code, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return _run


@pytest.fixture
def jupyter(test_plugin_context, monkeypatch):
    converter = JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )
    converter.use_uv_tool = False
    calls: list = []
    monkeypatch.setattr(f"{JUPYTER_MODULE}.subprocess.run", notebook_double(calls))
    return converter, calls


class TestNotebookInputs:
    def test_a_symlinked_notebook_is_refused_and_never_reaches_nbconvert(
        self, jupyter, tree, host, test_plugin_context, monkeypatch, ash_warnings
    ):
        converter, calls = jupyter
        (host / "nb.ipynb").write_text(notebook_json(f"print('{MARKER}')\n"))
        (tree / "nb.ipynb").symlink_to(host / "nb.ipynb")
        monkeypatch.setattr(
            f"{JUPYTER_MODULE}.scan_set", lambda **kw: [str(tree / "nb.ipynb")]
        )

        assert converter.convert() == []
        assert calls == []
        assert output_contains_marker(test_plugin_context) == []
        assert warnings_text(ash_warnings) == [
            "Skipped converter input 'nb.ipynb': it is a symbolic link"
        ]
        assert [r.model_dump() for r in refused(converter)] == [
            {"path": "nb.ipynb", "member": None, "reason": "it is a symbolic link"}
        ]

    def test_a_regular_notebook_beside_a_symlinked_one_still_converts(
        self, jupyter, tree, host, test_plugin_context, monkeypatch, ash_warnings
    ):
        """The positive control: nbconvert is given the in-tree notebook's bytes."""
        converter, calls = jupyter
        (tree / "ok.ipynb").write_text(notebook_json("print('in tree')\n"))
        (host / "nb.ipynb").write_text(notebook_json(f"print('{MARKER}')\n"))
        (tree / "nb.ipynb").symlink_to(host / "nb.ipynb")
        monkeypatch.setattr(
            f"{JUPYTER_MODULE}.scan_set",
            lambda **kw: [str(tree / "ok.ipynb"), str(tree / "nb.ipynb")],
        )

        (converted,) = converter.convert()

        assert converted.read_text() == "print('in tree')\n"
        assert len(calls) == 1
        assert output_contains_marker(test_plugin_context) == []
        assert [r.path for r in refused(converter)] == ["nb.ipynb"]
        assert len(warnings_text(ash_warnings)) == 1

    def test_a_symlinked_notebook_is_not_a_candidate_input(
        self, jupyter, tree, host, monkeypatch
    ):
        """The completeness gate is not told a refused notebook was lost coverage."""
        converter, _ = jupyter
        (host / "nb.ipynb").write_text(notebook_json("print('host')\n"))
        (tree / "nb.ipynb").symlink_to(host / "nb.ipynb")
        (tree / "ok.ipynb").write_text(notebook_json("print('in tree')\n"))
        monkeypatch.setattr(
            f"{JUPYTER_MODULE}.scan_set",
            lambda **kw: [str(tree / "nb.ipynb"), str(tree / "ok.ipynb")],
        )

        assert converter.candidate_input_count() == 1
