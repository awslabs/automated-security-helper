# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On POSIX an archive member named ``a\\b.js`` is scanned under an ``a/**`` ignore path.

A backslash is a filename character on POSIX. zipfile and the tar "data" filter write
a member named ``a\\b.js`` as one file of that name at the archive's top, so an ignore
path for ``<archive>/a/**`` or ``**/a/**`` names nothing the archive holds, as ``a/**``
names no file ``a\\b.js`` at the top of the tree. Member names are the archive
author's, so reading the backslash as a separator would let an archive keep a member
out of the scan behind an ignore path written for a directory.

Two readers could take it as ``a/b.js``: ``member_source_path``, which names the member
by the file its extraction writes, and the path matcher, which compares a path as
given. Either one alone reading it that way leaves the member out: before extraction, through the
converter's ignore match, and after it, through the converted target's filter
(detect-secrets matches work-dir files with ``file_path_matches``). These cells run
the converter and both matchers on the one member.
"""

from __future__ import annotations

import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.sep != "/", reason="a backslash separates where os.sep is one"
    ),
]

PATTERNS = ["lib/b.KIND/a/**", "**/a/**"]


def _archive(path: Path, kind: str, members: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(path, "w") as out:
            for name, text in members.items():
                out.writestr(name, text)
    else:
        with tarfile.open(path, "w") as out:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
    return path


def _converted(tmp_path: Path, monkeypatch, kind: str, member: str, pattern: str):
    """Run the archive converter over lib/b.<kind> holding ``member`` and ok.js, with
    ``pattern`` the one ignore path and the work directory where ASH puts it by
    default, below the source; the source, the extraction directory and its files."""
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=pattern, reason="vendored")
    ]
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )
    archive = _archive(
        source / "lib" / f"b.{kind}", kind, {member: "b = 1\n", "ok.js": "ok = 1\n"}
    )
    monkeypatch.setattr(archive_converter, "scan_set", lambda **kwargs: [str(archive)])
    converter = archive_converter.ArchiveConverter(
        context=context, config=archive_converter.ArchiveConverterConfig()
    )
    (extracted,) = converter.convert()
    return (
        source,
        extracted,
        sorted(
            p.relative_to(extracted).as_posix()
            for p in extracted.rglob("*")
            if p.is_file()
        ),
    )


@pytest.mark.parametrize("kind", ["zip", "tar"])
@pytest.mark.parametrize("pattern", PATTERNS)
def test_a_member_named_a_backslash_b_is_extracted_and_not_filtered(
    tmp_path, monkeypatch, kind, pattern
):
    pattern = pattern.replace("KIND", kind)

    source, extracted, files = _converted(
        tmp_path, monkeypatch, kind, "a\\b.js", pattern
    )

    assert files == ["a\\b.js", "ok.js"]
    # The converted file's path below the source, as the converted target's filter
    # matches it.
    member = (extracted / "a\\b.js").relative_to(source).as_posix()
    assert not file_path_matches(member, pattern), member
    assert not ignore_path_matches(member, pattern), member


@pytest.mark.parametrize("kind", ["zip", "tar"])
@pytest.mark.parametrize("pattern", PATTERNS)
def test_the_control_a_member_in_a_directory_a_is_left_out(
    tmp_path, monkeypatch, kind, pattern
):
    pattern = pattern.replace("KIND", kind)

    _source, _extracted, files = _converted(
        tmp_path, monkeypatch, kind, "a/b.js", pattern
    )

    assert files == ["ok.js"]
