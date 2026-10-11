# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Plain gzip files are decompressed and scanned; Git LFS pointers are reported.

Two kinds of file the converter selects by suffix are not archives it failed to
read, and treating them as unreadable archives failed the scan:

- A ``.gz`` that is one gzip-compressed file rather than a tarball, such as
  ``data.json.gz``. It is decompressed, within the extraction limits and the scan's
  budget, to the name without ``.gz``, and that file is scanned. A name ending
  ``.tar.gz`` says it is a tarball, so its content must be one.
- A Git LFS pointer named like an archive, which is what a checkout without the LFS
  objects holds in place of every ``.zip`` or ``.tar.gz`` tracked by LFS. It is
  recorded as a refused input that names the file and says to fetch the LFS
  objects, and it does not fail the completeness gate: the archive it stands for is
  not in the tree to scan.

An archive that is damaged, truncated or empty still fails the gate, and so does a
file that only starts like an LFS pointer.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    RATIO_FLOOR_BYTES,
    ArchiveConverter,
    ArchiveConverterConfig,
    ArchiveConverterConfigOptions,
)
from tests.utils.archive_builders import GENEROUS_LIMITS, incompressible, tar_bytes

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)

LFS_OID_LINE = (
    b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
)
LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n" + LFS_OID_LINE + b"size 12345\n"
)

#: The version URLs git-lfs reads (lfs/pointer.go, v1Aliases): the current one, the
#: pre-release one docs/spec.md shows ("Blobs created with the pre-release version
#: of the tool generated files with a different version URL"), and the alpha one.
LFS_VERSION_URLS = [
    pytest.param(b"https://git-lfs.github.com/spec/v1", id="v1"),
    pytest.param(b"https://hawser.github.com/spec/v1", id="pre-release-hawser"),
    pytest.param(b"http://git-media.io/v/2", id="alpha-git-media"),
]


def pointer_with_version(url: bytes) -> bytes:
    return b"version " + url + b"\n" + LFS_OID_LINE + b"size 12345\n"


def pointer_of_length(length: int) -> bytes:
    """A valid pointer padded with an extension-style line to exactly ``length`` bytes."""
    padding = length - len(LFS_POINTER) - len(b"x \n")
    return LFS_POINTER + b"x " + b"a" * padding + b"\n"


def zip_that_also_reads_as_a_pointer() -> bytes:
    """A readable zip after pointer lines, inside a ``k <zip bytes>`` line.

    zipfile finds a zip by its end record and reads past data in front of it, so
    a zip whose bytes hold no CR or LF, given a one-byte comment ``\\n``, ends the
    last ``key value`` line of a file that otherwise looks like a pointer. The
    member's content is varied until its CRC has no CR, LF or byte over 0x7f.
    """
    prefix = (
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:" + b"a" * 64 + b"\n" + b"size 1\n" + b"k "
    )
    for n in range(100_000):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("app.py", date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o444 << 16
            info.create_system = 0
            archive.comment = b"\n"
            archive.writestr(info, f"password = 'hunter{n}'")
        data = prefix + buffer.getvalue()
        inner = data[len(prefix) : -1]
        if max(data) < 0x80 and b"\n" not in inner and b"\r" not in inner:
            return data
    raise AssertionError("no content gave a CRC without CR, LF or high bytes")


@pytest.fixture
def copy_limits(monkeypatch) -> List[int]:
    """The byte limit of every _copy_at_most call, in order."""
    limits: List[int] = []
    real = archive_converter._copy_at_most

    def spy(source, out, limit):
        limits.append(limit)
        return real(source, out, limit)

    monkeypatch.setattr(f"{ARCHIVE_MODULE}._copy_at_most", spy, raising=True)
    return limits


def convert(context, monkeypatch, files: Dict[str, bytes], limits=None):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    paths: List[Path] = []
    for name, data in files.items():
        path = tree / name
        path.write_bytes(data)
        paths.append(path)
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(p) for p in paths]
    )
    config = (
        context.config.converters.archive
        if limits is None
        else ArchiveConverterConfig(
            options=ArchiveConverterConfigOptions(**{**GENEROUS_LIMITS, **limits})
        )
    )
    context.config.converters.archive = config
    converter = ArchiveConverter(context=context, config=config)
    return converter, converter.convert()


def written(converter) -> Dict[str, bytes]:
    root = Path(converter.results_dir)
    if not root.exists():
        return {}
    return {p.name: p.read_bytes() for p in root.rglob("*") if p.is_file()}


def gate(converter) -> List[str]:
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[],
        refused_inputs=list(converter.refused_inputs),
        failed_inputs=list(converter.failed_inputs),
    )
    return [name for name, _ in incomplete_converters(model)]


class TestPlainGzip:
    @pytest.mark.parametrize(
        "name, inner", [("data.json.gz", "data.json"), ("notes.txt.GZ", "notes.txt")]
    )
    def test_a_plain_gzip_is_decompressed_and_handed_on(
        self, name, inner, test_plugin_context, monkeypatch
    ):
        content = b'{"api_key": "placeholder"}\n'
        converter, results = convert(
            test_plugin_context, monkeypatch, {name: gzip.compress(content, mtime=0)}
        )

        (extracted,) = results
        assert (extracted / inner).read_bytes() == content
        assert converter.refused_inputs == []

    def test_a_plain_gzip_over_max_member_bytes_is_refused_and_leaves_nothing(
        self, test_plugin_context, monkeypatch
    ):
        data = gzip.compress(incompressible(2000), mtime=0)
        converter, results = convert(
            test_plugin_context,
            monkeypatch,
            {"blob.json.gz": data},
            limits={"max_member_bytes": 1000},
        )

        assert results == []
        assert written(converter) == {}
        assert [(r.path, r.limit) for r in converter.refused_inputs] == [
            ("blob.json.gz", "max_member_bytes")
        ]
        assert gate(converter) == ["archive"]

    # A plain gzip's size is known only by reading it, so room() bounds the copy and
    # admit() then judges what was copied. The two must agree on every limit: a
    # bound below admit's cuts the file short and still admits it, one above writes
    # more before the refusal, or names a different limit. Zeros compress far past
    # any ratio, so each limit below is the one that binds.

    def test_a_gzip_under_the_ratio_floor_is_decompressed_whole(
        self, test_plugin_context, monkeypatch, copy_limits
    ):
        content = b"\x00" * (300 * 1024)
        converter, results = convert(
            test_plugin_context,
            monkeypatch,
            {"zeros.json.gz": gzip.compress(content, mtime=0)},
            limits={"max_compression_ratio": 100},
        )

        (extracted,) = results
        assert (extracted / "zeros.json").stat().st_size == len(content)
        assert converter.refused_inputs == []
        assert copy_limits == [RATIO_FLOOR_BYTES + 1]

    def test_a_gzip_over_the_ratio_copies_at_most_the_floor_and_names_the_ratio(
        self, test_plugin_context, monkeypatch, copy_limits
    ):
        converter, results = convert(
            test_plugin_context,
            monkeypatch,
            {"zeros.json.gz": gzip.compress(b"\x00" * (1 << 20), mtime=0)},
            limits={"max_member_bytes": 600 * 1024, "max_compression_ratio": 100},
        )

        assert results == []
        assert written(converter) == {}
        assert [r.limit for r in converter.refused_inputs] == ["max_compression_ratio"]
        assert copy_limits == [RATIO_FLOOR_BYTES + 1]

    def test_a_gzip_over_max_total_bytes_copies_at_most_that_plus_one(
        self, test_plugin_context, monkeypatch, copy_limits
    ):
        converter, results = convert(
            test_plugin_context,
            monkeypatch,
            {"zeros.json.gz": gzip.compress(b"\x00" * 300_000, mtime=0)},
            limits={"max_total_bytes": 1000},
        )

        assert results == []
        assert [r.limit for r in converter.refused_inputs] == ["max_total_bytes"]
        assert copy_limits == [1001]

    def test_a_gzip_copies_at_most_what_is_left_of_the_scan_budget(
        self, test_plugin_context, monkeypatch, copy_limits
    ):
        total = 100_000
        files = {
            f"z{i}.json.gz": gzip.compress(b"\x00" * 90_000, mtime=0) for i in range(5)
        }
        converter, results = convert(
            test_plugin_context, monkeypatch, files, limits={"max_total_bytes": total}
        )

        assert len(results) == 4
        assert [(r.path, r.limit) for r in converter.refused_inputs] == [
            ("z4.json.gz", "max_total_bytes")
        ]
        left = archive_converter.SCAN_BUDGET_ARCHIVES * total - 4 * 90_000
        assert copy_limits == [total + 1] * 4 + [left + 1]

    def test_a_plain_gzip_counts_toward_the_scan_budget(
        self, test_plugin_context, monkeypatch
    ):
        files = {
            f"a{i}.json.gz": gzip.compress(incompressible(3600, seed=i), mtime=0)
            for i in range(5)
        }
        converter, results = convert(
            test_plugin_context, monkeypatch, files, limits={"max_total_bytes": 4000}
        )

        assert len(results) == 4
        assert [(r.path, r.limit) for r in converter.refused_inputs] == [
            ("a4.json.gz", "max_total_bytes")
        ]
        assert "a4.json" not in written(converter)

    def test_a_damaged_plain_gzip_fails_the_gate_and_leaves_nothing(
        self, test_plugin_context, monkeypatch
    ):
        data = gzip.compress(incompressible(4000), mtime=0)[:-40]
        converter, results = convert(
            test_plugin_context, monkeypatch, {"cut.json.gz": data}
        )

        assert results == []
        assert written(converter) == {}
        assert [r.path for r in converter.failed_inputs] == ["cut.json.gz"]
        assert converter.refused_inputs == []
        assert gate(converter) == ["archive"]

    def test_a_gz_that_holds_a_tar_is_extracted_as_a_tar(
        self, test_plugin_context, monkeypatch
    ):
        data = tar_bytes({"inside.py": "x = 1\n"}, gz=True)
        converter, results = convert(test_plugin_context, monkeypatch, {"pkg.gz": data})

        (extracted,) = results
        assert (extracted / "inside.py").read_bytes() == b"x = 1\n"
        assert converter.refused_inputs == []

    def test_a_tar_gz_that_holds_no_tar_fails_the_gate(
        self, test_plugin_context, monkeypatch
    ):
        data = gzip.compress(b"print('not a tar')\n" * 40, mtime=0)
        converter, results = convert(
            test_plugin_context, monkeypatch, {"pkg.tar.gz": data}
        )

        assert results == []
        assert [r.path for r in converter.failed_inputs] == ["pkg.tar.gz"]
        assert converter.refused_inputs == []

    def test_a_plain_gzip_named_as_a_nested_archive_is_recorded_not_scanned(
        self, test_plugin_context, monkeypatch
    ):
        data = gzip.compress(b"PK\x05\x06" + bytes(18), mtime=0)
        converter, _ = convert(test_plugin_context, monkeypatch, {"inner.zip.gz": data})

        assert written(converter) == {}
        assert [(r.member, r.limit) for r in converter.refused_inputs] == [
            ("inner.zip", None)
        ]
        assert converter.failed_inputs == []


class TestGitLfsPointers:
    @pytest.mark.parametrize("name", ["assets.zip", "vendor/lib.tar.gz", "data.tar"])
    def test_an_lfs_pointer_is_reported_and_does_not_fail_the_gate(
        self, name, test_plugin_context, monkeypatch
    ):
        Path(test_plugin_context.source_dir, name).parent.mkdir(
            parents=True, exist_ok=True
        )
        converter, results = convert(
            test_plugin_context, monkeypatch, {name: LFS_POINTER}
        )

        assert results == []
        assert written(converter) == {}
        (refusal,) = converter.refused_inputs
        assert (refusal.path, refusal.member, refusal.limit) == (name, None, None)
        assert converter.failed_inputs == []
        assert "Git LFS pointer" in refusal.reason
        assert "git lfs pull" in refusal.reason
        assert gate(converter) == []

    @pytest.mark.parametrize("url", LFS_VERSION_URLS)
    def test_a_pointer_with_any_version_git_lfs_reads_is_reported(
        self, url, test_plugin_context, monkeypatch
    ):
        converter, results = convert(
            test_plugin_context, monkeypatch, {"assets.zip": pointer_with_version(url)}
        )

        assert results == []
        assert [r.path for r in converter.refused_inputs] == ["assets.zip"]
        assert "Git LFS pointer" in converter.refused_inputs[0].reason
        assert converter.failed_inputs == []

    def test_a_pointer_of_1023_bytes_is_reported(
        self, test_plugin_context, monkeypatch
    ):
        data = pointer_of_length(1023)
        assert len(data) == 1023
        converter, _ = convert(test_plugin_context, monkeypatch, {"x.zip": data})

        assert [r.path for r in converter.refused_inputs] == ["x.zip"]
        assert converter.failed_inputs == []

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param(LFS_POINTER + b"\x00" * 600, id="trailing-binary"),
            pytest.param(LFS_POINTER + b"x" * 1100, id="over-1024-bytes"),
            pytest.param(
                b"version https://git-lfs.github.com/spec/v1\nnot a pointer line\n",
                id="not-key-value",
            ),
            pytest.param(
                b"version https://git-lfs.github.com/spec/v1\nsize 1\n",
                id="no-oid",
            ),
            pytest.param(LFS_POINTER + b"k a\x00b\n", id="nul-inside-a-value"),
            pytest.param(LFS_POINTER + b"k a\x7fb\n", id="control-byte-in-a-value"),
            pytest.param(
                b"version https://git-lfs.github.com/spec/v1\n" + LFS_OID_LINE,
                id="no-size",
            ),
            pytest.param(LFS_POINTER + b"ext-0 \xff\xfe\n", id="non-ascii-value"),
            pytest.param(pointer_of_length(1024), id="exactly-1024-bytes"),
            pytest.param(
                pointer_with_version(b"https://git-lfs.github.com/spec/v2"),
                id="unknown-version",
            ),
        ],
    )
    def test_a_file_that_only_starts_like_a_pointer_fails_the_gate(
        self, data, test_plugin_context, monkeypatch
    ):
        converter, results = convert(test_plugin_context, monkeypatch, {"x.zip": data})

        assert results == []
        assert [r.path for r in converter.failed_inputs] == ["x.zip"]
        assert converter.refused_inputs == []
        assert gate(converter) == ["archive"]

    def test_a_zip_that_also_reads_as_a_pointer_is_extracted(
        self, test_plugin_context, monkeypatch
    ):
        data = zip_that_also_reads_as_a_pointer()
        assert len(data) < 1024 and data.startswith(b"version ")
        assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["app.py"]

        converter, results = convert(test_plugin_context, monkeypatch, {"x.zip": data})

        (extracted,) = results
        assert (extracted / "app.py").read_bytes().startswith(b"password = ")
        assert converter.refused_inputs == []
        assert converter.failed_inputs == []

    def test_a_tar_whose_first_name_starts_like_a_pointer_is_still_a_tar(
        self, test_plugin_context, monkeypatch
    ):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as t:
            payload = b"x = 1\n"
            info = tarfile.TarInfo("version https:/git-lfs.github.com/spec/v1.py")
            info.size = len(payload)
            t.addfile(info, io.BytesIO(payload))
        converter, results = convert(
            test_plugin_context, monkeypatch, {"odd.tar": buffer.getvalue()}
        )

        assert len(results) == 1
        assert not [r for r in converter.refused_inputs if "LFS" in r.reason]
