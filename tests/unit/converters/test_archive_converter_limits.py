# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The archive converter bounds what extracting an archive can write.

Four options of ``ArchiveConverterConfigOptions`` bound it: ``max_members`` (members
in the archive), ``max_member_bytes`` (one member's size), ``max_total_bytes`` (the
members' sizes added up) and ``max_compression_ratio`` (that total over the archive's
size on disk). They are checked against the sizes the archive declares before
anything is written, and the copy stops at them as well, because a tar member can
write more than it declares.

An archive over a limit is refused whole: none of its members is left on disk, it is
not handed on to the scanners, and the refusal is recorded once through the
converter's refused inputs with a reason that names the option. A member that is
itself an archive is not extracted a second time. It is recorded as a refused member
of its archive, so its content is reported as not scanned instead of being left out
without a trace.

Each limit is tested on every reading path: zip, tar and tar.gz, and tar and tar.gz
through ``_copy_tar_members``, the path taken when tarfile has no "data" filter. Each
has a control at the limit, which extracts.

No archive here holds more than a few kilobytes of content that a reader can
extract, except the sparse tar in ``TestDeclaredSizes``, which writes about 1 MiB;
the large sizes are declared, never present. See ``tests/utils/archive_builders.py``.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import logging
import tarfile
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
    ArchiveConverterConfigOptions,
)
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
)
from tests.utils.archive_builders import (
    GENEROUS_LIMITS,
    GIBIBYTE,
    LIMIT_OPTIONS,
    MEBIBYTE,
    TEBIBYTE,
    archive_bytes,
    compressible_text,
    incompressible,
    ordinary_source_files,
    sparse_tar_bytes,
    sparse_tar_with_data_bytes,
    zip_bytes,
)

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)

#: (archive kind, read without tarfile's "data" filter)
READ_PATHS = [
    pytest.param("zip", False, id="zip"),
    pytest.param("tar", False, id="tar"),
    pytest.param("tar.gz", False, id="tar.gz"),
    pytest.param("tar", True, id="tar-without-data-filter"),
    pytest.param("tar.gz", True, id="tar.gz-without-data-filter"),
]

#: The paths whose archive is compressed, so a compression ratio means something.
COMPRESSED_READ_PATHS = [
    pytest.param("zip", False, id="zip"),
    pytest.param("tar.gz", False, id="tar.gz"),
    pytest.param("tar.gz", True, id="tar.gz-without-data-filter"),
]

TAR_KINDS = [pytest.param(False, id="tar"), pytest.param(True, id="tar.gz")]


@pytest.fixture
def ash_warnings():
    """Every WARNING the 'ash' logger emits during the test.

    ASH_LOGGER does not propagate, so caplog never sees it; a handler is attached
    directly instead.
    """
    records: List[logging.LogRecord] = []

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


def warnings_naming(records, archive: str) -> List[str]:
    return [
        r.getMessage()
        for r in records
        if r.levelno == logging.WARNING and f"'{archive}'" in r.getMessage()
    ]


@pytest.fixture
def tree(test_plugin_context) -> Path:
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    return source


def place(tree: Path, kind: str, members: Dict[str, bytes], stem: str = "a") -> Path:
    path = tree / f"{stem}.{kind}"
    path.write_bytes(archive_bytes(kind, members))
    return path


def converter_for(
    context,
    monkeypatch,
    archives: List[Path],
    without_data_filter: bool = False,
    limits: Dict[str, int] | None = None,
) -> ArchiveConverter:
    """The converter over ``archives``, with ``limits`` over generous ones, or defaults.

    The options are set on the context's config as well as on the converter, as a
    scan has them: ConvertPhase builds each converter's config from the scan's
    AshConfig.
    """
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(p) for p in archives]
    )
    if without_data_filter:
        monkeypatch.setattr(
            f"{ARCHIVE_MODULE}._TAR_HAS_DATA_FILTER", False, raising=True
        )
    if limits is None:
        config = ArchiveConverterConfig()
    else:
        config = ArchiveConverterConfig(
            options=ArchiveConverterConfigOptions(**{**GENEROUS_LIMITS, **limits})
        )
    context.config.converters.archive = config
    return ArchiveConverter(context=context, config=config)


def files_written(converter: ArchiveConverter) -> Dict[str, int]:
    """Size of every member file under the converter's output, by path below it.

    The converter's own record of what it extracted (converted-sources.json, at
    the top of the results directory) is not extracted content and is left out: an
    archive whose every member was refused still has an extraction directory and
    an entry there, and writes no member.
    """
    root = Path(converter.results_dir)
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.stat().st_size
        for path in root.rglob("*")
        if path.is_file() and path != root / CONVERTED_SOURCES_FILE_NAME
    }


def refusals_of(converter: ArchiveConverter, archive: str) -> list:
    return [r for r in converter.refused_inputs if r.path == archive]


def summary(written: Dict[str, int]) -> str:
    return f"{len(written)} file(s), {sum(written.values())} bytes"


def assert_refused(converter, results, archive: str, records, option=None) -> None:
    """``archive`` was refused whole and the refusal recorded once."""
    assert results == [], (
        f"{archive} was extracted and handed on: "
        f"{summary(files_written(converter))} written"
    )
    written = files_written(converter)
    assert written == {}, f"a refused archive left {summary(written)} on disk"
    refusals = refusals_of(converter, archive)
    assert len(refusals) == 1, converter.refused_inputs
    if option is None:
        assert any(name in refusals[0].reason for name in LIMIT_OPTIONS), refusals[0]
    else:
        assert option in refusals[0].reason, refusals[0]
    assert len(warnings_naming(records, archive)) == 1, warnings_naming(
        records, archive
    )


def digests(files: Dict[str, bytes]) -> Dict[str, str]:
    return {name: hashlib.sha256(data).hexdigest()[:16] for name, data in files.items()}


def assert_extracted(converter, results, members: Dict[str, bytes]) -> None:
    """The archive extracted to exactly ``members`` and nothing was refused.

    Compared by digest, so a failure lists names rather than megabytes of content.
    """
    assert len(results) == 1, (results, converter.refused_inputs)
    (extracted,) = results
    assert digests(
        {
            path.relative_to(extracted).as_posix(): path.read_bytes()
            for path in extracted.rglob("*")
            if path.is_file()
        }
    ) == digests(members)
    assert converter.refused_inputs == []


def numbered(count: int, size: int = 16) -> Dict[str, bytes]:
    return {f"m{i}.py": incompressible(size, seed=i) for i in range(count)}


class TestConvertedSources:
    """An extracted archive is recorded, beside the output, as the source of every
    member below its extraction directory, so a finding in a member follows the
    archive under --changed-files-only."""

    @pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz"])
    def test_an_extracted_archive_is_recorded_as_its_members_source(
        self, tree, test_plugin_context, monkeypatch, kind
    ):
        import json

        from automated_security_helper.utils.scan_output_dirs import (
            CONVERTED_SOURCES_FILE_NAME,
        )

        archive = place(tree, kind, {"m.py": b"x = 1\n"}, stem="lib")
        converter = converter_for(test_plugin_context, monkeypatch, [archive])

        (extracted,) = converter.convert()

        recorded = json.loads(
            (Path(converter.results_dir) / CONVERTED_SOURCES_FILE_NAME).read_text(
                encoding="utf-8"
            )
        )
        key = (
            extracted.resolve()
            .relative_to(Path(test_plugin_context.work_dir).resolve())
            .as_posix()
            + "/"
        )
        assert recorded == {key: f"lib.{kind}"}

    def test_a_refused_archive_is_not_recorded(
        self, tree, test_plugin_context, monkeypatch, ash_warnings
    ):
        from automated_security_helper.utils.scan_output_dirs import (
            CONVERTED_SOURCES_FILE_NAME,
        )

        archive = place(tree, "zip", numbered(3))
        converter = converter_for(
            test_plugin_context, monkeypatch, [archive], limits={"max_members": 2}
        )

        results = converter.convert()

        assert_refused(converter, results, "a.zip", ash_warnings, "max_members")
        assert not (Path(converter.results_dir) / CONVERTED_SOURCES_FILE_NAME).exists()


def gnu_sparse_header_over_stored_data(name: str, stored: int, gz: bool) -> bytes:
    """A tar of one old GNU sparse member whose header says ``stored`` bytes of
    data follow while its real size and sparse map are zero.

    tarfile reads such a header (``_proc_sparse``) by taking the member's size
    from the real-size field, 0 here, and the next header's offset from the
    stored size, so the member is reported as empty while ``stored`` zero bytes
    sit between its header and the end-of-archive blocks. Zeros keep the gzip
    form small; what the header pass decompresses to skip them is the point.
    """
    info = tarfile.TarInfo(name)
    info.type = tarfile.GNUTYPE_SPARSE
    info.size = stored
    header = info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape")
    body = header + bytes(stored) + b"\0" * (2 * tarfile.BLOCKSIZE)
    return gzip.compress(body, mtime=0) if gz else body


class TestMemberCount:
    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_an_archive_with_more_members_than_max_members_is_refused(
        self,
        kind,
        without_data_filter,
        tree,
        test_plugin_context,
        monkeypatch,
        ash_warnings,
    ):
        archive = place(tree, kind, numbered(4))
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_members": 3},
        )

        results = converter.convert()

        assert_refused(
            converter, results, archive.name, ash_warnings, option="max_members"
        )

    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_an_archive_with_max_members_members_is_extracted(
        self, kind, without_data_filter, tree, test_plugin_context, monkeypatch
    ):
        members = numbered(3)
        archive = place(tree, kind, members)
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_members": 3},
        )

        assert_extracted(converter, converter.convert(), members)


class TestMemberSize:
    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_a_member_larger_than_max_member_bytes_refuses_the_whole_archive(
        self,
        kind,
        without_data_filter,
        tree,
        test_plugin_context,
        monkeypatch,
        ash_warnings,
    ):
        members = {
            "small.py": incompressible(100, seed=1),
            "large.py": incompressible(1001, seed=2),
        }
        archive = place(tree, kind, members)
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_member_bytes": 1000},
        )

        results = converter.convert()

        assert_refused(
            converter, results, archive.name, ash_warnings, option="max_member_bytes"
        )

    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_a_member_of_max_member_bytes_is_extracted(
        self, kind, without_data_filter, tree, test_plugin_context, monkeypatch
    ):
        members = {
            "small.py": incompressible(100, seed=1),
            "large.py": incompressible(1000, seed=2),
        }
        archive = place(tree, kind, members)
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_member_bytes": 1000},
        )

        assert_extracted(converter, converter.convert(), members)


class TestTotalSize:
    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_members_adding_up_to_more_than_max_total_bytes_are_refused(
        self,
        kind,
        without_data_filter,
        tree,
        test_plugin_context,
        monkeypatch,
        ash_warnings,
    ):
        archive = place(tree, kind, numbered(3, size=1400))
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_total_bytes": 4000},
        )

        results = converter.convert()

        assert_refused(
            converter, results, archive.name, ash_warnings, option="max_total_bytes"
        )

    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_members_adding_up_to_max_total_bytes_are_extracted(
        self, kind, without_data_filter, tree, test_plugin_context, monkeypatch
    ):
        members = numbered(4, size=1000)
        archive = place(tree, kind, members)
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_total_bytes": 4000},
        )

        assert_extracted(converter, converter.convert(), members)


class TestCompressionRatio:
    @pytest.mark.parametrize("kind, without_data_filter", COMPRESSED_READ_PATHS)
    def test_an_archive_that_expands_beyond_max_compression_ratio_is_refused(
        self,
        kind,
        without_data_filter,
        tree,
        test_plugin_context,
        monkeypatch,
        ash_warnings,
    ):
        """1 MiB of zeros compresses about 900 to 1 in zip and in gzip."""
        archive = place(tree, kind, {"zeros.py": bytes(MEBIBYTE)})
        assert MEBIBYTE / archive.stat().st_size > 500
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_compression_ratio": 100},
        )

        results = converter.convert()

        assert_refused(
            converter,
            results,
            archive.name,
            ash_warnings,
            option="max_compression_ratio",
        )

    @pytest.mark.parametrize("kind, without_data_filter", COMPRESSED_READ_PATHS)
    def test_an_archive_that_compresses_like_source_code_is_extracted(
        self, kind, without_data_filter, tree, test_plugin_context, monkeypatch
    ):
        members = {"values.py": compressible_text(64 * 1024)}
        archive = place(tree, kind, members)
        assert 2 < 64 * 1024 / archive.stat().st_size < 100
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter,
            limits={"max_compression_ratio": 100},
        )

        assert_extracted(converter, converter.convert(), members)


class TestDefaultLimits:
    """With no limits configured, the defaults refuse what no source archive declares."""

    def test_a_member_declaring_a_tebibyte_is_refused(
        self, tree, test_plugin_context, monkeypatch, ash_warnings
    ):
        archive = tree / "declared.zip"
        archive.write_bytes(
            zip_bytes(
                {"declared.py": "print('declared large')\n"},
                declared_sizes={"declared.py": TEBIBYTE},
            )
        )
        converter = converter_for(test_plugin_context, monkeypatch, [archive])

        results = converter.convert()

        assert_refused(converter, results, "declared.zip", ash_warnings)

    def test_members_declaring_two_tebibytes_together_are_refused(
        self, tree, test_plugin_context, monkeypatch, ash_warnings
    ):
        """No single member declares more than 1 GiB."""
        members = {f"pkg/m{i}.py": f"N = {i}\n" for i in range(2048)}
        archive = tree / "declared.zip"
        archive.write_bytes(
            zip_bytes(members, declared_sizes=dict.fromkeys(members, GIBIBYTE))
        )
        converter = converter_for(test_plugin_context, monkeypatch, [archive])

        results = converter.convert()

        assert_refused(converter, results, "declared.zip", ash_warnings)

    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_an_ordinary_source_archive_is_extracted(
        self, kind, without_data_filter, tree, test_plugin_context, monkeypatch
    ):
        """The positive control for the defaults: 2 MiB of real source code."""
        members = ordinary_source_files()
        assert len(members) > 100, len(members)
        archive = place(tree, kind, members)
        converter = converter_for(
            test_plugin_context, monkeypatch, [archive], without_data_filter
        )

        assert_extracted(converter, converter.convert(), members)


class TestDeclaredSizes:
    """The copy stops at the limits whatever a tar member declares.

    The limits below allow 1000 bytes for a member and 4000 in total. Each archive's
    one member declares less than that, so the checks on declared sizes pass it, and
    the bytes written are what is measured.
    """

    LIMITS = {"max_member_bytes": 1000, "max_total_bytes": 4000}

    def assert_within_limits(self, converter) -> None:
        written = files_written(converter)
        largest = max(written.values(), default=0)
        assert largest <= 1000, f"a member wrote {largest} bytes; {summary(written)}"
        assert sum(written.values()) <= 4000, summary(written)

    @pytest.mark.parametrize("gz", TAR_KINDS)
    def test_a_sparse_member_writes_no_more_than_the_limits_allow(
        self, gz, tree, test_plugin_context, monkeypatch
    ):
        """The member declares 1 byte; tarfile's extractall copies 1 MiB for it."""
        archive = tree / ("sparse.tar.gz" if gz else "sparse.tar")
        archive.write_bytes(
            sparse_tar_bytes(
                "big.py",
                declared_size=1,
                map_length=2 * MEBIBYTE,
                trailing=MEBIBYTE,
                gz=gz,
            )
        )
        converter = converter_for(
            test_plugin_context, monkeypatch, [archive], limits=self.LIMITS
        )

        converter.convert()

        self.assert_within_limits(converter)

    @pytest.mark.parametrize("gz", TAR_KINDS)
    def test_a_member_is_admitted_for_the_stored_extent_its_header_pass_skips(
        self, gz, tree, test_plugin_context, monkeypatch, ash_warnings
    ):
        """An old GNU sparse header declares a real size of 0 over 2 MiB of stored
        data. tarfile reports the member as 0 bytes and seeks past the 2 MiB to
        reach the next header, decompressing it for a tar.gz, so admitting the
        reported size bounded none of that. The stored extent is admitted, and
        it is over max_member_bytes."""
        archive = tree / ("sparse.tar.gz" if gz else "sparse.tar")
        archive.write_bytes(
            gnu_sparse_header_over_stored_data("big.py", stored=2 * MEBIBYTE, gz=gz)
        )
        converter = converter_for(
            test_plugin_context, monkeypatch, [archive], limits=self.LIMITS
        )

        results = converter.convert()

        assert_refused(
            converter, results, archive.name, ash_warnings, option="max_member_bytes"
        )

    @pytest.mark.parametrize(
        "without_data_filter", [False, True], ids=["filter", "copy"]
    )
    @pytest.mark.parametrize("gz", TAR_KINDS)
    def test_a_sparse_member_whose_map_passes_its_size_is_refused_before_any_copy(
        self, gz, without_data_filter, tree, test_plugin_context, monkeypatch
    ):
        """The mapped data is in the stream, so only the refusal keeps it unwritten.

        tarfile truncates the file to its declared size after copying the map, so the
        bytes copied are counted at tarfile.copyfileobj, which copies every entry.
        The limits sit above the 2 MiB the member stores, so the header pass admits
        it for that extent and the sparse-map check is what refuses it.
        """
        archive = tree / ("sparse.tar.gz" if gz else "sparse.tar")
        archive.write_bytes(
            sparse_tar_with_data_bytes(
                "big.py", declared_size=1, map_length=2 * MEBIBYTE, gz=gz
            )
        )
        copied = []
        real_copy = tarfile.copyfileobj

        def counting_copy(src, dst, length=None, *args, **kwargs):
            copied.append(length)
            return real_copy(src, dst, length, *args, **kwargs)

        monkeypatch.setattr(tarfile, "copyfileobj", counting_copy, raising=True)
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter=without_data_filter,
            limits={"max_member_bytes": 4 * MEBIBYTE, "max_total_bytes": 8 * MEBIBYTE},
        )

        converter.convert()

        assert [(r.member, r.limit) for r in converter.refused_inputs] == [
            ("big.py", None)
        ]
        assert "sparse" in converter.refused_inputs[0].reason
        assert copied == [], f"tarfile copied {copied} bytes for a refused member"
        assert files_written(converter) == {}

    @pytest.mark.parametrize("gz", TAR_KINDS)
    def test_without_the_data_filter_a_sparse_member_writes_no_more_than_the_limits_allow(
        self, gz, tree, test_plugin_context, monkeypatch
    ):
        """The control: extractfile reads the same member as the 1 byte it declares."""
        archive = tree / ("sparse.tar.gz" if gz else "sparse.tar")
        archive.write_bytes(
            sparse_tar_bytes(
                "big.py",
                declared_size=1,
                map_length=2 * MEBIBYTE,
                trailing=MEBIBYTE,
                gz=gz,
            )
        )
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter=True,
            limits=self.LIMITS,
        )

        converter.convert()

        self.assert_within_limits(converter)

    @pytest.mark.parametrize("gz", TAR_KINDS)
    def test_without_the_data_filter_the_copy_stops_at_the_limits_when_a_member_reads_longer(
        self, gz, tree, test_plugin_context, monkeypatch
    ):
        """A member stream that yields 1 MiB for a member declaring 10 bytes.

        tarfile's own reader stops at the declared size; this stands in for one that
        does not, which is what the copy loop's own bound is for.
        """
        kind = "tar.gz" if gz else "tar"
        archive = place(tree, kind, {"short.py": b"print(1)\n\n"})
        monkeypatch.setattr(
            tarfile.TarFile,
            "extractfile",
            lambda self, member: io.BytesIO(b"A" * MEBIBYTE),
        )
        converter = converter_for(
            test_plugin_context,
            monkeypatch,
            [archive],
            without_data_filter=True,
            limits=self.LIMITS,
        )

        converter.convert()

        self.assert_within_limits(converter)


class TestNestedArchives:
    NESTED = ("inner.zip", "deps/lib.tar.gz", "vendor/Pkg.TAR")

    @pytest.mark.parametrize("kind, without_data_filter", READ_PATHS)
    def test_a_member_that_is_an_archive_is_recorded_as_not_scanned(
        self,
        kind,
        without_data_filter,
        tree,
        test_plugin_context,
        monkeypatch,
        ash_warnings,
    ):
        inner = {"inner.py": b"print('inside the inner archive')\n"}
        members = {
            "top.py": b"print('top level')\n",
            "inner.zip": archive_bytes("zip", inner),
            "deps/lib.tar.gz": archive_bytes("tar.gz", inner),
            "vendor/Pkg.TAR": archive_bytes("tar", inner),
        }
        archive = place(tree, kind, members, stem="outer")
        converter = converter_for(
            test_plugin_context, monkeypatch, [archive], without_data_filter
        )

        (extracted,) = converter.convert()

        assert (extracted / "top.py").read_bytes() == b"print('top level')\n"
        refusals = refusals_of(converter, archive.name)
        assert sorted(r.member for r in refusals) == sorted(self.NESTED)
        assert all(r.reason for r in refusals)
        for member in self.NESTED:
            assert (
                len(
                    [
                        w
                        for w in warnings_naming(ash_warnings, archive.name)
                        if member in w
                    ]
                )
                == 1
            ), warnings_naming(ash_warnings, archive.name)
