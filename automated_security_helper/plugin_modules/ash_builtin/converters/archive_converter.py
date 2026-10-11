# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the ArchiveConverter implementation."""

import os
import shutil
import stat
from pathlib import Path, PurePosixPath
import tarfile
from typing import Annotated, BinaryIO, Dict, List, Literal, Optional, Tuple
import zipfile

from pydantic import Field, PositiveInt

from automated_security_helper.core.constants import (
    KNOWN_SCANNABLE_EXTENSIONS,
)
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import (
    honors_ignore_files,
    scan_set,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    relative_display,
)
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches as path_matches_pattern,
)


def _is_plain_gzip(name: str, head: bytes) -> bool:
    """A ``.gz`` that is gzip but not named as a tarball: a single compressed file."""
    lowered = name.lower()
    return (
        lowered.endswith(".gz")
        and not lowered.endswith(".tar.gz")
        and head == b"\x1f\x8b"
    )


#: The suffixes the converter selects archives in the tree on. Compared lowercased
#: against the last one only, so ``.tar.gz`` is ``gz`` and ``.tgz`` is not selected.
ARCHIVE_SUFFIXES = ("zip", "tar", "gz")

#: The suffixes that mark an archive member as an archive or compressed file of its
#: own. Kept apart from ARCHIVE_SUFFIXES, which decides what is extracted: any of
#: these inside an archive is recorded as not scanned, because extraction is one
#: level deep. Compared lowercased against the member's last suffix.
NESTED_ARCHIVE_SUFFIXES = (
    *ARCHIVE_SUFFIXES,
    "tgz",
    "bz2",
    "tbz",
    "tbz2",
    "xz",
    "txz",
    "zst",
    "lzma",
    "7z",
    "rar",
    "jar",
    "war",
    "ear",
    "whl",
    "egg",
)

#: The options of ArchiveConverterConfigOptions that bound what extracting an archive
#: can write. A config file inside the scanned tree can lower them but not raise
#: them; see config/archive_limits.py.
EXTRACTION_LIMIT_OPTIONS = (
    "max_members",
    "max_member_bytes",
    "max_total_bytes",
    "max_compression_ratio",
)


class ArchiveConverterConfigOptions(ConverterOptionsBase):
    """Limits on what extracting one archive may write.

    Each is an inclusive maximum, checked against what the archive declares, for
    every member, before anything is written. An archive over any of them is not
    extracted at all. The defaults are far above an ordinary source archive. Set
    inside the scanned tree (``.ash/.ash.yaml``), by a config an MCP client
    supplied, or by a workspace project's own config, a value can only lower a
    limit; raise one with ``--config-overrides`` or a config file outside the tree.
    """

    max_members: Annotated[
        PositiveInt,
        Field(
            description=(
                "The most members an archive may have, directories included. An "
                "archive with more is not extracted. All the archives one scan "
                "extracts may hold four times this many together."
            )
        ),
    ] = 100_000
    max_member_bytes: Annotated[
        PositiveInt,
        Field(
            description=(
                "The largest size in bytes one member of an archive may declare. An "
                "archive with a larger member is not extracted. Default 256 MiB."
            )
        ),
    ] = 256 * 1024 * 1024
    max_total_bytes: Annotated[
        PositiveInt,
        Field(
            description=(
                "The most bytes an archive's members may declare added up, each "
                "counted as at least 512. An archive whose members declare more is "
                "not extracted. All the archives one scan extracts may declare four "
                "times this together. Default 1 GiB."
            )
        ),
    ] = 1024 * 1024 * 1024
    max_compression_ratio: Annotated[
        PositiveInt,
        Field(
            description=(
                "The most times its own size on disk that an archive's members may "
                "declare added up. An archive that declares more is not extracted. "
                "Checked only once the members declare more than 512 KiB in all."
            )
        ),
    ] = 100


#: The compression ratio is checked only once an archive's members declare more
#: than this many bytes added up. Below it an archive writes at most this much,
#: whatever it compresses to, and small archives of repetitive text (a fixtures
#: directory of indented JSON) routinely compress better than 100 to 1: 313 KiB of
#: JSON in a 2.3 KB zip is 139. Apache POI's ZipSecureFile skips its inflate-ratio
#: check for an entry of 100 KiB or less; the ratio here is over a whole archive, a
#: sum of entries, so the floor is higher.
RATIO_FLOOR_BYTES = 512 * 1024


#: Every member counts as at least this many bytes toward max_total_bytes and the
#: scan's budget: the size of a tar header, which reading the member costs whatever
#: it holds. Without it an archive of empty members was free in bytes.
MEMBER_FLOOR_BYTES = 512

#: The archives one conversion extracts share a budget of this many times
#: max_members members and max_total_bytes bytes. Four archives at the
#: per-archive limits fit, which with the defaults is 400,000 members and 4 GiB,
#: under the 5 GB GitHub strongly recommends a whole repository stays below. It
#: follows the per-archive limits, so an operator who raises those raises it too.
SCAN_BUDGET_ARCHIVES = 4


class _ScanBudget:
    """What the archives already extracted in one conversion have used of its budget."""

    def __init__(self) -> None:
        self.members = 0
        self.total = 0

    def commit(self, budget: "_ExtractionBudget") -> None:
        self.members += budget.members
        self.total += budget.total


class _ExtractionLimitExceeded(Exception):
    """An archive declares more than one of the extraction limits allows."""

    def __init__(self, option: str, reason: str):
        super().__init__(reason)
        self.option = option
        self.reason = reason


class _UnreadableArchive(Exception):
    """An archive the converter cannot read, with why, for its refusal record."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _ExtractionBudget:
    """Admits an archive's members one at a time against the extraction limits.

    Every member counts, whether or not it would be extracted: reading a compressed
    tar means decompressing every member to reach the next header, and the ratio is
    a property of the archive as a whole. A tar is read one header at a time through
    this, so an archive over a limit is refused at the header that takes it over,
    without reading the rest.
    """

    def __init__(
        self,
        options: ArchiveConverterConfigOptions,
        archive_size: int,
        scan: Optional[_ScanBudget] = None,
    ):
        self.options = options
        self.archive_size = max(archive_size, 1)
        self.scan = scan
        self.members = 0
        # Bytes counted toward the totals, each member at least MEMBER_FLOOR_BYTES.
        self.total = 0
        # Bytes the members declare, which the compression ratio is taken over.
        self.declared = 0

    def admit(self, name: str, size: int) -> None:
        options = self.options
        self.members += 1
        if self.members > options.max_members:
            raise _ExtractionLimitExceeded(
                "max_members",
                f"it has more than {options.max_members} members, the max_members "
                "extraction limit",
            )
        if size < 0 or size > options.max_member_bytes:
            raise _ExtractionLimitExceeded(
                "max_member_bytes",
                f"its member '{name}' declares {size} bytes, outside the "
                f"max_member_bytes extraction limit of {options.max_member_bytes}",
            )
        self.total += max(size, MEMBER_FLOOR_BYTES)
        self.declared += size
        if self.total > options.max_total_bytes:
            raise _ExtractionLimitExceeded(
                "max_total_bytes",
                f"its members declare more than {options.max_total_bytes} bytes, the "
                "max_total_bytes extraction limit (each member counts at least "
                f"{MEMBER_FLOOR_BYTES} bytes)",
            )
        if (
            self.declared > RATIO_FLOOR_BYTES
            and self.declared > options.max_compression_ratio * self.archive_size
        ):
            raise _ExtractionLimitExceeded(
                "max_compression_ratio",
                f"its members declare more than {options.max_compression_ratio} times "
                f"its own size of {self.archive_size} bytes, the "
                "max_compression_ratio extraction limit",
            )
        if self.scan is None:
            return
        scan_members = SCAN_BUDGET_ARCHIVES * options.max_members
        if self.scan.members + self.members > scan_members:
            raise _ExtractionLimitExceeded(
                "max_members",
                "together with the archives this scan extracted before it, it would "
                f"make more than {scan_members} members, {SCAN_BUDGET_ARCHIVES} "
                "times the max_members extraction limit",
            )
        scan_total = SCAN_BUDGET_ARCHIVES * options.max_total_bytes
        if self.scan.total + self.total > scan_total:
            raise _ExtractionLimitExceeded(
                "max_total_bytes",
                "together with the archives this scan extracted before it, it would "
                f"declare more than {scan_total} bytes, {SCAN_BUDGET_ARCHIVES} times "
                "the max_total_bytes extraction limit",
            )


def _tar_members_within(
    tar_ref: tarfile.TarFile, budget: _ExtractionBudget
) -> List[tarfile.TarInfo]:
    """Every member of ``tar_ref``, each admitted to ``budget`` as its header is read."""
    members = []
    for member in tar_ref:
        budget.admit(member.name, member.size)
        members.append(member)
    return members


def _is_archive_name(name: str) -> bool:
    """Whether a member's name marks it as an archive or compressed file of its own."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return "." in base and base.rsplit(".", 1)[-1].lower() in NESTED_ARCHIVE_SUFFIXES


# tarfile's "data" extraction filter refuses links that leave the destination, device
# files and absolute names, and drops unsafe mode bits. It is in 3.12 and was
# backported to 3.10.12 and 3.11.4, so it is detected rather than inferred from the
# version. The member checks below apply whether or not it is present.
_TAR_HAS_DATA_FILTER = hasattr(tarfile, "data_filter")

_MEMBER_ABSOLUTE = "its path is absolute"
_MEMBER_PARENT = "its path contains a '..' component"
_MEMBER_ESCAPES = "it would be extracted outside the destination directory"
_MEMBER_LINK = "it is a symbolic or hard link"
_MEMBER_NOT_REGULAR = "it is not a regular file"
_MEMBER_SPARSE_BEYOND_SIZE = (
    "it is a sparse file whose map places data beyond the size it declares"
)
_MEMBER_NESTED_ARCHIVE = (
    "it is named as an archive or compressed file (such as .zip, .tar.gz, .jar or "
    ".7z), and an archive inside an archive is not extracted, so its contents are "
    "not scanned"
)

_COPY_CHUNK = 1024 * 1024

#: How many refused members of one archive are listed one by one for each reason.
#: The rest are counted in one record, so an archive of many links or nested
#: archives does not produce a record, a warning and a SARIF notification apiece.
MEMBER_REFUSALS_LISTED = 20


def _sparse_map_problem(member: tarfile.TarInfo) -> Optional[str]:
    """Why a sparse tar member's map cannot be extracted within its size, or None.

    ``TarFile.extractall`` writes each map entry at its offset and only truncates
    the file to the declared size once every entry is written, and nothing in
    tarfile ties the map to that size. An entry past the size leaves a file larger
    than the member declares, which is what the size limits were checked against,
    and when the copy stops with ReadError the truncation never happens at all.
    With every entry inside the size, the file never grows past it.
    """
    # Read with getattr: typeshed declares TarInfo.sparse as an int, while tarfile
    # sets it to a list of (offset, length) pairs, or None for a member that is not
    # sparse.
    entries: List[Tuple[int, int]] = getattr(member, "sparse", None) or []
    for offset, length in entries:
        if offset < 0 or length < 0 or offset + length > member.size:
            return _MEMBER_SPARSE_BEYOND_SIZE
    return None


def _copy_at_most(source: BinaryIO, out: BinaryIO, limit: int) -> None:
    """Copy from ``source`` to ``out`` until ``limit`` bytes or the end of ``source``."""
    remaining = limit
    while remaining > 0:
        chunk = source.read(min(_COPY_CHUNK, remaining))
        if not chunk:
            return
        out.write(chunk)
        remaining -= len(chunk)


def _copy_tar_members(
    tar_ref: tarfile.TarFile, members: List[tarfile.TarInfo], target_path: Path
) -> None:
    """Write each member's bytes under ``target_path``, applying none of its metadata.

    For a Python whose tarfile has no "data" filter. ``extractall`` without one applies
    each member's mode, owner and times, so a setuid bit or a foreign owner (when ASH
    runs as root) would carry over. The members reaching here are regular files whose
    names inspect_members has already checked, so copying their content is all there
    is to do. Each file is created without following a link at its name, and no more
    than the member's declared size is copied into it, whatever its stream yields:
    the declared sizes are what the extraction limits admitted.
    """
    for member in members:
        source = tar_ref.extractfile(member)
        if source is None:
            continue
        destination = target_path.joinpath(*PurePosixPath(member.name).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
            0o644,
        )
        with source, os.fdopen(fd, "wb") as out:
            _copy_at_most(source, out, member.size)


def _member_name_problem(member_name: str) -> Optional[str]:
    """Why an archive member's name is unsafe to extract, or None.

    Read on the text with both separators, so a name written on Windows is judged
    the same way on every platform.
    """
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return _MEMBER_ABSOLUTE
    if ".." in PurePosixPath(normalized).parts:
        return _MEMBER_PARENT
    return None


class ArchiveConverterConfig(ConverterPluginConfigBase):
    """Archive (ZIP/TAR/GZIP/etc) converter configuration."""

    name: Literal["archive"] = "archive"
    enabled: bool = True
    options: Annotated[
        ArchiveConverterConfigOptions,
        Field(description="Configure Archive converter"),
    ] = ArchiveConverterConfigOptions()


@ash_converter_plugin
class ArchiveConverter(ConverterPluginBase[ArchiveConverterConfig]):
    """Converter implementation for Archive file extraction."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = ArchiveConverterConfig()
        return super().model_post_init(context)

    def _extraction_limits(self) -> ArchiveConverterConfigOptions:
        """The extraction limits from this converter's options, defaults where unset."""
        options = getattr(self.config, "options", None)
        if isinstance(options, ArchiveConverterConfigOptions):
            return options
        if hasattr(options, "model_dump"):
            options = options.model_dump()
        return ArchiveConverterConfigOptions.model_validate(dict(options or {}))

    def validate_plugin_dependencies(self):
        # Return True since this scanner is entirely within the same Python module,
        # so there is nothing further to validate in terms of availability.
        return True

    @staticmethod
    def _is_path_traversal(member_path: str, target_path: Path) -> bool:
        """Check if a member path would escape the target extraction directory.

        Args:
            member_path: The path of the archive member.
            target_path: The intended extraction directory.

        Returns:
            True if the path is unsafe (traversal detected), False if safe.
        """
        # Reject absolute paths
        if os.path.isabs(member_path):
            return True

        # Resolve the full extraction path and verify it stays within target
        resolved = (target_path / member_path).resolve()
        target_resolved = target_path.resolve()

        # Check that the resolved path is within the target directory
        try:
            resolved.relative_to(target_resolved)
        except ValueError:
            return True

        return False

    def _refuse_member(self, archive: Optional[str], member: str, reason: str) -> None:
        if archive is None:
            ASH_LOGGER.warning(f"Skipped archive member '{member}': {reason}")
        else:
            self.record_refused_input(TreeInputRefused(archive, reason), member=member)

    def inspect_members(
        self,
        members: List[str | zipfile.ZipInfo | tarfile.TarInfo],
        target_path: Optional[Path] = None,
        archive: Optional[str] = None,
    ):
        """The members worth extracting: scannable, regular files that stay inside.

        A member is refused, with a warning naming it, when it is a link (a tar
        symlink or hard link, or a zip entry whose mode marks it a symlink), is not a
        regular file, is a sparse tar member whose map reaches past its declared
        size, or has a name that is absolute, contains ``..`` or would land outside
        ``target_path``. A member named as an archive or compressed file (a suffix in
        ``NESTED_ARCHIVE_SUFFIXES``, in any case) is refused as well: extraction is
        one level deep, and the refusal is what reports its contents as not scanned. Members without a
        scannable extension are left out silently, as before, so a refusal is only
        reported for a member that would otherwise have been extracted.

        Args:
            members: The archive's members.
            target_path: The extraction directory. The escape check needs it, so it
                is skipped when this is None.
            archive: The archive's path relative to the scanned tree. When given, each
                refusal is also recorded in the converter's results row.
        """
        ASH_LOGGER.verbose(f"Inspecting {len(members)} members from archive")
        filtered_members = []
        # Refusals by reason: how many were listed, and how many more were not.
        listed: Dict[str, int] = {}
        unlisted: Dict[str, int] = {}
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                member_name = member.name
                if member.isdir():
                    continue
                is_link = member.issym() or member.islnk()
                is_regular = member.isreg()
                content_problem = _sparse_map_problem(member)
            elif isinstance(member, zipfile.ZipInfo):
                member_name = member.filename
                if member.is_dir():
                    continue
                # Unix mode bits live in the high 16 bits of external_attr. zipfile
                # writes a symlink entry out as a file holding the link's target, so
                # it would not become a link, but it is not a file either.
                is_link = stat.S_ISLNK(member.external_attr >> 16)
                is_regular = True
                content_problem = None
            elif isinstance(member, str):
                member_name = member
                is_link = False
                is_regular = True
                content_problem = None
            else:
                ASH_LOGGER.debug(
                    f"Skipping uknown extension from archive: {type(member)}"
                )
                continue

            nested = _is_archive_name(member_name)
            member_ext = member_name.split(".")[-1]
            if not nested and member_ext not in KNOWN_SCANNABLE_EXTENSIONS:
                continue

            problem = _member_name_problem(member_name)
            if problem is None and target_path is not None:
                if self._is_path_traversal(member_name, target_path):
                    problem = _MEMBER_ESCAPES
            if problem is None and is_link:
                problem = _MEMBER_LINK
            if problem is None and not is_regular:
                problem = _MEMBER_NOT_REGULAR
            if problem is None:
                problem = content_problem
            if problem is None and nested:
                problem = _MEMBER_NESTED_ARCHIVE
            if problem is not None:
                if listed.get(problem, 0) < MEMBER_REFUSALS_LISTED:
                    listed[problem] = listed.get(problem, 0) + 1
                    self._refuse_member(archive, member_name, problem)
                else:
                    unlisted[problem] = unlisted.get(problem, 0) + 1
                continue

            ASH_LOGGER.verbose(f"Found .{member_ext} file: {member}")
            filtered_members.append(member)
        for problem, count in unlisted.items():
            if archive is None:
                ASH_LOGGER.warning(f"Skipped {count} more archive members: {problem}")
            else:
                self.record_refused_input(
                    TreeInputRefused(archive, problem), unlisted_members=count
                )
        return filtered_members

    def convert(self) -> List[Path]:
        """Convert archive files by extracting their contents.

        Args:
            target: Optional target path to convert. If None, all archives in source_dir are extracted.

        Returns:
            List[Path]: List of paths to extracted files
        """
        # TODO : Convert utils/identifyipynb.sh script to python using nbconvert as lib
        ASH_LOGGER.debug(
            f"Searching for archive files in search_path within the ASH scan set: {self.context.source_dir}"
        )

        # Find all archive files to scan from the scan set
        archive_files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
            honor_ignore_files=honors_ignore_files(self.context.config),
        )
        archive_files = [
            f.strip()
            for f in archive_files
            if f.strip().split(".")[-1].lower() in ARCHIVE_SUFFIXES
        ]

        ASH_LOGGER.debug(f"Found {len(archive_files)} files to convert in scan set.")
        results: List[Path] = []

        # Add warning if no archive files found
        if not archive_files:
            ASH_LOGGER.info(
                f"No archive files (.zip, .tar, .gz) found in {self.context.source_dir}"
            )
            return results

        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Shared by every archive below; only an archive that is extracted uses it.
        scan_budget = _ScanBudget()
        for archive_file in archive_files:
            # Whether this iteration made the archive's target directory, so a
            # failure part way through removes what it wrote and nothing else.
            created_target: Optional[Path] = None
            archive_display = relative_display(archive_file, self.context.source_dir)
            try:
                skip_item = False
                # Skip directories
                if Path(archive_file).is_dir():
                    ASH_LOGGER.debug(f"Skipping directory: {archive_file}")
                    skip_item = True
                else:
                    for ignore_path in self.context.config.global_settings.ignore_paths:
                        rel_path = (
                            Path(archive_file)
                            .relative_to(self.context.source_dir)
                            .as_posix()
                        )
                        if path_matches_pattern(rel_path, ignore_path.path):
                            ASH_LOGGER.debug(
                                f"Skipping conversion of ignored path: {archive_file} due to global ignore_path '{ignore_path.path}' with reason '{ignore_path.reason}'"
                            )
                            skip_item = True
                            break
                if skip_item:
                    continue

                short_archive_file = get_shortest_name(archive_file)
                normalized_archive_file = get_normalized_filename(short_archive_file)
                target_path = self.results_dir.joinpath(normalized_archive_file)
                ASH_LOGGER.verbose(
                    f"Extracting {archive_file} contents to target_path: {Path(target_path).as_posix()}"
                )

                # Opened under the scanned-tree rule, and everything below reads from
                # this handle rather than reopening the path, so the archive that is
                # extracted is the one that was checked.
                try:
                    archive_handle = self.open_source_file(archive_file)
                except TreeInputRefused as refused:
                    self.record_refused_input(refused)
                    continue

                with archive_handle:
                    # Every member is admitted against the extraction limits before
                    # anything is written, and the target directory is created only
                    # after that, so a refused archive leaves nothing behind.
                    budget = _ExtractionBudget(
                        self._extraction_limits(),
                        os.fstat(archive_handle.fileno()).st_size,
                        scan=scan_budget,
                    )

                    # Extract ZIP to target path after inspecting members
                    is_zip = archive_file.lower().endswith(
                        ".zip"
                    ) and zipfile.is_zipfile(archive_handle)
                    archive_handle.seek(0)
                    if is_zip:
                        with zipfile.ZipFile(archive_handle, "r") as zip_ref:
                            zip_members = zip_ref.infolist()
                            for info in zip_members:
                                budget.admit(info.filename, info.file_size)
                            if not target_path.exists():
                                created_target = target_path
                            target_path.mkdir(parents=True, exist_ok=True)
                            # zipfile stops each member's output at the size its
                            # entry declares, so the declared sizes admitted above
                            # bound what is written.
                            zip_ref.extractall(
                                path=target_path,
                                members=self.inspect_members(
                                    zip_members,
                                    target_path=target_path,
                                    archive=archive_display,
                                ),
                            )
                    # Extract Tarball to target path after inspecting members
                    elif tarfile.is_tarfile(archive_handle):
                        archive_handle.seek(0)
                        with tarfile.open(
                            fileobj=archive_handle, mode="r:*", encoding="utf-8"
                        ) as tar_ref:
                            tar_members = _tar_members_within(tar_ref, budget)
                            if not target_path.exists():
                                created_target = target_path
                            target_path.mkdir(parents=True, exist_ok=True)
                            # Both paths below write no more than each member
                            # declares: _copy_tar_members copies at most that, and
                            # extractall does once inspect_members has refused a
                            # sparse map that reaches past the declared size.
                            safe_members = self.inspect_members(
                                tar_members,
                                target_path=target_path,
                                archive=archive_display,
                            )
                            if _TAR_HAS_DATA_FILTER:
                                tar_ref.extractall(  # nosec B202
                                    path=target_path,
                                    members=safe_members,
                                    filter="data",
                                )
                            else:
                                _copy_tar_members(tar_ref, safe_members, target_path)
                    else:
                        archive_handle.seek(0)
                        if _is_plain_gzip(archive_file, archive_handle.read(2)):
                            # data.json.gz: one compressed file, not an archive of
                            # files. There is nothing to extract.
                            ASH_LOGGER.debug(
                                f"Skipping {archive_file}: a gzip-compressed file, "
                                "not an archive"
                            )
                            continue
                        raise _UnreadableArchive(
                            "it is not a zip or tar archive that can be read"
                        )

                # Add the extracted directory to results
                results.append(target_path)
                scan_budget.commit(budget)
            except IsADirectoryError:
                ASH_LOGGER.debug(f"Skipping directory: {archive_file}")
            except _ExtractionLimitExceeded as exceeded:
                # The whole archive, not a member: none of it reaches the scanners,
                # so the record carries the limit, which the completeness gate
                # reads.
                self.record_refused_input(
                    TreeInputRefused(archive_display, exceeded.reason),
                    limit=exceeded.option,
                )
            except Exception as e:
                # Named for the converter, a .zip, .tar or .gz it could not read: a
                # bad CRC, a truncated or damaged stream, a gzip-compressed file
                # that is not a tarball, an empty file. None of it is scanned, and
                # whatever was written before the failure is removed, so the
                # scanners do not read a partial extraction as the archive.
                if created_target is not None:
                    shutil.rmtree(created_target, ignore_errors=True)
                reason = (
                    e.reason
                    if isinstance(e, _UnreadableArchive)
                    else f"it could not be read as an archive ({type(e).__name__}: {e})"
                )
                self.record_refused_input(
                    TreeInputRefused(archive_display, reason), scan_incomplete=True
                )

        return results
