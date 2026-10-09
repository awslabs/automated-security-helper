# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the ArchiveConverter implementation."""

import os
import shutil
import stat
from pathlib import Path, PurePosixPath
import tarfile
from typing import Annotated, List, Literal, Optional
import zipfile

from pydantic import Field

from automated_security_helper.models.core import ignore_paths_that_skip_scanning
from automated_security_helper.core.constants import (
    KNOWN_SCANNABLE_EXTENSIONS,
)
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import scan_set
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


class ArchiveConverterConfigOptions(ConverterOptionsBase):
    pass


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


def _copy_tar_members(
    tar_ref: tarfile.TarFile, members: List[tarfile.TarInfo], target_path: Path
) -> None:
    """Write each member's bytes under ``target_path``, applying none of its metadata.

    For a Python whose tarfile has no "data" filter. ``extractall`` without one applies
    each member's mode, owner and times, so a setuid bit or a foreign owner (when ASH
    runs as root) would carry over. The members reaching here are regular files whose
    names inspect_members has already checked, so copying their content is all there
    is to do. Each file is created without following a link at its name.
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
            shutil.copyfileobj(source, out)


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
        return super().model_post_init(context)

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
        regular file, or has a name that is absolute, contains ``..`` or would land
        outside ``target_path``. Members without a scannable extension are left out
        silently, as before, so a refusal is only reported for a member that would
        otherwise have been extracted.

        Args:
            members: The archive's members.
            target_path: The extraction directory. The escape check needs it, so it
                is skipped when this is None.
            archive: The archive's path relative to the scanned tree. When given, each
                refusal is also recorded in the converter's results row.
        """
        ASH_LOGGER.verbose(f"Inspecting {len(members)} members from archive")
        filtered_members = []
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                member_name = member.name
                if member.isdir():
                    continue
                is_link = member.issym() or member.islnk()
                is_regular = member.isreg()
            elif isinstance(member, zipfile.ZipInfo):
                member_name = member.filename
                if member.is_dir():
                    continue
                # Unix mode bits live in the high 16 bits of external_attr. zipfile
                # writes a symlink entry out as a file holding the link's target, so
                # it would not become a link, but it is not a file either.
                is_link = stat.S_ISLNK(member.external_attr >> 16)
                is_regular = True
            elif isinstance(member, str):
                member_name = member
                is_link = False
                is_regular = True
            else:
                ASH_LOGGER.debug(
                    f"Skipping uknown extension from archive: {type(member)}"
                )
                continue

            member_ext = member_name.split(".")[-1]
            if member_ext not in KNOWN_SCANNABLE_EXTENSIONS:
                continue

            problem = _member_name_problem(member_name)
            if problem is None and target_path is not None:
                if self._is_path_traversal(member_name, target_path):
                    problem = _MEMBER_ESCAPES
            if problem is None and is_link:
                problem = _MEMBER_LINK
            if problem is None and not is_regular:
                problem = _MEMBER_NOT_REGULAR
            if problem is not None:
                self._refuse_member(archive, member_name, problem)
                continue

            ASH_LOGGER.verbose(f"Found .{member_ext} file: {member}")
            filtered_members.append(member)
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
        )
        archive_files = [
            f.strip()
            for f in archive_files
            if f.strip().split(".")[-1].lower() in ["zip", "tar", "gz"]
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

        for archive_file in archive_files:
            try:
                skip_item = False
                # Skip directories
                if Path(archive_file).is_dir():
                    ASH_LOGGER.debug(f"Skipping directory: {archive_file}")
                    skip_item = True
                else:
                    for ignore_path in ignore_paths_that_skip_scanning(
                        self.context.config.global_settings.ignore_paths
                    ):
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

                archive_display = relative_display(
                    archive_file, self.context.source_dir
                )

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
                    # Create target directory if it doesn't exist
                    target_path.mkdir(parents=True, exist_ok=True)

                    # Extract ZIP to target path after inspecting members
                    is_zip = archive_file.lower().endswith(
                        ".zip"
                    ) and zipfile.is_zipfile(archive_handle)
                    archive_handle.seek(0)
                    if is_zip:
                        with zipfile.ZipFile(archive_handle, "r") as zip_ref:
                            zip_ref.extractall(
                                path=target_path,
                                members=self.inspect_members(
                                    zip_ref.infolist(),
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
                            safe_members = self.inspect_members(
                                tar_ref.getmembers(),
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
                        ASH_LOGGER.debug(
                            f"Skipping unsupported archive format: {archive_file}"
                        )
                        continue

                # Add the extracted directory to results
                results.append(target_path)
            except IsADirectoryError:
                ASH_LOGGER.debug(f"Skipping directory: {archive_file}")
            except Exception as e:
                ASH_LOGGER.error(f"Error processing archive {archive_file}: {e}")

        return results
