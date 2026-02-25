# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the ArchiveConverter implementation."""

import os
from pathlib import Path
import tarfile
from typing import Annotated, List, Literal, Optional
import zipfile

from pydantic import Field

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
from automated_security_helper.utils.sarif_utils import path_matches_pattern


class ArchiveConverterConfigOptions(ConverterOptionsBase):
    pass


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

    def inspect_members(
        self,
        members: List[str | zipfile.ZipInfo | tarfile.TarInfo],
        target_path: Optional[Path] = None,
    ):
        ASH_LOGGER.verbose(f"Inspecting {len(members)} members from archive")
        filtered_members = []
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                member_name = member.name
                member_ext = member_name.split(".")[-1]

                # Reject symlinks and hard links in tar archives
                if member.issym() or member.islnk():
                    ASH_LOGGER.warning(
                        f"Skipping symbolic/hard link in archive: {member_name}"
                    )
                    continue
            elif isinstance(member, zipfile.ZipInfo):
                member_name = member.filename
                member_ext = member_name.split(".")[-1]
            elif isinstance(member, str):
                member_name = member
                member_ext = member.split(".")[-1]
            else:
                ASH_LOGGER.debug(
                    f"Skipping uknown extension from archive: {type(member)}"
                )
                continue

            # Validate path safety when target_path is provided
            if target_path is not None and self._is_path_traversal(
                member_name, target_path
            ):
                ASH_LOGGER.warning(
                    f"Skipping archive member with path traversal: {member_name}"
                )
                continue

            if member_ext in KNOWN_SCANNABLE_EXTENSIONS:
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
            if f.strip().split(".")[-1] in ["zip", "tar", "gz"]
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

                # Create target directory if it doesn't exist
                target_path.mkdir(parents=True, exist_ok=True)

                # Extract ZIP to target path after inspecting members
                if archive_file.endswith(".zip") and zipfile.is_zipfile(archive_file):
                    with zipfile.ZipFile(archive_file, "r") as zip_ref:
                        zip_ref.extractall(
                            path=target_path,
                            members=self.inspect_members(
                                zip_ref.filelist, target_path=target_path
                            ),
                        )
                # Extract Tarball to target path after inspecting members
                elif tarfile.is_tarfile(archive_file):
                    with tarfile.open(
                        archive_file, mode="r", encoding="utf-8"
                    ) as tar_ref:
                        tar_ref.extractall(
                            path=target_path,
                            members=self.inspect_members(
                                tar_ref.getmembers(), target_path=target_path
                            ),
                        )
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
