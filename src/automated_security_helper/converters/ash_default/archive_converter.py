# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the JupyterScanner implementation."""

from pathlib import Path
import tarfile
from typing import Annotated, List, Literal
import zipfile

from pydantic import Field

from automated_security_helper.core.constants import KNOWN_SCANNABLE_EXTENSIONS
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)

from automated_security_helper.base.options import (
    ConverterOptionsBase,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename


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


class ArchiveConverter(ConverterPluginBase[ArchiveConverterConfig]):
    """Converter implementation for Archive file extraction."""

    def model_post_init(self, context):
        self.work_dir = (
            self.output_dir.joinpath("converted")
            .joinpath("converters")
            .joinpath("archive")
        )
        if self.config is None:
            self.config = ArchiveConverterConfig()
        return super().model_post_init(context)

    def validate(self):
        # Return True since this scanner is entirely within the same Python module,
        # so there is nothing further to validate in terms of availability.
        return True

    def inspect_members(self, members: List[str | zipfile.ZipInfo | tarfile.TarInfo]):
        ASH_LOGGER.debug(f"Inspecting {len(members)} members from archive")
        filtered_members = []
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                member_ext = member.name.split(".")[-1]
            elif isinstance(member, zipfile.ZipInfo):
                member_ext = member.filename.split(".")[-1]
            elif isinstance(member, str):
                member_ext = member.split(".")[-1]
            else:
                ASH_LOGGER.debug(
                    f"Skipping uknown extension from archive: {type(member)}"
                )
                continue
            if member_ext in KNOWN_SCANNABLE_EXTENSIONS:
                ASH_LOGGER.debug(f"Found .{member_ext} file: {member}")
                filtered_members.append(member)
        return filtered_members

    def convert(
        self,
    ) -> List[Path]:
        # TODO : Convert utils/identifyipynb.sh script to python using nbconvert as lib
        ASH_LOGGER.debug(
            f"Searching for archive files in search_path within the ASH scan set: {self.source_dir}"
        )
        # Find all archive files to scan from the scan set
        archive_files = scan_set(
            source=self.source_dir,
            output=self.output_dir,
        )
        archive_files = [
            f.strip()
            for f in archive_files
            if f.strip().split(".")[-1] in ["zip", "tar", "gz"]
        ]
        ASH_LOGGER.debug(f"Found {len(archive_files)} files to convert in scan set.")
        results: List[Path] = []
        for archive_file in archive_files:
            short_archive_file = get_shortest_name(archive_file)
            normalized_archive_file = get_normalized_filename(short_archive_file)
            target_path = self.work_dir.joinpath(self.config.name).joinpath(
                normalized_archive_file
            )
            ASH_LOGGER.verbose(
                f"Extracting {archive_file} contents to target_path: {Path(target_path).as_posix()}"
            )
            # Extract ZIP to target path after inspecting members
            if archive_file.endswith(".zip") and zipfile.is_zipfile(archive_file):
                with zipfile.ZipFile(archive_file, "r") as zip_ref:
                    zip_ref.extractall(
                        path=target_path,
                        members=self.inspect_members(zip_ref.filelist),
                    )
            # Extract Tarball to target path after inspecting members
            elif tarfile.is_tarfile(archive_file):
                with tarfile.open(archive_file, "r") as tar_ref:
                    tar_ref.extractall(
                        path=target_path,
                        members=self.inspect_members(tar_ref.getmembers()),
                    )
            else:
                ASH_LOGGER.error(
                    f"Unsupported/undeterminable archive format: {archive_file}"
                )
                continue
            results.append(Path(target_path))

        return results
