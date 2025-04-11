# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the JupyterScanner implementation."""

from pathlib import Path
import tarfile
from typing import Annotated, List, Literal
import zipfile

from pydantic import Field

from automated_security_helper.models.converter_plugin import ConverterPlugin
from automated_security_helper.models.core import (
    ConverterBaseConfig,
    ConverterPluginConfig,
)
from automated_security_helper.models.core import (
    BaseConverterOptions,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER


class ArchiveConverterConfigOptions(BaseConverterOptions):
    pass


class ArchiveConverterConfig(ConverterBaseConfig):
    """Archive (ZIP/TAR/GZIP/etc) converter configuration."""

    name: Literal["archive"] = "archive"
    options: Annotated[
        ArchiveConverterConfigOptions,
        Field(description="Configure Archive converter"),
    ] = ArchiveConverterConfigOptions()


class ArchiveConverter(ConverterPlugin, ArchiveConverterConfig):
    """Converter implementation for Archive file extraction."""

    options: ArchiveConverterConfigOptions = ArchiveConverterConfigOptions()

    def model_post_init(self, context):
        self.options
        self.work_dir = (
            self.output_dir.joinpath("work").joinpath("converters").joinpath("archive")
        )
        return super().model_post_init(context)

    def configure(
        self,
        config: ConverterPluginConfig | None = None,
        options: ArchiveConverterConfigOptions | None = None,
    ) -> None:
        """Configure the scanner with provided settings."""
        super().configure(config=config, options=options)

    def validate(self):
        # Return True since this scanner is entirely within the same Python module,
        # so there is nothing further to validate in terms of availability.
        return True

    def convert(
        self,
    ) -> List[Path]:
        # TODO : Convert utils/identifyipynb.sh script to python using nbconvert as lib
        ASH_LOGGER.debug(
            f"Searching for .ipynb files in search_path within the ASH scan set: {self.source_dir}"
        )
        # Find all JSON/YAML files to scan from the scan set
        archive_files = scan_set(
            source=self.source_dir,
            output=self.output_dir,
            # filter_pattern=r"\.(ipynb)",
        )
        archive_files = [
            f.strip()
            for f in archive_files
            if f.strip().endswith(".zip")
            or f.strip().endswith(".tar")
            or f.strip().endswith(".tar.gz")
        ]
        ASH_LOGGER.debug(f"Found {len(archive_files)} .ipynb files in scan set.")
        results: List[Path] = []
        for archive_file in archive_files:
            normalized_archive_file = self.get_normalized_filename(archive_file)
            target_path = self.work_dir.joinpath(normalized_archive_file)
            ASH_LOGGER.debug(
                f"Extracting {archive_file} contents to target_path: {target_path.as_posix()}"
            )
            # Extract archive to target path
            if archive_file.endswith(".zip") and zipfile.is_zipfile(archive_file):
                with zipfile.ZipFile(archive_file, "r") as zip_ref:
                    zip_ref.extractall(target_path)
            elif tarfile.is_tarfile(archive_file):
                with tarfile.open(archive_file, "r") as tar_ref:
                    tar_ref.extractall(target_path)
            else:
                ASH_LOGGER.error(
                    f"Unsupported/undeterminable archive format: {archive_file}"
                )
                continue
            results.append(Path(target_path))

        return results
