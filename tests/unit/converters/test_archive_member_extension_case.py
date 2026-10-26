# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""An archive member is selected on its suffix whatever case the suffix is in."""

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)


def test_members_with_uppercase_suffixes_are_extracted(test_plugin_context):
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    members = converter.inspect_members(
        ["Main.JS", "lib/Config.JSON", "lib/notes.txt", "README", "a.unknownext"]
    )

    assert members == ["Main.JS", "lib/Config.JSON", "lib/notes.txt"]
