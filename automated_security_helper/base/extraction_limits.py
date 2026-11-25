# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The converter options that bound what extracting an archive can write.

Declared here, in the plugin contract, because two layers need the names: the
archive converter (which owns the options) and the config trust layer (which lets
a config file inside the scanned tree lower them but not raise them, see
``config/archive_limits.py``). The config layer cannot import the converter, so
the names live below both.
"""

#: The options of the archive converter's options model that bound what extracting
#: an archive can write. A config file inside the scanned tree can lower them but
#: not raise them.
EXTRACTION_LIMIT_OPTIONS = (
    "max_members",
    "max_member_bytes",
    "max_total_bytes",
    "max_compression_ratio",
)
