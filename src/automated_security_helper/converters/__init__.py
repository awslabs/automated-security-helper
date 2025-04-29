# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.converters.ash_default import (
    ArchiveConverter,
    JupyterConverter,
)

# Make plugins discoverable
ASH_CONVERTERS = [ArchiveConverter, JupyterConverter]
