# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_spectral_plugins.spectral_scanner import (
    SpectralScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SpectralScanner,
]
ASH_REPORTERS: list[type] = []
