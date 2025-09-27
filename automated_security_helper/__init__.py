# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib.metadata

try:
    __version__ = importlib.metadata.version("automated_security_helper")
except importlib.metadata.PackageNotFoundError:
    __version__ = "3.0.1"  # Fallback version for development
