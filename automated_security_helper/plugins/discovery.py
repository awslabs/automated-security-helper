# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import pkgutil
from typing import List
from automated_security_helper.utils.log import ASH_LOGGER


def discover_plugins(plugin_modules: List[str] = ["ash_plugins"]):
    """Discover plugins in the given namespace"""
    discovered = {"converters": [], "scanners": [], "reporters": []}

    # Look for packages with the ash_plugins namespace
    for finder, name, ispkg in pkgutil.iter_modules():
        for namespace in plugin_modules:
            if name.startswith(namespace) and ispkg:
                try:
                    # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                    module = importlib.import_module(name)
                    # The import itself should trigger plugin registration
                    # via the AshPlugin metaclass
                    ASH_LOGGER.info(f"Discovered plugin package: {name}")

                    # Track what was discovered
                    if hasattr(module, "ASH_CONVERTERS"):
                        discovered["converters"].extend(module.ASH_CONVERTERS)
                    if hasattr(module, "ASH_SCANNERS"):
                        discovered["scanners"].extend(module.ASH_SCANNERS)
                    if hasattr(module, "ASH_REPORTERS"):
                        discovered["reporters"].extend(module.ASH_REPORTERS)

                except ImportError as e:
                    ASH_LOGGER.warning(f"Failed to import plugin {name}: {e}")

    return discovered
