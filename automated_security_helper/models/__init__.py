# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Package models for Automated Security Helper (ASH).

The names below are loaded on first use, not at import. ``models.vocab`` imports
nothing from the package so that every layer can use it, including
``core.constants``, which ``models.asharp_model`` itself imports; an eager import
of those models here would make ``import automated_security_helper.models.vocab``
run them first and close that cycle.
"""

from importlib import import_module
from typing import Any

__all__ = [
    "ReportMetadata",
    "ExportFormat",
    "AshAggregatedResults",
    "FlatVulnerability",
]

_LAZY = {
    "ExportFormat": "automated_security_helper.core.enums",
    "ReportMetadata": "automated_security_helper.models.asharp_model",
    "AshAggregatedResults": "automated_security_helper.models.asharp_model",
    "FlatVulnerability": "automated_security_helper.models.flat_vulnerability",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
