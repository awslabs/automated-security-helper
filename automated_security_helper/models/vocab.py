# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Vocabularies shared by more than one layer of the package.

This module imports nothing from the package (standard-library ``enum`` only), so
core, config, base, cli, utils and plugin modules can all import it without a
cycle. A vocabulary used inside one module or one small cluster lives in that
module instead.

Every enum here is a ``(str, Enum)``: a member IS its wire string, compares equal
to it, and serializes as it. ``enum.StrEnum`` is 3.11+ and the project floor is
3.10, so the mixin form is the one that works everywhere.
"""

from __future__ import annotations

from enum import Enum


class TargetType(str, Enum):
    """Which tree a scanner is asked to scan: the source tree or the converted one.

    ``SOURCE`` is the directory the user pointed ASH at. ``CONVERTED`` is the work
    directory holding what converters produced from archives and notebooks. The
    wire spellings (``"source"`` / ``"converted"``) are in result files, identity
    keys and log lines and never change.

    ``__str__`` returns the value so ``f"{target_type}"`` and ``str(target_type)``
    render ``source`` on every supported interpreter. Without it the rendering of a
    mixed-in ``str`` enum differs across 3.10, 3.11 and 3.12 (``TargetType.SOURCE``
    on some), and scanner modules that interpolate the label into messages and
    paths would change with the interpreter.
    """

    SOURCE = "source"
    CONVERTED = "converted"

    def __str__(self) -> str:
        return self.value
