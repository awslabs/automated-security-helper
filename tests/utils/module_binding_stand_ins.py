# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A module with a few attributes replaced, to stand in for one module's binding.

``monkeypatch.setattr(os, "open", ...)`` replaces the function on the shared
module for the whole process while the test runs: pathlib, logging and pytest
itself call it too. A module reads the standard library through its own name
for it (``error_handling.os``), and replacing that name reaches that module
alone. The stand-in has to answer every other attribute the module reads, so it
delegates what it does not replace to the real module; a bare namespace that
carries only the replaced attributes fails on the first other one the code
under test reads.
"""

import os
from typing import Any


class ModuleWith:
    """``module`` with the keyword arguments' attributes replaced."""

    def __init__(self, module: Any, **replacements: Any) -> None:
        self.__dict__.update(replacements)
        self._module = module

    def __getattr__(self, name: str) -> Any:
        # Called only for a name not set above. Reading ``_module`` before it is
        # set (a copy made without __init__) would recurse without this.
        if name == "_module":
            raise AttributeError(name)
        return getattr(self._module, name)


class OsWith(ModuleWith):
    """The ``os`` module with some functions replaced."""

    def __init__(self, **replacements: Any) -> None:
        super().__init__(os, **replacements)
