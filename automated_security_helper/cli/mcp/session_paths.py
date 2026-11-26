# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Compatibility path for ``automated_security_helper.config.session_paths``.

The module moved down into ``config`` because the config trust layer judges
whether a file reached the scan through an MCP client, and that judgment needs
this module's path rules. The layer order is ``cli -> config``, so the code
cannot stay here. This module IS the config module (it replaces itself in
``sys.modules``), so ``from ...cli.mcp.session_paths import x`` and a patch on
``automated_security_helper.cli.mcp.session_paths.x`` act on the one set of
objects.
"""

import sys
from typing import TYPE_CHECKING

from automated_security_helper.config import session_paths as _moved

if TYPE_CHECKING:
    # For type checkers and IDEs only, which do not follow the ``sys.modules``
    # swap below and would see a module that defines nothing. The star import
    # follows the module's ``__all__``, which ``config.session_paths`` defines, so
    # it brings the public names listed there and no underscore name. The private
    # names the tests reach through this path are therefore listed, each as
    # ``_a as _a`` to mark it a deliberate re-export.
    from automated_security_helper.config.session_paths import *  # noqa: F401,F403
    from automated_security_helper.config.session_paths import (  # noqa: F401
        _ALLOWED_COMPONENT as _ALLOWED_COMPONENT,
        _listable_parents_warned as _listable_parents_warned,
    )

sys.modules[__name__] = _moved
