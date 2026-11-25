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

from automated_security_helper.config import session_paths as _moved

sys.modules[__name__] = _moved
