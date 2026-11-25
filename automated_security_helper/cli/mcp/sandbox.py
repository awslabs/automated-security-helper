# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Compatibility path for ``automated_security_helper.config.mcp_sandbox``.

The MCP session sandbox moved down into ``config`` because the config trust
layer decides whether a config file is client-supplied
(``config_is_client_supplied``) by the sandbox's path rules, and the layer order
is ``cli -> config``. This module IS the config module (it replaces itself in
``sys.modules``), so imports through this path and a patch on
``automated_security_helper.cli.mcp.sandbox.x`` act on the one set of objects.
"""

import sys

from automated_security_helper.config import mcp_sandbox as _moved

sys.modules[__name__] = _moved
