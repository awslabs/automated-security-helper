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
from typing import TYPE_CHECKING

from automated_security_helper.config import mcp_sandbox as _moved

if TYPE_CHECKING:
    # For type checkers and IDEs only, which do not follow the ``sys.modules``
    # swap below and would see a module that defines nothing. The star import
    # follows the module's ``__all__``, which ``config.mcp_sandbox`` defines, so
    # it brings the public names listed there and no underscore name. The
    # private names the tests reach through this path are therefore listed, each
    # as ``_a as _a`` to mark it a deliberate re-export.
    from automated_security_helper.config.mcp_sandbox import *  # noqa: F401,F403
    from automated_security_helper.config.mcp_sandbox import (  # noqa: F401
        _components_down_to as _components_down_to,
        _config_input_refusal as _config_input_refusal,
        _is_a_live_scan_copy_of_this_sessions_file as _is_a_live_scan_copy_of_this_sessions_file,
        _names_a_windows_share as _names_a_windows_share,
        _refusal as _refusal,
        _refusal_before_resolving as _refusal_before_resolving,
        _server_config_dir_refusal as _server_config_dir_refusal,
    )

sys.modules[__name__] = _moved
