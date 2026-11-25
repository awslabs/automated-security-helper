# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Compatibility path for ``automated_security_helper.config.session_profiles``.

The session profile registry moved down into ``config`` because the config
trust layer asks it whether a session's profile was changed by the client
(``session_config_was_patched``), and the layer order is ``cli -> config``. This
module IS the config module (it replaces itself in ``sys.modules``), so imports
through this path and a patch on
``automated_security_helper.cli.mcp.profile_registry.x`` act on the one set of
objects.
"""

import sys
from typing import TYPE_CHECKING

from automated_security_helper.config import session_profiles as _moved

if TYPE_CHECKING:
    # For type checkers and IDEs only, which do not follow the ``sys.modules``
    # swap below and would see a module that defines nothing. A star import skips
    # names with a leading underscore, so the private names the tests reach
    # through this path are listed.
    from automated_security_helper.config.session_profiles import *  # noqa: F401,F403
    from automated_security_helper.config.session_profiles import (  # noqa: F401
        _binding_write_locks,
        _rematerialize_binding,
        _replace_staged,
        _session_lock,
        _session_state,
    )

sys.modules[__name__] = _moved
