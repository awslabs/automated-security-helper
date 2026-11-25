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

from automated_security_helper.config import session_profiles as _moved

sys.modules[__name__] = _moved
