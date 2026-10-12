# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How to keep a setting ASH dropped from a config file the operator did not write.

``resolve_config`` confines five things a config file inside a git checkout or the
scanned directory, or one an MCP client supplied, may not choose: the sandbox grants
(``config/sandbox_grants.py``), ``ash_plugin_modules``
(``config/plugin_module_trust.py``), detect-secrets' scan settings
(``config/secret_verification_trust.py``), ``honor_ignore_files`` and the archive
extraction limits (``config/archive_limits.py``). Each one warns when it drops or
caps a setting, naming the file and the setting, and every one of those warnings
ends with :data:`KEEP_A_SETTING`, so the remedy reads the same wherever the setting
was. An option that sets one of them directly (``--ash-plugin-modules``,
``--no-honor-ignore-files``) is named after it.

Kept free of imports, so any of those modules can use it without an import cycle.
"""

#: The remedy every confinement warning gives.
KEEP_A_SETTING = (
    "To keep a setting, move the file outside every git checkout, or pass the "
    "setting with --config-overrides. A file inside the scanned directory has to "
    "move out of it as well."
)
