# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How to keep a setting ASH dropped from a config file the operator did not write.

``resolve_config`` confines what a config file inside a git checkout or the scanned
directory, or one an MCP client supplied, may not choose. The steps
``confine_to_trusted_base`` runs (the sandbox grants, ``ash_plugin_modules``, the
reporters' destinations, the scanners' own config files and ``tool_version``) end
their warnings with ``untrusted_source.IN_TREE_OR_DELIVERED.remedy``, which is
:data:`KEEP_A_SETTING`; the content database staleness step does the same, and
detect-secrets' scan settings (``config/secret_verification_trust.py``),
``honor_ignore_files``, the archive extraction limits (``config/archive_limits.py``)
and the refusal of a tool path such a file names (``config/path_trust.py``) append
it directly. Each warning names the file and the setting, so the remedy reads the
same wherever the setting was. An option that sets one of them directly
(``--ash-plugin-modules``, ``--no-honor-ignore-files``, ``--allow-stale-content-db``)
is named after it.

Kept free of imports, so any of those modules can use it without an import cycle.
"""

#: The remedy every confinement warning gives.
KEEP_A_SETTING = (
    "To keep a setting, move the file outside every git checkout, or pass the "
    "setting with --config-overrides. A file inside the scanned directory has to "
    "move out of it as well."
)
