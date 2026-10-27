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

A file whose name walk stopped before the end is not known to be in a checkout, so
moving it out of one is no remedy: :data:`KEEP_A_SETTING_WHEN_THE_WALK_STOPPED` and
:data:`KEEP_A_SETTING_BESIDE_A_LOCATED_FILE` take its place in those warnings.

:data:`SET_BY_THE_OPERATOR` is the same rule as a scanner option's description
states it: the options ``config/tool_config_trust.py`` takes from the trusted base
(a scanner's own config file and the options that choose part of it) describe who
may set them with it, so the descriptions, the JSON schemas built from them and the
reference pages say the same thing.

Kept free of imports, so any of those modules can use it without an import cycle.
"""

#: The remedy every confinement warning gives.
KEEP_A_SETTING = (
    "To keep a setting, move the file outside every git checkout, or pass the "
    "setting with --config-overrides. A file inside the scanned directory has to "
    "move out of it as well."
)

#: What to do about a file ASH read as the repository's only because resolving its
#: name stopped before the end (``sandbox_grants.confined_files``'s undecided
#: answer). The file is not known to be in a checkout, so moving it out of one
#: changes nothing: the walk has to be able to finish. It ends undecided at a
#: directory it cannot search, at a link it cannot read, and at the bound on the
#: links it follows; the text names each.
LET_THE_WALK_FINISH = (
    "make each directory on the file's path searchable and each link on it "
    "readable, and name the file through fewer links if it goes through a long "
    "chain of them, so that ASH can resolve the file's name to the end"
)

#: The remedy a warning gives for a file whose name walk stopped, in place of
#: :data:`KEEP_A_SETTING`.
KEEP_A_SETTING_WHEN_THE_WALK_STOPPED = (
    f"To keep a setting, pass it with --config-overrides, or {LET_THE_WALK_FINISH}."
)

#: The same where the line also holds a file found in a checkout or the scanned
#: directory: that one moves out as above, and the one whose walk stopped is made
#: resolvable instead.
KEEP_A_SETTING_BESIDE_A_LOCATED_FILE = (
    f"{KEEP_A_SETTING} For a file whose name walk stopped, instead "
    f"{LET_THE_WALK_FINISH}."
)

#: Who sets an option that only the operator chooses, as the option's description
#: gives it.
SET_BY_THE_OPERATOR = (
    "Used only when the operator sets it, with --config-overrides or in a config "
    "file outside every git checkout and the scanned directory: a config file "
    "inside one, or one an MCP client delivered, does not choose it."
)
