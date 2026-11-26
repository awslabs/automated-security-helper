# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The name of the command v4 installs, for the layers below ``cli``.

Container mode, the plugins and the uv tool runner name the command in the
messages they print, and the layer order (tests/unit/test_layer_dag_boundaries.py)
keeps them from importing the ``cli`` package, so the constant lives here and
``cli.deprecations`` reads it from here for its table of deprecated aliases.
"""

#: The console script v4 installs as the canonical command. Everything that
#: names the command in a message reads it from here, so a rename is one edit.
CANONICAL_CLI_NAME = "ashx"
