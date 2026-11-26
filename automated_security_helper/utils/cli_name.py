# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The name of the console script v4 installs as the canonical command.

Everything that names the command in a message or an argv reads it from here, so a
rename is one edit. It lives in ``utils`` rather than in ``cli`` because three of its
readers sit below the CLI in the layer order tests/unit/test_layer_dag_boundaries.py
holds: the container argv (``interactions/run_ash_container.py``), cdk-nag's SARIF
``commandLine`` (a plugin) and the sandboxed install refusal in
``utils/uv_tool_runner.py``. Every package may read ``utils``; ``utils`` and the
plugins may not read ``cli``. ``cli/deprecations.py`` re-exports the name for the
CLI's own readers and keeps the deprecated command aliases that point at it.
"""

CANONICAL_CLI_NAME = "ashx"
