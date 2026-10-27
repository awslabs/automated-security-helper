# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal of a named config file that is not there.

``resolve_config`` answers a named path that does not exist with the default
configuration and a warning. A scan and ``ash report`` check the path themselves
before they resolve anything. ``ash plugin list`` and ``ash dependencies install``
did not: the first listed the plugins of a configuration other than the one named,
and the second installed the dependencies of the built-in plugin set. Both call
:func:`refuse_a_named_config_that_does_not_exist` first, so the rule is written once
and each command prints the refusal in its own format.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.core.exceptions import ASHConfigFileNotFoundError
from automated_security_helper.utils.path_stat import (
    MISSING,
    StatProblem,
    stat_named_path,
)


def refuse_a_named_config_that_does_not_exist(config: Optional[str]) -> None:
    """Raise ``ASHConfigFileNotFoundError`` when ``config`` names a file that is
    not there.

    The message is ``Configuration file not found: <path>``, the words ``ash report``
    and a scan use. The path is shown through ``describe_config_path``, so its
    control characters are escaped and the message is one line. The caller prints it
    in its own format and exits 3.

    Only a path whose stat says it is missing (``path_stat.MISSING``) is refused
    here. These are left to ``resolve_config``, as they were:

    - no value, and a blank one;
    - the file ASH_CONFIG names (``config`` equal to ``os.environ["ASH_CONFIG"]``),
      which ``get_default_config`` refuses in the words reserved for ASH_CONFIG;
    - a link loop, a denied stat, a directory and a file that does not parse, which
      ``resolve_config`` refuses already.
    """
    if config is None or not config.strip():
        return
    if config == os.environ.get("ASH_CONFIG"):
        return
    answer = stat_named_path(config)
    if isinstance(answer, StatProblem) and answer.kind == MISSING:
        raise ASHConfigFileNotFoundError(
            f"Configuration file not found: {describe_config_path(Path(config))}"
        )
