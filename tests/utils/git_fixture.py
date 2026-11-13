# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run plain git for a test: building fixture repositories and checking git itself.

Tests that need a real repository, or need to show what plain git does with an
argument, call :func:`run_git` instead of ``subprocess.run`` so the call, and the
bandit annotation it carries, is written once. Plain git on purpose: this is not
``utils/git_command.git_argv``, because several tests compare ASH's git commands
with what git does without ASH's options.
"""

from __future__ import annotations

import subprocess  # nosec B404 -- the one place tests start git for fixture repositories
from pathlib import Path
from typing import Mapping, Optional, Union


def run_git(
    *args: str,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Mapping[str, str]] = None,
    check: bool = False,
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    """``git <args>`` in *cwd*, output captured as text.

    *env* replaces the process environment when given, as with ``subprocess.run``.
    *check* raises ``CalledProcessError`` on a non-zero exit.
    """
    return subprocess.run(  # nosec B603 B607 -- list argv, no shell, fixture repositories only
        ["git", *args],
        cwd=cwd,
        env=None if env is None else dict(env),
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )
