# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whether a test may write a file in the passwd entry's home directory.

The passwd entry's home (``pwd.getpwuid(os.getuid()).pw_dir``) is the real home of
the account the tests run as, whatever HOME says. A test may plant a file there
only in a CI job whose runner is thrown away with it, and only when that job asks
for it:

- ``GITHUB_ACTIONS`` is ``true``, and ``OPT_IN`` is ``1``. The variable is set
  only in the env of the sandbox job in .github/workflows/ash-unified-ci.yml, so a
  developer who exports ``GITHUB_ACTIONS`` or ``RUNNER_ENVIRONMENT`` by hand, or
  runs another job, is refused.
- Outside act, ``RUNNER_ENVIRONMENT`` is ``github-hosted``: a fresh virtual
  machine per job.
- Under act (``ACT`` set, whatever its value), the process must be in act's own
  job container, which act marks with ``/var/run/act``. act can run a job on the
  host instead (``-self-hosted``), where the passwd home is the host user's, and a
  container marker alone (``/.dockerenv``) would also be met inside a developer's
  own dev container.

Anywhere else the answer is the reason not to, and the test skips with it.

Not covered: a job that sets the opt-in on purpose somewhere its runner is not
thrown away. A process killed before its cleanup leaves the planted file behind,
which is why the guard is narrow.
"""

from __future__ import annotations

import os
from typing import Callable, Mapping, Optional

#: Set to "1" only by the sandbox job in .github/workflows/ash-unified-ci.yml.
OPT_IN = "ASH_ESCAPE_TEST_WRITES_PASSWD_HOME"

#: The directory act mounts into its job container for the run's own files.
ACT_JOB_CONTAINER_MARKER = "/var/run/act"


def passwd_home_write_refusal(
    environ: Optional[Mapping[str, str]] = None,
    is_dir: Optional[Callable[[str], bool]] = None,
) -> Optional[str]:
    """None when writing in the passwd home is safe here, otherwise why it is not."""
    environ = os.environ if environ is None else environ
    is_dir = os.path.isdir if is_dir is None else is_dir
    if environ.get("GITHUB_ACTIONS") != "true":
        return "not a GitHub Actions job (GITHUB_ACTIONS is not true)"
    if environ.get(OPT_IN) != "1":
        return f"this job does not opt in ({OPT_IN} is not 1)"
    if "ACT" in environ:
        if not is_dir(ACT_JOB_CONTAINER_MARKER):
            return (
                f"act without its job container ({ACT_JOB_CONTAINER_MARKER} is "
                "missing), so the passwd home may be the host user's"
            )
        return None
    if environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        return (
            "not a GitHub-hosted runner (RUNNER_ENVIRONMENT is not github-hosted), "
            "so the passwd home may be a real user's"
        )
    return None
