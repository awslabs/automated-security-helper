# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/setup-nerdctl-linux.sh``'s worker check refuses a present OCI worker.

Why this file exists
--------------------
The script writes a buildkitd.toml that disables the OCI worker, restarts
buildkitd and then asserts the result from ``buildctl debug workers``. That
assertion was one grep for the containerd executor label over the whole worker
list. A no-config buildkitd registers both workers, with the OCI one as default,
so the containerd label was in that list too and the check passed in exactly the
state it exists to refuse: the toml not applied, and ``nerdctl build`` unable to
see the pre-pulled base image.

The check must find the containerd executor AND find no OCI executor. The script
needs root and systemd, so this is a text assertion over the ``if`` that guards
the refusal, in the idiom of the sibling file.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP = REPO_ROOT / "scripts" / "setup-nerdctl-linux.sh"
EXECUTOR = "org.mobyproject.buildkit.worker.executor"


def _worker_check_condition() -> str:
    """The text of the ``if`` condition that greps the executor label."""
    body = SETUP.read_text(encoding="utf-8")
    # The condition may span continued lines; join them before matching.
    joined = body.replace("\\\n", " ")
    conditions = [
        m.group(1)
        for m in re.finditer(r"^if (.+?); then$", joined, flags=re.MULTILINE)
        if EXECUTOR in m.group(1)
    ]
    assert len(conditions) == 1, conditions
    return conditions[0]


def test_the_check_requires_the_containerd_executor():
    """The control: the assertion the script always had."""
    condition = _worker_check_condition()
    assert re.search(rf'! grep -q \'"{re.escape(EXECUTOR)}":"containerd"\'', condition)


def test_the_check_refuses_a_registered_oci_worker():
    condition = _worker_check_condition()
    assert re.search(rf'\|\| grep -q \'"{re.escape(EXECUTOR)}":"oci"\'', condition), (
        "the worker check accepts a list that still holds the OCI worker, which is "
        "what a no-config buildkitd reports with the OCI worker as default"
    )


def test_the_refusal_names_both_readings():
    body = SETUP.read_text(encoding="utf-8")
    assert "or the OCI worker is still registered" in body
