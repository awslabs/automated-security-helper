# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace re-mask masks tokens of the exposed values' shapes in reports.

Why this file exists
--------------------
The workspace masks every project's output again with the values all of its
projects exposed, and the per-project results file is re-masked as a model, so
it masks a token of a recorded value SHAPE as well as the value itself. The
rendered reports beside it, which cannot be re-rendered, were masked with
``mask_secret_values_in_text``, which takes values only: a value another project
knew only by its masked form was masked by shape in the results file and left in
clear in the HTML and text reports of the same tree.

The values are derived at import time, so this source holds no string a secret
scanner would report.
"""

from __future__ import annotations

import hashlib
import string

import pytest

from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.utils.secret_masking import _mask_secret_value
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


#: The value one project's finding exposed.
VALUE = _derived("remask-shapes-value", 16)
#: Another value of the same shape (the same visible characters and length),
#: which only the shape masker can reach: the values masker knows VALUE alone.
SAME_SHAPE = VALUE[:2] + _derived("remask-shapes-other", 16)[2:-1] + VALUE[-1:]


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _plant_report(tmp_path, key, text):
    reports = tmp_path / "out" / "projects" / key / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / "ash.html"
    path.write_text(f"<pre>{text}</pre>\n", encoding="utf-8")
    return path


def test_a_token_of_an_exposed_values_shape_is_masked_in_another_projects_report(
    tmp_path,
):
    assert SAME_SHAPE != VALUE
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="error", count=1),
        "secret_values": [VALUE],
    }
    planted = _plant_report(tmp_path, "web", SAME_SHAPE)

    outcome = _run(tmp_path, plan)

    statuses = {entry.project: entry.status for entry in outcome.payload.projects}
    assert statuses["web"] is ProjectRunStatus.COMPLETED
    masked = planted.read_text(encoding="utf-8")
    assert SAME_SHAPE not in masked, (
        "a token of an exposed value's shape stayed in clear in a rendered report "
        "while the results file masks the same token by shape"
    )
    assert _mask_secret_value(SAME_SHAPE) in masked


def test_the_value_itself_is_still_masked(tmp_path):
    """Must-not-regress control: the values masker's work is unchanged."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="error", count=1),
        "secret_values": [VALUE],
    }
    planted = _plant_report(tmp_path, "web", VALUE)

    _run(tmp_path, plan)

    masked = planted.read_text(encoding="utf-8")
    assert VALUE not in masked
    assert _mask_secret_value(VALUE) in masked


def test_an_ordinary_word_of_the_shape_is_kept(tmp_path):
    """Must-not-flag control: letters alone of the shape's length are no value."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("web", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="error", count=1),
        "secret_values": [VALUE],
    }
    word = VALUE[:2] + "x" * (len(VALUE) - 3) + VALUE[-1:]
    planted = _plant_report(tmp_path, "web", word)

    _run(tmp_path, plan)

    assert word in planted.read_text(encoding="utf-8")
