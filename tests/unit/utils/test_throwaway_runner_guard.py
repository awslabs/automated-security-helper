# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The guard on the escape test that plants files in the passwd entry's home.

Written only in a GitHub Actions job that opts in: on a GitHub-hosted runner, or
under act inside act's own job container. Every other combination refuses, with
the reason the test skips with.
"""

from __future__ import annotations

import pytest

from tests.utils.throwaway_runner import (
    ACT_JOB_CONTAINER_MARKER,
    OPT_IN,
    passwd_home_write_refusal,
)

pytestmark = pytest.mark.unit

JOB = {"GITHUB_ACTIONS": "true", OPT_IN: "1"}
HOSTED = {**JOB, "RUNNER_ENVIRONMENT": "github-hosted"}


def _refusal(environ, directories=()):
    return passwd_home_write_refusal(environ, lambda path: path in directories)


@pytest.mark.parametrize(
    "environ, directories, allowed",
    [
        (HOSTED, (), True),
        ({**JOB, "ACT": "true"}, (ACT_JOB_CONTAINER_MARKER,), True),
        ({**JOB, "ACT": ""}, (ACT_JOB_CONTAINER_MARKER,), True),
        ({}, (), False),
        ({"RUNNER_ENVIRONMENT": "github-hosted"}, (), False),
        ({"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, (), False),
        ({**HOSTED, OPT_IN: "0"}, (), False),
        ({**HOSTED, "GITHUB_ACTIONS": "false"}, (), False),
        (JOB, (), False),
        ({**JOB, "RUNNER_ENVIRONMENT": "self-hosted"}, (), False),
        ({**HOSTED, "ACT": "true"}, (), False),
        ({**HOSTED, "ACT": "true"}, ("/.dockerenv", "/run/.containerenv"), False),
        (
            {"ACT": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
            (ACT_JOB_CONTAINER_MARKER,),
            False,
        ),
    ],
    ids=[
        "github-hosted-job-that-opts-in",
        "act-job-container",
        "act-set-empty-in-its-job-container",
        "nothing",
        "runner-variable-exported-by-hand",
        "actions-and-runner-variables-without-the-opt-in",
        "opt-in-not-1",
        "github-actions-not-true",
        "no-runner-environment",
        "self-hosted-runner",
        "act-on-the-host",
        "act-in-a-dev-container",
        "act-without-the-opt-in",
    ],
)
def test_the_passwd_home_is_written_only_in_a_job_that_opts_in(
    environ, directories, allowed
):
    refusal = _refusal(environ, directories)

    if allowed:
        assert refusal is None
    else:
        assert refusal, "a refusal has to say why"


def test_the_reasons_name_what_is_missing():
    assert "GITHUB_ACTIONS" in _refusal({})
    assert OPT_IN in _refusal({"GITHUB_ACTIONS": "true"})
    assert ACT_JOB_CONTAINER_MARKER in _refusal({**JOB, "ACT": "true"})
    assert "RUNNER_ENVIRONMENT" in _refusal(JOB)


def test_it_reads_the_process_environment_by_default(monkeypatch):
    monkeypatch.delenv(OPT_IN, raising=False)

    assert passwd_home_write_refusal() is not None
