# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plan names the private cache directory its backend made, for the sweep.

_private_caches makes one directory under the results directory and gives each
redirected cache variable a subdirectory of it. It returns the cleanup step that
removes the directory and the directory itself, which the backends put in
SpawnPlan.private_dirs so the spawn's sweep passes it over. With nothing to
redirect, both are empty, and a plan built without the field names no directory.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.sandbox import backends
from automated_security_helper.utils.sandbox.backends import SpawnPlan

pytestmark = pytest.mark.unit


def test_the_private_cache_directory_is_returned_with_its_cleanup(tmp_path):
    policy = SimpleNamespace(cache_env=["UV_CACHE_DIR"], results_dir=tmp_path)
    env = {"UV_CACHE_DIR": "/shared/uv"}

    cleanup, private_dirs = backends._private_caches(policy, env)

    assert len(private_dirs) == 1
    private = private_dirs[0]
    assert private.parent == tmp_path
    assert private.name.startswith(".sandbox-cache-")
    assert env["UV_CACHE_DIR"] == (private / "uv_cache_dir").as_posix()
    assert Path(env["UV_CACHE_DIR"]).is_dir()
    assert len(cleanup) == 1
    cleanup[0]()
    assert not private.exists()


def test_nothing_to_redirect_names_no_directory(tmp_path):
    policy = SimpleNamespace(cache_env=[], results_dir=tmp_path)

    assert backends._private_caches(policy, {}) == ([], [])
    assert list(tmp_path.iterdir()) == []


def test_a_plan_built_without_the_field_names_no_directory():
    assert SpawnPlan(argv=["tool"], env={}).private_dirs == []
