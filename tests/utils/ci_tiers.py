# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The job ids of the three test tiers in ``ash-unified-ci.yml``, in one place.

Several tests read the unified workflow by tier: the shard and parity checks, the job
counts, the required-checks census and the step gates. Each used to keep its own copy of
these tuples, so adding a runner pool meant editing four files that could drift apart.
They import the ids from here instead.

Each tier is three jobs, one per runner pool, so every pool has its own ``max-parallel``
cap. The workflow's comments call the three unit jobs one family, "unit-test", which is
also what each of their check names starts with. The integration tier's ids end in the
pool name too, since the single ``integration-test`` job (the one that installs the real
scanners) already owns that name.
"""

from __future__ import annotations

#: The runner pools, in the order every family lists its three jobs.
POOLS = ("linux", "macos", "windows")

#: The unit tier: ``-m unit``, unsharded.
UNIT_TEST_JOB_IDS = tuple(f"unit-test-{pool}" for pool in POOLS)

#: The integration tier: ``-m integration``, with a shard axis.
INTEGRATION_TEST_JOB_IDS = tuple(f"integration-test-{pool}" for pool in POOLS)

#: The e2e tier: ``-m e2e``, with neither a shard axis nor a Python axis.
E2E_TEST_JOB_IDS = tuple(f"e2e-test-{pool}" for pool in POOLS)

#: The six jobs of the integration and e2e tiers, which carry the same job-level condition.
TIER_JOB_IDS = (*INTEGRATION_TEST_JOB_IDS, *E2E_TEST_JOB_IDS)
