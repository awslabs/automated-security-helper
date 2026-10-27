# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Releasing a scope nothing holds does not close it.

A release pairs with a hold. An extra release -- a double-release bug, or a
release on a path where the hold was never taken -- must not tear down a live
scope that other writers still log under: handlers would retire mid-run and
the run's remaining lines would lose their home. The scope stays open and the
mismatch is ignored; only the last of the real holders closes it.
"""

from automated_security_helper.utils import log as ash_log


def test_an_unheld_release_leaves_a_live_scope_open():
    scope, token = ash_log.open_run_log_scope()
    try:
        ash_log.release_run_log_scope(scope)
        assert scope in ash_log._ACTIVE_RUN_LOG_SCOPES, (
            "a release with no matching hold closed the live scope"
        )
        # The real holders still work: one hold, one release, closed.
        ash_log.hold_run_log_scope(scope)
        ash_log.release_run_log_scope(scope)
        assert scope not in ash_log._ACTIVE_RUN_LOG_SCOPES, (
            "the last real holder's release did not close the scope"
        )
    finally:
        ash_log.disown_run_log_scope(token)
        ash_log.close_run_log_scope(scope)
