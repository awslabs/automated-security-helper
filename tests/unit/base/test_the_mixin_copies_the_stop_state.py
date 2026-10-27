# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv tool mixin copies the could-not-stop state of a returned run.

A failed wait ASH could not stop arrives as post_run_error with the state set
and an error carrying no marker text, so only the recorded state can put it on
the scanner.
"""

from base.test_scanner_spawn_failure import _uv_scanner_whose_run_returns


class _PostRunCarrier:
    """A failed wait ASH could not stop: post_run_error, no code, the carrier set,
    and an error with no marker text. Not a timeout, so no shape stands in."""

    args = ["uv", "tool", "run"]
    stdout = ""
    stderr = "tool-err\n"
    returncode = None
    post_run_error = True
    could_not_stop = True
    error = "reading the output failed"


def test_the_mixin_copies_the_carrier_of_a_returned_run(tmp_path, monkeypatch):
    scanner = _uv_scanner_whose_run_returns(tmp_path, monkeypatch, _PostRunCarrier())
    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )
    assert response.get("post_run_error") is True, response
    assert response.get("could_not_stop") is True, response
    assert scanner.scan_could_not_stop, scanner.scan_could_not_stop
