"""Deliberately vulnerable fixture. bandit has to find something here.

This file exists so the end-to-end test can tell a working pipeline from one that
always reports clean. If a scan of this tree returns zero findings, the test fails:
a green scan of a tree with a known finding in it is the failure mode that looks
most like success, and given that `ash scan` checks source/output collision by
equality only, it is also a reachable one.
"""

import subprocess


def run_user_command(user_input):
    # bandit B602: subprocess call with shell=True. The point of the fixture.
    return subprocess.call(user_input, shell=True)  # noqa: S602


def evaluate(expression):
    # bandit B307: use of eval. Also the point of the fixture.
    return eval(expression)  # noqa: S307
